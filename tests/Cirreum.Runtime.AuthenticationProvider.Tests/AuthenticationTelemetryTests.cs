namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum;
using Cirreum.Authentication;
using Cirreum.AuthenticationProvider;
using Cirreum.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using System.Diagnostics.Metrics;
using System.Security.Claims;

/// <summary>
/// Locks the authentication telemetry contract: instrument names, tag names, and the tag
/// set each recording method emits.
/// </summary>
/// <remarks>
/// <para>
/// Every test tags its measurements with a scheme value unique to that test and filters the
/// capture on it. The meter is a process-wide static, so a listener would otherwise observe
/// measurements from tests running in parallel.
/// </para>
/// <para>
/// The instrument-name assertions are not tautologies against the constants: they assert the
/// literal strings, because the meter and instrument names are one half of a cross-package
/// contract with Kernel's <c>AddCirreum()</c> registration. A rename that updated only the
/// constant would leave the instrument unsubscribed and silently inert.
/// </para>
/// </remarks>
public class AuthenticationTelemetryTests {

	private sealed record Recorded(string Instrument, double Value, Dictionary<string, object?> Tags);

	private sealed class MetricCapture : IDisposable {

		private readonly MeterListener _listener = new();
		private readonly List<Recorded> _recorded = [];
		private readonly Lock _gate = new();

		public MetricCapture() {
			this._listener.InstrumentPublished = (instrument, listener) => {
				if (instrument.Meter.Name == CirreumTelemetry.Meters.Authentication) {
					listener.EnableMeasurementEvents(instrument);
				}
			};
			this._listener.SetMeasurementEventCallback<long>(
				(instrument, value, tags, _) => this.Add(instrument, value, tags));
			this._listener.SetMeasurementEventCallback<double>(
				(instrument, value, tags, _) => this.Add(instrument, value, tags));
			this._listener.Start();
		}

		private void Add(Instrument instrument, double value, ReadOnlySpan<KeyValuePair<string, object?>> tags) {
			Dictionary<string, object?> copy = [];
			foreach (var tag in tags) {
				copy[tag.Key] = tag.Value;
			}
			lock (this._gate) {
				this._recorded.Add(new(instrument.Name, value, copy));
			}
		}

		/// <summary>Measurements carrying the given scheme tag — this test's own, and no other's.</summary>
		public IReadOnlyList<Recorded> ForScheme(string scheme) {
			lock (this._gate) {
				return [.. this._recorded.Where(r =>
					r.Tags.TryGetValue(AuthenticationTelemetry.SchemeTag, out var v) && (string?)v == scheme)];
			}
		}

		public void Dispose() => this._listener.Dispose();
	}

	private static AudienceProviderRoleClaimsTransformer TransformerFor(
		HttpContext context, params IApplicationUserResolver[] resolvers) {
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		return new(resolvers, accessor, NullLogger<AudienceProviderRoleClaimsTransformer>.Instance);
	}

	private static IApplicationUserResolver ResolverFor(string? scheme, params string[] roles) {
		var user = Substitute.For<IApplicationUser>();
		user.Roles.Returns(roles);
		var resolver = Substitute.For<IApplicationUserResolver>();
		resolver.Scheme.Returns(scheme);
		resolver.ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
			.Returns(Task.FromResult<IApplicationUser?>(user));
		return resolver;
	}

	[Fact]
	public void InstrumentNames_MatchTheRegisteredCrossPackageContract() {
		// Dot-separated segments; underscores only within a segment; no _total suffix.
		AuthenticationTelemetry.TransformationsMetric.Should().Be("cirreum.authn.transformations");
		AuthenticationTelemetry.TransformationDurationMetric.Should().Be("cirreum.authn.transformation.duration");
		AuthenticationTelemetry.SelectionsMetric.Should().Be("cirreum.authn.selections");

		AuthenticationTelemetry.SchemeTag.Should().Be("cirreum.authn.scheme");
		AuthenticationTelemetry.OutcomeTag.Should().Be("cirreum.authn.outcome");
		AuthenticationTelemetry.ResolverTag.Should().Be("cirreum.authn.resolver");
		AuthenticationTelemetry.SelectorTag.Should().Be("cirreum.authn.selector");
		AuthenticationTelemetry.RoleClaimTypeTag.Should().Be("cirreum.authn.role_claim_type");
	}

	[Fact]
	public void StartTransformActivity_IsInternal_NotAnEntryPointSpan() {
		// Transformation neither receives work nor sends it — it runs inside the ASP.NET
		// request pipeline, always as a child of the server span that already accepted the
		// request. Using the host-dependent DomainContext.EntryPointActivityKind here would,
		// on a server host, mark this as a second Server span for one request and draw the
		// wrong graph.
		using var listener = new System.Diagnostics.ActivityListener {
			ShouldListenTo = source => source.Name == CirreumTelemetry.ActivitySources.Authentication,
			Sample = (ref System.Diagnostics.ActivityCreationOptions<System.Diagnostics.ActivityContext> _)
				=> System.Diagnostics.ActivitySamplingResult.AllData
		};
		System.Diagnostics.ActivitySource.AddActivityListener(listener);

		using var activity = AuthenticationTelemetry.StartTransformActivity("SomeTransformer");

		activity.Should().NotBeNull();
		activity!.Kind.Should().Be(System.Diagnostics.ActivityKind.Internal);
		activity.GetTagItem(AuthenticationTelemetry.TransformerTag).Should().Be("SomeTransformer");
	}

	[Fact]
	public void RecordSchemeSelection_EmitsCounter_TaggedWithSchemeAndSelector() {
		using var capture = new MetricCapture();

		AuthenticationTelemetry.RecordSchemeSelection("selection-tagged", "JwtAudienceSchemeSelector");

		var measurement = capture.ForScheme("selection-tagged").Should().ContainSingle().Subject;
		measurement.Instrument.Should().Be(AuthenticationTelemetry.SelectionsMetric);
		measurement.Value.Should().Be(1);
		measurement.Tags[AuthenticationTelemetry.SelectorTag].Should().Be("JwtAudienceSchemeSelector");
	}

	[Fact]
	public void RecordSchemeSelection_NothingClaimed_IsDistinguishableFromAClaimedRequest() {
		// The backlog's "how often does selection find no match" question: an unclaimed
		// request must not look like a successful Anonymous selection.
		using var capture = new MetricCapture();

		AuthenticationTelemetry.RecordSchemeSelection("selection-unclaimed", AuthenticationTelemetry.SelectorNone);

		var measurement = capture.ForScheme("selection-unclaimed").Should().ContainSingle().Subject;
		measurement.Tags[AuthenticationTelemetry.SelectorTag].Should().Be("none");
	}

	[Fact]
	public void RecordTransformation_EmitsBothCounterAndDuration() {
		using var capture = new MetricCapture();

		AuthenticationTelemetry.RecordTransformation(
			activity: null,
			AuthenticationTelemetry.OutcomeRolesResolved,
			scheme: "transform-both",
			resolver: "FakeResolver",
			durationMs: 12.5);

		var measurements = capture.ForScheme("transform-both");
		measurements.Should().HaveCount(2);

		var counter = measurements.Single(m => m.Instrument == AuthenticationTelemetry.TransformationsMetric);
		counter.Value.Should().Be(1);
		counter.Tags[AuthenticationTelemetry.OutcomeTag].Should().Be("roles-resolved");
		counter.Tags[AuthenticationTelemetry.ResolverTag].Should().Be("FakeResolver");

		var duration = measurements.Single(m => m.Instrument == AuthenticationTelemetry.TransformationDurationMetric);
		duration.Value.Should().Be(12.5);
		duration.Tags[AuthenticationTelemetry.OutcomeTag].Should().Be("roles-resolved");

		// Deliberate: buckets multiply per series, so the resolver dimension stays on the
		// counter and off the histogram.
		duration.Tags.Should().NotContainKey(AuthenticationTelemetry.ResolverTag);
	}

	[Fact]
	public async Task Transformer_TagsTheCounterWithTheResolvedScheme() {
		// The gap that made this item worth doing: the authenticated scheme is the single
		// authoritative answer to "which IdP handled this request", so it has to be a metric
		// dimension, not activity-only.
		using var capture = new MetricCapture();
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "scheme-distribution";
		var transformer = TransformerFor(context, ResolverFor("scheme-distribution", "admin"));

		await transformer.TransformAsync(new ClaimsPrincipal(
			new ClaimsIdentity([new Claim("sub", "user-1")], "AuthenticationTypes.Federation")));

		var counter = capture.ForScheme("scheme-distribution")
			.Single(m => m.Instrument == AuthenticationTelemetry.TransformationsMetric);
		counter.Tags[AuthenticationTelemetry.OutcomeTag].Should().Be(AuthenticationTelemetry.OutcomeRolesResolved);
	}

	[Fact]
	public async Task Transformer_NeverPutsTheExternalUserIdOnAMetricTag() {
		// Unbounded cardinality — one time series per user would be a metrics-backend
		// incident. It belongs on the activity only.
		using var capture = new MetricCapture();
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "no-user-id-tag";
		var transformer = TransformerFor(context, ResolverFor("no-user-id-tag", "admin"));

		await transformer.TransformAsync(new ClaimsPrincipal(
			new ClaimsIdentity([new Claim("sub", "unbounded-user-identifier")], "AuthenticationTypes.Federation")));

		capture.ForScheme("no-user-id-tag").Should().NotBeEmpty()
			.And.AllSatisfy(m => m.Tags.Values.Should().NotContain("unbounded-user-identifier"));
	}

	[Fact]
	public async Task Transformer_ReentrantCall_RecordsTheAlreadyTransformedOutcome() {
		// "Is the transformer being hit more than once per request?" — answerable from the
		// counter alone.
		using var capture = new MetricCapture();
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "reentrant";
		var transformer = TransformerFor(context, ResolverFor("reentrant", "admin"));
		var principal = new ClaimsPrincipal(
			new ClaimsIdentity([new Claim("sub", "user-1")], "AuthenticationTypes.Federation"));

		await transformer.TransformAsync(principal);
		await transformer.TransformAsync(principal);

		var outcomes = capture.ForScheme("reentrant")
			.Where(m => m.Instrument == AuthenticationTelemetry.TransformationsMetric)
			.Select(m => (string?)m.Tags[AuthenticationTelemetry.OutcomeTag])
			.ToList();

		outcomes.Should().BeEquivalentTo([
			AuthenticationTelemetry.OutcomeRolesResolved,
			AuthenticationTelemetry.OutcomeAlreadyTransformed]);
	}

	[Fact]
	public async Task Transformer_ResolverThrows_RecordsTheFailureOutcome() {
		// "How often does a scheme's resolver fail?" — attributable to a scheme because the
		// failure outcome carries the scheme tag.
		using var capture = new MetricCapture();
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "resolver-throws";
		var resolver = Substitute.For<IApplicationUserResolver>();
		resolver.Scheme.Returns("resolver-throws");
		resolver.ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>())
			.Returns<Task<IApplicationUser?>>(_ => throw new InvalidOperationException("store offline"));
		var transformer = TransformerFor(context, resolver);

		await transformer.TransformAsync(new ClaimsPrincipal(
			new ClaimsIdentity([new Claim("sub", "user-1")], "AuthenticationTypes.Federation")));

		var counter = capture.ForScheme("resolver-throws")
			.Single(m => m.Instrument == AuthenticationTelemetry.TransformationsMetric);
		counter.Tags[AuthenticationTelemetry.OutcomeTag]
			.Should().Be(AuthenticationTelemetry.OutcomeRoleResolutionFailed);
	}

}
