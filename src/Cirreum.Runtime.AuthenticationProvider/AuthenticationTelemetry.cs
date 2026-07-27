namespace Cirreum.AuthenticationProvider;

using Cirreum.Diagnostics;
using System.Diagnostics;
using System.Diagnostics.Metrics;

/// <summary>
/// Centralized telemetry for the Cirreum authentication pipeline. Publishes a shared
/// <see cref="ActivitySource"/> and <see cref="Meter"/>, plus stable tag-name, outcome
/// and metric-name constants used by every authentication emitter.
/// </summary>
/// <remarks>
/// <para>
/// The source and meter names come from <see cref="CirreumTelemetry"/> rather than local
/// literals. Those constants are the registration half of a cross-package contract — Kernel's
/// <c>AddCirreum()</c> subscribes exactly those names, and a source or meter whose name is never
/// registered is silently inert, recording into the void with no listener attached. Restating the
/// literal here would let the two drift apart with nothing failing to say so.
/// </para>
/// <para>
/// Instrument and tag names are dot-separated; underscores separate words <em>within</em> a
/// segment and never separate segments. Metric names carry no <c>_total</c> suffix — that is a
/// Prometheus exposition detail an exporter appends, not part of the instrument name.
/// </para>
/// <para>
/// The high-cardinality external user identifier is deliberately absent from every metric tag
/// set. It belongs on the <see cref="Activity"/>, where a single trace carries it, not on a
/// counter dimension that would mint one time series per user.
/// </para>
/// </remarks>
public static class AuthenticationTelemetry {

	// Outcome values ———————————————————————————————————————————

	/// <summary>Outcome: no <c>HttpContext</c> was available, so the transformation could not run.</summary>
	public const string OutcomeNoHttpContext = "no-http-context";

	/// <summary>Outcome: the request had already been transformed on an earlier pass.</summary>
	public const string OutcomeAlreadyTransformed = "already-transformed";

	/// <summary>Outcome: the principal's identity was not a <see cref="System.Security.Claims.ClaimsIdentity"/>.</summary>
	public const string OutcomeNoClaimsIdentity = "no-claims-identity";

	/// <summary>Outcome: no <see cref="IApplicationUserResolver"/> matched the request's scheme, and no null-scheme fallback was registered.</summary>
	public const string OutcomeNoResolver = "no-resolver";

	/// <summary>Outcome: the principal already carried role claims, so the resolver was not consulted.</summary>
	public const string OutcomeRolesAlreadyPresent = "roles-already-present";

	/// <summary>Outcome: no supported user-identifier claim was present on the principal.</summary>
	public const string OutcomeNoUserIdentifier = "no-user-identifier";

	/// <summary>Outcome: the resolver ran but the application store held no user for the identifier.</summary>
	public const string OutcomeNoApplicationUser = "no-application-user";

	/// <summary>Outcome: an application user was resolved but carried no roles.</summary>
	public const string OutcomeNoRolesResolved = "no-roles-resolved";

	/// <summary>Outcome: roles were resolved and added to the identity.</summary>
	public const string OutcomeRolesResolved = "roles-resolved";

	/// <summary>Outcome: the resolver threw.</summary>
	public const string OutcomeRoleResolutionFailed = "role-resolution-failed";

	/// <summary>
	/// Selector tag value used when no <c>ISchemeSelector</c> claimed the request and the
	/// resolver fell through to its default. Distinguishes "the Anonymous selector claimed"
	/// from "nothing claimed at all" — the latter means the selector set is misconfigured.
	/// </summary>
	public const string SelectorNone = "none";

	// Tag names ————————————————————————————————————————————————

	/// <summary>Tag: the authentication scheme that handled the request.</summary>
	public const string SchemeTag = "cirreum.authn.scheme";

	/// <summary>Tag: transformation outcome — one of the <c>Outcome*</c> constants.</summary>
	public const string OutcomeTag = "cirreum.authn.outcome";

	/// <summary>Tag: the concrete <see cref="IApplicationUserResolver"/> type name.</summary>
	public const string ResolverTag = "cirreum.authn.resolver";

	/// <summary>Tag: the <c>ISchemeSelector</c> type name that claimed the request, or <see cref="SelectorNone"/>.</summary>
	public const string SelectorTag = "cirreum.authn.selector";

	/// <summary>Tag: the <see cref="Microsoft.AspNetCore.Authentication.IClaimsTransformation"/> type name.</summary>
	public const string TransformerTag = "cirreum.authn.transformer";

	/// <summary>Tag: the claim type roles are read from and written to.</summary>
	public const string RoleClaimTypeTag = "cirreum.authn.role_claim_type";

	/// <summary>Tag: the number of roles resolved and added. Activity only.</summary>
	public const string RoleCountTag = "cirreum.authn.role_count";

	/// <summary>Tag: the external user identifier. Activity only — never a metric dimension.</summary>
	public const string UserIdTag = "cirreum.authn.user_id";

	// Metrics ——————————————————————————————————————————————————

	/// <summary>Metric: total claims transformations, tagged with outcome/scheme/resolver.</summary>
	public const string TransformationsMetric = "cirreum.authn.transformations";

	/// <summary>Metric: claims transformation duration in milliseconds, tagged with outcome/scheme.</summary>
	public const string TransformationDurationMetric = "cirreum.authn.transformation.duration";

	/// <summary>Metric: total scheme selections, tagged with the resolved scheme and the claiming selector.</summary>
	public const string SelectionsMetric = "cirreum.authn.selections";

	// ActivitySource / Meter ————————————————————————————————

	internal static readonly ActivitySource ActivitySource =
		new(CirreumTelemetry.ActivitySources.Authentication, CirreumTelemetry.Version);

	private static readonly Meter _meter =
		new(CirreumTelemetry.Meters.Authentication, CirreumTelemetry.Version);

	private static readonly Counter<long> _transformationsCounter = _meter.CreateCounter<long>(
		TransformationsMetric,
		description: "Total number of claims transformations performed by the Cirreum authentication pipeline");

	private static readonly Histogram<double> _transformationDuration = _meter.CreateHistogram<double>(
		TransformationDurationMetric,
		unit: "ms",
		description: "Claims transformation duration in milliseconds");

	private static readonly Counter<long> _selectionsCounter = _meter.CreateCounter<long>(
		SelectionsMetric,
		description: "Total number of authentication scheme selections, by resolved scheme and claiming selector");

	// Activity management ——————————————————————————————————

	/// <summary>
	/// Starts the claims-transformation activity. Returns <see langword="null"/> when no
	/// listeners are attached — every caller null-checks the activity.
	/// </summary>
	/// <param name="transformer">The transformer type name, recorded as <see cref="TransformerTag"/>.</param>
	public static Activity? StartTransformActivity(string transformer) {
		var activity = ActivitySource.StartActivity("ClaimsTransformation");
		activity?.SetTag(TransformerTag, transformer);
		return activity;
	}

	// Claims transformation ————————————————————————————————

	/// <summary>
	/// Records a completed claims transformation: increments the transformation counter,
	/// records the duration, and tags the activity with the outcome.
	/// </summary>
	/// <param name="activity">The activity started by <see cref="StartTransformActivity"/>, or <see langword="null"/>.</param>
	/// <param name="outcome">One of the <c>Outcome*</c> constants.</param>
	/// <param name="scheme">The authentication scheme the request was dispatched through, when known.</param>
	/// <param name="resolver">The resolver type name, when resolution was attempted.</param>
	/// <param name="roleClaimType">The role claim type in effect, when an identity was present.</param>
	/// <param name="roleCount">The number of roles added, when any were.</param>
	/// <param name="durationMs">Elapsed transformation time in milliseconds.</param>
	public static void RecordTransformation(
		Activity? activity,
		string outcome,
		string? scheme = null,
		string? resolver = null,
		string? roleClaimType = null,
		int? roleCount = null,
		double durationMs = 0) {

		if (activity is not null) {
			activity.SetTag(OutcomeTag, outcome);
			if (scheme is not null) {
				activity.SetTag(SchemeTag, scheme);
			}
			if (resolver is not null) {
				activity.SetTag(ResolverTag, resolver);
			}
			if (roleClaimType is not null) {
				activity.SetTag(RoleClaimTypeTag, roleClaimType);
			}
			if (roleCount.HasValue) {
				activity.SetTag(RoleCountTag, roleCount.Value);
			}
			activity.SetStatus(outcome == OutcomeRoleResolutionFailed
				? ActivityStatusCode.Error
				: ActivityStatusCode.Ok);
		}

		var tags = new TagList {
			{ OutcomeTag, outcome }
		};

		if (scheme is not null) {
			tags.Add(SchemeTag, scheme);
		}

		// The duration histogram takes the lower-cardinality subset — outcome and scheme.
		// Buckets multiply per series, so the resolver dimension stays on the counter.
		_transformationDuration.Record(durationMs, tags);

		if (resolver is not null) {
			tags.Add(ResolverTag, resolver);
		}

		_transformationsCounter.Add(1, tags);
	}

	// Scheme selection ——————————————————————————————————————

	/// <summary>
	/// Records the outcome of dynamic scheme selection for one request. Called by the
	/// authentication umbrella's forward-scheme resolver, which is the single site every
	/// <c>ISchemeSelector</c> is dispatched through — so one call here covers every selector
	/// the app has registered, framework-shipped or not.
	/// </summary>
	/// <param name="scheme">The scheme the request resolved to.</param>
	/// <param name="selector">
	/// The type name of the selector that claimed the request, or <see cref="SelectorNone"/>
	/// when none did and the resolver fell through to its default.
	/// </param>
	public static void RecordSchemeSelection(string scheme, string selector) {
		_selectionsCounter.Add(1, new TagList {
			{ SchemeTag, scheme },
			{ SelectorTag, selector }
		});
	}

}
