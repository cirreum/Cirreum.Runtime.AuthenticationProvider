namespace Cirreum.AuthenticationProvider;

using Cirreum.Diagnostics;
using System.Diagnostics;
using System.Diagnostics.Metrics;

/// <summary>
/// Diagnostics for the Authentication runtime. Produces traces and metrics
/// consumed by the OpenTelemetry pipeline subscribed by the umbrella package
/// (<c>Cirreum.Runtime.Authentication</c>).
/// </summary>
/// <remarks>
/// The source and meter names come from <see cref="CirreumTelemetry"/> rather than local
/// literals. Those constants are the registration half of a cross-package contract — Kernel's
/// <c>AddCirreum()</c> subscribes exactly those names, and a source or meter whose name is never
/// registered is silently inert, recording into the void with no listener attached. Restating the
/// literal here would let the two drift apart with nothing failing to say so.
/// </remarks>
public static class AuthenticationProviderDiagnostics {

	/// <summary>
	/// Metric: total claims transformations performed, tagged with the transformer name.
	/// </summary>
	/// <remarks>
	/// Dot-separated, matching every other instrument in the framework
	/// (<c>cirreum.authz.decisions</c>, <c>conductor.operations.total</c>). Underscores separate
	/// words <em>within</em> a segment; they never separate segments. The <c>_total</c> suffix is
	/// also dropped — it is a Prometheus exposition detail an exporter appends, not part of the
	/// instrument name.
	/// </remarks>
	public const string TransformationsMetric = "cirreum.authn.transformations";

	internal static readonly ActivitySource ActivitySource =
		new(CirreumTelemetry.ActivitySources.Authentication, CirreumTelemetry.Version);

	internal static readonly Meter Meter =
		new(CirreumTelemetry.Meters.Authentication, CirreumTelemetry.Version);
	internal static readonly Counter<long> TransformCounter = Meter.CreateCounter<long>(TransformationsMetric);

}
