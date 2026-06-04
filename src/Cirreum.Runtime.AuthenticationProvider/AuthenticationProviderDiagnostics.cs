namespace Cirreum.AuthenticationProvider;

using System.Diagnostics;
using System.Diagnostics.Metrics;

/// <summary>
/// Diagnostics for the Authentication runtime. Produces traces and metrics
/// consumed by the OpenTelemetry pipeline subscribed by the umbrella package
/// (<c>Cirreum.Runtime.Authentication</c>).
/// </summary>
/// <remarks>
/// The claims-transformer runtime diagnostics live alongside the transformer
/// itself — the umbrella package subscribes them via the shared
/// <see cref="DiagnosticName"/> constant.
/// </remarks>
public static class AuthenticationProviderDiagnostics {

	/// <summary>
	/// Diagnostic name for the ActivitySource and Meter. Referenced by the umbrella
	/// package to subscribe to telemetry.
	/// </summary>
	public const string DiagnosticName = "Cirreum.Authentication";

	internal static readonly ActivitySource ActivitySource = new(DiagnosticName);
	internal static readonly Meter Meter = new(DiagnosticName);
	internal static readonly Counter<long> TransformCounter = Meter.CreateCounter<long>("auth_transformations_total");

}
