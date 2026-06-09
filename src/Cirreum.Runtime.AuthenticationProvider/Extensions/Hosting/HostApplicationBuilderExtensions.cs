namespace Microsoft.Extensions.Hosting;

using Cirreum.AuthenticationProvider;
using Cirreum.AuthenticationProvider.Configuration;
using Cirreum.Logging.Deferred;
using Cirreum.Providers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Hosting extensions for the Authentication track. Provides the typed
/// <see cref="RegisterAuthenticationProvider"/> bootstrap that the umbrella package
/// (<c>Cirreum.Runtime.Authentication</c>) calls once per framework-shipped
/// scheme registrar.
/// </summary>
public static class HostApplicationBuilderExtensions {

	/// <summary>
	/// Reads the provider's configuration section at
	/// <c>Cirreum:Authentication:Providers:{ProviderName}</c>, binds it to
	/// <typeparamref name="TSettings"/>, instantiates <typeparamref name="TRegistrar"/>,
	/// and calls its
	/// <see cref="AuthenticationProviderRegistrar{TSettings, TInstanceSettings}.Register"/>
	/// method to wire schemes / handlers / selectors / supporting services.
	/// </summary>
	/// <typeparam name="TRegistrar">The scheme registrar type.</typeparam>
	/// <typeparam name="TSettings">The provider's settings type (collection of instances).</typeparam>
	/// <typeparam name="TInstanceSettings">The provider's per-instance settings type.</typeparam>
	/// <param name="builder">The host application builder.</param>
	/// <param name="authBuilder">The ASP.NET Core authentication builder.</param>
	/// <param name="required">When <see langword="true"/>, throws if the provider's
	/// configuration section is missing. Default <see langword="false"/> — apps that
	/// don't configure a provider skip its registration silently.</param>
	/// <returns>The host application builder for chaining.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the configuration
	/// section exists but cannot be bound to <typeparamref name="TSettings"/>, or
	/// when <paramref name="required"/> is <see langword="true"/> and the section is
	/// missing.</exception>
	/// <remarks>
	/// <para>
	/// Composition is explicit: the umbrella package calls this method once per
	/// framework-shipped registrar (ApiKey, SignedRequest, SessionTicket,
	/// Entra, Oidc, External). Apps that add custom schemes call this method
	/// themselves with their own registrar type — same mechanism, no parallel
	/// discovery contract.
	/// </para>
	/// <para>
	/// Idempotent per registrar type: subsequent calls with the same
	/// <typeparamref name="TRegistrar"/> are no-ops (logged at Debug). This makes
	/// the umbrella's composition robust to apps that re-register a Cirreum-shipped
	/// scheme alongside their own custom variant.
	/// </para>
	/// </remarks>
	public static IHostApplicationBuilder RegisterAuthenticationProvider<TRegistrar, TSettings, TInstanceSettings>(
		this IHostApplicationBuilder builder,
		AuthenticationBuilder authBuilder,
		bool required = false)
		where TRegistrar : AuthenticationProviderRegistrar<TSettings, TInstanceSettings>, new()
		where TSettings : AuthenticationProviderSettings<TInstanceSettings>
		where TInstanceSettings : AuthenticationProviderInstanceSettings {

		ArgumentNullException.ThrowIfNull(builder);
		ArgumentNullException.ThrowIfNull(authBuilder);

		var registrarName = typeof(TRegistrar).Name;
		var deferredLogger = Logger.CreateDeferredLogger();

		using (deferredLogger.BeginScope(new { RegistrarName = registrarName })) {

			if (builder.Services.IsMarkerTypeRegistered<TRegistrar>()) {
				deferredLogger.LogDebug(
					"Duplicate request for {RegistrarName} skipped.",
					registrarName);
				return builder;
			}

			builder.Services.MarkTypeAsRegistered<TRegistrar>();

			var registrar = new TRegistrar();
			var sectionKey = GetProviderConfigPath(registrar.ProviderType, registrar.ProviderName);
			var section = builder.Configuration.GetSection(sectionKey);
			if (!section.Exists()) {
				if (required) {
					throw new InvalidOperationException(
						$"Configuration required but not found for '{registrarName}' at '{sectionKey}'.");
				}

				deferredLogger.LogDebug(
					"Skipping '{RegistrarName}' — no configuration found at '{SectionKey}'.",
					registrarName,
					sectionKey);
				return builder;
			}

			var providerSettings = section.Get<TSettings>()
				?? throw new InvalidOperationException(
					$"Invalid configuration for '{registrarName}' — section exists but cannot be bound to settings.");

			// Call Register even when Instances is empty — the registrar may stash
			// provider-level state (e.g. BearerPrefix for the ApiKey track) that
			// downstream composition (e.g. AddNamedSource&lt;T&gt; / AddDefaultSource&lt;T&gt;) reads at
			// composition time. The registrar's implementation is responsible for
			// handling the empty-Instances case appropriately.
			registrar.Register(
				providerSettings,
				builder.Services,
				builder.Configuration,
				authBuilder);

			deferredLogger.LogDebug(
				"Registered {InstanceCount} provider instances for {RegistrarName}.",
				providerSettings.Instances.Count,
				registrarName);
		}

		return builder;
	}

	private static string GetProviderConfigPath(ProviderType providerType, string providerName) =>
		$"Cirreum:{providerType}:Providers:{providerName}";

}
