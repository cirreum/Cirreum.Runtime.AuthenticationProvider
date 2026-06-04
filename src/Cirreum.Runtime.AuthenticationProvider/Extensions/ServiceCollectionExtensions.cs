namespace Cirreum.AuthenticationProvider;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Service-collection extensions for the Authentication runtime.
/// </summary>
public static class ServiceCollectionExtensions {

	/// <summary>
	/// Registers the framework-shipped audience-based role claims transformation
	/// pipeline (<see cref="AudienceProviderRoleClaimsTransformer"/>) and its
	/// dependencies. The umbrella package (<c>Cirreum.Runtime.Authentication</c>) calls
	/// this once during composition; apps don't typically call it directly.
	/// </summary>
	/// <param name="services">The service collection.</param>
	/// <returns>The service collection for chaining.</returns>
	public static IServiceCollection AddAudienceRoleClaimsTransformation(this IServiceCollection services) {
		services.AddHttpContextAccessor();
		services.AddScoped<IClaimsTransformation, AudienceProviderRoleClaimsTransformer>();
		return services;
	}

}
