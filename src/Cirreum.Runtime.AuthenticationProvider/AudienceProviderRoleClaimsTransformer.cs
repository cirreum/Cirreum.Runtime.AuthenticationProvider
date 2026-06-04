namespace Cirreum.AuthenticationProvider;

using Cirreum;
using Cirreum.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

/// <summary>
/// ASP.NET <see cref="IClaimsTransformation"/> that enriches the principal authenticated
/// through an audience-based provider by dispatching to the per-scheme
/// <see cref="IApplicationUserResolver"/>, loading the application user, caching it on
/// <c>HttpContext.Items</c>, and adding the user's roles as
/// <see cref="ClaimTypes.Role"/> claims.
/// </summary>
/// <remarks>
/// <para>
/// Replaces the legacy
/// <c>Cirreum.AuthorizationProvider.AudienceProviderRoleClaimsTransformer</c> that
/// dispatched through <c>IRoleResolver</c>. The seam is now
/// <see cref="IApplicationUserResolver"/> directly — apps register one resolver per
/// authentication scheme via <c>CirreumAuthenticationBuilder.AddApplicationUserResolver&lt;T&gt;()</c>;
/// this transformer reads the request's <see cref="AuthenticationContextKeys.AuthenticatedScheme"/>
/// and selects the matching resolver, falling back to the resolver whose
/// <see cref="IApplicationUserResolver.Scheme"/> is <see langword="null"/>.
/// </para>
/// <para>
/// When no resolver is registered for the current scheme (and no null-scheme fallback
/// exists), the transformer is a no-op. This is the correct behavior for workforce-only
/// apps where roles arrive in the JWT directly — the framework-shipped
/// transformer doesn't fight the IdP's roles claim.
/// </para>
/// </remarks>
internal sealed partial class AudienceProviderRoleClaimsTransformer(
	IEnumerable<IApplicationUserResolver> resolvers,
	IHttpContextAccessor httpContextAccessor,
	ILogger<AudienceProviderRoleClaimsTransformer> logger
) : IClaimsTransformation {

	private const string TransformedKey = "__Cirreum_AudienceProviderRoleClaimsTransformer";
	private const string RolesName = "roles";
	private const string RoleName = "role";
	private const string Oid = "oid";
	private const string Sub = "sub";
	private const string UserId = "user_id";

	private static class WellKnownClaimTypes {
		/// <summary>Entra / Azure AD object identifier URI claim.</summary>
		public const string ObjectId = "http://schemas.microsoft.com/identity/claims/objectidentifier";
	}

	private readonly IApplicationUserResolver[] _resolvers = [.. resolvers];

	/// <inheritdoc/>
	public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal) {

		var context = httpContextAccessor.HttpContext;
		if (context is null) {
			Log.NoHttpContext(logger);
			return principal;
		}

		using var activity = AuthenticationProviderDiagnostics.ActivitySource.StartActivity("ClaimsTransformation");
		activity?.SetTag("auth.transformer.name", nameof(AudienceProviderRoleClaimsTransformer));

		if (context.Items.ContainsKey(TransformedKey)) {
			AuthenticationProviderDiagnostics.TransformCounter.Add(1, new KeyValuePair<string, object?>("outcome", "already_transformed"));
			activity?.SetTag("auth.transform.outcome", "AlreadyTransformed");
			Log.AlreadyTransformed(logger);
			return Return(principal, context, "AlreadyTransformed");
		}

		// Mark immediately — prevents re-entry if ASP.NET calls TransformAsync again
		// on the same request before the async work completes.
		context.Items[TransformedKey] = true;

		if (principal.Identity is not ClaimsIdentity identity) {
			AuthenticationProviderDiagnostics.TransformCounter.Add(1, new KeyValuePair<string, object?>("outcome", "no_claims_identity"));
			activity?.SetTag("auth.transform.outcome", "NoClaimsIdentity");
			Log.NoClaimsIdentity(logger);
			return Return(principal, context, "NoClaimsIdentity");
		}

		// Defensive stamp of the canonical scheme key for routes wired to an explicit
		// scheme that bypass the dynamic ForwardDefaultSelector. TryAdd preserves the
		// forward selector's value when both run.
		context.Items.TryAdd(AuthenticationContextKeys.AuthenticatedScheme, identity.AuthenticationType);

		var scheme = identity.AuthenticationType;
		activity?.SetTag("auth.scheme", scheme);

		// Per-scheme dispatch over IApplicationUserResolver. Falls back to the
		// resolver whose Scheme is null when no per-scheme resolver matches.
		var resolver = SelectResolver(scheme);
		var resolverType = resolver?.GetType().Name;
		activity?.SetTag("auth.resolver.type", resolverType);

		if (resolver is null) {
			AuthenticationProviderDiagnostics.TransformCounter.Add(1, new KeyValuePair<string, object?>("outcome", "no_resolver"));
			activity?.SetTag("auth.transform.outcome", "NoResolver");
			Log.NoResolver(logger, scheme ?? "(null)");
			return Return(principal, context, "NoResolver", scheme: scheme);
		}

		// Skip when the principal already carries role claims (workforce IdP path).
		var roleClaimType = identity.RoleClaimType;
		activity?.SetTag("auth.role_claim_type", roleClaimType);
		if (ContainsRoles(identity, roleClaimType)) {
			AuthenticationProviderDiagnostics.TransformCounter.Add(1, new KeyValuePair<string, object?>("outcome", "roles_already_present"));
			activity?.SetTag("auth.transform.outcome", "RolesAlreadyPresent");
			Log.RolesAlreadyPresent(logger, roleClaimType);
			return Return(principal, context, "RolesAlreadyPresent", resolverType, scheme, roleClaimType: roleClaimType);
		}

		var userId = FindUserId(principal);
		if (userId is null) {
			AuthenticationProviderDiagnostics.TransformCounter.Add(1, new KeyValuePair<string, object?>("outcome", "no_user_id"));
			activity?.SetTag("auth.transform.outcome", "NoUserIdentifier");
			Log.NoUserIdentifier(logger);
			return Return(principal, context, "NoUserIdentifier", resolverType, scheme, roleClaimType: roleClaimType);
		}
		activity?.SetTag("external.user.id", userId);

		try {
			var applicationUser = await resolver.ResolveAsync(userId, context.RequestAborted);

			if (applicationUser is null) {
				AuthenticationProviderDiagnostics.TransformCounter.Add(1, new KeyValuePair<string, object?>("outcome", "no_application_user"));
				activity?.SetTag("auth.transform.outcome", "NoApplicationUser");
				Log.NoApplicationUser(logger, userId);
				return Return(principal, context, "NoApplicationUser", resolverType, scheme, userId, roleClaimType);
			}

			// Cache the resolved user for downstream request-scoped consumers
			// (UserStateAccessor etc.) so they avoid a redundant resolver call.
			context.Items[AuthenticationContextKeys.ApplicationUserCache] = applicationUser;

			var roles = applicationUser.Roles;
			if (roles is null or { Count: 0 }) {
				AuthenticationProviderDiagnostics.TransformCounter.Add(1, new KeyValuePair<string, object?>("outcome", "no_roles_resolved"));
				activity?.SetTag("auth.transform.outcome", "NoRolesResolved");
				Log.NoRolesResolved(logger, userId);
				return Return(principal, context, "NoRolesResolved", resolverType, scheme, userId, roleClaimType);
			}

			activity?.SetTag("auth.roles.count", roles.Count);
			AuthenticationProviderDiagnostics.TransformCounter.Add(1, new KeyValuePair<string, object?>("outcome", "roles_resolved"));
			foreach (var role in roles) {
				identity.AddClaim(new Claim(roleClaimType, role));
			}

			if (logger.IsEnabled(LogLevel.Debug)) {
				Log.RolesResolvedDetail(logger, string.Join(", ", roles), userId);
			}

			activity?.SetTag("auth.transform.outcome", "RolesResolved");
			Log.RolesResolved(logger, roles.Count, userId, roleClaimType);
			return Return(principal, context, "RolesResolved", resolverType, scheme, userId, roleClaimType, roles.Count);

		} catch (Exception e) {
			AuthenticationProviderDiagnostics.TransformCounter.Add(1, new KeyValuePair<string, object?>("outcome", "role_resolution_failed"));
			Log.RoleResolutionFailed(logger, e, userId);
			activity?.SetTag("auth.transform.outcome", "RoleResolutionFailed");
			return Return(principal, context, "RoleResolutionFailed", resolverType, scheme, userId, roleClaimType);
		}
	}

	private IApplicationUserResolver? SelectResolver(string? scheme) {
		if (_resolvers.Length == 0) {
			return null;
		}

		if (!string.IsNullOrEmpty(scheme)) {
			foreach (var r in _resolvers) {
				if (string.Equals(r.Scheme, scheme, StringComparison.Ordinal)) {
					return r;
				}
			}
		}

		// Fall back to the null-scheme (default) resolver.
		foreach (var r in _resolvers) {
			if (r.Scheme is null) {
				return r;
			}
		}

		return null;
	}

	private static bool ContainsRoles(ClaimsIdentity identity, string roleType) {
		foreach (var c in identity.Claims) {
			var t = c.Type;
			if (string.Equals(t, roleType, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(t, RolesName, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(t, RoleName, StringComparison.OrdinalIgnoreCase)) {
				return true;
			}
		}
		return false;
	}

	private static string? FindUserId(ClaimsPrincipal principal) {
		foreach (var c in principal.Claims) {
			var t = c.Type;
			if (string.Equals(t, Oid, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(t, Sub, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(t, UserId, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(t, WellKnownClaimTypes.ObjectId, StringComparison.Ordinal)) {
				return c.Value;
			}
		}
		return null;
	}

	private static ClaimsPrincipal Return(
		ClaimsPrincipal principal,
		HttpContext context,
		string outcome,
		string? resolverType = null,
		string? scheme = null,
		string? userId = null,
		string? roleClaimType = null,
		int? roleCount = null) {
		context.Items[ClaimsTransformResult.ItemsKey] = new ClaimsTransformResult(
			outcome, resolverType, scheme, userId, roleClaimType, roleCount);
		return principal;
	}

	private static partial class Log {

		[LoggerMessage(EventId = 1000, Level = LogLevel.Trace, Message = "Claims transformation skipped because HttpContext was not available.")]
		public static partial void NoHttpContext(ILogger logger);

		[LoggerMessage(EventId = 1001, Level = LogLevel.Trace, Message = "Claims transformation skipped because the request was already transformed.")]
		public static partial void AlreadyTransformed(ILogger logger);

		[LoggerMessage(EventId = 1002, Level = LogLevel.Debug, Message = "Claims transformation skipped because the principal identity was not a ClaimsIdentity.")]
		public static partial void NoClaimsIdentity(ILogger logger);

		[LoggerMessage(EventId = 1003, Level = LogLevel.Debug, Message = "Claims transformation skipped because role claims already exist. RoleClaimType: {RoleClaimType}")]
		public static partial void RolesAlreadyPresent(ILogger logger, string roleClaimType);

		[LoggerMessage(EventId = 1004, Level = LogLevel.Debug, Message = "Claims transformation skipped because no supported user identifier claim was found.")]
		public static partial void NoUserIdentifier(ILogger logger);

		[LoggerMessage(EventId = 1005, Level = LogLevel.Warning, Message = "Application user resolution failed for user identifier '{UserId}'.")]
		public static partial void RoleResolutionFailed(ILogger logger, Exception exception, string userId);

		[LoggerMessage(EventId = 1006, Level = LogLevel.Debug, Message = "No roles were resolved for user identifier '{UserId}'.")]
		public static partial void NoRolesResolved(ILogger logger, string userId);

		[LoggerMessage(EventId = 1007, Level = LogLevel.Information, Message = "Resolved {RoleCount} roles for user identifier '{UserId}' using role claim type '{RoleClaimType}'.")]
		public static partial void RolesResolved(ILogger logger, int roleCount, string userId, string roleClaimType);

		[LoggerMessage(EventId = 1008, Level = LogLevel.Debug, Message = "Resolved roles [{Roles}] for user identifier '{UserId}'.")]
		public static partial void RolesResolvedDetail(ILogger logger, string roles, string userId);

		[LoggerMessage(EventId = 1009, Level = LogLevel.Debug, Message = "Claims transformation skipped because no IApplicationUserResolver is registered for scheme '{Scheme}'.")]
		public static partial void NoResolver(ILogger logger, string scheme);

		[LoggerMessage(EventId = 1010, Level = LogLevel.Debug, Message = "Claims transformation: no application user found in app store for external user identifier '{UserId}'.")]
		public static partial void NoApplicationUser(ILogger logger, string userId);
	}

}
