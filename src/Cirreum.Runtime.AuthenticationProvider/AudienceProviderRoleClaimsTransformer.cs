namespace Cirreum.AuthenticationProvider;

using Cirreum;
using Cirreum.Authentication;
using Cirreum.Security;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
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

	private readonly IApplicationUserResolver[] _resolvers = [.. resolvers];

	/// <inheritdoc/>
	public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal) {

		var startedAt = Stopwatch.GetTimestamp();
		using var activity = AuthenticationTelemetry.StartTransformActivity(
			nameof(AudienceProviderRoleClaimsTransformer));

		var context = httpContextAccessor.HttpContext;
		if (context is null) {
			// No context to stash a ClaimsTransformResult on — record straight to telemetry
			// so the counter's total still equals the invocation count.
			AuthenticationTelemetry.RecordTransformation(
				activity,
				AuthenticationTelemetry.OutcomeNoHttpContext,
				durationMs: Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds);
			Log.NoHttpContext(logger);
			return principal;
		}

		// Read the forward selector's stamp up front so the outcomes that exit before
		// dispatch still carry the scheme dimension — otherwise a double transformation or
		// a malformed identity is unattributable to the IdP that caused it.
		var stampedScheme = context.Items[AuthenticationContextKeys.AuthenticatedScheme] as string;

		if (context.Items.ContainsKey(TransformedKey)) {
			Log.AlreadyTransformed(logger);
			return Complete(principal, context, activity, startedAt,
				AuthenticationTelemetry.OutcomeAlreadyTransformed, scheme: stampedScheme);
		}

		// Mark immediately — prevents re-entry if ASP.NET calls TransformAsync again
		// on the same request before the async work completes.
		context.Items[TransformedKey] = true;

		if (principal.Identity is not ClaimsIdentity identity) {
			Log.NoClaimsIdentity(logger);
			return Complete(principal, context, activity, startedAt,
				AuthenticationTelemetry.OutcomeNoClaimsIdentity, scheme: stampedScheme);
		}

		// Defensive stamp of the canonical scheme key for routes wired to an explicit
		// scheme that bypass the dynamic ForwardDefaultSelector. TryAdd preserves the
		// forward selector's value when both run.
		context.Items.TryAdd(AuthenticationContextKeys.AuthenticatedScheme, identity.AuthenticationType);

		// Dispatch on the slot, not on AuthenticationType: JWT identities carry the token
		// handler's fixed "AuthenticationTypes.Federation" label rather than a scheme name,
		// so only the forward selector's stamp identifies which scheme authenticated.
		var scheme = stampedScheme ?? identity.AuthenticationType;

		// Per-scheme dispatch over IApplicationUserResolver. Falls back to the
		// resolver whose Scheme is null when no per-scheme resolver matches.
		var resolver = this.SelectResolver(scheme);

		if (resolver is null) {
			Log.NoResolver(logger, scheme ?? "(null)");
			return Complete(principal, context, activity, startedAt,
				AuthenticationTelemetry.OutcomeNoResolver, scheme: scheme);
		}

		var resolverType = resolver.GetType().Name;

		// Skip when the principal already carries role claims (workforce IdP path). Roles are
		// the one aggregate here, so the check spans every identity — the breadth
		// ClaimsPrincipal.IsInRole already has. A role on a secondary identity is one the
		// principal genuinely answers to, so adding application-store roles on top would be
		// fighting an IdP whose roles are already in effect.
		var roleClaimType = identity.RoleClaimType;
		if (ContainsRoles(principal)) {
			Log.RolesAlreadyPresent(logger, roleClaimType);
			return Complete(principal, context, activity, startedAt,
				AuthenticationTelemetry.OutcomeRolesAlreadyPresent, resolverType, scheme, roleClaimType: roleClaimType);
		}

		// Singular fact — resolved from the primary identity or not at all, via the Kernel
		// resolver rather than a second copy of its claim order. `identity` is
		// `principal.Identity`, matched above.
		var userId = ClaimsHelper.ResolveId(identity);
		if (userId is null) {
			Log.NoUserIdentifier(logger);
			return Complete(principal, context, activity, startedAt,
				AuthenticationTelemetry.OutcomeNoUserIdentifier, resolverType, scheme, roleClaimType: roleClaimType);
		}

		// Activity only — the external user identifier is unbounded, so it never becomes
		// a metric dimension.
		activity?.SetTag(AuthenticationTelemetry.UserIdTag, userId);

		try {
			var applicationUser = await resolver.ResolveAsync(userId, context.RequestAborted);

			if (applicationUser is null) {
				Log.NoApplicationUser(logger, userId);
				return Complete(principal, context, activity, startedAt,
					AuthenticationTelemetry.OutcomeNoApplicationUser, resolverType, scheme, userId, roleClaimType);
			}

			// Cache the resolved user for downstream request-scoped consumers
			// (UserStateAccessor etc.) so they avoid a redundant resolver call.
			context.Items[AuthenticationContextKeys.ApplicationUserCache] = applicationUser;

			var roles = applicationUser.Roles;
			if (roles is null or { Count: 0 }) {
				Log.NoRolesResolved(logger, userId);
				return Complete(principal, context, activity, startedAt,
					AuthenticationTelemetry.OutcomeNoRolesResolved, resolverType, scheme, userId, roleClaimType);
			}

			// IApplicationUser.Roles is an IReadOnlyList with no distinctness contract, so a
			// resolver joining user → group → role can return the same role twice. HasClaim's
			// predicate is exactly the one ClaimsPrincipal.IsInRole uses — type
			// ordinal-ignore-case, value ordinal — so a role skipped here is one the identity
			// already answers to. Each add is visible to the next check, which dedups within
			// the list as well as against what is already there.
			var added = 0;
			foreach (var role in roles) {
				if (identity.HasClaim(roleClaimType, role)) {
					continue;
				}
				identity.AddClaim(new Claim(roleClaimType, role));
				added++;
			}

			if (added < roles.Count) {
				Log.DuplicateRolesSkipped(logger, resolverType, roles.Count - added, userId);
			}

			if (logger.IsEnabled(LogLevel.Debug)) {
				var rolesList = string.Join(", ", roles);
				Log.RolesResolvedDetail(logger, rolesList, userId);
			}

			Log.RolesResolved(logger, added, userId, roleClaimType);
			return Complete(principal, context, activity, startedAt,
				AuthenticationTelemetry.OutcomeRolesResolved, resolverType, scheme, userId, roleClaimType, added);

		} catch (Exception e) {
			Log.RoleResolutionFailed(logger, e, userId);
			return Complete(principal, context, activity, startedAt,
				AuthenticationTelemetry.OutcomeRoleResolutionFailed, resolverType, scheme, userId, roleClaimType);
		}
	}

	private IApplicationUserResolver? SelectResolver(string? scheme) {
		if (this._resolvers.Length == 0) {
			return null;
		}

		if (!string.IsNullOrEmpty(scheme)) {
			foreach (var r in this._resolvers) {
				if (string.Equals(r.Scheme, scheme, StringComparison.Ordinal)) {
					return r;
				}
			}
		}

		// Fall back to the null-scheme (default) resolver.
		foreach (var r in this._resolvers) {
			if (r.Scheme is null) {
				return r;
			}
		}

		return null;
	}

	/// <summary>
	/// Whether any identity the principal carries already holds a role claim. Each identity is
	/// read against its own <see cref="ClaimsIdentity.RoleClaimType"/>, matching how
	/// <see cref="ClaimsPrincipal.IsInRole(string)"/> spans a multi-identity principal, and
	/// allocation-free with an early exit.
	/// </summary>
	private static bool ContainsRoles(ClaimsPrincipal principal) {
		foreach (var identity in principal.Identities) {
			if (ContainsRoles(identity, identity.RoleClaimType)) {
				return true;
			}
		}
		return false;
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

	/// <summary>
	/// The single exit path: records telemetry and stashes the diagnostic result. Every
	/// outcome routes through here so a future branch cannot record one instrument and
	/// forget the other.
	/// </summary>
	private static ClaimsPrincipal Complete(
		ClaimsPrincipal principal,
		HttpContext context,
		Activity? activity,
		long startedAt,
		string outcome,
		string? resolverType = null,
		string? scheme = null,
		string? userId = null,
		string? roleClaimType = null,
		int? roleCount = null) {

		AuthenticationTelemetry.RecordTransformation(
			activity, outcome, scheme, resolverType, roleClaimType, roleCount,
			Stopwatch.GetElapsedTime(startedAt).TotalMilliseconds);

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

		[LoggerMessage(EventId = 1011, Level = LogLevel.Debug, Message = "Resolver '{ResolverType}' returned {DuplicateCount} duplicate role(s) for user identifier '{UserId}'; they were not added a second time.")]
		public static partial void DuplicateRolesSkipped(ILogger logger, string resolverType, int duplicateCount, string userId);
	}

}
