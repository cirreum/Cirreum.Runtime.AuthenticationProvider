namespace Cirreum.Runtime.Authentication.Tests;

using System.Security.Claims;
using Cirreum;
using Cirreum.Authentication;
using Cirreum.AuthenticationProvider;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Tests for <see cref="AudienceProviderRoleClaimsTransformer"/> per-scheme resolver
/// dispatch. Locks the slot contract: the transformer dispatches on the request's
/// stamped <c>AuthenticationContextKeys.AuthenticatedScheme</c> — never on
/// <c>ClaimsIdentity.AuthenticationType</c>, which for JWT identities is the token
/// handler's fixed <c>"AuthenticationTypes.Federation"</c> label rather than a scheme
/// name — falling back to <c>AuthenticationType</c> only to seed the slot on routes
/// where the forward selector never ran.
/// </summary>
public class AudienceProviderRoleClaimsTransformerTests {

	private const string FederationAuthenticationType = "AuthenticationTypes.Federation";

	private static ClaimsPrincipal JwtPrincipal(string subject = "user-1", string? role = null) {
		List<Claim> claims = [new Claim("sub", subject)];
		if (role is not null) {
			claims.Add(new Claim(ClaimTypes.Role, role));
		}
		return new(new ClaimsIdentity(claims, FederationAuthenticationType));
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

	private static AudienceProviderRoleClaimsTransformer TransformerFor(
		HttpContext context, params IApplicationUserResolver[] resolvers) {
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		return new(resolvers, accessor, NullLogger<AudienceProviderRoleClaimsTransformer>.Instance);
	}

	private static ClaimsTransformResult Result(HttpContext context) =>
		(ClaimsTransformResult)context.Items[ClaimsTransformResult.ItemsKey]!;

	[Fact]
	public async Task TransformAsync_JwtWithStampedScheme_DispatchesToSchemeKeyedResolver() {
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var resolver = ResolverFor("descope", "admin", "editor");
		var transformer = TransformerFor(context, resolver);
		var principal = JwtPrincipal();

		var transformed = await transformer.TransformAsync(principal);

		Result(context).Outcome.Should().Be(AuthenticationTelemetry.OutcomeRolesResolved);
		transformed.IsInRole("admin").Should().BeTrue();
		transformed.IsInRole("editor").Should().BeTrue();
		await resolver.Received(1).ResolveAsync("user-1", Arg.Any<CancellationToken>());
		context.Items[AuthenticationContextKeys.ApplicationUserCache].Should().NotBeNull();
	}

	[Fact]
	public async Task TransformAsync_SelectorStamp_SurvivesTransformation() {
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var transformer = TransformerFor(context, ResolverFor("descope", "admin"));

		await transformer.TransformAsync(JwtPrincipal());

		// The defensive TryAdd must never overwrite the forward selector's stamp with
		// the identity's AuthenticationType label.
		context.Items[AuthenticationContextKeys.AuthenticatedScheme].Should().Be("descope");
	}

	[Fact]
	public async Task TransformAsync_NoStamp_SeedsSlotFromAuthenticationTypeAndDispatchesOnIt() {
		// Explicitly-wired route: the forward selector never ran, so the slot is empty.
		// Here AuthenticationType is the only signal available; custom handlers set it
		// to their scheme name.
		var context = new DefaultHttpContext();
		var resolver = ResolverFor("ApiKey", "admin");
		var transformer = TransformerFor(context, resolver);
		var principal = new ClaimsPrincipal(new ClaimsIdentity(
			[new Claim("sub", "user-1")], authenticationType: "ApiKey"));

		var transformed = await transformer.TransformAsync(principal);

		Result(context).Outcome.Should().Be(AuthenticationTelemetry.OutcomeRolesResolved);
		transformed.IsInRole("admin").Should().BeTrue();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme].Should().Be("ApiKey");
	}

	[Fact]
	public async Task TransformAsync_StampedSchemeWithoutResolver_FallsBackToNullSchemeResolver() {
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var other = ResolverFor("entraWorkforce", "operator");
		var fallback = ResolverFor(null, "member");
		var transformer = TransformerFor(context, other, fallback);

		var transformed = await transformer.TransformAsync(JwtPrincipal());

		transformed.IsInRole("member").Should().BeTrue();
		await other.DidNotReceive().ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
		await fallback.Received(1).ResolveAsync("user-1", Arg.Any<CancellationToken>());
	}

	[Fact]
	public async Task TransformAsync_StampedSchemeWithoutAnyMatch_IsNoOp() {
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var other = ResolverFor("entraWorkforce", "operator");
		var transformer = TransformerFor(context, other);

		var transformed = await transformer.TransformAsync(JwtPrincipal());

		Result(context).Outcome.Should().Be(AuthenticationTelemetry.OutcomeNoResolver);
		transformed.Claims.Should().NotContain(c => c.Type == ClaimTypes.Role);
		await other.DidNotReceive().ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
	}

	[Fact]
	public async Task TransformAsync_UserIdOnSecondaryIdentity_IsNotBorrowed() {
		// A singular fact read across identities is not a broader answer, it is an answer
		// about someone else -- and here it would load THAT subject's application user and
		// stamp their roles onto this principal. Primary identity or nothing.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var resolver = ResolverFor("descope", "admin");
		var transformer = TransformerFor(context, resolver);

		var principal = new ClaimsPrincipal(new ClaimsIdentity([], FederationAuthenticationType));
		principal.AddIdentity(new ClaimsIdentity([new Claim("sub", "other-subject")], "secondary"));

		var transformed = await transformer.TransformAsync(principal);

		Result(context).Outcome.Should().Be(AuthenticationTelemetry.OutcomeNoUserIdentifier);
		transformed.Claims.Should().NotContain(c => c.Type == ClaimTypes.Role);
		await resolver.DidNotReceive().ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
	}

	[Fact]
	public async Task TransformAsync_RolesOnSecondaryIdentity_ShortCircuits() {
		// Roles are the one aggregate: IsInRole already spans every identity, so a role on a
		// secondary identity is one the principal genuinely answers to. Adding application
		// roles on top would fight an IdP whose roles are already in effect.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var resolver = ResolverFor("descope", "shadowed");
		var transformer = TransformerFor(context, resolver);

		var principal = JwtPrincipal();
		principal.AddIdentity(new ClaimsIdentity([new Claim(ClaimTypes.Role, "operator")], "secondary"));

		await transformer.TransformAsync(principal);

		Result(context).Outcome.Should().Be(AuthenticationTelemetry.OutcomeRolesAlreadyPresent);
		await resolver.DidNotReceive().ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
	}

	[Fact]
	public async Task TransformAsync_BlankOidDoesNotShadowPopulatedSub() {
		// A present-but-blank claim is treated as absent rather than as an answer -- it must
		// not shadow a populated claim further down the resolution order, and must not escape
		// as a non-null identifier into the resolver.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var resolver = ResolverFor("descope", "admin");
		var transformer = TransformerFor(context, resolver);

		var principal = new ClaimsPrincipal(new ClaimsIdentity(
			[new Claim("oid", "   "), new Claim("sub", "real-subject")], FederationAuthenticationType));

		await transformer.TransformAsync(principal);

		await resolver.Received(1).ResolveAsync("real-subject", Arg.Any<CancellationToken>());
	}

	[Fact]
	public async Task TransformAsync_MappedNameIdentifier_ResolvesTheUser() {
		// OIDC middleware maps `sub` to the nameidentifier URI when MapInboundClaims is
		// enabled. The Kernel resolver covers that claim type; the transformer's own former
		// copy did not, so those principals resolved no identifier and got no roles.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var resolver = ResolverFor("descope", "admin");
		var transformer = TransformerFor(context, resolver);

		var principal = new ClaimsPrincipal(new ClaimsIdentity(
			[new Claim(ClaimTypes.NameIdentifier, "mapped-subject")], FederationAuthenticationType));

		var transformed = await transformer.TransformAsync(principal);

		await resolver.Received(1).ResolveAsync("mapped-subject", Arg.Any<CancellationToken>());
		transformed.IsInRole("admin").Should().BeTrue();
	}

	[Fact]
	public async Task TransformAsync_IdentifierPriority_DoesNotDependOnClaimOrder() {
		// oid is tenant-stable; sub can be pairwise per application, so the Kernel order
		// prefers the long-form Entra OID over sub. `sub` is deliberately listed FIRST here:
		// a resolver that scans the claim collection for the first type-match rather than
		// walking types in priority order returns whichever the token happened to emit first,
		// which is not a property of the token worth depending on.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var resolver = ResolverFor("descope", "admin");
		var transformer = TransformerFor(context, resolver);

		var principal = new ClaimsPrincipal(new ClaimsIdentity([
			new Claim("sub", "pairwise-sub"),
			new Claim("http://schemas.microsoft.com/identity/claims/objectidentifier", "entra-oid")],
			FederationAuthenticationType));

		await transformer.TransformAsync(principal);

		await resolver.Received(1).ResolveAsync("entra-oid", Arg.Any<CancellationToken>());
		await resolver.DidNotReceive().ResolveAsync("pairwise-sub", Arg.Any<CancellationToken>());
	}

	[Fact]
	public async Task TransformAsync_ResolverReturnsDuplicateRoles_AddsEachRoleOnce() {
		// IApplicationUser.Roles has no distinctness contract, so a resolver joining
		// user -> group -> role can return the same role twice. Duplicated claims ride the
		// principal into session tickets and connection state, so they cost payload on
		// every round trip.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var transformer = TransformerFor(context, ResolverFor("descope", "admin", "editor", "admin"));

		var transformed = await transformer.TransformAsync(JwtPrincipal());

		var identity = (ClaimsIdentity)transformed.Identity!;
		identity.Claims.Count(c => c.Type == identity.RoleClaimType && c.Value == "admin")
			.Should().Be(1);
		transformed.IsInRole("admin").Should().BeTrue();
		transformed.IsInRole("editor").Should().BeTrue();

		// The reported count is what was added, not what the resolver returned.
		Result(context).RoleCount.Should().Be(2);
	}

	[Fact]
	public async Task TransformAsync_RolesAlreadyPresent_ShortCircuitsBeforeDispatch() {
		// Workforce path: IdP-issued roles arrive in the token; the transformer must
		// not fight them — and the resolver must never be consulted.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "entraWorkforce";
		var resolver = ResolverFor("entraWorkforce", "shadowed");
		var transformer = TransformerFor(context, resolver);

		await transformer.TransformAsync(JwtPrincipal(role: "operator"));

		Result(context).Outcome.Should().Be(AuthenticationTelemetry.OutcomeRolesAlreadyPresent);
		await resolver.DidNotReceive().ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
	}

}
