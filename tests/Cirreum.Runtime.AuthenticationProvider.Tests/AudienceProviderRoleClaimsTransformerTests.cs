namespace Cirreum.Runtime.Authentication.Tests;

using System.Security.Claims;
using Cirreum;
using Cirreum.Authentication;
using Cirreum.AuthenticationProvider;
using Cirreum.Security;
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
		HttpContext context, params IApplicationUserResolver[] resolvers) =>
		TransformerFor(context, authorityMap: null, resolvers);

	private static AudienceProviderRoleClaimsTransformer TransformerFor(
		HttpContext context,
		ISchemeClaimAuthorityMap? authorityMap,
		params IApplicationUserResolver[] resolvers) {
		var accessor = Substitute.For<IHttpContextAccessor>();
		accessor.HttpContext.Returns(context);
		return new(resolvers, accessor, NullLogger<AudienceProviderRoleClaimsTransformer>.Instance, authorityMap);
	}

	/// <summary>A map declaring one scheme; every other scheme resolves Undeclared.</summary>
	private static ISchemeClaimAuthorityMap MapFor(
		string scheme,
		SubjectKind subjectKind = SubjectKind.Human,
		ClaimAuthority roles = ClaimAuthority.Unspecified) {
		var map = Substitute.For<ISchemeClaimAuthorityMap>();
		map.Get(Arg.Any<string?>()).Returns(SchemeClaimAuthority.Undeclared);
		map.Get(scheme).Returns(new SchemeClaimAuthority(subjectKind, ClaimAuthority.Unspecified, roles));
		return map;
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
	public async Task TransformAsync_RolesOnSecondaryIdentity_NoLongerSuppressesTheStore() {
		// The deleted ContainsRoles short-circuit: role claims anywhere on the principal used
		// to suppress the resolver. A DB-owns scheme must re-read the store on every request —
		// suppressing it is precisely how revocation stopped being immediate.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var resolver = ResolverFor("descope", "current");
		var transformer = TransformerFor(context, resolver);

		var principal = JwtPrincipal();
		principal.AddIdentity(new ClaimsIdentity([new Claim(ClaimTypes.Role, "operator")], "secondary"));

		var transformed = await transformer.TransformAsync(principal);

		Result(context).Outcome.Should().Be(AuthenticationTelemetry.OutcomeRolesResolved);
		await resolver.Received(1).ResolveAsync("user-1", Arg.Any<CancellationToken>());
		transformed.IsInRole("current").Should().BeTrue();
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
	public async Task TransformAsync_IdentityProviderRoles_ShortCircuitsBeforeDispatch() {
		// Workforce path, now declared rather than inferred: the IdP owns roles, so the token's
		// roles stand and the store is never consulted — even with a resolver registered.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "entraWorkforce";
		var resolver = ResolverFor("entraWorkforce", "shadowed");
		var map = MapFor("entraWorkforce", roles: ClaimAuthority.IdentityProvider);
		var transformer = TransformerFor(context, map, resolver);

		var transformed = await transformer.TransformAsync(JwtPrincipal(role: "operator"));

		Result(context).Outcome.Should().Be(AuthenticationTelemetry.OutcomeIdentityProviderRoles);
		await resolver.DidNotReceive().ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
		transformed.IsInRole("operator").Should().BeTrue();
		transformed.IsInRole("shadowed").Should().BeFalse();
	}

	[Fact]
	public async Task TransformAsync_MachineSubject_NeverConsultsTheApplicationStore() {
		// A machine's roles travel on the credential record the handler minted them from —
		// a third source neither ClaimAuthority pole names.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "ApiKey:Header";
		var resolver = ResolverFor("ApiKey:Header", "shadowed");
		var map = MapFor("ApiKey:Header", subjectKind: SubjectKind.Machine);
		var transformer = TransformerFor(context, map, resolver);

		await transformer.TransformAsync(JwtPrincipal(role: "integration"));

		Result(context).Outcome.Should().Be(AuthenticationTelemetry.OutcomeMachineSubject);
		await resolver.DidNotReceive().ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
	}

	[Fact]
	public async Task TransformAsync_ApplicationStoreRoles_ReReadsDespiteTokenRoles() {
		// The declared form of the same correctness rule: the store is authoritative, so a
		// token that already carries roles does not suppress the per-request read.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var resolver = ResolverFor("descope", "current");
		var map = MapFor("descope", roles: ClaimAuthority.ApplicationStore);
		var transformer = TransformerFor(context, map, resolver);

		var transformed = await transformer.TransformAsync(JwtPrincipal(role: "stale"));

		Result(context).Outcome.Should().Be(AuthenticationTelemetry.OutcomeRolesResolved);
		await resolver.Received(1).ResolveAsync("user-1", Arg.Any<CancellationToken>());
		transformed.IsInRole("current").Should().BeTrue();
	}

	[Fact]
	public async Task TransformAsync_OriginScheme_GovernsDispatchAndDeclaration() {
		// A ticketed connection: the transport is SessionTicket, but descope established the
		// subject — descope's resolver and descope's declaration are the ones that apply.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "SessionTicket:Bearer";
		context.Items[AuthenticationContextKeys.OriginScheme] = "descope";
		var originResolver = ResolverFor("descope", "subscriber");
		var transportResolver = ResolverFor("SessionTicket:Bearer", "wrong");
		var map = MapFor("descope", roles: ClaimAuthority.ApplicationStore);
		var transformer = TransformerFor(context, map, originResolver, transportResolver);

		var transformed = await transformer.TransformAsync(JwtPrincipal());

		await originResolver.Received(1).ResolveAsync("user-1", Arg.Any<CancellationToken>());
		await transportResolver.DidNotReceive().ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
		transformed.IsInRole("subscriber").Should().BeTrue();
		Result(context).Scheme.Should().Be("descope");
	}

	[Fact]
	public async Task TransformAsync_CanonicalizesProfileClaims_ButNeverMintedRoles() {
		// The wave's root-cause fix on the server side: customName reaches the name claim, so
		// audit and profile stop reading a machine-ish blank. customRoles is deliberately left
		// as inert wire bytes — materializing it would answer IsInRole from a token snapshot.
		var context = new DefaultHttpContext();
		context.Items[AuthenticationContextKeys.AuthenticatedScheme] = "descope";
		var transformer = TransformerFor(context, ResolverFor("descope", "current"));

		var identity = new ClaimsIdentity(
			[
				new Claim("sub", "user-1"),
				new Claim("customName", "Jane Smith"),
				new Claim("customRoles", """["stale-admin"]"""),
			],
			FederationAuthenticationType,
			nameType: "name",
			roleType: ClaimTypes.Role);

		var transformed = await transformer.TransformAsync(new ClaimsPrincipal(identity));

		transformed.Identity!.Name.Should().Be("Jane Smith");
		transformed.IsInRole("stale-admin").Should().BeFalse();
		transformed.IsInRole("current").Should().BeTrue();
		// Additive: the wire claim survives, it is simply never evaluated.
		identity.FindAll("customRoles").Should().ContainSingle();
	}

}
