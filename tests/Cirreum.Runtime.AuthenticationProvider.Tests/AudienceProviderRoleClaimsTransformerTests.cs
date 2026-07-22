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

		Result(context).Outcome.Should().Be("RolesResolved");
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

		Result(context).Outcome.Should().Be("RolesResolved");
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

		Result(context).Outcome.Should().Be("NoResolver");
		transformed.Claims.Should().NotContain(c => c.Type == ClaimTypes.Role);
		await other.DidNotReceive().ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
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

		Result(context).Outcome.Should().Be("RolesAlreadyPresent");
		await resolver.DidNotReceive().ResolveAsync(Arg.Any<string>(), Arg.Any<CancellationToken>());
	}

}
