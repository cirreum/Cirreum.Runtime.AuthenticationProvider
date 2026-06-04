namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using System.Reflection;

/// <summary>
/// Unit tests for <see cref="AuthenticationRuntime.ResolveScheme"/>. Verifies the
/// iteration order: ascending <see cref="SchemeCategory"/>, then descending
/// <c>Priority</c> within category, returning the first claimant's scheme name.
/// </summary>
public class AuthenticationRuntimeResolveSchemeTests {

	private static readonly MethodInfo _resolveScheme = typeof(AuthenticationRuntime)
		.GetMethod("ResolveScheme", BindingFlags.NonPublic | BindingFlags.Static)!;

	[Fact]
	public void ResolveScheme_EmptySelectorSet_FallsThroughToAnonymous() {
		var context = CreateContext();

		var result = Invoke(context);

		result.Should().Be(AuthenticationSchemes.Anonymous);
	}

	[Fact]
	public void ResolveScheme_SingleMatchingSelector_ReturnsItsSchemeName() {
		var context = CreateContext(
			new TestSelector(SchemeCategory.Machine, matches: true, schemeName: "ApiKey"));

		var result = Invoke(context);

		result.Should().Be("ApiKey");
	}

	[Fact]
	public void ResolveScheme_MultipleCategoriesMatching_LowestCategoryValueWins() {
		// Machine = 100, Tenant = 300 → Machine wins (ascending category order).
		var context = CreateContext(
			new TestSelector(SchemeCategory.Tenant, matches: true, schemeName: "External"),
			new TestSelector(SchemeCategory.Machine, matches: true, schemeName: "ApiKey"));

		var result = Invoke(context);

		result.Should().Be("ApiKey");
	}

	[Fact]
	public void ResolveScheme_SameCategoryDifferentPriorities_HighestPriorityWins() {
		// Same Machine category, different priorities → higher priority wins.
		var context = CreateContext(
			new TestSelector(SchemeCategory.Machine, priority: 50, matches: true, schemeName: "LowPri"),
			new TestSelector(SchemeCategory.Machine, priority: 100, matches: true, schemeName: "HighPri"));

		var result = Invoke(context);

		result.Should().Be("HighPri");
	}

	[Fact]
	public void ResolveScheme_SelectorMatchesButReturnsNullName_SkippedAndCascades() {
		// Defensive: a buggy selector returns matches=true with null name → skip,
		// cascade to next claimant. Should reach the Anonymous fallback.
		var context = CreateContext(
			new TestSelector(SchemeCategory.Machine, matches: true, schemeName: null),
			new TestSelector(SchemeCategory.Anonymous, matches: true, schemeName: AuthenticationSchemes.Anonymous));

		var result = Invoke(context);

		result.Should().Be(AuthenticationSchemes.Anonymous);
	}

	[Fact]
	public void ResolveScheme_NoMatchAndNoAnonymous_StillReturnsAnonymousAsDefense() {
		// All selectors return matches=false. Production registers an Anonymous fallback
		// selector that always matches, but the resolver method itself has a defensive
		// fallback returning Anonymous when iteration exits without a hit.
		var context = CreateContext(
			new TestSelector(SchemeCategory.Machine, matches: false),
			new TestSelector(SchemeCategory.Tenant, matches: false));

		var result = Invoke(context);

		result.Should().Be(AuthenticationSchemes.Anonymous);
	}

	[Fact]
	public void ResolveScheme_ConflictSentinelClaims_ReturnsAmbiguousBeforeOtherSelectors() {
		// Conflict category = 0 → iterates first. If it matches (≥2 indicators), it wins
		// regardless of other claimants.
		var context = CreateContext(
			new TestSelector(SchemeCategory.Conflict, matches: true, schemeName: AuthenticationSchemes.Ambiguous),
			new TestSelector(SchemeCategory.Machine, matches: true, schemeName: "ApiKey"));

		var result = Invoke(context);

		result.Should().Be(AuthenticationSchemes.Ambiguous);
	}

	private static string Invoke(HttpContext context) =>
		(string)_resolveScheme.Invoke(null, [context])!;

	private static HttpContext CreateContext(params ISchemeSelector[] selectors) {
		var services = new ServiceCollection();
		foreach (var selector in selectors) {
			services.AddSingleton(selector);
		}
		var provider = services.BuildServiceProvider();

		return new DefaultHttpContext {
			RequestServices = provider
		};
	}

}
