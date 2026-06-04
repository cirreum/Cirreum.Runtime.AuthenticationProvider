namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Unit tests for <see cref="ConflictSentinelSchemeSelector"/>. Verifies the
/// count-based open/closed scheme-shopping detection.
/// </summary>
public class ConflictSentinelSchemeSelectorTests {

	[Fact]
	public void TrySelect_NoSelectorsRegistered_ReturnsNoMatch() {
		var context = CreateContext();
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeFalse();
		result.SchemeName.Should().BeNull();
	}

	[Fact]
	public void TrySelect_SingleSelectorWithIndicator_ReturnsNoMatch() {
		var context = CreateContext(
			new TestSelector(SchemeCategory.Machine, hasIndicator: true));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeFalse();
		result.SchemeName.Should().BeNull();
	}

	[Fact]
	public void TrySelect_TwoSelectorsSameCategoryWithIndicators_ReturnsNoMatch() {
		// Two ApiKey selectors (e.g., one for static clients, one for dynamic) both
		// signal indicators. Same category → not a conflict; priority resolves the winner.
		var context = CreateContext(
			new TestSelector(SchemeCategory.Machine, priority: 100, hasIndicator: true),
			new TestSelector(SchemeCategory.Machine, priority: 50, hasIndicator: true));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeFalse();
	}

	[Fact]
	public void TrySelect_TwoSelectorsDifferentCategoriesWithIndicators_ReturnsAmbiguous() {
		// Classic scheme-shopping: an API key header AND a tenant indicator both
		// present on one request. Two distinct categories → ambiguous.
		var context = CreateContext(
			new TestSelector(SchemeCategory.Machine, hasIndicator: true),
			new TestSelector(SchemeCategory.Tenant, hasIndicator: true));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be(AuthenticationSchemes.Ambiguous);
	}

	[Fact]
	public void TrySelect_ThreeCategoriesWithIndicators_ReturnsAmbiguous() {
		var context = CreateContext(
			new TestSelector(SchemeCategory.Machine, hasIndicator: true),
			new TestSelector(SchemeCategory.SessionEstablishment, hasIndicator: true),
			new TestSelector(SchemeCategory.Tenant, hasIndicator: true));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be(AuthenticationSchemes.Ambiguous);
	}

	[Fact]
	public void TrySelect_MixOfIndicatorAndNonIndicatorSelectors_CountsOnlyIndicating() {
		// Two distinct categories present but only one signals an indicator → no conflict.
		var context = CreateContext(
			new TestSelector(SchemeCategory.Machine, hasIndicator: true),
			new TestSelector(SchemeCategory.Tenant, hasIndicator: false),
			new TestSelector(SchemeCategory.SessionEstablishment, hasIndicator: false));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		result.Matches.Should().BeFalse();
	}

	[Fact]
	public void TrySelect_ConflictSentinelItselfIsFiltered_DoesNotSelfTrigger() {
		// The Conflict sentinel's own HasIndicator returns false, but defensively
		// verify it's filtered even if a Conflict-categorized selector signaled.
		var context = CreateContext(
			new TestSelector(SchemeCategory.Conflict, hasIndicator: true),
			new TestSelector(SchemeCategory.Machine, hasIndicator: true));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		// Only Machine counts (Conflict filtered) → one distinct category → no ambiguity.
		result.Matches.Should().BeFalse();
	}

	[Fact]
	public void TrySelect_AnonymousFallbackFiltered_DoesNotCountAsCategory() {
		// Anonymous fallback always claims requests; if it counted as an indicator,
		// every request with any other selector signaling would be ambiguous.
		var context = CreateContext(
			new TestSelector(SchemeCategory.Anonymous, hasIndicator: true),
			new TestSelector(SchemeCategory.Machine, hasIndicator: true));
		var sentinel = new ConflictSentinelSchemeSelector();

		var result = sentinel.TrySelect(context);

		// Only Machine counts (Anonymous filtered) → one distinct category → no ambiguity.
		result.Matches.Should().BeFalse();
	}

	[Fact]
	public void Category_IsConflict_SoItIteratesFirst() {
		var sentinel = new ConflictSentinelSchemeSelector();

		sentinel.Category.Should().Be(SchemeCategory.Conflict);
	}

	[Fact]
	public void Priority_IsMaxValue_SoItWinsTiesWithinCategory() {
		var sentinel = new ConflictSentinelSchemeSelector();

		sentinel.Priority.Should().Be(int.MaxValue);
	}

	[Fact]
	public void HasIndicator_AlwaysFalse_SoSentinelDoesntCountItself() {
		var sentinel = new ConflictSentinelSchemeSelector();

		sentinel.HasIndicator(CreateContext()).Should().BeFalse();
	}

	// Builds an HttpContext whose RequestServices resolves the provided test selectors
	// via DI. Mirrors how the production code resolves selectors at request time —
	// the conflict sentinel iterates IEnumerable<ISchemeSelector> from RequestServices.
	private static HttpContext CreateContext(params ISchemeSelector[] selectors) {
		var services = new ServiceCollection();
		foreach (var selector in selectors) {
			services.AddSingleton(selector);
		}
		var provider = services.BuildServiceProvider();

		var httpContext = new DefaultHttpContext {
			RequestServices = provider
		};
		return httpContext;
	}

}
