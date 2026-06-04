namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Confidence tests for <see cref="AnonymousAuthenticationSchemeSelector"/> — the
/// bottom-of-dispatch fallback. Trivial behavior; tests guard against regression.
/// </summary>
public class AnonymousAuthenticationSchemeSelectorTests {

	[Fact]
	public void TrySelect_AlwaysReturnsAnonymousMatch() {
		var selector = new AnonymousAuthenticationSchemeSelector();

		var result = selector.TrySelect(new DefaultHttpContext());

		result.Matches.Should().BeTrue();
		result.SchemeName.Should().Be(AuthenticationSchemes.Anonymous);
	}

	[Fact]
	public void Category_IsAnonymous_SoIterationVisitsItLast() {
		var selector = new AnonymousAuthenticationSchemeSelector();

		selector.Category.Should().Be(SchemeCategory.Anonymous);
	}

	[Fact]
	public void HasIndicator_AlwaysFalse_SoFallbackDoesNotPolluteConflictCount() {
		var selector = new AnonymousAuthenticationSchemeSelector();

		selector.HasIndicator(new DefaultHttpContext()).Should().BeFalse();
	}

}
