namespace Cirreum.Runtime.Authentication.Tests;

using Cirreum.Authentication;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Hand-rolled <see cref="ISchemeSelector"/> for tests — gives precise control over
/// Category, Priority, HasIndicator, and TrySelect without mocking the interface.
/// More readable than NSubstitute setups for the simple shape this interface has.
/// </summary>
internal sealed class TestSelector(
	SchemeCategory category,
	int priority = 0,
	bool hasIndicator = false,
	bool matches = false,
	string? schemeName = null
) : ISchemeSelector {

	public SchemeCategory Category => category;
	public int Priority => priority;
	public bool HasIndicator(HttpContext context) => hasIndicator;
	public (bool Matches, string? SchemeName) TrySelect(HttpContext context) => (matches, schemeName);

}
