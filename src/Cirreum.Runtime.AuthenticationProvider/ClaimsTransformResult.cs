namespace Cirreum.AuthenticationProvider;

/// <summary>
/// Diagnostic record stashed in <see cref="Microsoft.AspNetCore.Http.HttpContext.Items"/>
/// after each claims transformation pass. Inspect via
/// <c>httpContext.Items[ClaimsTransformResult.ItemsKey]</c> during debugging or in
/// diagnostic middleware.
/// </summary>
/// <param name="Outcome">The transformation outcome (e.g. <c>RolesResolved</c>,
/// <c>AlreadyTransformed</c>, <c>NoUserIdentifier</c>).</param>
/// <param name="ResolverType">The concrete <see cref="IApplicationUserResolver"/>
/// type name, if resolution was attempted.</param>
/// <param name="Scheme">The authentication scheme the request was dispatched
/// through, used to select the per-scheme resolver.</param>
/// <param name="UserId">The external user identifier extracted from the token,
/// if found.</param>
/// <param name="RoleClaimType">The claim type used for role claims.</param>
/// <param name="RoleCount">The number of roles resolved and added, if any.</param>
public sealed record ClaimsTransformResult(
	string Outcome,
	string? ResolverType = null,
	string? Scheme = null,
	string? UserId = null,
	string? RoleClaimType = null,
	int? RoleCount = null) {

	/// <summary>
	/// The <see cref="Microsoft.AspNetCore.Http.HttpContext.Items"/> key used to
	/// store this result.
	/// </summary>
	public const string ItemsKey = "Cirreum.Authentication.TransformResult";
}
