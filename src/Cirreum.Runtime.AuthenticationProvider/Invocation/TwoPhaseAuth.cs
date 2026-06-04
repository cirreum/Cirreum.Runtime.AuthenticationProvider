namespace Cirreum.Authentication;

using System.Security.Claims;
using Cirreum.Invocation.Connections;

/// <summary>
/// Spine-shipped helper for the Two-Phase Auth pattern —
/// promotes a long-lived connection that started anonymous-pending-auth into an
/// authenticated state mid-flight by stamping a <see cref="ClaimsPrincipal"/> into the
/// connection's <see cref="IInvocationConnection.Items"/> under
/// <see cref="AuthenticationContextKeys.PromotedPrincipal"/>.
/// </summary>
/// <remarks>
/// <para>
/// Used for flows where authentication arrives <em>after</em> the connection is
/// established — cold-IVA telephony (the caller is identified mid-conversation),
/// browser AI chat warm sessions (the user signs in mid-session), webhook-driven partner
/// handoffs (the partner exchanges a one-time code for an authenticated principal).
/// </para>
/// <para>
/// After <see cref="Promote"/>, the per-invocation <c>UserStateAccessor</c> reads the
/// promoted principal in preference to the connection's original (anonymous) principal,
/// so subsequent invocations on the connection flow with the upgraded identity.
/// </para>
/// <para>
/// The framework's connection-terminator handler honors promotion when
/// resolving subjects — a connection whose <c>PromotedPrincipal</c> claim subject
/// matches an incoming <c>SessionTerminationRequested</c> or
/// <c>CredentialRevoked</c> event is aborted as expected.
/// </para>
/// </remarks>
public static class TwoPhaseAuth {

	/// <summary>
	/// Promotes the connection by stamping the authenticated principal into
	/// <see cref="IInvocationConnection.Items"/>. Replaces any prior promoted principal
	/// (re-promotion is supported — apps that re-authenticate mid-connection overwrite
	/// the prior promoted state).
	/// </summary>
	/// <param name="connection">The connection to promote. Must not be
	/// <see langword="null"/>.</param>
	/// <param name="principal">The authenticated <see cref="ClaimsPrincipal"/> to bind.
	/// Must carry a valid identity (<see cref="ClaimsPrincipal.Identity"/>.IsAuthenticated
	/// is <see langword="true"/>). Throws on anonymous principals — use the connection's
	/// existing <see cref="IInvocationConnection.User"/> for unauthenticated state.</param>
	/// <exception cref="ArgumentNullException">When <paramref name="connection"/> or
	/// <paramref name="principal"/> is <see langword="null"/>.</exception>
	/// <exception cref="ArgumentException">When <paramref name="principal"/> is
	/// unauthenticated.</exception>
	public static void Promote(IInvocationConnection connection, ClaimsPrincipal principal) {
		ArgumentNullException.ThrowIfNull(connection);
		ArgumentNullException.ThrowIfNull(principal);
		if (principal.Identity?.IsAuthenticated != true) {
			throw new ArgumentException(
				"TwoPhaseAuth.Promote requires an authenticated principal. " +
				"Anonymous principals cannot promote a connection.",
				nameof(principal));
		}
		connection.Items[AuthenticationContextKeys.PromotedPrincipal] = principal;
	}

	/// <summary>
	/// Returns the currently-promoted principal, or <see langword="null"/> when the
	/// connection has not been promoted (still in anonymous-pending-auth state).
	/// </summary>
	public static ClaimsPrincipal? GetPromotedPrincipal(IInvocationConnection connection) {
		ArgumentNullException.ThrowIfNull(connection);
		return connection.Items.TryGetValue(AuthenticationContextKeys.PromotedPrincipal, out var v)
			&& v is ClaimsPrincipal p
				? p
				: null;
	}

	/// <summary>
	/// Returns <see langword="true"/> when the connection has been promoted via
	/// <see cref="Promote"/>; <see langword="false"/> when still anonymous-pending-auth.
	/// </summary>
	public static bool IsPromoted(IInvocationConnection connection) =>
		GetPromotedPrincipal(connection) is not null;

}
