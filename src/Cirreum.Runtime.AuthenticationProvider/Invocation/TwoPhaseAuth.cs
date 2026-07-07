namespace Cirreum.Invocation.Connections;

using Cirreum.Authentication;
using System.Security.Claims;

/// <summary>
/// Spine-shipped write surface for the Two-Phase Auth pattern —
/// promotes a long-lived connection that started anonymous-pending-auth into an
/// authenticated state mid-flight via <c>connection.Promote(principal)</c>, stamping the
/// <see cref="ClaimsPrincipal"/> into the connection's
/// <see cref="IInvocationConnection.Items"/> under
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
/// The read surface lives on <c>Cirreum.Contracts</c> as extension members of
/// <see cref="IInvocationConnection"/>: <c>PromotedUser</c> (the nullable primitive),
/// <c>EffectiveUser</c> (promoted-or-upgrade-time), and <c>IsUserPromoted</c>. After
/// <c>Promote</c>, the framework's per-invocation contexts snapshot
/// <c>connection.EffectiveUser</c> at construction, so the promoted identity flows into
/// every <em>subsequent</em> invocation on the connection; an invocation already in
/// flight keeps the principal it was constructed with.
/// </para>
/// <para>
/// The framework's connection-terminator handler (in <c>Cirreum.Services.Server</c>)
/// honors promotion when resolving subjects — a connection whose effective principal
/// matches an incoming <c>CredentialRevoked</c>, <c>UserAccountDisabled</c>, or
/// <c>SessionTerminationRequested</c> event is aborted as expected.
/// </para>
/// </remarks>
public static class TwoPhaseAuth {

	extension(IInvocationConnection connection) {

		/// <summary>
		/// Promotes the connection by stamping the authenticated principal into
		/// <see cref="IInvocationConnection.Items"/>. Replaces any prior promoted principal
		/// (re-promotion is supported — apps that re-authenticate mid-connection overwrite
		/// the prior promoted state).
		/// </summary>
		/// <remarks>
		/// <para>
		/// Also evicts any cached application user
		/// (<see cref="AuthenticationContextKeys.ApplicationUserCache"/>) from the
		/// connection — it was resolved for the pre-promotion identity. The eviction
		/// happens <em>before</em> the promoted principal is stamped: an invocation
		/// constructed concurrently may observe the old principal with the old (matching)
		/// cache, or either value briefly absent, but never the promoted principal paired
		/// with the previous identity's application user. The lazy resolve path repopulates
		/// the slot for the promoted identity on the next invocation.
		/// </para>
		/// <para>
		/// <see cref="AuthenticationContextKeys.AuthenticatedScheme"/> deliberately
		/// survives promotion — it describes how the <em>connection</em> (transport) was
		/// authenticated, not the current occupant.
		/// </para>
		/// </remarks>
		/// <param name="principal">The authenticated <see cref="ClaimsPrincipal"/> to bind.
		/// Must carry a valid identity (<see cref="ClaimsPrincipal.Identity"/>.IsAuthenticated
		/// is <see langword="true"/>). Throws on anonymous principals — use the connection's
		/// existing <see cref="IInvocationConnection.User"/> for unauthenticated state.</param>
		/// <exception cref="ArgumentNullException">When the connection or
		/// <paramref name="principal"/> is <see langword="null"/>.</exception>
		/// <exception cref="ArgumentException">When <paramref name="principal"/> is
		/// unauthenticated.</exception>
		public void Promote(ClaimsPrincipal principal) {
			ArgumentNullException.ThrowIfNull(connection);
			ArgumentNullException.ThrowIfNull(principal);
			if (principal.Identity?.IsAuthenticated != true) {
				throw new ArgumentException(
					"Promote requires an authenticated principal. " +
					"Anonymous principals cannot promote a connection.",
					nameof(principal));
			}

			// Evict BEFORE stamping — order matters. A concurrently-constructed invocation
			// seeds its auth slots from Connection.Items; evict-then-stamp means it can see
			// old-principal + old-cache, old-principal + no-cache, or new-principal +
			// no-cache, but never new-principal + the previous identity's cached user.
			// See Services.Server: UserStateAccessor where its re-hydrated on demand.
			connection.Items.Remove(AuthenticationContextKeys.ApplicationUserCache);

			// Stamp the promoted principal into the connection's items bag. The framework
			// connection-terminator handler (in Cirreum.Services.Server) honors promotion when
			// resolving subjects — a connection whose effective principal matches an
			// incoming CredentialRevoked, UserAccountDisabled, or SessionTerminationRequested
			// event is aborted as expected.
			connection.Items[AuthenticationContextKeys.PromotedPrincipal] = principal;
		}

	}

}
