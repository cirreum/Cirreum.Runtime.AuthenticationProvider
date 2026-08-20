namespace Cirreum.Runtime.Authentication.Tests;

using System.Security.Claims;
using Cirreum.Authentication;
using Cirreum.Invocation.Connections;

/// <summary>
/// Tests for the <c>connection.Promote(principal, originScheme)</c> extension member — the
/// Two-Phase Auth write surface. Locks the promotion invariants: authenticated-principal
/// validation, the clear-derived-slots-BEFORE-stamp ordering (a concurrently-constructed
/// invocation must never observe the promoted principal paired with the previous subject's
/// cached application user or origin), origin stamping and clearing, scheme survival, and
/// re-promotion overwrite semantics.
/// </summary>
public class TwoPhaseAuthTests {

	private static ClaimsPrincipal AuthenticatedPrincipal(string subject = "user-1") =>
		new(new ClaimsIdentity(
			[new Claim("sub", subject)],
			authenticationType: "TestScheme"));

	private static ClaimsPrincipal AnonymousPrincipal() =>
		new(new ClaimsIdentity());

	private static IInvocationConnection ConnectionWith(IDictionary<object, object?> items) {
		var connection = Substitute.For<IInvocationConnection>();
		connection.Items.Returns(items);
		return connection;
	}

	[Fact]
	public void Promote_StampsPromotedPrincipal_ReadableViaContractsSurface() {
		var items = new Dictionary<object, object?>();
		var connection = ConnectionWith(items);
		var principal = AuthenticatedPrincipal();

		connection.Promote(principal, originScheme: "entraExternal");

		items[AuthenticationContextKeys.PromotedPrincipal].Should().BeSameAs(principal);
		items[AuthenticationContextKeys.OriginScheme].Should().Be("entraExternal");
		connection.PromotedUser.Should().BeSameAs(principal);
		connection.EffectiveUser.Should().BeSameAs(principal);
		connection.IsUserPromoted.Should().BeTrue();
	}

	[Fact]
	public void Promote_NullOrigin_LeavesTheOriginSlotAbsent() {
		var items = new Dictionary<object, object?>();
		var connection = ConnectionWith(items);

		connection.Promote(AuthenticatedPrincipal(), originScheme: null);

		items.Should().NotContainKey(AuthenticationContextKeys.OriginScheme);
	}

	[Fact]
	public void Promote_BlankOrigin_IsTreatedAsNull() {
		var items = new Dictionary<object, object?>();
		var connection = ConnectionWith(items);

		connection.Promote(AuthenticatedPrincipal(), originScheme: "   ");

		items.Should().NotContainKey(AuthenticationContextKeys.OriginScheme);
	}

	[Fact]
	public void Promote_EvictsApplicationUserCache() {
		var items = new Dictionary<object, object?> {
			[AuthenticationContextKeys.ApplicationUserCache] = new object(),
		};
		var connection = ConnectionWith(items);

		connection.Promote(AuthenticatedPrincipal(), originScheme: null);

		items.Should().NotContainKey(AuthenticationContextKeys.ApplicationUserCache);
	}

	[Fact]
	public void Promote_ClearsDerivedSlots_BeforeStampingPrincipal_AndStampsOriginLast() {
		var items = new RecordingDictionary {
			[AuthenticationContextKeys.ApplicationUserCache] = new object(),
			[AuthenticationContextKeys.OriginScheme] = "descope",
		};
		items.Operations.Clear();
		var connection = ConnectionWith(items);

		connection.Promote(AuthenticatedPrincipal(), originScheme: "entraExternal");

		// Clear both derived slots, stamp the principal, then the origin: a concurrent
		// reader sees the old subject complete, either principal with derived slots absent
		// (degraded, never wrong), or the new subject complete — never a cross-pairing.
		items.Operations.Should().ContainInOrder(
			$"remove:{AuthenticationContextKeys.ApplicationUserCache}",
			$"remove:{AuthenticationContextKeys.OriginScheme}",
			$"set:{AuthenticationContextKeys.PromotedPrincipal}",
			$"set:{AuthenticationContextKeys.OriginScheme}");
	}

	[Fact]
	public void Promote_AnonymousPrincipal_Throws_AndMutatesNothing() {
		var cached = new object();
		var items = new Dictionary<object, object?> {
			[AuthenticationContextKeys.ApplicationUserCache] = cached,
			[AuthenticationContextKeys.OriginScheme] = "descope",
		};
		var connection = ConnectionWith(items);

		var act = () => connection.Promote(AnonymousPrincipal(), originScheme: "entraExternal");

		act.Should().Throw<ArgumentException>();
		// Validation precedes mutation — a rejected Promote must not disturb the subject.
		items[AuthenticationContextKeys.ApplicationUserCache].Should().BeSameAs(cached);
		items[AuthenticationContextKeys.OriginScheme].Should().Be("descope");
		items.Should().NotContainKey(AuthenticationContextKeys.PromotedPrincipal);
	}

	[Fact]
	public void Promote_NullPrincipal_ThrowsArgumentNull() {
		var connection = ConnectionWith(new Dictionary<object, object?>());

		var act = () => connection.Promote(null!, originScheme: null);

		act.Should().Throw<ArgumentNullException>();
	}

	[Fact]
	public void Promote_NullConnection_ThrowsArgumentNull() {
		IInvocationConnection connection = null!;

		var act = () => connection.Promote(AuthenticatedPrincipal(), originScheme: null);

		act.Should().Throw<ArgumentNullException>();
	}

	[Fact]
	public void Promote_RePromotion_OverwritesPriorPrincipal_AndEvictsItsCache() {
		var items = new Dictionary<object, object?>();
		var connection = ConnectionWith(items);
		var first = AuthenticatedPrincipal("user-1");
		var second = AuthenticatedPrincipal("user-2");

		connection.Promote(first, originScheme: null);
		items[AuthenticationContextKeys.ApplicationUserCache] = new object();
		connection.Promote(second, originScheme: null);

		connection.PromotedUser.Should().BeSameAs(second);
		items.Should().NotContainKey(AuthenticationContextKeys.ApplicationUserCache);
	}

	[Fact]
	public void Promote_RePromotion_ReplacesThePriorOrigin() {
		var items = new Dictionary<object, object?>();
		var connection = ConnectionWith(items);

		connection.Promote(AuthenticatedPrincipal("user-1"), originScheme: "descope");
		connection.Promote(AuthenticatedPrincipal("user-2"), originScheme: "entraExternal");

		items[AuthenticationContextKeys.OriginScheme].Should().Be("entraExternal");
	}

	[Fact]
	public void Promote_RePromotion_ClearsThePriorOrigin_WhenUnattributed() {
		var items = new Dictionary<object, object?>();
		var connection = ConnectionWith(items);

		connection.Promote(AuthenticatedPrincipal("user-1"), originScheme: "descope");
		connection.Promote(AuthenticatedPrincipal("user-2"), originScheme: null);

		// The previous subject's origin must never pair with the new subject: an
		// unattributed re-promotion clears the slot rather than inheriting it.
		items.Should().NotContainKey(AuthenticationContextKeys.OriginScheme);
	}

	[Fact]
	public void Promote_AuthenticatedScheme_SurvivesPromotion() {
		var items = new Dictionary<object, object?> {
			[AuthenticationContextKeys.AuthenticatedScheme] = "ApiKey",
		};
		var connection = ConnectionWith(items);

		connection.Promote(AuthenticatedPrincipal(), originScheme: "entraExternal");

		// The scheme describes how the CONNECTION (transport) was authenticated,
		// not the current occupant — promotion must not disturb it.
		items[AuthenticationContextKeys.AuthenticatedScheme].Should().Be("ApiKey");
	}

	/// <summary>
	/// Dictionary that records mutation order, so the evict-before-stamp invariant is
	/// locked as an observable sequence rather than inferred from end state.
	/// </summary>
	private sealed class RecordingDictionary : IDictionary<object, object?> {

		private readonly Dictionary<object, object?> _inner = [];

		public List<string> Operations { get; } = [];

		public object? this[object key] {
			get => _inner[key];
			set {
				Operations.Add($"set:{key}");
				_inner[key] = value;
			}
		}

		public bool Remove(object key) {
			Operations.Add($"remove:{key}");
			return _inner.Remove(key);
		}

		public ICollection<object> Keys => _inner.Keys;
		public ICollection<object?> Values => _inner.Values;
		public int Count => _inner.Count;
		public bool IsReadOnly => false;
		public void Add(object key, object? value) {
			Operations.Add($"add:{key}");
			_inner.Add(key, value);
		}
		public void Add(KeyValuePair<object, object?> item) => Add(item.Key, item.Value);
		public void Clear() => _inner.Clear();
		public bool Contains(KeyValuePair<object, object?> item) => _inner.Contains(item);
		public bool ContainsKey(object key) => _inner.ContainsKey(key);
		public void CopyTo(KeyValuePair<object, object?>[] array, int arrayIndex) =>
			((ICollection<KeyValuePair<object, object?>>)_inner).CopyTo(array, arrayIndex);
		public IEnumerator<KeyValuePair<object, object?>> GetEnumerator() => _inner.GetEnumerator();
		public bool Remove(KeyValuePair<object, object?> item) {
			Operations.Add($"remove:{item.Key}");
			return ((ICollection<KeyValuePair<object, object?>>)_inner).Remove(item);
		}
		public bool TryGetValue(object key, out object? value) => _inner.TryGetValue(key, out value);
		System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
	}

}
