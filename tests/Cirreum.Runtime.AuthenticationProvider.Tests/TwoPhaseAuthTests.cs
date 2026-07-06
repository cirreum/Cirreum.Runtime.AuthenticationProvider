namespace Cirreum.Runtime.Authentication.Tests;

using System.Security.Claims;
using Cirreum.Authentication;
using Cirreum.Invocation.Connections;

/// <summary>
/// Tests for the <c>connection.Promote(principal)</c> extension member — the Two-Phase
/// Auth write surface. Locks the promotion invariants: authenticated-principal
/// validation, the evict-<c>ApplicationUserCache</c>-BEFORE-stamp ordering (a
/// concurrently-constructed invocation must never observe the promoted principal paired
/// with the previous identity's cached application user), scheme survival, and
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

		connection.Promote(principal);

		items[AuthenticationContextKeys.PromotedPrincipal].Should().BeSameAs(principal);
		connection.PromotedUser.Should().BeSameAs(principal);
		connection.EffectiveUser.Should().BeSameAs(principal);
		connection.IsUserPromoted.Should().BeTrue();
	}

	[Fact]
	public void Promote_EvictsApplicationUserCache() {
		var items = new Dictionary<object, object?> {
			[AuthenticationContextKeys.ApplicationUserCache] = new object(),
		};
		var connection = ConnectionWith(items);

		connection.Promote(AuthenticatedPrincipal());

		items.Should().NotContainKey(AuthenticationContextKeys.ApplicationUserCache);
	}

	[Fact]
	public void Promote_EvictsCache_BeforeStampingPrincipal() {
		var items = new RecordingDictionary {
			[AuthenticationContextKeys.ApplicationUserCache] = new object(),
		};
		items.Operations.Clear();
		var connection = ConnectionWith(items);

		connection.Promote(AuthenticatedPrincipal());

		items.Operations.Should().ContainInOrder(
			$"remove:{AuthenticationContextKeys.ApplicationUserCache}",
			$"set:{AuthenticationContextKeys.PromotedPrincipal}");
	}

	[Fact]
	public void Promote_AnonymousPrincipal_Throws_AndMutatesNothing() {
		var cached = new object();
		var items = new Dictionary<object, object?> {
			[AuthenticationContextKeys.ApplicationUserCache] = cached,
		};
		var connection = ConnectionWith(items);

		var act = () => connection.Promote(AnonymousPrincipal());

		act.Should().Throw<ArgumentException>();
		// Validation precedes mutation — a rejected Promote must not evict the cache.
		items[AuthenticationContextKeys.ApplicationUserCache].Should().BeSameAs(cached);
		items.Should().NotContainKey(AuthenticationContextKeys.PromotedPrincipal);
	}

	[Fact]
	public void Promote_NullPrincipal_ThrowsArgumentNull() {
		var connection = ConnectionWith(new Dictionary<object, object?>());

		var act = () => connection.Promote(null!);

		act.Should().Throw<ArgumentNullException>();
	}

	[Fact]
	public void Promote_NullConnection_ThrowsArgumentNull() {
		IInvocationConnection connection = null!;

		var act = () => connection.Promote(AuthenticatedPrincipal());

		act.Should().Throw<ArgumentNullException>();
	}

	[Fact]
	public void Promote_RePromotion_OverwritesPriorPrincipal_AndEvictsItsCache() {
		var items = new Dictionary<object, object?>();
		var connection = ConnectionWith(items);
		var first = AuthenticatedPrincipal("user-1");
		var second = AuthenticatedPrincipal("user-2");

		connection.Promote(first);
		items[AuthenticationContextKeys.ApplicationUserCache] = new object();
		connection.Promote(second);

		connection.PromotedUser.Should().BeSameAs(second);
		items.Should().NotContainKey(AuthenticationContextKeys.ApplicationUserCache);
	}

	[Fact]
	public void Promote_AuthenticatedScheme_SurvivesPromotion() {
		var items = new Dictionary<object, object?> {
			[AuthenticationContextKeys.AuthenticatedScheme] = "ApiKey",
		};
		var connection = ConnectionWith(items);

		connection.Promote(AuthenticatedPrincipal());

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
