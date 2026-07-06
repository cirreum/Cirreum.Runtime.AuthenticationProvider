# Cirreum.Runtime.AuthenticationProvider 1.1.0 — `connection.Promote(principal)`

## Why this release exists

Two-Phase Auth's write surface predated the connection-ownership surface that now ships
in `Cirreum.Contracts` (`PromotedUser` / `EffectiveUser` / `IsUserPromoted`). The old
static helpers (`TwoPhaseAuth.Promote(connection, principal)`,
`GetPromotedPrincipal`, `IsPromoted`) duplicated the read side and — more importantly —
left a correctness gap: promoting a connection did not evict the application user cached
for the pre-promotion identity, so an invocation constructed mid-promotion could pair
the promoted principal with the previous identity's domain user.

## What's new

```csharp
connection.Promote(authenticatedPrincipal);
```

- **Promotion is now an extension member on `IInvocationConnection`** — the write-side
  complement of the Contracts read surface. Authenticated-principal validation is
  unchanged; re-promotion still overwrites.
- **The eviction invariant.** `Promote` removes the connection's cached application user
  *before* stamping the promoted principal. A concurrently-constructed invocation can
  observe old-principal + old-cache, or either value briefly absent — never
  new-principal + the previous identity's cached user. The lazy resolve path repopulates
  the cache for the promoted identity on the next invocation.
- `AuthenticatedScheme` deliberately survives promotion — it describes how the
  connection (transport) authenticated, not the current occupant.
- The `GetPromotedPrincipal` / `IsPromoted` statics are gone — read
  `connection.PromotedUser` / `connection.IsUserPromoted` from `Cirreum.Contracts`
  instead. No shims: the old surface had no external consumers.

## Compatibility

Source-breaking for the (unconsumed) static forms; behavior-additive otherwise. First
test coverage for the promotion surface ships with this release (8 tests, including an
operation-order test locking the evict-before-stamp invariant).

## See also

- `Cirreum.Contracts` 1.4.x — the connection-ownership read surface
- `Cirreum.Services.Server` 1.3.0 — per-invocation contexts snapshot `EffectiveUser`;
  the connection registry and termination handler honor promotion
