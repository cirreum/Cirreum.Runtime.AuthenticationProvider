# Cirreum.Runtime.AuthenticationProvider 2.1.0 — roles resolve from the declaration

## Why this release exists

The framework never asked an application who owns a user's attributes. It inferred, and the
inference lived here: `ContainsRoles(principal)` read "this token carries role claims" as "the
identity provider owns roles," and skipped the application-store lookup on that basis.

For a workforce token that guess is right. For a **DB-owns** token it is exactly backwards. Such
a token is deliberately thin — the application is the authority, so the identity provider
carries little — and when the application mints its own roles into the token under the
`custom*` convention, the presence check fires on data the application itself owns. The store
read that keeps revocation immediate gets skipped in favour of a snapshot frozen at token
issue, bounded only by the refresh window. Nothing fails; roles just quietly stop being
current.

This release replaces the inference with the declaration, and closes the same gap on the
claims side.

## What's new

**The roles stage reads `ISchemeClaimAuthorityMap`.** Resolved optionally — no registered map,
no change in behaviour — and consulted for the *effective* scheme, so a subject that arrived
over a session ticket is judged by the scheme that established it rather than the ticket that
re-presents it:

| Declaration | Behaviour | Outcome |
|---|---|---|
| `SubjectKind.Machine` | store never consulted — a machine's roles travel on the credential record | `machine-subject` |
| `Roles: IdentityProvider` | the token's roles stand | `identity-provider-roles` |
| `Roles: ApplicationStore` | per-request store read, every request | `roles-resolved` |
| Undeclared | legacy rule: a registered resolver means the store owns roles | as before |

**`ContainsRoles` is gone.** Under both `ApplicationStore` and the undeclared legacy rule, the
store is read on every request. A token that already carries roles no longer suppresses it —
that case *is* the one a store-owns scheme must re-read.

**Profile claims canonicalize server-side, roles never do.** `custom*` claims are aliased to the
names the framework reads — `customName` reaches the name claim, so audit lines and profile
enrichment stop seeing a blank where an application-owned name exists. Roles are excluded via
`Cirreum.Kernel` 2.2.0's `excludeRoles` posture: on the server, materializing a minted role
snapshot as a live role claim is an authorization act, and `IsInRole` treats presence as grant.
The wire claim survives untouched; it is simply never evaluated.

**`Promote` requires the origin scheme.**

```csharp
connection.Promote(principal, originScheme: "entraExternal");
connection.Promote(principal, originScheme: null);   // deliberately unattributed
```

One signature, no default. A promoted subject's facts — subject kind, claim authority — resolve
from the scheme that authenticated them rather than the transport now carrying them, and the
call site has to say which that is. Null or blank is legal and resolves `SubjectKind.Unknown`:
degraded, never wrong. It also *clears* any prior origin, so a re-promotion cannot pair the
previous subject's origin with the new subject.

## Compatibility

- **`Promote(principal)` no longer compiles.** Replace with
  `Promote(principal, originScheme: null)` to preserve exact prior behaviour, or supply the
  scheme that established the principal to gain the declaration-aware resolution.
- **`RegisterAuthenticationProvider` takes `IAuthenticationBuilder`.** Registrar plumbing
  following `Cirreum.AuthenticationProvider` 3.x; the umbrella package passes the new type.
- **`AuthenticationTelemetry.OutcomeRolesAlreadyPresent` is removed** — no code path produces
  it. Dashboards filtering the string value `roles-already-present` will see it stop appearing;
  `identity-provider-roles` and `machine-subject` are its declared successors.
- **Behavioural change without a declaration map:** a scheme with a registered resolver whose
  tokens carry role claims now performs a store read per request instead of skipping it. That
  is the defect being fixed, and it is the shape the `ApplicationStore` declaration makes
  explicit.
- Removing a public overload and changing a parameter type are breaking by the letter of
  SemVer; both ship in a Minor deliberately, consistent with the rest of this wave's
  pre-adoption surface changes, and both are one-line mechanical fixes.

## See also

- `Cirreum.Kernel 2.2.0` — the `excludeRoles` canonicalization posture this release consumes.
- `Cirreum.Contracts 4.4.0` — `OriginScheme` / `EffectiveScheme`, the same effective-scheme
  rule on the invocation read surface.
- `Cirreum.Services.Server 1.5.0` — the user-state consumer: subject kind, effective-scheme
  resolver dispatch, fill-only app-name fallback.
- `Cirreum.Runtime.Authentication` (upcoming) — registers the declaration map; until it does,
  every reader in this release resolves `Undeclared` and preserves existing behaviour.
