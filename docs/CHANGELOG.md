# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

## [2.1.3] - 2026-08-29

### Updated

- Updated NuGet packages.

## [2.1.2] - 2026-08-25

### Updated

- Updated NuGet packages.

## [2.1.1] - 2026-08-25

### Updated

- Updated NuGet packages.

## [2.1.0] - 2026-08-20

### Added

- **The role-claims transformer reads the scheme's declaration** instead of inferring authority
  from token contents. `ISchemeClaimAuthorityMap` is resolved optionally, so a host that
  registers no map behaves exactly as before. With one registered: a `SubjectKind.Machine`
  scheme never consults the application-user store (a machine's roles travel on the credential
  record the handler minted them from — a third source neither `ClaimAuthority` pole names),
  and a scheme declaring `ClaimAuthority.IdentityProvider` for roles keeps the roles its token
  issued. New telemetry outcomes `machine-subject` and `identity-provider-roles` name both.
- **Server-side canonicalization of `custom*` claims** at claims transformation, excluding
  roles (`CustomClaimCanonicalizer.Canonicalize(identity, excludeRoles: true)`). App-minted
  profile claims now reach the native names the framework reads — the server-side half of the
  fix for an audit line naming the calling application as the user. Minted roles are
  deliberately not aliased: materializing a token's role snapshot as a live role claim would
  let `IsInRole` answer from data frozen at token issue.

### Changed

- **`connection.Promote` requires the origin scheme:**
  `Promote(ClaimsPrincipal principal, string? originScheme)` is now the only signature — the
  one-argument overload is gone rather than retained as a default. Attribution is declared,
  not defaulted: a surviving one-argument form would let every call site quietly not answer,
  leaving an operator unable to distinguish "genuinely unattributable" from "nobody stated
  it". The parameter stays nullable — an unattributed promotion is legal and resolves
  `SubjectKind.Unknown`, degraded rather than wrong — and null or blank now *clears* any prior
  origin stamp, so a re-promotion can never pair the previous subject's origin with the new
  subject. Removing a public overload is breaking on paper; shipped in a Minor deliberately,
  consistent with the rest of this wave's pre-adoption surface changes.
  Find/replace: `Promote(principal)` → `Promote(principal, originScheme: null)`.
- **`RegisterAuthenticationProvider` takes `IAuthenticationBuilder`** (was ASP.NET's
  `AuthenticationBuilder`), and calls the consolidated two-argument
  `AuthenticationProviderRegistrar.Register`. Registrar plumbing that follows
  `Cirreum.AuthenticationProvider` 3.x; breaking on paper, deliberate in a Minor.
- **Role resolution keys on the effective scheme** — the origin scheme when a continuation or
  a promotion established the subject elsewhere, otherwise the stamped transport scheme. A
  subject reaching the server over a session ticket resolves through the scheme that
  established it, not the ticket that re-presents it.
- **`ContainsRoles` is deleted.** The presence of role claims on the principal no longer
  suppresses the application-store read. That inference was the wave's root defect: a token
  carrying roles is exactly the case a store-owns scheme must re-read, since suppressing it
  trades per-request roles for a snapshot bounded only by the token's refresh window.
  Behavioral change for a scheme that declares nothing and has a resolver registered: the
  resolver is now consulted on every request rather than skipped when the token already
  carried roles. `AuthenticationTelemetry.OutcomeRolesAlreadyPresent` is removed with it — no
  code path can produce that outcome any longer.

### Updated

- Updated NuGet packages (`Cirreum.AuthenticationProvider` 3.0.4, carrying `Cirreum.Kernel`
  2.2.0's `excludeRoles` canonicalization posture).

## [2.0.3] - 2026-08-04

### Updated

- Updated NuGet packages.

## [2.0.2] - 2026-07-31

### Updated

- Updated NuGet packages (Cirreum spine 4.0.1 wave: `Cirreum.Domain` 4.0.1 / `Cirreum.AuthenticationProvider` 2.0.3 / `Cirreum.Services.*` repins).

## [2.0.1] - 2026-07-29

### Updated

- Updated NuGet packages.

## [2.0.0] - 2026-07-27

### Added

- **The authentication track is now instrumented to answer *which scheme* and *why*, not
  only *how many*.** Authentication emitted a single counter carrying an `outcome` tag;
  authorization emitted four instruments across eleven dimensions. The gap was not cosmetic —
  none of these were answerable from telemetry alone: which scheme was selected for a request,
  how often selection matched nothing, how often a scheme's `IApplicationUserResolver` failed
  or found no user, how long the claims transformer took, and how authenticated schemes were
  distributed across a multi-IdP deployment. That last one matters most since
  `IdentityProviderType` was removed: the authenticated scheme is now the single authoritative
  answer to "which identity provider handled this request", and it was recorded only on the
  activity, never as a metric dimension.
- **`AuthenticationTelemetry`** — the authentication counterpart to `AuthorizationTelemetry`,
  publishing the shared `ActivitySource` and `Meter` plus public tag-name, outcome-value and
  metric-name constants. Replaces `AuthenticationProviderDiagnostics` (see **Changed**).
- **`cirreum.authn.transformation.duration`** — claims transformation duration in
  milliseconds, tagged with outcome and scheme.
- **`cirreum.authn.selections`** — scheme-selection counter, tagged with the resolved scheme
  and the `ISchemeSelector` that claimed the request. A `none` selector value means nothing
  claimed the request and the resolver fell through to its default, which distinguishes a
  genuine Anonymous selection from a misconfigured selector set. Recorded via the public
  `AuthenticationTelemetry.RecordSchemeSelection`, which the umbrella package
  (`Cirreum.Runtime.Authentication`) calls from its forward-scheme resolver — the single site
  every selector is dispatched through, so one call covers the whole registered set,
  framework-shipped and app-supplied alike.
- **`cirreum.authn.transformations` now carries `scheme` and `resolver` dimensions**, and
  records a `no-http-context` outcome that previously returned silently — so the counter's
  total equals the invocation count.
- The transformation duration histogram deliberately takes only the outcome and scheme
  dimensions. Histogram buckets multiply per series, so the resolver dimension stays on the
  counter.
- The claims-transformation activity states `ActivityKind.Internal` explicitly rather than
  relying on the `StartActivity` default. The span neither receives work nor sends it — it
  runs inside the ASP.NET request pipeline, always as a child of the server span that already
  accepted the request — so it is never an entry point and the host-dependent
  `DomainContext.EntryPointActivityKind` would be wrong here. Stating the kind is what
  `DomainContext` asks of a track gaining telemetry: the default is the same value, but
  declaring it records that the choice was made.
- Test coverage for the telemetry contract (11 tests): instrument and tag names asserted as
  literals rather than against their own constants — the names are half of a cross-package
  contract with Kernel's `AddCirreum()` registration, and a rename that updated only the
  constant would leave the instrument unsubscribed and silently inert.

### Fixed

- **The application user is no longer resolved from an identifier borrowed off a secondary
  identity.** The transformer searched `principal.Claims`, which spans every identity the
  principal carries. A user identifier is a singular fact, and the Kernel's resolvers scope
  those to the primary identity precisely because a value taken from a second authentication
  context is not a broader answer — it is an answer about someone else. Here the consequence
  was concrete rather than cosmetic: that identifier is handed to
  `IApplicationUserResolver.ResolveAsync`, so a `sub` belonging to a second identity would load
  *that* subject's application user and stamp their roles onto the current principal.

  Resolution now runs against the primary identity, which is the identity the transformer had
  already matched and is mutating.

- **Three further divergences closed by deleting a hand-rolled copy of `ClaimsHelper.ResolveId`.**
  The transformer carried its own claim-order search rather than calling the Kernel resolver,
  and the copy had drifted:

  - **A blank claim shadowed a populated one.** The copy returned the first claim of a matching
    *type* regardless of its value, so a present-but-empty `oid` suppressed a valid `sub` and
    escaped as a non-null identifier into the resolver. `ClaimsHelper` treats a blank claim as
    absent; this is the same defect class swept across four packages on 2026-07-26, surviving
    here in a duplicate of the helper that was fixed.
  - **`ClaimTypes.NameIdentifier` was not recognized.** The OIDC middleware maps `sub` onto that
    URI when `MapInboundClaims` is enabled, so those principals resolved no identifier at all —
    outcome `no-user-identifier`, and no application roles were ever added.
  - **There was no priority order at all.** The copy scanned the claim collection and returned
    the first claim whose *type* matched any of the four it knew — so with both `sub` and the
    long-form Entra object identifier present, which one identified the user depended on the
    order the token happened to emit them in. `ClaimsHelper` walks claim *types* in priority
    order instead, preferring `oid` because it is tenant-stable while `sub` can be pairwise per
    application. The application user now keys on the same identifier `UserProfile` and
    `IUserState` key on, deterministically.

- **The role short-circuit now spans every identity.** It inspected only the primary identity,
  while `ClaimsPrincipal.IsInRole` — and the Kernel's own `IdentityScope.AllIdentities` default
  for roles — span all of them. Roles are the one aggregate among these reads, so breadth is
  correct: a role on a secondary identity is one the principal genuinely answers to, and adding
  application-store roles on top of it fights an IdP whose roles are already in effect. Each
  identity is read against its own `RoleClaimType`, matching how `IsInRole` evaluates a
  multi-identity principal.

  On the single-identity principals the Cirreum Server, Serverless and Client hosts compose,
  this changes nothing. It matters when parts of Cirreum run in a host that composes principals
  differently.

- **A resolver returning the same role twice no longer produces duplicate role claims.**
  `IApplicationUser.Roles` is an `IReadOnlyList<string>` with no distinctness contract, so a
  resolver joining user → group → role can legitimately return `["admin", "editor", "admin"]`
  — and every entry was added unconditionally. The duplicate was not an authorization bug
  (`IsInRole` still answers correctly) but the claims ride the principal into session tickets
  and long-lived connection state, so they cost payload on every round trip.

  Each role is now added only if the identity does not already answer to it. The check uses
  `ClaimsIdentity.HasClaim`, whose predicate is exactly the one `ClaimsPrincipal.IsInRole`
  uses — claim type ordinal-ignore-case, value ordinal — so a skipped role is precisely one
  the identity already satisfies. Because each add is visible to the next check, the same pass
  dedups within the resolver's list.

  `ClaimsTransformResult.RoleCount` and the `RolesResolved` log now report the number of roles
  actually added rather than the number returned. A `Debug` entry names the resolver and the
  duplicate count so the resolver's own data issue is visible.

  Note this is narrower than it may appear: roles already present on the identity were never
  duplicated, because the transformer short-circuits with `roles-already-present` when the
  identity carries any claim of the role claim type (or `roles` / `role`). The exposure was
  duplicates *within* a single resolver's return value.

### Changed

- **`AuthenticationProviderDiagnostics` → `AuthenticationTelemetry`.** Every peer telemetry
  class in the framework is named `*Telemetry` (`AuthorizationTelemetry`,
  `ProvisioningTelemetry`); this one was the outlier, and it now carries the full tag and
  outcome vocabulary rather than a lone metric name. See `MIGRATION-v2.md`.
- **Transformation outcomes are a single vocabulary across metrics, traces and the diagnostic
  record.** The counter reported `already_transformed` while the activity and the public
  `ClaimsTransformResult.Outcome` reported `AlreadyTransformed` — two spellings of one fact, so
  joining a metric to a trace or to the stashed result needed a translation table. All three now
  emit the lowercase-hyphenated `AuthenticationTelemetry.Outcome*` constants
  (`already-transformed`, `roles-resolved`, `role-resolution-failed`, …), matching
  `AuthorizationTelemetry`'s value style. **`ClaimsTransformResult.Outcome` values changed** —
  see `MIGRATION-v2.md`.
- **Activity tag names are now `cirreum.authn.*` constants** rather than the local literals
  `auth.transformer.name`, `auth.transform.outcome`, `auth.scheme`, `auth.resolver.type`,
  `auth.role_claim_type`, `auth.roles.count` and `external.user.id`. The old set was neither
  prefixed consistently nor internally consistent (`auth.transform.*` alongside
  `auth.transformer.*`).
- **Outcomes that exit before resolver dispatch now carry the scheme dimension.** The
  already-transformed and no-claims-identity paths recorded no scheme, so a double
  transformation or a malformed identity was unattributable to the IdP that caused it. The
  transformer reads the forward selector's stamp up front and passes it to every exit.
- Every transformation outcome now routes through one exit path that records the counter, the
  duration and the activity tags together. Each outcome previously repeated three separate
  calls, so a new branch could record one instrument and forget the others.
- **`auth_transformations_total` → `cirreum.authn.transformations`.** The instrument was the only
  one in the framework using underscores as segment separators; everything else is dot-separated
  (`cirreum.authz.decisions`, `conductor.operations.total`). Underscores now separate words
  *within* a segment only, matching OpenTelemetry conventions. The `_total` suffix is dropped as
  well — that is a Prometheus exposition detail an exporter appends, not part of an instrument
  name. The name is now the public constant `AuthenticationTelemetry.TransformationsMetric`.

### Removed

- **`AuthenticationProviderDiagnostics.DiagnosticName`** (on the class now named
  `AuthenticationTelemetry`). It restated the literal
  `"Cirreum.Authentication"` — the same value as `CirreumTelemetry.ActivitySources.Authentication`
  and `.Meters.Authentication`. Those constants are the registration half of a cross-package
  contract: Kernel's `AddCirreum()` subscribes exactly those names, and a source or meter whose name
  is never registered is silently inert. A second copy of the literal could drift from the
  registered one with nothing failing to say so.

  Its documentation also claimed the constant was "referenced by the umbrella package to subscribe
  to telemetry" — nothing referenced it, in this package or any other.

  The `ActivitySource` and `Meter` now take their names from `CirreumTelemetry` directly, using the
  source constant for the source and the meter constant for the meter. Those are equal today;
  nothing guarantees they stay equal, and the single alias was quietly conflating them. See
  `MIGRATION-v2.md`.

### Fixed

- The `ActivitySource` and `Meter` are created with `CirreumTelemetry.Version`. Without a version a
  backend has no way to attribute spans or metrics to a release of the instrumenting library, and
  every other telemetry class in the framework already passed it. Closes one of the three
  unversioned sources identified in the 2026-07-04 framework-wide tracing review.

## [1.1.5] - 2026-07-24

### Updated

- Updated NuGet packages.

## [1.1.4] - 2026-07-22

### Fixed

- `AudienceProviderRoleClaimsTransformer` now dispatches the per-scheme
  `IApplicationUserResolver` lookup on the request's stamped
  `AuthenticationContextKeys.AuthenticatedScheme` slot, as its contract documents —
  previously it dispatched on `ClaimsIdentity.AuthenticationType`, which for JWT
  identities is the token handler's fixed `"AuthenticationTypes.Federation"` label
  rather than a scheme name, so scheme-keyed resolvers never matched JWT-authenticated
  requests: application-store roles were never added (role-gated policies returned 403)
  and no application user was cached. The defensive slot seeding for explicitly-wired
  routes that bypass the forward selector is unchanged. First regression tests for the
  transformer added alongside (fixes
  [#1](https://github.com/cirreum/Cirreum.Runtime.AuthenticationProvider/issues/1)).

## [1.1.3] - 2026-07-20

### Updated

- Updated NuGet packages.

## [1.1.2] - 2026-07-19

### Updated

- Updated NuGet packages.

## [1.1.1] - 2026-07-08

### Updated

- Updated NuGet packages as part of the lower-layer changes.

## [1.1.0] - 2026-07-06

### Added

- `connection.Promote(principal)` — Two-Phase Auth promotion is now an extension member on `IInvocationConnection` (C# 14 extension member on the `TwoPhaseAuth` class), completing the connection-ownership surface whose read side (`PromotedUser` / `EffectiveUser` / `IsUserPromoted`) ships in `Cirreum.Contracts`. Keeps the authenticated-principal validation.
- **Promotion now evicts the cached application user before stamping.** `Promote` removes `AuthenticationContextKeys.ApplicationUserCache` from `connection.Items` *before* writing `PromotedPrincipal` — ordered so an invocation constructed concurrently can never observe the promoted principal paired with the previous identity's cached application user. The lazy resolve path repopulates the slot for the promoted identity. `AuthenticatedScheme` deliberately survives promotion (it describes how the connection/transport authenticated, not the current occupant).
- First test coverage for the promotion surface (8 tests), including an operation-order test locking the evict-before-stamp invariant.

### Changed

- The static `TwoPhaseAuth.Promote(connection, principal)` form and the `GetPromotedPrincipal` / `IsPromoted` statics are gone, superseded by `connection.Promote(...)` and the `Cirreum.Contracts` extension members (`PromotedUser` / `EffectiveUser` / `IsUserPromoted`). No shims — the surface was published but had no external consumers.
- Relocated four misplaced test files that targeted `Cirreum.Runtime.Authentication` (umbrella) types to that repo; they never compiled here. Added the standard dedicated tests solution (`tests/Cirreum.Runtime.AuthenticationProvider.Tests.slnx`).

## [1.0.2] - 2026-07-04

### Updated

- Updated NuGet packages.

## [1.0.1] - 2026-07-04

### Updated

- Updated NuGet packages.

## [1.0.0] - 2026-07-03

### Added

- **Initial release** as part of the **Cirreum 1.0 Foundation Reset** wave. The runtime composition driver for the Authentication track.
- `RegisterAuthenticationProvider<TRegistrar, TSettings, TInstanceSettings>()` — the typed bootstrap the umbrella package (`Cirreum.Runtime.Authentication`) calls once per framework-shipped scheme registrar. Binds the provider's `Cirreum:Authentication:Providers:{Name}` configuration section, dedups via a marker type, and runs the registrar against the ASP.NET `AuthenticationBuilder` — bailing when the section is absent so only configured providers activate.
- `AudienceProviderRoleClaimsTransformer` + `services.AddAudienceRoleClaimsTransformation()` — the framework-shipped `IClaimsTransformation` that runs after ASP.NET authentication, reads the resolved scheme for the request, and dispatches to the per-scheme `IApplicationUserResolver` the app registered to produce the Cirreum `IApplicationUser` and its role claims.
- `TwoPhaseAuth` — connection-state promotion helper for long-lived connections (SignalR / WebSocket): promotes an anonymous-sentinel principal to a fully authenticated one mid-connection after an in-band handshake.
- `AuthenticationProviderDiagnostics` — `ActivitySource` + `Meter` for the Authentication runtime.
