# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
