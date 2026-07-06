# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

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
