# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

- **Initial release** as part of the **Cirreum 1.0 Foundation Reset** wave. The runtime composition driver for the Authentication track.
- `RegisterAuthenticationProvider<TRegistrar, TSettings, TInstanceSettings>()` — the typed bootstrap the umbrella package (`Cirreum.Runtime.Authentication`) calls once per framework-shipped scheme registrar. Binds the provider's `Cirreum:Authentication:Providers:{Name}` configuration section, dedups via a marker type, and runs the registrar against the ASP.NET `AuthenticationBuilder` — bailing when the section is absent so only configured providers activate.
- `AudienceProviderRoleClaimsTransformer` + `services.AddAudienceRoleClaimsTransformation()` — the framework-shipped `IClaimsTransformation` that runs after ASP.NET authentication, reads the resolved scheme for the request, and dispatches to the per-scheme `IApplicationUserResolver` the app registered to produce the Cirreum `IApplicationUser` and its role claims.
- `TwoPhaseAuth` — connection-state promotion helper for long-lived connections (SignalR / WebSocket): promotes an anonymous-sentinel principal to a fully authenticated one mid-connection after an in-band handshake.
- `AuthenticationProviderDiagnostics` — `ActivitySource` + `Meter` for the Authentication runtime.
