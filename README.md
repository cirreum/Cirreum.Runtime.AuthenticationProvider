# Cirreum Runtime AuthenticationProvider

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Runtime.AuthenticationProvider.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Runtime.AuthenticationProvider/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Runtime.AuthenticationProvider.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Runtime.AuthenticationProvider/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Runtime.AuthenticationProvider?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Runtime.AuthenticationProvider/releases)
[![License](https://img.shields.io/badge/license-MIT-F2F2F2?style=flat-square&labelColor=1F1F1F)](https://github.com/cirreum/Cirreum.Runtime.AuthenticationProvider/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**Runtime driver for the Cirreum Authentication track — the composition engine behind the `AddAuthentication()` umbrella.**

## Overview

`Cirreum.Runtime.AuthenticationProvider` is the Runtime-layer driver for Cirreum's Authentication pillar. It supplies the typed bootstrap that turns a scheme **registrar** into registered ASP.NET authentication services, plus the framework-shipped claims transformer that maps an authenticated principal onto a Cirreum `IApplicationUser` per scheme.

Apps do **not** reference this package directly — they install the umbrella `Cirreum.Runtime.Authentication`, which calls into this driver once per framework-shipped scheme. It flows in transitively.

## API

### `RegisterAuthenticationProvider<TRegistrar, TSettings, TInstanceSettings>()`

```csharp
using Microsoft.Extensions.Hosting;

builder.RegisterAuthenticationProvider<
    OidcAuthenticationRegistrar,
    OidcAuthenticationSettings,
    OidcAuthenticationInstanceSettings>(authBuilder);
```

The single bootstrap entry point, invoked by the umbrella package (`AddAuthentication`) once per framework-shipped registrar — not from app code.

**What it does:**

1. Dedup check via marker-type registration — repeated calls for the same `TRegistrar` are no-ops.
2. Binds `Cirreum:Authentication:Providers:{ProviderName}` from `IConfiguration` to `TSettings`.
3. Skips with a debug log when the section is missing — so only configured providers activate.
4. Runs the registrar against the ASP.NET `AuthenticationBuilder`, registering one scheme per configured instance.

### `AudienceProviderRoleClaimsTransformer` / `services.AddAudienceRoleClaimsTransformation()`

The framework-shipped `IClaimsTransformation` that runs after ASP.NET authentication completes. It reads the resolved scheme for the request and dispatches to the per-scheme `IApplicationUserResolver` the app registered, producing the Cirreum `IApplicationUser` and its role claims. Wired by the umbrella; one registration covers every scheme.

### `TwoPhaseAuth`

Connection-state promotion helper for long-lived connections (SignalR / WebSocket). Lets a connection that established with an anonymous sentinel principal be promoted to a fully authenticated principal mid-connection (e.g. after an in-band handshake), without tearing down and re-establishing.

### Diagnostics

`AuthenticationProviderDiagnostics` exposes the Authentication runtime's `ActivitySource` and `Meter` for tracing and metrics.

## Dependencies

- **Cirreum.AuthenticationProvider** — Authentication track contracts and registrar base (`Cirreum.Kernel`, `Cirreum.Common`, `Cirreum.Providers` flow in transitively)
- **Microsoft.AspNetCore.App** — ASP.NET authentication primitives

## Versioning

Follows [Semantic Versioning](https://semver.org/). Foundational library — major bumps are rare and coordinated with `Cirreum.AuthenticationProvider` releases.

## License

MIT — see [LICENSE](LICENSE).

---

**Cirreum Foundation Framework**  
*Layered simplicity for modern .NET*
