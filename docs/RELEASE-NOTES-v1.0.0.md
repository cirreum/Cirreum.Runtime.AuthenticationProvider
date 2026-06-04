# Cirreum.Runtime.AuthenticationProvider 1.0.0 — The composition engine behind `AddAuthentication()`

`Cirreum.Runtime.AuthenticationProvider` is the runtime driver for Cirreum's Authentication pillar. It turns a scheme **registrar** into registered ASP.NET authentication services, and supplies the claims transformer that maps an authenticated principal onto a Cirreum `IApplicationUser`. Apps never reference it directly — it flows in transitively behind the `Cirreum.Runtime.Authentication` umbrella.

**Strictly additive — initial release.** A new package in the Cirreum 1.0 Foundation Reset; no predecessor. Targets .NET 10.0.

---

## Why this release exists

The Authentication pillar is split into three layers: the *contracts* (`Cirreum.AuthenticationProvider`), the *runtime composition* (this package), and the *app-facing umbrella* (`Cirreum.Runtime.Authentication`). This package is the middle layer — the typed bootstrap that the umbrella calls once per framework-shipped scheme to bind configuration and register handlers, plus the post-authentication machinery (the claims transformer and connection-promotion helper) that every scheme shares. Keeping it separate from the umbrella lets the composition logic evolve and version alongside the contracts, independent of the one-call app surface above it.

---

## What's new

### `RegisterAuthenticationProvider<TRegistrar, TSettings, TInstanceSettings>()`

```csharp
builder.RegisterAuthenticationProvider<
    OidcAuthenticationRegistrar,
    OidcAuthenticationSettings,
    OidcAuthenticationInstanceSettings>(authBuilder);
```

The single bootstrap entry point (invoked by the umbrella, not app code). It dedups via a marker type (repeat calls for the same registrar are no-ops), binds `Cirreum:Authentication:Providers:{ProviderName}` to the typed settings, **skips with a debug log when the section is absent** — so only configured providers activate — and runs the registrar against the ASP.NET `AuthenticationBuilder`, registering one scheme per configured instance.

### `AudienceProviderRoleClaimsTransformer` + `AddAudienceRoleClaimsTransformation()`

The framework-shipped `IClaimsTransformation` that runs after ASP.NET authentication completes: it reads the resolved scheme for the request and dispatches to the per-scheme `IApplicationUserResolver` the app registered, producing the Cirreum `IApplicationUser` and its role claims. One registration covers every scheme.

### `TwoPhaseAuth`

Connection-state promotion for long-lived connections (SignalR / WebSocket): a connection that established with an anonymous sentinel principal can be promoted to a fully authenticated principal mid-connection — after an in-band handshake — without tearing down and re-establishing.

### Diagnostics

`AuthenticationProviderDiagnostics` exposes the Authentication runtime's `ActivitySource` and `Meter` for tracing and metrics.

---

## Why this lives in Cirreum.Runtime.AuthenticationProvider

This is runtime *composition* — neither a contract (those are in `Cirreum.AuthenticationProvider`) nor the app-facing entry point (that's the umbrella). Isolating the bootstrap, the claims transformer, and connection promotion here means the umbrella stays a thin one-call surface while the composition engine versions with the contracts it drives.

---

## Coordinated downstream work

`Cirreum.Runtime.Authentication` (the umbrella) calls `RegisterAuthenticationProvider<…>` once per framework-shipped scheme and wires `AddAudienceRoleClaimsTransformation()`; this package flows into apps transitively through it. Publishes after `Cirreum.AuthenticationProvider`.

---

## Compatibility

- **Additive.** Initial release.
- **.NET 10.0.**
- References `Cirreum.AuthenticationProvider` (the track contracts and registrar base) and the ASP.NET shared framework. `Cirreum.Kernel` / `Cirreum.Common` / `Cirreum.Providers` flow in transitively.

---

## See also

- `CHANGELOG.md` — condensed change list for `1.0.0`.
