# Cirreum.Runtime.AuthenticationProvider v1 → v2 Migration

## Why v2

Two changes to the diagnostics surface: a metric is renamed, and a public constant that duplicated a
Kernel constant is removed.

## Breaking Changes — Find/Replace Table

| Before | After |
|---|---|
| `auth_transformations_total` (metric) | `cirreum.authn.transformations` |
| `AuthenticationProviderDiagnostics.DiagnosticName` | `CirreumTelemetry.ActivitySources.Authentication` / `.Meters.Authentication` |

## 1. Metric rename

`auth_transformations_total` → **`cirreum.authn.transformations`**, now published as the public
constant `AuthenticationProviderDiagnostics.TransformationsMetric`.

It was the only instrument in the framework using underscores as *segment* separators. Everything
else is dot-separated — `cirreum.authz.decisions`, `conductor.operations.total`,
`messaging.messages.received`. Underscores separate words **within** a segment
(`cirreum.authz.resource_type`, `messaging.processor.queue_time`); they never separate segments.

The `_total` suffix is dropped as well. That is a Prometheus exposition detail an exporter appends
when it renders a counter — it is not part of an OpenTelemetry instrument name, and no other counter
in the framework carries it.

`authn` parallels the existing `cirreum.authz.*` namespace, so authentication and authorization sort
together and read as the pair they are.

**Update any dashboard, alert, or saved query bound to the old name.** Nothing else changes: the
instrument is the same counter, incremented at the same point, with the same tags.

## 2. `DiagnosticName` removed

```csharp
// Before
public const string DiagnosticName = "Cirreum.Authentication";
```

That literal is the same value as `CirreumTelemetry.ActivitySources.Authentication` and
`CirreumTelemetry.Meters.Authentication`. Those constants are the **registration half of a
cross-package contract**: Kernel's `AddCirreum()` subscribes exactly those names, and a source or
meter whose name is never registered is silently inert — recording into the void with no listener
attached and nothing failing to say so. A second copy of the literal could drift from the registered
one, and the only symptom would be telemetry quietly disappearing.

Its documentation also claimed the constant was "referenced by the umbrella package to subscribe to
telemetry." Nothing referenced it — not the umbrella, not this package outside its own file.

### If you referenced it

```csharp
// Before
t.AddSource(AuthenticationProviderDiagnostics.DiagnosticName);

// After — and check whether you need it at all
t.AddSource(CirreumTelemetry.ActivitySources.Authentication);
```

`AddCirreum()` already registers this name, so an application calling it collects authentication
telemetry without subscribing anything by hand.

Note the source and meter now take their names from the **matching** constant each —
`ActivitySources.Authentication` for the source, `Meters.Authentication` for the meter. They hold
equal values today; nothing guarantees they stay equal, and one alias serving both was quietly
assuming they would.

## Also in this release

The `ActivitySource` and `Meter` are now created with `CirreumTelemetry.Version`. Without a version,
a backend has no way to attribute spans or metrics to a release of the instrumenting library. This
closes one of the three unversioned sources identified in the 2026-07-04 framework-wide tracing
review. Not breaking — spans and metrics simply gain a version attribute.

## What Didn't Change

- `AudienceProviderRoleClaimsTransformer` and its dispatch through `AuthenticatedScheme`
- `IApplicationUserResolver` selection, caching on `HttpContext.Items`, and role claim mapping
- Two-phase auth promotion and `AuthenticationContextKeys`
- The `Cirreum.Authentication` source and meter *names* — only where the literal comes from

## Downstream Package Impact

`Cirreum.Runtime.Authentication` (the umbrella) re-pins. If it subscribed telemetry by hand using
`DiagnosticName`, replace it per §2 — or drop the subscription, since `AddCirreum()` covers it.
