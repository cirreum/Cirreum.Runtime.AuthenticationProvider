# Cirreum.Runtime.AuthenticationProvider 2.0.0 — Re-point One Metric

## Read this first if you have dashboards

One instrument is renamed. It is the only change here that breaks something outside your source
tree:

| Before | After |
|---|---|
| `auth_transformations_total` | `cirreum.authn.transformations` |

Now published as `AuthenticationProviderDiagnostics.TransformationsMetric`, so the next rename is a
compile-time reference rather than a search.

Two things were wrong with the old name. It was the **only instrument in the framework using
underscores as segment separators** — everything else is dot-separated (`cirreum.authz.decisions`,
`conductor.operations.total`, `messaging.messages.received`), with underscores reserved for
multi-word segments like `cirreum.authz.resource_type`. And the `_total` suffix is a Prometheus
exposition detail an exporter appends; it does not belong in an OpenTelemetry instrument name, and no
other counter here carries it.

`authn` parallels the existing `cirreum.authz.*` namespace, so authentication and authorization sort
together and read as the pair they are.

## What else breaks

**`AuthenticationProviderDiagnostics.DiagnosticName` is removed.** It restated the literal
`"Cirreum.Authentication"` — the same value as `CirreumTelemetry.ActivitySources.Authentication` and
`.Meters.Authentication`.

Those constants are the registration half of a cross-package contract: `AddCirreum()` subscribes
exactly those names, and a source or meter whose name is never registered is **silently inert**. A
second copy of the literal could drift from the registered one, and the only symptom would be
telemetry quietly disappearing.

Its documentation claimed the constant was "referenced by the umbrella package to subscribe to
telemetry." Nothing referenced it — not the umbrella, not this package outside its own file.

If you did reference it, use `CirreumTelemetry.ActivitySources.Authentication` — and check whether
you need it at all, since `AddCirreum()` already registers that name.

## Also fixed

The `ActivitySource` and `Meter` are now created **with a version**. Without one, a backend has no
way to attribute spans or metrics to a release of the instrumenting library. Not breaking — spans and
metrics simply gain a version attribute.

This closes one of three unversioned sources identified in the 2026-07-04 framework-wide tracing
review.

## Compatibility

Breaking. The removed constant is a compile error; the metric rename is silent and affects dashboards
rather than code.

See [`MIGRATION-v2.md`](MIGRATION-v2.md).

## Coordinated downstream work

Part of the `Cirreum.Kernel` 2.0.0 wave. `Cirreum.Domain` renames four Conductor instruments in the
same wave — `conductor.notifications.*` → `conductor.domain_events.*` — so a single observability
pass covering both is worth doing once rather than twice.

## See also

- [`MIGRATION-v2.md`](MIGRATION-v2.md)
- [`CHANGELOG.md`](CHANGELOG.md)
