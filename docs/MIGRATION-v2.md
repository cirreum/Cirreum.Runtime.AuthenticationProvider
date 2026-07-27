# Cirreum.Runtime.AuthenticationProvider v1 → v2 Migration

## Why v2

The diagnostics surface is rebuilt: the class is renamed to match its peers, a metric is renamed, a
public constant that duplicated a Kernel constant is removed, and the transformation outcome
vocabulary is unified across metrics, traces and the diagnostic record. The release also *adds* the
instrumentation the authentication track was missing — see §5.

## Breaking Changes — Find/Replace Table

| Before | After |
|---|---|
| `AuthenticationProviderDiagnostics` (class) | `AuthenticationTelemetry` |
| `auth_transformations_total` (metric) | `cirreum.authn.transformations` |
| `AuthenticationProviderDiagnostics.DiagnosticName` | `CirreumTelemetry.ActivitySources.Authentication` / `.Meters.Authentication` |
| `ClaimsTransformResult.Outcome == "RolesResolved"` | `== AuthenticationTelemetry.OutcomeRolesResolved` (`"roles-resolved"`) |
| Activity tag `auth.transform.outcome` | `cirreum.authn.outcome` |
| Activity tag `auth.scheme` | `cirreum.authn.scheme` |
| Activity tag `auth.resolver.type` | `cirreum.authn.resolver` |
| Activity tag `auth.transformer.name` | `cirreum.authn.transformer` |
| Activity tag `auth.role_claim_type` | `cirreum.authn.role_claim_type` |
| Activity tag `auth.roles.count` | `cirreum.authn.role_count` |
| Activity tag `external.user.id` | `cirreum.authn.user_id` |

## 1. Class renamed to `AuthenticationTelemetry`

Every peer telemetry class in the framework is named `*Telemetry` — `AuthorizationTelemetry` in
`Cirreum.Contracts`, `ProvisioningTelemetry` in `Cirreum.IdentityProvider`. This one was the outlier,
and the name understated it: it now carries the whole tag, outcome and metric vocabulary for the
track, not a lone metric name.

```csharp
// Before
AuthenticationProviderDiagnostics.TransformationsMetric

// After
AuthenticationTelemetry.TransformationsMetric
```

The namespace is unchanged (`Cirreum.AuthenticationProvider`), so only the type name moves.

## 2. Metric rename

`auth_transformations_total` → **`cirreum.authn.transformations`**, now published as the public
constant `AuthenticationTelemetry.TransformationsMetric`.

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

## 3. `DiagnosticName` removed

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

## 4. Outcome values are one vocabulary

The counter reported `already_transformed`. The activity reported `AlreadyTransformed`. The public
`ClaimsTransformResult.Outcome` reported `AlreadyTransformed`. Three surfaces describing one fact in
two spellings, so joining a metric to a trace or to the stashed diagnostic record needed a
translation table nobody had written down.

All three now emit the same lowercase-hyphenated constants, matching `AuthorizationTelemetry`'s value
style (`owner-scope`, `l1-hit`):

| Old value | New constant | New value |
|---|---|---|
| `AlreadyTransformed` | `OutcomeAlreadyTransformed` | `already-transformed` |
| `NoClaimsIdentity` | `OutcomeNoClaimsIdentity` | `no-claims-identity` |
| `NoResolver` | `OutcomeNoResolver` | `no-resolver` |
| `RolesAlreadyPresent` | `OutcomeRolesAlreadyPresent` | `roles-already-present` |
| `NoUserIdentifier` | `OutcomeNoUserIdentifier` | `no-user-identifier` |
| `NoApplicationUser` | `OutcomeNoApplicationUser` | `no-application-user` |
| `NoRolesResolved` | `OutcomeNoRolesResolved` | `no-roles-resolved` |
| `RolesResolved` | `OutcomeRolesResolved` | `roles-resolved` |
| `RoleResolutionFailed` | `OutcomeRoleResolutionFailed` | `role-resolution-failed` |
| *(nothing recorded)* | `OutcomeNoHttpContext` | `no-http-context` |

### If you compared `ClaimsTransformResult.Outcome` against a literal

```csharp
// Before
if (result.Outcome == "RolesResolved") { … }

// After — compare against the constant, not a new literal
if (result.Outcome == AuthenticationTelemetry.OutcomeRolesResolved) { … }
```

This is a diagnostic record meant for debugging and diagnostic middleware; if you were only reading
it in a debugger or logging it, nothing to do.

## 5. New instrumentation (additive)

The authentication track emitted one counter with one tag while authorization emitted four
instruments across eleven dimensions. None of these were answerable from telemetry alone: which
scheme was selected, how often selection matched nothing, how often a scheme's
`IApplicationUserResolver` failed or found no user, how long the transformer took, and how
authenticated schemes were distributed across a multi-IdP deployment. That last one is the one that
matters most now that `IdentityProviderType` is gone — the authenticated scheme is the single
authoritative answer to "which identity provider handled this request", and it was recorded only on
the activity.

| Instrument | Kind | Tags |
|---|---|---|
| `cirreum.authn.transformations` | Counter | `outcome`, `scheme`, `resolver` |
| `cirreum.authn.transformation.duration` | Histogram (ms) | `outcome`, `scheme` |
| `cirreum.authn.selections` | Counter | `scheme`, `selector` |

`cirreum.authn.selections` is recorded by the umbrella package's forward-scheme resolver — the single
site every `ISchemeSelector` is dispatched through, so one call covers the whole registered set,
framework-shipped and app-supplied alike. A `selector` value of `none` means nothing claimed the
request and the resolver fell through to its default, which distinguishes a genuine Anonymous
selection from a misconfigured selector set.

Nothing needs subscribing: `AddCirreum()` already registers the `Cirreum.Authentication` source and
meter, so these appear wherever the existing counter already did.

The external user identifier stays on the activity and is never a metric dimension — it is unbounded,
and one time series per user is a metrics-backend incident rather than an observability win.

## Also in this release

The `ActivitySource` and `Meter` are now created with `CirreumTelemetry.Version`. Without a version,
a backend has no way to attribute spans or metrics to a release of the instrumenting library. This
closes one of the three unversioned sources identified in the 2026-07-04 framework-wide tracing
review. Not breaking — spans and metrics simply gain a version attribute.

## What Didn't Change

- `AudienceProviderRoleClaimsTransformer` and its dispatch through `AuthenticatedScheme`
- `IApplicationUserResolver` selection, caching on `HttpContext.Items`, and role claim mapping
- Two-phase auth promotion and `AuthenticationContextKeys`
- `ClaimsTransformResult`'s shape and its `ItemsKey` — only the `Outcome` *values* changed
- The `Cirreum.Authentication` source and meter *names* — only where the literal comes from

## Downstream Package Impact

`Cirreum.Runtime.Authentication` (the umbrella) re-pins, and gains one call to
`AuthenticationTelemetry.RecordSchemeSelection` in its forward-scheme resolver. If it subscribed
telemetry by hand using `DiagnosticName`, replace it per §3 — or drop the subscription, since
`AddCirreum()` covers it.
