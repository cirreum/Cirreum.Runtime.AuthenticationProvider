# Cirreum.Runtime.AuthenticationProvider v1 → v2 Migration

## Why v2

The diagnostics surface is rebuilt: the class is renamed to match its peers, a metric is renamed, a
public constant that duplicated a Kernel constant is removed, and the transformation outcome
vocabulary is unified across metrics, traces and the diagnostic record. The release also *adds* the
instrumentation the authentication track was missing (§5), and corrects how the claims transformer
resolves a user identifier and detects existing roles (§6).

> **Read §6 even if the compiler is quiet.** §1–§4 break the build and tell you where to look. §6
> changes runtime behavior with no compile signal at all — which principals resolve an application
> user, and which get roles.

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

## 6. Claims transformer behavior — silent changes

**Nothing here breaks the build.** These change which principals resolve an application user and
which receive roles. On a single-identity principal carrying one identifier claim — what the Cirreum
Server, Serverless and Client hosts compose — none of them fire. They matter when a token carries
more than one identifier form, or when parts of Cirreum run in a host that composes principals
differently.

The transformer had its own copy of the Kernel's claim-resolution logic, on the wrong side of the
framework's identity-scope rule in both directions. The copy is gone; it calls `ClaimsHelper`.

### 6a. The user identifier comes from the primary identity only

It previously searched `principal.Claims`, which spans **every** identity the principal carries. A
user identifier is a singular fact, and the Kernel scopes those to the primary identity because a
value taken from a second authentication context is not a broader answer — it is an answer about
someone else. Here that mattered concretely: the identifier is handed to
`IApplicationUserResolver.ResolveAsync`, so a `sub` on a secondary identity would load **that
subject's** application user and stamp their roles onto the current principal.

*If a principal's only identifier lived on a secondary identity, it now resolves nothing* — outcome
`no-user-identifier`, no roles. That is the fix, not a regression: it was previously resolving the
wrong subject.

### 6b. A blank claim no longer shadows a populated one

The copy returned the first claim of a matching *type* regardless of its value, so a present-but-empty
`oid` suppressed a valid `sub` and escaped as a non-null identifier into your resolver.
`ClaimsHelper` treats a blank claim as absent and continues down the order.

### 6c. `ClaimTypes.NameIdentifier` is now recognized

The OIDC middleware maps `sub` onto `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier`
when `MapInboundClaims` is enabled. The copy did not know that claim type, so those principals
resolved no identifier at all and never received application roles.

*Those principals now resolve and receive roles.* If you had worked around this — mapping the claim
yourself, or granting roles by another route — check for double-granting.

### 6d. Identifier priority is deterministic

The copy scanned the claim collection and returned the first claim whose *type* matched any of the
four it knew. With both `sub` and the long-form Entra object identifier present, which one identified
the user depended on the order the token happened to emit them in. `ClaimsHelper` walks claim types
in priority order, preferring `oid` — tenant-stable, where `sub` can be pairwise per application.

*If your user store is keyed on `sub` and your tokens also carry the Entra object identifier, lookups
will now miss.* This is the change most likely to surprise: re-key on the identifier
`ClaimsHelper.ResolveId` returns, which is what `UserProfile` and `IUserState` already use for the
same user.

### 6e. The "roles already present" check spans every identity

It inspected only the primary identity, while `ClaimsPrincipal.IsInRole` — and the Kernel's
`IdentityScope.AllIdentities` default for roles — span all of them. Roles are the one aggregate among
these reads, so breadth is correct: a role on a secondary identity is one the principal genuinely
answers to. Each identity is read against **its own** `RoleClaimType`, matching how `IsInRole`
evaluates a multi-identity principal.

*On a multi-identity principal whose secondary carries roles, application-store roles are no longer
added on top.*

### 6f. A role resolved twice is added once

`IApplicationUser.Roles` is an `IReadOnlyList<string>` with no distinctness contract, so a resolver
joining user → group → role can return the same role twice — and every entry was added
unconditionally. Not an authorization bug (`IsInRole` still answered correctly), but the duplicate
claims ride the principal into session tickets and long-lived connection state, costing payload on
every round trip.

`ClaimsTransformResult.RoleCount` and the `RolesResolved` log now report the number of roles
**added** rather than the number the resolver returned. A `Debug` entry names the resolver and the
duplicate count.

## Also in this release

The `ActivitySource` and `Meter` are now created with `CirreumTelemetry.Version`. Without a version,
a backend has no way to attribute spans or metrics to a release of the instrumenting library. This
closes one of the three unversioned sources identified in the 2026-07-04 framework-wide tracing
review. Not breaking — spans and metrics simply gain a version attribute.

The claims-transformation activity states `ActivityKind.Internal` explicitly rather than relying on
the default. Same value, now declared.

## What Didn't Change

- `AudienceProviderRoleClaimsTransformer`'s dispatch through `AuthenticatedScheme`, and its
  short-circuit when no resolver matches the scheme
- `IApplicationUserResolver` selection and the application-user cache on `HttpContext.Items`
- The claim type roles are written to — still the identity's `RoleClaimType`
- Two-phase auth promotion and `AuthenticationContextKeys`
- `ClaimsTransformResult`'s shape and its `ItemsKey` — the `Outcome` *values* changed (§4) and
  `RoleCount` now counts what was added (§6f)
- The `Cirreum.Authentication` source and meter *names* — only where the literal comes from

## Downstream Package Impact

`Cirreum.Runtime.Authentication` (the umbrella) re-pins, and gains one call to
`AuthenticationTelemetry.RecordSchemeSelection` in its forward-scheme resolver. If it subscribed
telemetry by hand using `DiagnosticName`, replace it per §3 — or drop the subscription, since
`AddCirreum()` covers it.
