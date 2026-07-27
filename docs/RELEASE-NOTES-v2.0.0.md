# Cirreum.Runtime.AuthenticationProvider 2.0.0 — Instrument the Authentication Track

Authentication emitted **one counter with one tag**. Authorization emitted **four instruments across
eleven dimensions**. This release closes that gap and renames the telemetry surface to match its
peers.

## The questions you couldn't answer before

None of these were answerable from telemetry alone:

- Which scheme was selected for a request, and how often selection matched nothing
- How often a scheme's `IApplicationUserResolver` failed, or found no user
- How long the claims transformer took, and whether it ran more than once per request
- How authenticated schemes were distributed across a multi-IdP deployment

The last one is the one that started this. Since `IdentityProviderType` was removed in this same
wave, **the authenticated scheme is the single authoritative answer to "which identity provider
handled this request"** — and it was recorded only on the activity, never as a metric dimension. You
could see it in a trace you already knew to look at. You could not see the distribution.

## What you get

| Instrument | Kind | Tags |
|---|---|---|
| `cirreum.authn.transformations` | Counter | `outcome`, `scheme`, `resolver` |
| `cirreum.authn.transformation.duration` | Histogram (ms) | `outcome`, `scheme` |
| `cirreum.authn.selections` | Counter | `scheme`, `selector` |

Nothing needs subscribing. `AddCirreum()` already registers the `Cirreum.Authentication` source and
meter, so these show up wherever the existing counter already did.

**`cirreum.authn.selections` is recorded once, at the forward-scheme resolver** in the umbrella
package — the single site every `ISchemeSelector` is dispatched through. One call covers the whole
registered set, framework-shipped and app-supplied alike, so adding a scheme never leaves a hole in
the distribution. A `selector` value of `none` means nothing claimed the request and the resolver
fell through to its default: that distinguishes a genuine Anonymous selection from a misconfigured
selector set, which previously looked identical.

Two deliberate omissions. The **duration histogram carries only `outcome` and `scheme`** — buckets
multiply per series, so the resolver dimension stays on the counter. And the **external user
identifier never becomes a metric tag**; it is unbounded, and one time series per user is a
metrics-backend incident rather than an observability win. It stays on the activity, where a single
trace carries it.

## Read this first if you have dashboards

One instrument is renamed:

| Before | After |
|---|---|
| `auth_transformations_total` | `cirreum.authn.transformations` |

Two things were wrong with the old name. It was the **only instrument in the framework using
underscores as segment separators** — everything else is dot-separated (`cirreum.authz.decisions`,
`conductor.operations.total`, `messaging.messages.received`), with underscores reserved for
multi-word segments like `cirreum.authz.resource_type`. And the `_total` suffix is a Prometheus
exposition detail an exporter appends; it does not belong in an OpenTelemetry instrument name, and no
other counter here carries it.

`authn` parallels the existing `cirreum.authz.*` namespace, so authentication and authorization sort
together and read as the pair they are.

## What else breaks

**`AuthenticationProviderDiagnostics` is now `AuthenticationTelemetry`.** Every peer is named
`*Telemetry` — `AuthorizationTelemetry`, `ProvisioningTelemetry`. This one was the outlier, and the
old name understated what it now holds: the whole tag, outcome and metric vocabulary for the track.
The namespace is unchanged, so only the type name moves.

**`AuthenticationProviderDiagnostics.DiagnosticName` is removed.** It restated the literal
`"Cirreum.Authentication"` — the same value as `CirreumTelemetry.ActivitySources.Authentication` and
`.Meters.Authentication`. Those constants are the registration half of a cross-package contract:
`AddCirreum()` subscribes exactly those names, and a source or meter whose name is never registered is
**silently inert**. A second copy of the literal could drift from the registered one, and the only
symptom would be telemetry quietly disappearing.

Its documentation claimed the constant was "referenced by the umbrella package to subscribe to
telemetry." Nothing referenced it — not the umbrella, not this package outside its own file. If you
did reference it, use `CirreumTelemetry.ActivitySources.Authentication`, and check whether you need it
at all.

**Transformation outcome values changed.** The counter said `already_transformed`; the activity and
the public `ClaimsTransformResult.Outcome` said `AlreadyTransformed`. Two spellings of one fact meant
joining a metric to a trace, or to the stashed diagnostic record, needed a translation table nobody
had written down. All three now emit the same lowercase-hyphenated
`AuthenticationTelemetry.Outcome*` constants — `roles-resolved`, `already-transformed`,
`role-resolution-failed`, and so on — matching `AuthorizationTelemetry`'s value style.

Activity tag names moved to the same `cirreum.authn.*` namespace. The old set was neither prefixed
consistently nor internally consistent: `auth.transform.outcome` sat alongside
`auth.transformer.name`, and the user identifier was `external.user.id`. Full table in
[`MIGRATION-v2.md`](MIGRATION-v2.md).

## The part that breaks nothing and changes everything

The claims transformer carried its own copy of the Kernel's claim-resolution logic, and the copy was
on the wrong side of the framework's identity-scope rule **in both directions**: it read the user
identifier across every identity (a singular fact, which the Kernel scopes to the primary identity)
and checked for existing roles on only one (an aggregate, which `ClaimsPrincipal.IsInRole` spans).

The identifier one was not cosmetic. That value goes to `IApplicationUserResolver.ResolveAsync`, so a
`sub` on a secondary identity would load **that subject's application user and stamp their roles onto
the current principal**. It now resolves from the primary identity or not at all.

Deleting the copy in favor of `ClaimsHelper.ResolveId` closed three more divergences it had
accumulated:

- **A blank claim shadowed a populated one** — an empty `oid` suppressed a valid `sub` and escaped as
  a non-null identifier into your resolver.
- **`ClaimTypes.NameIdentifier` was unknown** — the OIDC middleware maps `sub` onto that URI when
  `MapInboundClaims` is enabled, so those principals resolved nothing and never received application
  roles.
- **There was no priority order at all** — it returned the first claim in the collection whose *type*
  matched, so with both `sub` and the Entra object identifier present, which one identified the user
  depended on the order the token emitted them in.

Also: a role the resolver returns twice is now added once. Not an authorization bug — `IsInRole`
answered correctly either way — but duplicate claims ride the principal into session tickets and
long-lived connection state, costing payload on every round trip.

**None of this breaks the build**, which is exactly why it is worth reading. On a single-identity
principal carrying one identifier claim — what the Cirreum Server, Serverless and Client hosts
compose — none of it fires. Two cases deserve a check before you upgrade:

- **Your store is keyed on `sub` and your tokens also carry the Entra object identifier.** Lookups
  will now resolve on `oid` and miss. Re-key on what `ClaimsHelper.ResolveId` returns — which is what
  `UserProfile` and `IUserState` already use for the same user.
- **You worked around the missing `NameIdentifier` mapping.** Those principals now resolve on their
  own; check for double-granting.

Full detail in [`MIGRATION-v2.md`](MIGRATION-v2.md) §6.

## Also fixed

**Outcomes that exit before resolver dispatch now carry the scheme.** The already-transformed and
no-claims-identity paths recorded no scheme tag, so a double transformation or a malformed identity
was unattributable to the IdP that caused it — the exact blind spot this release exists to close.
Caught by the new tests rather than by review.

**A `no-http-context` outcome is now recorded.** That path previously returned silently, so the
counter's total did not equal the invocation count.

**The `ActivitySource` and `Meter` are created with a version.** Without one, a backend has no way to
attribute spans or metrics to a release of the instrumenting library. This closes one of three
unversioned sources identified in the 2026-07-04 framework-wide tracing review.

**Every outcome now routes through one exit path** that records the counter, the duration and the
activity tags together. Each outcome previously repeated three separate calls, so a new branch could
record one instrument and forget the others — which is how the missing scheme tag got there.

## Compatibility

Breaking. The renamed class and removed constant are compile errors.

Everything else is silent. The metric rename, the tag renames and the outcome-value change affect
dashboards, saved queries and any code comparing `ClaimsTransformResult.Outcome` against a string
literal. The transformer corrections change which principals resolve an application user and which
receive roles, with no compile signal at all.

See [`MIGRATION-v2.md`](MIGRATION-v2.md) — find/replace table for the compile breaks, §6 for the
silent ones.

## Coordinated downstream work

Part of the `Cirreum.Kernel` 2.0.0 wave. `Cirreum.Runtime.Authentication` re-pins and picks up the
`RecordSchemeSelection` call in its forward-scheme resolver — the selection counter only starts
reporting once that ships. `Cirreum.Domain` renames four Conductor instruments in the same wave
(`conductor.notifications.*` → `conductor.domain_events.*`), so a single observability pass covering
both is worth doing once rather than twice.

## See also

- [`MIGRATION-v2.md`](MIGRATION-v2.md)
- [`CHANGELOG.md`](CHANGELOG.md)
