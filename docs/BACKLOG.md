# Backlog

Deferred work for **Cirreum.Runtime.AuthenticationProvider**. Items here are tracked but not yet ready
to ship — either because the cost outweighs the benefit in isolation, or
because they're waiting on a forcing function (a related change, a consumer
upgrade, a coordinated multi-repo rollout).

## How this file works

- Each item is a `###` heading so it can be linked to and parsed.
- Each item declares **`SemVer:`** (`Patch` | `Minor` | `Major` | `Unspecified`),
  **`Trigger:`** (the human-readable condition that will make it ready), and
  **`Noted:`** (the date the item was added).
- The Cirreum DevOps release scripts (`PatchRelease`, `MinorRelease`,
  `MajorRelease`) surface items at-or-below the requested bump level so the
  operator can decide whether to fold them in before tagging.
- Items that ship: move from this file to `docs/CHANGELOG.md` under
  `[Unreleased]`. Items that grow into design discussions: promote to an ADR.

## Queued

### Instrument the authentication track to match the authorization track

- **SemVer:** Minor
- **Trigger:** The Kernel 2.0.0 rename/removal wave — this package is already being re-released for the metric rename, so the instrumentation lands without a separate release.
- **Noted:** 2026-07-25

Authentication emits **one counter, no tags** (`cirreum.authn.transformations`). Authorization emits
**four instruments and eleven tags** — decisions by stage/step/decision/reason, pipeline duration,
grant-resolution duration on the cold path, and grant cache hit/miss.

The gap is not cosmetic. Today there is no way to answer, from telemetry alone:

- Which scheme was selected for a request, and how often selection finds no match
- How often a scheme's `IApplicationUserResolver` fails or returns no user
- How long the claims transformer takes, and whether it is being hit more than once per request
- The authenticated-scheme distribution across a multi-IdP deployment

That last one matters more since the removal of `IdentityProviderType`: the authenticated scheme is
now the single authoritative answer to "which identity provider handled this request," and it is
currently unobservable.

`AuthorizationTelemetry` (`Cirreum.Contracts`) is the blueprint — it is the one telemetry class in
the framework that gets everything right: names sourced from `CirreumTelemetry` constants rather
than literals, `CirreumTelemetry.Version` passed to both source and meter, metric names as public
constants, dot-separated, and tags rich enough to answer *why* rather than only *how many*. Follow
its shape rather than inventing a new one.

Scope note: the claims transformer lives here, but scheme selection lives in
`Cirreum.Runtime.Authentication` (`JwtAudienceSchemeSelector`) — so full coverage spans both
packages, and the shared names must come from `CirreumTelemetry.ActivitySources.Authentication` /
`.Meters.Authentication` so a single registration covers them.
