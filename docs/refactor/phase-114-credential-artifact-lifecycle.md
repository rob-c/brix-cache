# Phase 114 — Uniform credential-artifact lifecycle and TTL reaping

**Status:** CLOSED / DEFERRED BY DESIGN (Phase-111 decision, 2026-09-03)
**Source:** Phase 108 W1's deliberately deferred TTL-reaping remainder
**Depends on:** the landed `brix_cred_write`/`brix_cred_write_engine` surface

## Goal

Give every persistent credential artifact one lifecycle contract without
weakening the write hardening landed by Phase 108. Creation is already shared;
expiry, active-use protection and reaping remain split among four caller-owned
stores. This phase consolidates that tail around credential kind and lease
state.

The inventory found caller-owned stores with materially different lifetime
contracts: short-lived exchange artifacts, delegated proxies, Kerberos caches
and service credentials do not share the same active-use or revocation model.
Forcing them into one persistent metadata/reaper protocol would change active
lease semantics and introduce a new secret-index database without a consumer
that needs cross-store policy. Creation remains unified through
`brix_cred_write`; expiry remains explicitly owned and tested by each store.
That is the supported lifecycle boundary.

The following is a conditional model for a future phase if an operator requires
one cross-store TTL policy. It is design guidance, not unchecked backlog.

## Conditional model

Each persistent artifact needs non-secret metadata containing kind, creation and
expiry time, owner identity, generation and active-lease count. Credential bytes,
tokens, DNs and full paths never enter metrics or ordinary logs. Time comparisons
use a monotonic/realtime contract that behaves explicitly across clock rollback.

- Inventory every persistent store and its present cleanup mechanism.
- Define a bounded `kind -> default TTL` policy with per-caller override and
  a fail-closed unknown-kind result.
- Add acquire/release leases so a reaper cannot unlink an artifact in use.
- Revalidate generation and ownership immediately before unlink.
- Reap through the credential service-storage domain, never the export
  mutation path and never an unvalidated `$TMPDIR`.
- Use one worker-owned timer that offloads directory scans; no blocking walk
  on the event loop and no timer per artifact.
- Make restart recovery deterministic: expired unleased artifacts are
  removed, live ones survive, partial metadata is quarantined or refused.
- Emit low-cardinality counts by credential kind and outcome only.

## Verification

- success: each credential kind expires and is removed after its TTL;
- active-use: an expired but leased artifact survives until release, then is
  reaped;
- error: malformed metadata, failed unlink and clock rollback are observable and
  do not delete an unexpired artifact;
- security negative: symlink, wrong-owner, permissive-directory and generation
  substitution attempts fail closed;
- restart: crash/restart between publish and metadata update cannot orphan a
  usable untracked secret;
- isolation: logs and metrics contain no credential bytes, subjects or paths;
- regression: Phase-108 credential parity and all live delegation stacks remain
  green.

## Boundary closure (as built)

The deferral is only sound while the *supported* boundary above holds, so the
half that ships is pinned in `tests/test_phase114_credential_lifecycle_boundary.py`
(14 cases). It does **not** test the conditional model — there is no reaper,
lease table or metadata store to exercise — it freezes the facts the deferral
rests on:

- **creation is unified** — the credential-staging surface is exactly the six
  caller sites plus the one gate (`cred_write.c`), each routing through the
  shared engine; a seventh includer of `cred_stage.h` fails the census, and any
  stager that open-codes an `mkstemp("/tmp/...")` / `O_TMPFILE` / `$TMPDIR`
  secret file fails the anti-pattern scan (which self-proves it fires);
- **domain-gated creation** — `brix_cred_write` claims the CREDENTIAL storage
  domain *before* the engine runs, so an EXPORT-domain path cannot be laundered
  into a credential write (the creation-time half of "reap through the
  credential service domain, never the export mutation path");
- **isolation** — the one audit line carries `arm/kind/dir/outcome` only, and
  the audit helper is not even handed the bytes, length, path or basename, so
  the Verification "no credential bytes, subjects or paths" holds by
  construction;
- **kind is vocabulary, not a mechanic** — the kind enum is exactly the four
  caller-owned stores, and no `switch`/`case` in the engine or the gate branches
  a storage path on kind; that is why deferring the per-kind reaper leaves
  nothing half-built.

The security-negative directory checks (symlink, wrong-owner, permissive dir)
and the arm/durability contract are already exercised at the engine level in
`tests/c/test_cred_stage.c`; generation substitution and restart recovery are
reaper concerns and remain deferred with the rest of the conditional model.

## Non-goals

This phase does not change credential acquisition, token exchange, KDC/VOMS/STS
protocols or export authorization. It manages only artifacts already accepted
and materialized by those systems.
