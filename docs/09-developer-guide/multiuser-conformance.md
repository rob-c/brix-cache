# Multi-User Permission Conformance Suite

A ~80-cell conformance suite that answers one question with evidence: **does nginx-xrootd
enforce per-user access permissions identically whether data is served from origin,
read-cache, or stage — across `root://`, WebDAV, and S3?**

- Spec: [`docs/superpowers/specs/2026-07-06-multiuser-permission-conformance-design.md`](../superpowers/specs/2026-07-06-multiuser-permission-conformance-design.md)
- Plan: [`docs/superpowers/plans/2026-07-06-multiuser-permission-conformance.md`](../superpowers/plans/2026-07-06-multiuser-permission-conformance.md)

## The invariant

Every test is one instance of the **cache-transparency invariant**:

```
verdict_cached(P, X, op, proto)  ==  verdict_cold(P, X, op, proto)
```

The cache-OFF **direct** server is the authoritative oracle (it always runs the full
three-tier gate: authdb → VO ACL → token scope). Every cache/stage server MUST reach the
identical `Verdict(decision, reason, tier)`. A cache hit that ALLOWs — or denies for a
*weaker tier* — where the cold path DENIES is a cross-user leak.

> **Status:** the cache-transparency fix has LANDED (`open_cache.c` runs the full gate;
> `prepare.c` gates the `noerrs`+absent branch). The leak-marked families below are now
> **regression tests**: they must stay green. A failure means the leak has been reintroduced.
> See [Cache Authorization — Conformance & Best Practice](cache-authz-best-practice.md) for the
> enforcement architecture and configuration guidance.

## Running it

The suite is **privileged**: it provisions real `brixtest_*` accounts and runs the fleet
with the impersonation broker (needs root).

```bash
sudo -E env PYTHONPATH=tests tests/run_multiuser_authz.sh -v          # full suite
sudo -E env PYTHONPATH=tests tests/run_multiuser_authz.sh -m leak     # just the leak ledger
sudo -E env PYTHONPATH=tests tests/run_multiuser_authz.sh -m "not leak"  # the green subset
```

Unprivileged, the harness self-tests and the F6 mapping C unit still run:

```bash
PYTHONPATH=tests pytest tests/mu_authz_lib/ -q      # harness self-tests (no fleet)
tests/c/run_mu_unit.sh                              # idmap collapse guards (no root)
```

## Family map

| Family | File | Threat | Expected (post-fix) |
|---|---|---|---|
| F1 | `test_mu_authz_cachetransp.py` | cross-user cache-hit re-auth | green (regression) |
| F2 | `test_mu_cvmfs_public.py` | cvmfs public-by-design guardrails | green |
| F3 | `test_mu_stage_laundering.py` | service-cred stage laundering | green (regression) |
| F4 | `test_mu_prepare_authz.py` | prepare/stage noerrs bypass | green (regression) |
| F5 | `test_mu_cross_protocol.py` | cross-protocol poisoning + S3 scope | green (regression); S3 single-key noted |
| F6 | `c/idmap_collapse_test.c` (mapping) + `test_impersonation_gridmap_root.py` (setfsuid ownership) | uid collapse + real setfsuid ownership | mapping green; runtime ownership covered by the host-root gridmap suite (see note) |
| F7 | `test_mu_decision_cache.py` | decision-cache identity isolation | green |
| F8 | `test_mu_revocation.py` | revocation after fill | green (regression) |
| F9 | `test_mu_writeback_attr.py` | write-back attribution + S3 parity | green (regression); S3 single-key noted |
| — | `test_mu_cache_serve_authz.py` | no-root cache-HIT enforcement smoke | green |

> **F6 note (runtime setfsuid ownership).** `test_mu_impersonation_e2e.py` targets
> `ports.MU.ROOT_CACHE`/`ROOT_DIRECT`, but the phase-81 registry rewrite
> (`89d38fd4`) and the earlier config-template overhaul (`66efecd0`, which deleted
> `configs/multiuser/root_cache.conf`/`root_direct.conf` — the only templates with
> `brix_impersonation map`) left `mu_authz_lib/fleet.py`'s `_SERVERS` starting only
> `*_noimp.conf` servers. Those two impersonation-ON ports are never bound, so the
> e2e writes to a dead port (it fails under `sudo`, or false-passes on the
> collapse case where both measurements fail identically). Real
> **host-root setfsuid byte-ownership** — a token/X.509 identity mapped via a real
> grid-mapfile to a real local account, asserting the written file's on-disk
> `st_uid`/`st_gid` — is now covered directly by
> `tests/test_impersonation_gridmap_root.py` (run under `sudo`). Reviving the MU
> impersonation fleet (re-adding a `map`-mode server to `_SERVERS`) is tracked
> separately.

## The harness

`tests/mu_authz_lib/` — a fixed cast of principals with matched cross-protocol credentials
(`principals.py`), a policy renderer that emits consistent gridmap/authdb/VO/S3 backends
(`policy.py`), a paired direct+cache fleet (`fleet.py`), the differential oracle
(`oracle.py`), per-protocol verdict adapters (`adapters.py`), and cache-state control via
`xrdcinfo` (`cache_state.py`). Fixtures live in `tests/conftest_mu.py`.

## Reading the result

Post-fix, the expected state is **all green** — including `-m leak`, which now runs the
regression tests for the closed leaks. If a `-m leak` cell fails, the leak ledger prints it
with its node id: a cache/stage serve whose verdict diverged from the origin oracle, i.e. the
leak has been reintroduced. Treat any red `leak` cell as a release blocker.

## Known limitations (surfaced by the suite)

- **S3 single key.** `brix_s3` supports one `access_key`/`secret_key`, so per-user S3 identity
  via distinct keys is not expressible — which *is* the F5/F9 finding (S3 authorizes on one
  SigV4 identity and never consults WLCG token scope). S3 cells use the service key.
- **cvmfs is out of scope as an enforcing protocol** — treated as a public content cache; F2
  asserts credentials are ignored and no privilege is inferred, not enforcement.
- **F7 decision-cache key isolation is e2e-only** — `auth_gate.c`'s key derivation is a
  static function with heavy nginx deps and is not cleanly linkable as a standalone C unit.
