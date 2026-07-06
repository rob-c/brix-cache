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
*weaker tier* — where the cold path DENIES is a cross-user leak. The suite is **bug-hunt /
fail-loudly**: leak cells encode the correct invariant and fail red until the code is fixed.

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

| Family | File | Threat | Expected |
|---|---|---|---|
| F1 | `test_mu_authz_cachetransp.py` | cross-user cache-hit re-auth | **leak (red)** |
| F2 | `test_mu_cvmfs_public.py` | cvmfs public-by-design guardrails | pass |
| F3 | `test_mu_stage_laundering.py` | service-cred stage laundering | **leak (red)** |
| F4 | `test_mu_prepare_authz.py` | prepare/stage noerrs bypass | **leak (red)** |
| F5 | `test_mu_cross_protocol.py` | cross-protocol poisoning + S3 scope | **leak (red)** |
| F6 | `test_mu_impersonation_e2e.py` + `c/idmap_collapse_test.c` | uid collapse + setfsuid ownership | mixed |
| F7 | `test_mu_decision_cache.py` | decision-cache identity isolation | pass |
| F8 | `test_mu_revocation.py` | revocation after fill | **leak (red)** |
| F9 | `test_mu_writeback_attr.py` | write-back attribution + S3 parity | mixed |

## The harness

`tests/mu_authz_lib/` — a fixed cast of principals with matched cross-protocol credentials
(`principals.py`), a policy renderer that emits consistent gridmap/authdb/VO/S3 backends
(`policy.py`), a paired direct+cache fleet (`fleet.py`), the differential oracle
(`oracle.py`), per-protocol verdict adapters (`adapters.py`), and cache-state control via
`xrdcinfo` (`cache_state.py`). Fixtures live in `tests/conftest_mu.py`.

## Reading the result

A green run of `-m "not leak"` plus a red `-m leak` ledger is the expected state. The ledger
lists each cross-user leak with its node id; fixing the underlying code (making the cached
path run the same gate as the direct path) flips that cell green — it becomes a passing
regression test. The whole point is that the suite is the evidence, not an assertion of what
the author expected.

## Known limitations (surfaced by the suite)

- **S3 single key.** `brix_s3` supports one `access_key`/`secret_key`, so per-user S3 identity
  via distinct keys is not expressible — which *is* the F5/F9 finding (S3 authorizes on one
  SigV4 identity and never consults WLCG token scope). S3 cells use the service key.
- **cvmfs is out of scope as an enforcing protocol** — treated as a public content cache; F2
  asserts credentials are ignored and no privilege is inferred, not enforcement.
- **F7 decision-cache key isolation is e2e-only** — `auth_gate.c`'s key derivation is a
  static function with heavy nginx deps and is not cleanly linkable as a standalone C unit.
