# Multi-User Permission Conformance Suite — Design

**Date:** 2026-07-06
**Status:** Approved (design locked; ready for implementation plan)
**Owner:** Rob Currie
**Goal:** A ~210-test conformance suite that proves — or disproves — that nginx-xrootd
enforces per-user access permissions *identically whether data is served from origin,
read-cache, or stage*, across `root://`, WebDAV/`davs://`, and S3.

---

## 1. Motivation — what the codebase map found

A six-way source investigation (identity, authz engine, read cache, staging cache,
cross-protocol, test harness) established one structural fact:

> **There are two caches with opposite security properties.** The authorization-*decision*
> cache is identity-scoped and safe. The byte-*content* caches (read cache, stage, cvmfs)
> are path-only and re-check either nothing or a weaker subset of the gate on a hit.

Verified in source (file:line):

| Claim | Evidence |
|---|---|
| Content cache key is **path-only, zero identity** | `src/fs/cache/cache_key.c:16-40` — `brix_cache_key_from()` takes `cache_root_canon` and `(void)`-discards it (line 21); key is the export-relative suffix only. |
| Root cached-read runs a **weaker gate** than the direct path | Branch at `src/protocols/root/read/open_request.c:652-656` returns into `brix_open_cached_read()`; that path (`src/protocols/root/read/open_cache.c:24-28`) runs **only** `brix_check_vo_acl_identity()`, then serves at `open_cache.c:43-48`. The non-cached path runs the full three-tier `brix_auth_gate(... BRIX_AUTH_READ ...)` at `open_request.c:685-689`. |
| Decision cache **is** identity-scoped (safe) | `src/auth/authz/auth_gate.c:153-189` — SHA-256 key folds `ctx->login.dn`, `vo_list`, and `scope_raw`. Tests must not conflate this with the content cache. |
| Prepare/stage **skips all three authz checks** for absent paths | `src/protocols/root/query/prepare.c:184-194` returns `NGX_OK` on `ENOENT/ENOTDIR + kXR_noerrs` *before* `brix_authz_check` (208), `brix_check_vo_acl_identity` (214), `brix_check_token_scope` (220). |
| cvmfs serves **anonymous**, no gate | `src/protocols/cvmfs/handler.c:135/145/209` hardcode `identity="anonymous"`; no `brix_auth_gate` call in the handler. scvmfs validates a bearer once in the preamble (`src/protocols/cvmfs/secure.c:84-89`) then serves anonymously. |
| Origin fill uses **service credentials only** | `src/fs/cache/origin_auth.c` (service X.509/SSS/WLCG), `src/fs/cache/origin_connection.c:179-185`. |

The consequence is **privilege laundering via caching**: a privileged principal fills the
cache; an under-privileged principal is served the identical bytes through a weaker (or
absent) hit-path gate. No existing test exercises this — the whole "does the cache respect
per-user permissions" question is currently unverified.

---

## 2. The single invariant

Every test in this suite is an instance of one assertion. This is what makes 210 tests
*meaningful* rather than padded — they are 210 measured points against one law, not 210
hand-authored expectations.

```
CACHE-TRANSPARENCY INVARIANT
For every principal P, path X, operation op, and enforcing protocol proto:

    verdict_cached(P, X, op, proto)  ==  verdict_cold(P, X, op, proto)

where verdict ∈ { ALLOW, DENY(reason, deciding-tier) }
```

`verdict_cold` — the decision the server reaches when the object is **not** resident, so the
full authorization path runs — is treated as the authoritative oracle. `verdict_cached` is
the decision when the object has been forced resident (filled/staged, typically *as a
different, more-privileged principal*). Any hit that ALLOWs where the cold path DENYs is,
by definition, a cross-user leak.

This one law subsumes threats T1 (cross-user read leak), T2 (cvmfs — see §4 exception),
T3 (service-cred stage laundering), and T5 (cross-protocol poisoning).

---

## 3. Locked decisions

| # | Decision | Choice | Consequence |
|---|---|---|---|
| D1 | **Suite intent** | **Bug-hunt, fail loudly** | Tests encode the *correct* invariant; leak cells fail red. No `xfail` cushioning. The currently-failing set is grouped under `@pytest.mark.leak` so the red ledger is visible and triageable as a group, but they are genuine failures. |
| D2 | **Ground-truth model** | **Cache-transparency** (§2) | Assertions compare cached-vs-cold verdicts. Fill-as-A / serve-as-B must equal B's cold-miss verdict. |
| D3 | **Enforcing protocols** | **root://, WebDAV, S3** (S3 held to token-scope/authdb parity, not just SigV4 signature validity) | cvmfs/scvmfs is **out** as an enforcing protocol — public content cache by design (§4). |
| D4 | **Impersonation depth** | **Full privileged e2e** | The whole suite runs under a privileged fleet. Real sub-1000 test accounts are provisioned every run; F6 exercises real `setfsuid` byte-ownership and cross-principal uid collapse end-to-end. Suite errors clearly (does not silently pass) if run unprivileged. |

---

## 4. Scope

**In scope (enforcing, held to cache-transparency):**

- `root://` / `roots://` (GSI, WLCG-token, SSS) — read cache + stage + prepare.
- WebDAV / `davs://` (GSI proxy cert + bearer token) — shares the read cache and the DN
  seam with `root://`; primary cross-protocol-poisoning target.
- S3 REST — must honor **scope/authdb parity**: a file filled under a read-only WLCG token
  must not be served to an S3 key whose own authz would not grant it, and S3 authorization
  must consult scope/authdb, not merely validate a SigV4 signature.

**Out of scope as an enforcing protocol:**

- `cvmfs://` / `scvmfs://` — treated as a **public content-distribution cache by design**.
  F2 does **not** assert enforcement. It asserts the *weaker* properties that must still
  hold for a public cache: (a) presented credentials are **ignored**, not honored partway;
  (b) **no privilege is inferred** from a presented credential (a scoped token must not
  *widen* access beyond anonymous); (c) an authenticated principal gets **exactly** what an
  anonymous one gets — no more. These pass against current behavior; they are guardrails
  against cvmfs silently *gaining* an auth-derived privilege later.

**Deliberately not covered:** performance/throughput of the authz path (covered elsewhere);
correctness of the *storage* plane (VFS seam has its own suite); TPC third-party-copy
credential delegation (own suite). This suite is strictly about *access-permission
verdicts and their cache/stage transparency*.

---

## 5. The differential oracle (the engine)

A naive suite hard-codes "GET /cms/f as bob → expect 403". That bakes today's behavior into
the expectation and cannot detect a leak (the leak *is* a wrong 200 where the author wrote
200). Instead, every cell is computed by a differential oracle:

```
def assert_cache_transparent(policy, principal_B, path, op, proto):
    cold = measure_verdict(proto, principal_B, path, op, cache_state=COLD)
    fill_as(policy.privileged_filler, path, proto)      # force resident
    assert cache_is_resident(path)                       # prove via xrdcinfo
    hot  = measure_verdict(proto, principal_B, path, op, cache_state=HOT)
    assert hot == cold, leak_report(cold, hot, policy, principal_B, path, op, proto)
```

Two capabilities make this deterministic:

1. **Forcing cache state.** COLD is achieved with a fresh per-case cache directory (or a
   cache-bypass server variant); HOT is achieved by an explicit fill step whose success is
   *verified* — not assumed — by dumping the `.cinfo` present-bitmap to JSON with the
   existing `xrdcinfo` tool before the measurement request is sent.
2. **Measuring a verdict, not a status.** `measure_verdict` returns a structured
   `Verdict(decision, reason, tier)` (see §7), so ALLOW-vs-DENY is compared along with the
   denial *reason* and the *tier that decided*.

The filler is always at least as privileged as the subject, so a correct server must still
deny the subject on the hot path exactly as it did cold. When it does not, `leak_report`
emits the principal pair, the path, the op, the protocol, the cold vs hot verdicts, and the
seam most likely responsible (from a static map, e.g. root-read → `open_cache.c:24`).

---

## 6. Test families

Counts are targets; each cell asserts a distinct, threat-relevant point (not a cartesian
blow-up). "Expected today" is the predicted result against current `main` under D1/D2.

| Family | File(s) | Threat | ~N | Layer | Expected today |
|---|---|---|---|---|---|
| **F1** Cross-user cache-hit re-auth | `test_mu_authz_cachetransp.py` | T1 | 40 | e2e | **FAIL (leak)** — `open_cache.c:24` VO-only |
| **F2** cvmfs creds-ignored / no-inferred-privilege | `test_mu_cvmfs_public.py` | T2 | 18 | e2e | PASS (public-by-design guardrails) |
| **F3** Service-cred stage laundering | `test_mu_stage_laundering.py` | T3 | 15 | e2e | **FAIL (leak)** — `origin_auth.c` |
| **F4** Prepare/stage authz incl. noerrs bypass | `test_mu_prepare_authz.py` | T4, T9 | 20 | e2e | **FAIL (leak)** — `prepare.c:184` |
| **F5** Cross-protocol poisoning + S3 scope parity | `test_mu_cross_protocol.py` | T5 | 26 | e2e | **FAIL (leak)** — S3 no-scope |
| **F6** Principal→uid collapse, squash, min_uid, setfsuid ownership | `test_mu_impersonation_e2e.py` + `tests/c/idmap_collapse_test.c` | T6, T11 | 30 | C-unit + priv-e2e | mixed |
| **F7** Decision-cache isolation (DN/VO/scope key, L1/L2, TTL, eviction, multi-worker) | `test_mu_decision_cache.py` + `tests/c/auth_gate_isolation_test.c` | T8, T7 | 28 | C-unit + e2e | mostly PASS |
| **F8** Revocation / staleness (token/gridmap/NSS × before/after-fill/mid-serve) | `test_mu_revocation.py` | T7 | 20 | e2e | **FAIL (leak)** on hit path |
| **F9** Write-back attribution + S3↔root scope parity | `test_mu_writeback_attr.py` | T5, T10 | 15 | e2e | mixed |

**Total ≈ 212.** Balance ≈ 58 C-unit / 154 e2e.

### Family detail (assertion content)

- **F1** — For each of {root, WebDAV} × {read-hit, staged} × {6 principal relationships:
  same-uid, diff-uid-allowed, diff-uid-denied, same-VO-diff-authdb, revoked, squashed} ×
  {deciding tier: authdb, token-scope, VO}: run the differential oracle. The
  same-VO-diff-authdb and diff-uid-denied cells are the leak cells.
- **F2** — {cvmfs, scvmfs} × {anonymous, valid-elsewhere-scoped-token, wrong-scope,
  revoked-mid-request} × {hit, miss} × {read, stat}. Assert authenticated ≡ anonymous and
  that no token *widens* access. These pass; they lock cvmfs to public semantics.
- **F3** — low-priv principal triggers a fill of a file readable only by the *service*
  identity; assert a subsequent serve to a denied/other-VO principal DENYs. The fill-vs-serve
  identity separation is the point.
- **F4** — {existing, absent+noerrs, absent-no-noerrs} × {authorized, authdb-deny, VO-deny,
  scope-deny} × {stage-self, cancel-by-other, recall-by-other}. The absent+noerrs × deny
  cells are the bypass (`prepare.c:184`); recall-by-other is T9.
- **F5** — fill-protocol × serve-protocol (4×4 minus same, minus illegal) × {read-only-token,
  wide-token}. Assert the serve protocol reaches its *own* cold verdict for the presented
  identity. S3-served cells with a scope-limited fill are the poisoning cells.
- **F6** — gridmap {hit, miss→literal-username fallback, DN-contains-local-username,
  squash, deny, below-min_uid} × {GSI, Kerberos, cross-protocol collision} × broker-edge
  re-check. C-unit for the mapping decision (extends `tests/c/idmap_test.c`); privileged
  e2e for real `setfsuid` byte-ownership (a file created as alice is owned by alice's uid;
  a collapsed principal cannot read carol's private file).
- **F7** — identity-scoped key {DN, VO, scope} collision/no-collision × {L1 hit, L2 promote,
  TTL expiry, >slot eviction, multi-worker coherence} × allow_write-before-scope ordering.
  Extends `tests/test_token_cache_l1.py`. Multi-worker coherence pins the
  per-worker-vs-shared question empirically before asserting.
- **F8** — revoke {token, gridmap entry, NSS user} at {before-fill, after-fill-before-serve,
  mid-serve} × {root, WebDAV}. The invariant: the *verdict* reflects revocation on the next
  request; the idmap uid/gid *creds* TTL-staleness (default 300s, `idmap.c:591-626`) is
  asserted only as *bounded*, not immediate.
- **F9** — S3 SigV4-vs-token-scope parity probes; write-back flush identity assertions
  (dirty bytes attributable to the writer; `brix_wt_flush_t` lacks `user_dn`,
  `cache_internal.h:123-135`).

---

## 7. Assertion granularity

Every measurement returns and asserts a `Verdict`:

```
Verdict(decision, reason, tier)
  decision ∈ {ALLOW, DENY}
  reason   = the server's denial-reason string (e.g. "token scope denied", "VO not authorized")
  tier     = the deciding layer ∈ {authdb, vo_acl, token_scope, allow_write, gridmap}
```

Comparing tier and reason — not just kXR/HTTP status — proves the **ordering** invariants
(e.g. `allow_write` denies *before* token-scope, `src/protocols/root/handshake/policy.c:65-86`;
the three-tier order authdb → VO ACL → token scope, `src/auth/authz/auth_gate.c:275-318`)
and catches "right status, wrong reason" regressions a status-only check would miss. The
reason/tier is derived from the wire error text and, where needed, the server access log
(`brix_access*.log`, `http_webdav_access.log`, `s3_access.log`).

---

## 8. Harness architecture

Reusable machinery lives in `tests/mu_authz_lib.py` (Python) and
`tests/configs/multiuser/` (server configs). It builds on existing anchors:
`tests/pki_helpers.py::blitz_test_pki`, `tests/kdc_helpers.py`, `tests/settings.py`,
`tests/manage_test_servers.sh`, and the dedicated-server pattern in
`tests/configs/DEDICATED_SERVERS.md`.

### 8.1 Privileged multi-user fleet

A dedicated fleet profile `tests/configs/multiuser/` with its own ports (new block in
`settings.py`, `TEST_MU_*`, default range 12100–12130) and its own cache/data/state roots,
so these tests never disturb the shared fleet. `tests/run_multiuser_authz.sh` orchestrates
start → pytest → stop. A session fixture asserts `os.geteuid() == 0` (or CAP_SETUID +
CAP_SETGID + CAP_DAC_OVERRIDE) up front and **errors the collection** with a clear message
if unprivileged (per D4), rather than silently passing.

### 8.2 The principal cast

`brix_test_principals` (session fixture) mints a fixed, deterministic cast, each with
*matched credentials across every protocol*:

| Principal | uid | GSI DN | WLCG token (sub / scope) | S3 key | Role in tests |
|---|---|---|---|---|---|
| `svc` | 1700 | `/DC=test/CN=brix-service` | service-wide | — | the privileged filler (origin service identity) |
| `alice` | 1701 | `/DC=test/CN=alice` | `alice` / `storage.read:/cms` | `AKIA_ALICE` | authorized reader |
| `bob` | 1702 | `/DC=test/CN=bob` | `bob` / `storage.read:/atlas` | `AKIA_BOB` | denied on `/cms` |
| `carol` | 1703 | `/DC=test/CN=carol` | `carol` / `storage.read:/cms` **but no authdb grant** | `AKIA_CAROL` | same-VO, authdb-denied (the sharpest leak probe) |
| `mallory` | 1704 | `/DC=test/CN=mallory` | revocable | `AKIA_MALLORY` | revocation subject |
| `collide` | 1701 | `/DC=test/CN=alice` **+** Kerberos `alice@TEST.REALM` | — | two principals → one uid (T6) |
| `squashed` | 65534 | `/DC=test/CN=root-ish` | — | — | squash / below-min_uid (T6) |

Credentials are produced by extending `pki_helpers` (per-DN user certs), a token-mint helper
(distinct `sub`+`scope`, following the existing `make_token`/JWKS pattern used across the
suite), `kdc_helpers` (the collision principal), and an S3-key generator.

### 8.3 Real-account provisioning + crash-safe teardown

- A **pre-session sweep** removes any leftover `brixtest_*` accounts first (idempotent), so a
  crashed prior run cannot poison the box.
- The cast's system accounts (`brixtest_alice=1701` … `brixtest_svc=1700`, plus the
  squash/min_uid account) are created every run.
- Teardown reaps them with guarded `userdel`, and is registered so it runs even on fixture
  setup failure. This respects the documented teardown hazards (orphaned workers, `killpg`
  via the correct pidfile) — account reaping happens *after* the fleet is stopped.

### 8.4 Policy config generator

`mu_authz_lib.render_policy(policy)` emits a **consistent** set of backend configs from a
single high-level policy declaration so a test says "alice allowed, bob+carol denied on
`/cms/secret`" once and the fixture renders all of:

- **gridmap** (DN/principal → uid),
- **authdb / XrdAcc** rules (`tests/configs/nginx_authdb.conf` is the existing template),
- **VO-ACL** (`brix_require_vo`, per `vo_acl.conf`),
- **token issuer / scope** expectations,
- **S3 bucket-policy / key-scope** mapping.

This guarantees the four authorization sources agree, so a test failure is a real
inconsistency, not a mis-configured backend.

### 8.5 Cache-state control

- `cache_is_resident(path, proto)` shells the existing `xrdcinfo` tool and parses the
  present-bitmap JSON to *prove* HOT/COLD, never assuming.
- COLD is a fresh per-case cache dir (fixture-scoped) or a cache-bypass server variant.
- HOT is an explicit verified fill as `policy.privileged_filler`.

### 8.6 Per-protocol adapter

A single `ProtocolAdapter` interface — `read/stat/list/write/delete/prepare` — with
`RootAdapter` (pyxrootd / raw-wire), `WebDAVAdapter` (requests + GSI/bearer),
`S3Adapter` (SigV4), and a read-only `CvmfsAdapter`. The oracle loops over protocols; there
is no per-protocol duplication of test bodies.

---

## 9. Test layout, markers, safety

```
tests/
  mu_authz_lib.py                     # oracle, principals, policy renderer, adapters
  test_mu_authz_cachetransp.py        # F1
  test_mu_cvmfs_public.py             # F2
  test_mu_stage_laundering.py         # F3
  test_mu_prepare_authz.py            # F4
  test_mu_cross_protocol.py           # F5
  test_mu_impersonation_e2e.py        # F6 (privileged e2e)
  test_mu_decision_cache.py           # F7 (e2e portion)
  test_mu_revocation.py               # F8
  test_mu_writeback_attr.py           # F9
  c/idmap_collapse_test.c             # F6 unit (extends idmap_test.c)
  c/auth_gate_isolation_test.c        # F7 unit (decision-cache key isolation)
  configs/multiuser/*.conf            # dedicated fleet
  run_multiuser_authz.sh              # orchestrator
```

- **Markers:** `@pytest.mark.leak` (the red ledger — currently-failing invariant violations),
  `@pytest.mark.privileged` (needs root; whole suite is privileged but the marker documents
  the setfsuid cells), `@pytest.mark.slow` for fleet-heavy fills.
- **xdist:** cells that mutate PKI/gridmap/accounts run **serial** (own fleet; xdist-unsafe),
  honoring the documented `-n12` cap and the "shared fleet ⇒ serial PKI" rule. The dedicated
  `multiuser` fleet isolates these from the shared fleet so the rest of the suite still
  parallelizes.
- **C-units** are added to `./config` source lists and run via a `run_mu_unit.sh` (mirrors
  `run_cache_unit.sh`), libc-only where possible (the cache-key and gridmap TUs already link
  without nginx).

---

## 10. Expected-red ledger — what "done" looks like

Under D1/D2, the suite is **intentionally red on merge**. "Done building the suite" means:

1. F2, and the PASS portions of F6/F7/F9, are **green** (correct behavior locked in).
2. F1, F3, F4, F5, F8-hit, and S3-parity in F5/F9 are **red**, each with a `leak_report`
   naming the principal pair, path, op, protocol, and the responsible seam.
3. `pytest tests/ -m leak -q` prints a clean, grouped ledger of every open cross-user leak
   with its `file:line` — the deliverable that answers "is this project correctly caching
   per-user permissions?" with evidence.

Each red cell becomes a passing regression test the moment the underlying code is fixed
(fill path and hit path made to run the same gate; cvmfs left as documented-public; S3 made
to consult scope). Fixing the code is **out of scope for this suite** — the suite's job is to
prove the gap exists and lock the fix once made.

---

## 11. Assumptions & non-goals

- **Revocation semantics (F8):** the authz *verdict* must reflect revocation on the next
  request; idmap uid/gid *creds* TTL-staleness is asserted only as bounded (≤ configured
  TTL). If the desired contract is "immediate creds invalidation too," F8 gains ~5 cells.
- **Counts** are targets (±10%); the invariant, not the number, is the deliverable. 200+ is
  reached by legal, threat-relevant cells only.
- **Non-goals:** fixing the leaks; TPC delegation; storage-plane correctness; authz
  performance.

---

## 12. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Privileged fleet + real accounts poison the box on crash | Pre-session sweep + guarded idempotent teardown registered against setup failure; account reap strictly after fleet stop. |
| `xrdcinfo` bitmap shape varies by backend (whole-file vs slice) | Adapter records backend; `cache_is_resident` tolerates both present-bitmap shapes (per the read-cache partial-fill suite's known behavior). |
| S3 "scope parity" has no current code path to assert against | S3 cells use the differential oracle against S3's *own* cold verdict; where S3 has no scope concept at all, the cell asserts the cross-protocol poisoning form (fill-via-root-scoped-token → serve-via-S3) rather than an intra-S3 scope check. |
| Multi-worker decision-cache coherence (F7) is unspecified | Pin behavior empirically first (a probe test), then assert the observed contract; flag if a worker-1 verdict is reachable by worker-2 with a different in-flight identity. |
| Red suite blocks unrelated merges | The `leak` marker lets CI exclude the known-red ledger (`-m "not leak"`) while the ledger itself is run and reviewed as its own job. Genuine failures, deliberately visible. |

---

## 13. Success criteria

1. ~210 cells across F1–F9, each an instance of the cache-transparency invariant or a
   public-cache guardrail (F2) or a mapping/isolation unit (F6/F7).
2. Runs green for correct behavior, red-with-evidence for every leak, under a single
   `run_multiuser_authz.sh`.
3. `-m leak` produces a reviewable ledger of cross-user leaks with `file:line`.
4. The privileged fleet provisions and reaps real accounts with zero box contamination
   across repeated runs.
5. Every assertion checks verdict **+ reason + deciding tier**, not bare status.
