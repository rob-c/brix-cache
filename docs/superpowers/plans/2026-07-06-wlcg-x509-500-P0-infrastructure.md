# WLCG x509 500-Conformance — P0 Infrastructure Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Build the shared machinery every later phase depends on: an ngx-free store-config helper (so the C oracle configures the store exactly like production), forge v2's clause-indexed `CLAUSES` registry + extended builders, the fixed conformance fleet, and the C oracle.

**Architecture:** Extract the store flag/callback/signing_policy setup out of `pki_build.c` into an ngx-free `brix_store_configure()` in `store_policy.c`, called by both production and the oracle. Refactor `tests/x509forge.py` to be table-driven: family modules under `tests/clauses/` register `Clause` rows; the forge materializes one big multi-CA directory + special dirs + a `manifest.json`. A `ConformanceFleet` stands up ~12–15 long-lived servers once; the C oracle replays the manifest through the real cores.

**Tech Stack:** C (OpenSSL 1.1/3.x), Python 3 (`cryptography` 48.x, pytest), bash.

## Global Constraints

- NO `goto`; functional/modular; WHAT/WHY/HOW block per function.
- Every new `.c` in repo-root `./config`; `export REPO=/home/rcurrie/HEP-x/nginx-xrootd` BEFORE `./configure` (bare-nginx footgun); incremental `make -j$(nproc)` otherwise.
- Build: `cd /tmp/nginx-1.28.3 && ./configure --with-stream --with-stream_ssl_module --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO && make -j$(nproc)`.
- Forge determinism: fixed epoch `_EPOCH=2026-01-01`, no `Date.now()`; CRL `nextUpdate` must be ahead of wall-clock now (default 3650d).
- Manifest is the single source of truth: `{id, clause, title, cred, expected, surface, group, reason}`.
- pytest fresh `--basetemp` (stale `/tmp/xrd-test/tmp` cleanup hangs runs).
- Existing files to preserve/extend, NOT rewrite: `tests/x509forge.py`, `tests/wlcg_fleet.py`, `src/auth/crypto/{store_policy,pki_build,signing_policy}.{c,h}`.

---

## File Structure

- `src/auth/crypto/store_policy.{h,c}` — **modify**: add `brix_store_configure()` + move `pki_proxy_check_issued`/`brix_crl_try_verify_cb` here (ngx-free).
- `src/auth/crypto/pki_build.c` — **modify**: `brix_build_ca_store()` delegates store config to `brix_store_configure()`.
- `tests/x509forge.py` — **modify**: add `Clause` dataclass, `register()`, `build_all()`, extended builders; keep v1 scenario fns working.
- `tests/clauses/__init__.py` — **create**: loads all family modules, exposes `ALL_CLAUSES`.
- `tests/clauses/_helpers.py` — **create**: shared per-family builder shortcuts.
- `tests/clauses/smoke.py` — **create**: a 6-row proof-of-registry family used in P0 (real families land in P1).
- `tests/wlcg_conformance_fleet.py` — **create**: `ConformanceFleet` (stands up group + special servers once).
- `tests/c/x509_oracle.c` + `tests/c/run_x509_oracle.sh` — **create**: manifest-driven C oracle.
- `config` — **modify**: no new `.c` (store_policy already listed); oracle links source directly, not via nginx build.

---

## Task 1: Extract `brix_store_configure()` (ngx-free store setup)

**Files:**
- Modify: `src/auth/crypto/store_policy.h`, `src/auth/crypto/store_policy.c`, `src/auth/crypto/pki_build.c`
- Test: extend `tests/c/x509_conformance_test.c`

**Interfaces:**
- Produces: `int brix_store_configure(X509_STORE *store, const char *cadir, unsigned long extra_flags, int crl_count, brix_sp_mode_t sp_mode, int crl_mode, void *log, brix_sp_log_fn log_fn);` — sets extra_flags, installs the proxy `check_issued` when `extra_flags & X509_V_FLAG_ALLOW_PROXY_CERTS`, sets CRL flags per `crl_mode`+`crl_count` and installs the TRY-downgrade callback, builds+attaches the signing_policy table. Returns 0 ok, -1 on require+bundle (cadir NULL). Store owns the attached table.

- [ ] **Step 1: Write the failing C test** in `tests/c/x509_conformance_test.c` — add after `test_store_attach()`:

```c
static void
test_store_configure(void)
{
    printf("store configure (shared helper):\n");
    X509_STORE *store = X509_STORE_new();
    /* require + no cadir (bundle) must fail. */
    CHECK(brix_store_configure(store, NULL, 0, 0,
              BRIX_SP_MODE_REQUIRE, BRIX_CRL_MODE_OFF, NULL, NULL) == -1,
          "SC-01 require+bundle rejected");
    X509_STORE_free(store);

    store = X509_STORE_new();
    int rc = brix_store_configure(store, path_of("sp_in_namespace", "ca"),
              X509_V_FLAG_ALLOW_PROXY_CERTS, 0,
              BRIX_SP_MODE_ON, BRIX_CRL_MODE_TRY, NULL, NULL);
    CHECK(rc == 0, "SC-02 configure ok on a real CA dir");
    X509_STORE_free(store);
}
```
Register the call in `main()` after `test_store_attach();`.

- [ ] **Step 2: Run to confirm failure**

Run: `rm -rf /tmp/x509conf; bash tests/c/run_x509_conformance_tests.sh`
Expected: FAIL — `brix_store_configure` undefined.

- [ ] **Step 3: Declare in `store_policy.h`** (after `brix_store_policy_attach`):

```c
/*
 * Apply the full production trust-store configuration to a freshly CA/CRL-
 * loaded store: extra_flags, the proxy check_issued override (when proxy certs
 * are allowed), crl_mode-gated CRL flags + TRY downgrade, and the signing_policy
 * table.  ngx-free so the C oracle configures a store identically to production.
 * Returns 0 on success, -1 on the require+bundle configuration error.
 */
int brix_store_configure(X509_STORE *store, const char *cadir,
                         unsigned long extra_flags, int crl_count,
                         brix_sp_mode_t sp_mode, int crl_mode,
                         void *log, brix_sp_log_fn log_fn);
```

- [ ] **Step 4: Move the two callbacks + implement the helper in `store_policy.c`.**
  Move `pki_proxy_check_issued` (rename `brix_sp_proxy_check_issued`) and
  `brix_crl_try_verify_cb` verbatim from `pki_build.c` into `store_policy.c`
  (they use only OpenSSL). Then:

```c
int
brix_store_configure(X509_STORE *store, const char *cadir,
                     unsigned long extra_flags, int crl_count,
                     brix_sp_mode_t sp_mode, int crl_mode,
                     void *log, brix_sp_log_fn log_fn)
{
    brix_sp_table_t *table;

    if (extra_flags != 0) {
        X509_STORE_set_flags(store, extra_flags);
    }
    if (extra_flags & X509_V_FLAG_ALLOW_PROXY_CERTS) {
        X509_STORE_set_check_issued(store, brix_sp_proxy_check_issued);
    }
    if (crl_mode == BRIX_CRL_MODE_REQUIRE
        || (crl_mode == BRIX_CRL_MODE_TRY && crl_count > 0)) {
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK
            | X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_USE_DELTAS);
    }
    if (crl_mode == BRIX_CRL_MODE_TRY) {
        X509_STORE_set_verify_cb(store, brix_crl_try_verify_cb);
    }
    if (cadir == NULL && sp_mode == BRIX_SP_MODE_REQUIRE) {
        return -1;
    }
    table = brix_sp_table_build(cadir, log, log_fn);
    if (table == NULL || !brix_store_policy_attach(store, table, sp_mode, crl_mode)) {
        brix_sp_table_free(table);
        return -1;
    }
    return 0;
}
```

- [ ] **Step 5: Rewire `pki_build.c`.** In `brix_build_ca_store`, delete the inline
  flag/callback/CRL-flag/signing_policy blocks (now in the helper) and the two
  moved static fns; after loading CA + CRLs (keep `crl_count`), replace with:

```c
    if (brix_store_configure(store, cadir, extra_flags, crl_count,
            sp_mode, crl_mode, log, brix_pki_sp_log) != 0) {
        X509_STORE_free(store);
        return NULL;
    }
    if (crl_count_out != NULL) { *crl_count_out = crl_count; }
    return store;
```
  Keep `pki_proxy_check_issued`'s old callers gone; keep `brix_pki_sp_log`.

- [ ] **Step 6: Run C test + rebuild the module**

Run: `bash tests/c/run_x509_conformance_tests.sh` → `NN checks, 0 failures`.
Run: `cd /tmp/nginx-1.28.3 && make -j$(nproc)` → exit 0.
Run: `/tmp/nginx-1.28.3/objs/nginx -t -c /tmp/x509_test2.conf -p /tmp 2>&1 | grep -c "syntax is ok"` → `1`.

- [ ] **Step 7: Regression** — the first-pass e2e still green (attach mode):

Run: `PYTHONPATH=tests pytest tests/test_wlcg_conformance_signing_policy.py -p no:xdist -q --basetemp=/tmp/p0t1` → all pass.

- [ ] **Step 8: Commit**

```bash
git add src/auth/crypto/store_policy.h src/auth/crypto/store_policy.c src/auth/crypto/pki_build.c tests/c/x509_conformance_test.c
git commit -m "refactor(auth): extract ngx-free brix_store_configure (shared by production + oracle)"
```

---

## Task 2: Forge v2 — `Clause` registry + extended builders

**Files:**
- Modify: `tests/x509forge.py`
- Create: `tests/clauses/__init__.py`, `tests/clauses/_helpers.py`, `tests/clauses/smoke.py`
- Test: `tests/test_x509forge_v2_selftest.py`

**Interfaces:**
- Produces (in `x509forge.py`):
  - `@dataclass class Clause: id:str; clause:str; title:str; expected:str; surface:str="davs"; group:str="sp_on_crl_off"; build: callable` where `build(ctx) -> BuildResult`.
  - `class ForgeCtx` — passed to `build`; exposes the extended builders and a `place(cert_chain, key) -> cred_name` that writes a credential file and returns its id, plus `add_ca(cert, *, policy=None, crls=None, group_dir="shared")` that registers a CA into the shared (or a named special) dir.
  - `def build_all(root: Path, clauses: list[Clause]) -> Path` — materializes `shared/ca`, `special/*/ca`, `creds/`, and `manifest.json`; returns root.
  - Extended builders (new kwargs on existing fns / new fns): `make_ca(..., key_type="rsa"|"ec", curve="P-256", digest="sha256")`, `make_eec(..., eku=[...], name_constraints=..., extra_ext=[(oid, der, critical)], dn_encoding={rdn:"utf8"|"printable"|"bmp"|"t61"})`, `make_crl(..., delta_of=<crl>, crl_number=N, reason=<code>)`, `raw_der_dn(spec) -> bytes`.
- Consumes: v1 builders (`make_ca`, `make_eec`, `make_proxy`, `make_crl`, `write_hashed_ca_dir`, `signing_policy_text`).

- [ ] **Step 1: Write the failing selftest** `tests/test_x509forge_v2_selftest.py`:

```python
import json
from pathlib import Path
import x509forge
from clauses import ALL_CLAUSES

def test_registry_nonempty():
    assert len(ALL_CLAUSES) >= 6  # smoke family in P0

def test_build_all_materializes(tmp_path):
    root = x509forge.build_all(tmp_path, ALL_CLAUSES)
    m = json.loads((root / "manifest.json").read_text())
    assert len(m) == len(ALL_CLAUSES)
    ids = {r["id"] for r in m}
    assert len(ids) == len(m), "duplicate test ids"
    for r in m:
        assert r["clause"] and r["expected"] in ("accept", "reject")
        assert (root / "creds" / f"{r['cred']}").exists() or r["surface"] == "config"
    assert (root / "shared" / "ca").is_dir()
```

- [ ] **Step 2: Run → fail** (`clauses` missing, `build_all` missing).
Run: `PYTHONPATH=tests pytest tests/test_x509forge_v2_selftest.py -q --basetemp=/tmp/p0t2`.

- [ ] **Step 3: Implement `Clause`, `ForgeCtx`, `build_all`** in `x509forge.py`. Keep v1 fns. `ForgeCtx.add_ca` dedups CAs by subject-hash into `shared/ca` (writing both hash links + policy + `.r0/.r1`) or `special/<group_dir>/ca`. `build_all` iterates clauses, runs each `build(ctx)`, writes creds + manifest rows.

- [ ] **Step 4: Implement extended builders** in `x509forge.py` (EC keys via `ec.generate_private_key`, digest select, `raw_der_dn` via the existing `_der_*` helpers, delta CRL via `DeltaCRLIndicator`, CRL reason/number, `extra_ext`/`name_constraints`/`dn_encoding` on `make_eec`).

- [ ] **Step 5: Write `tests/clauses/_helpers.py`** (per-family shortcuts: `ns_ca()`, `eec()`, `accept()/reject()` Clause builders) and `tests/clauses/smoke.py` (6 Clause rows across families) and `tests/clauses/__init__.py` (imports every `*.py` except `_helpers`, concatenates their `CLAUSES` into `ALL_CLAUSES`, asserts unique ids).

- [ ] **Step 6: Run selftest → pass.**
Run: `PYTHONPATH=tests pytest tests/test_x509forge_v2_selftest.py -q --basetemp=/tmp/p0t2b` → pass.

- [ ] **Step 7: Commit**

```bash
git add tests/x509forge.py tests/clauses/ tests/test_x509forge_v2_selftest.py
git commit -m "test(x509): forge v2 — Clause registry, extended builders, build_all + manifest"
```

---

## Task 3: Conformance fleet (stood up once)

**Files:**
- Create: `tests/wlcg_conformance_fleet.py`
- Test: `tests/test_conformance_fleet_smoke.py`

**Interfaces:**
- Consumes: `x509forge.build_all`, manifest, `wlcg_fleet` server-cert helper + render pattern.
- Produces:
  - `class ConformanceFleet:` `__init__(self, forge_root: Path)`; `start()` stands up one nginx per distinct `group` seen in the manifest (config-groups on `shared/ca`, special groups on `special/<name>/ca`), each on a free port; `verdict(cred_name, group) -> (accepted: bool, code: str)` dispatches a curl client-cert PROPFIND to that group's server; `stop()`.
  - Group→config map: `sp_on_crl_off`, `sp_off_crl_off`, `sp_require_crl_off`, `sp_on_crl_try`, `sp_on_crl_require`, `sp_off_crl_try`, plus special `md5_only`, `sha1_only`, `expired_ca`, `absent_ca`, `hash_collision`, `bundle` (each parses `sp_*`/`crl_*`/dir from the group name; specials default `sp_off_crl_off`).

- [ ] **Step 1: Write the failing smoke test** `tests/test_conformance_fleet_smoke.py`:

```python
import pytest, x509forge
from clauses import ALL_CLAUSES
from wlcg_conformance_fleet import ConformanceFleet

@pytest.mark.x509conf
@pytest.mark.slow
def test_fleet_serves_smoke(tmp_path):
    root = x509forge.build_all(tmp_path, ALL_CLAUSES)
    fleet = ConformanceFleet(root); fleet.start()
    try:
        import json
        for r in json.loads((root / "manifest.json").read_text()):
            if r["surface"] != "davs":
                continue
            acc, code = fleet.verdict(r["cred"], r["group"])
            assert acc == (r["expected"] == "accept"), f"{r['id']} {code}"
    finally:
        fleet.stop()
```

- [ ] **Step 2: Run → fail** (module missing).
- [ ] **Step 3: Implement `ConformanceFleet`** reusing `wlcg_fleet._ensure_server_cert` and the `WlcgInstance.render/start/stop/verdict` mechanics; one server per group, ports via `settings.free_ports`. `verdict` maps 2xx→accept.
- [ ] **Step 4: Run smoke → pass** (attach mode, fresh basetemp):
Run: `PYTHONPATH=tests pytest tests/test_conformance_fleet_smoke.py -p no:xdist -q --basetemp=/tmp/p0t3`.
- [ ] **Step 5: Commit** (`test(x509): conformance fleet — stand up group/special servers once, dispatch by manifest`).

---

## Task 4: C oracle (manifest-driven, real cores)

**Files:**
- Create: `tests/c/x509_oracle.c`, `tests/c/run_x509_oracle.sh`
- Test: the oracle IS the test; a smoke assertion on the smoke family.

**Interfaces:**
- Consumes: `brix_store_configure` (Task 1), manifest, forge output dirs.
- Produces: `run_x509_oracle.sh` — forges `ALL_CLAUSES`, compiles the oracle linking `signing_policy.c`+`store_policy.c`, runs it over `manifest.json`; exit 0 iff every `c-oracle`/`davs` case's oracle verdict matches `expected`.
- Oracle logic per case: resolve the group's `(cadir, sp_mode, crl_mode, extra_flags=ALLOW_PROXY_CERTS)`; build store (`X509_STORE_load_path` + CRL load), `brix_store_configure`, load the cred chain, `X509_verify_cert`, then `brix_gsi`-equivalent post-checks via `brix_sp_table_check` walk + `brix_proxy_chain_ok`; verdict accept iff all pass.

- [ ] **Step 1: Write `run_x509_oracle.sh`** (mirror `run_x509_conformance_tests.sh`: `PYTHONPATH=tests python3 -c "import x509forge,clauses,pathlib; x509forge.build_all(pathlib.Path('$FIX'), clauses.ALL_CLAUSES)"`, then gcc oracle + cores, run with `BRIX_X509_FIXTURES=$FIX`).
- [ ] **Step 2: Run → fail** (oracle source missing).
- [ ] **Step 3: Implement `x509_oracle.c`** — a tiny JSON reader (or emit a flat TSV sidecar from `build_all` to avoid a JSON C dep: add `manifest.tsv` with `id\tcred\texpected\tsurface\tgroup` in `build_all`). Prefer the TSV sidecar. Parse group name → config; run the pipeline; print `ok/FAIL` per row; exit nonzero on any mismatch.
- [ ] **Step 4: Run → pass** on the smoke family.
- [ ] **Step 5: Commit** (`test(x509): C oracle — replay manifest through real cores via brix_store_configure`).

---

## Self-Review (P0)

- **Spec coverage:** store-config helper (§4 C oracle "exact setup") → Task 1; forge v2 CLAUSES + builders (§3) → Task 2; conformance fleet (§4) → Task 3; C oracle (§4) → Task 4. P1–P4 in the roadmap.
- **Placeholders:** none — each task has real code or exact mechanics + a worked example.
- **Type consistency:** `Clause`/`ForgeCtx`/`build_all`/`ConformanceFleet.verdict`/`brix_store_configure` names used consistently across tasks; TSV sidecar decided in Task 4 to avoid a C JSON dep.
