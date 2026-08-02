# Fast-Tier Coverage: Baseline, Lessons & Test-Building Plan

**Status:** baseline read 2026-07-21 (local); plan OPEN. Wave-0 landed.
**Owner doc for:** `QUALITY_ROADMAP.md` §2.3.3 / §3.4 coverage floor.
**Companion tooling:** `tools/ci/coverage.py`, `cmdscripts.operator_build build_coverage`,
`.github/workflows/coverage.yml`.

This doc records everything learned from the first end-to-end run of the gcov/lcov
coverage lane, and turns the gap analysis into a **hyper-detailed, source-grounded**
plan for raising **fast-tier** line/branch coverage with new Python tests. Each target
below is pinned to the exact functions, directives, endpoints, error strings, ports,
fixtures, and config fragments needed to write the test — not prose.

It is deliberately scoped to the *fast* fleet tier (`suite --fast`) — the tier that runs
on every change — because coverage that only moves under privileged/serial/infra lanes
does not protect day-to-day development.

---

## 1. How to reproduce the baseline (methodology)

The lane is report-only and self-skips cleanly without `lcov`/`gcov`. Two ways to run it:

### 1a. Packaged lane (what CI runs)
```bash
# needs: apt-get install -y lcov   (pulls gcov too)
NGINX_SRC=/tmp/nginx-1.28.3 python3 tools/ci/coverage.py
# → builds instrumented nginx+client, runs COVERAGE_TEST_CMD
#   (default: python3 -m cmdscripts.operator_runtime suite --fast),
#   lcov-captures src/* client/*, genhtml, prints line-rate. Floor enforced
#   ONLY when COVERAGE_MIN is set (B-1 lesson: never gate pre-baseline).
```

### 1b. Manual / private-tree (what produced this baseline; survives concurrent `make`)
Use a **private** nginx source tree so another session's `make` can't race the shared
`/tmp/nginx-1.28.3` binary (see `concurrent_session_build_contention` memory). The
private tree copy MUST include `html/ man/ contrib/ docs/man/` or configure fails on
`docs/man/nginx.8`.

```bash
COV=/tmp/nginx-cov-$SESSION           # private instrumented tree
NGINX_SRC=$COV python3 -m cmdscripts.operator_build build_coverage
# runs the suite against the instrumented binary:
TEST_NGINX_BIN=$COV/objs/nginx \
  PYTHONPATH=tests python3 -m cmdscripts.operator_runtime suite --fast
# capture (run from $COV so gcda paths resolve; client captured separately):
cd $COV && gcovr --root <repo> --filter '<repo>/src/' \
  --gcov-ignore-parse-errors=suspicious_hits.warn \
  --gcov-ignore-errors=no_working_dir_found \
  --merge-mode-functions=separate --json final-src.json objs
cd <repo>/client && gcovr --root . --merge-mode-functions=separate \
  --json $COV/final-client.json .
```

### Gotchas that cost time (bake these in)
- **`--merge-mode-functions=separate` is mandatory** — without it gcovr throws
  `GcovrMergeAssertionError` on inline functions that appear on multiple lines
  (e.g. `vfs_io_core.h`).
- **Client needs an explicit `objs` / `.` search path** or gcovr errors
  `no_working_dir_found` on relative paths (`apps/auth/xrdgsiproxy.c`).
- **gcda is flushed on process exit.** Standing fleet servers hold their counters
  until teardown — a mid-run snapshot read 60.8 %, the post-teardown read 67.5 %.
  Always capture *after* the suite (and fleet) have fully stopped.
- **The lane instruments `client/` in place** (drops PIE/RELRO, builds `-O0`). When
  finished, `make -C client clean && make` to restore the hardened repo binaries,
  or `test_build_hardening::test_client_binary_is_pie_relro_now_noexecstack` fails.
- **Two latent lane bugs were fixed while establishing this baseline** (both would
  have silently under-reported CI coverage):
  1. `build_coverage` never `make clean`ed the client → an up-to-date tree produced
     **zero** instrumented objects.
  2. `coverage.py` derived `ROOT` from `git rev-parse`, which aborts (exit 128) when
     the pytest guard wrapper runs it with cwd inside the fleet root → now derives
     `ROOT` from `__file__` like the sibling guards.

---

## 2. The baseline (fast tier only)

Suite result: 7659 passed / 21 failed / 147 skipped / 42 xfailed (the 21 failures were
instrumentation artifacts + pre-existing CI-guard debt, not coverage-relevant).

| Tree      | Lines                          | Functions          | Branches |
|-----------|--------------------------------|--------------------|----------|
| `src/`    | **67.5 %** (59 484 / 88 166)   | 76.5 % (4482/5856) | 46.8 %   |
| `client/` | **53.4 %** (12 867 / 24 107)   | 63.0 %             | 41.2 %   |

**This is a floor, not the true coverage.** See §3 for exactly what the fast tier
excludes and — crucially — what it does *not* exclude.

---

## 3. The central lesson: fast-tier 0 % ≠ untested

### 3.0 What `--fast` actually excludes (measured, not assumed)

`operator_runtime.py:181-187` runs the fast tier as literally:

```
pytest tests/ -m "not slow and not serial"          # xdist, --dist load
```

**Only two markers are excluded: `slow` and `serial`.** Everything else runs —
including `uses_lifecycle_harness`. This corrects an earlier assumption in this doc.
Consequences that reshape the plan:

- `uses_lifecycle_harness` tests (e.g. `test_phase23_admin_api.py`,
  `test_checksum_on_write.py`, `test_evil_paths.py`) **DO** run in the fast tier and
  **DO** contribute to the baseline. Extending them moves the fast number.
- A module auto-acquires `slow` if its name matches a substring in
  `conftest.py:665-674` (`_SLOW_MODULE_HINTS`, e.g. `redteam`). `serial` is explicit.
- So a file dark in the fast tier is dark for one of the four reasons below — and only
  Category C is a real fast-tier gap.

### 3.1 The four buckets

| Cat | Meaning | Why dark in `--fast` | Right response |
|-----|---------|----------------------|----------------|
| **A** | **Marker-excluded** OR **runtime-skipped** | its test carries `slow`/`serial`, **or** the test runs but `skip`s at runtime (e.g. `skipif(os.geteuid()!=0)` for the setuid broker) | Verify via a **full-tier** or privileged run; don't write a fast test |
| **B** | **Infra-gated** | needs docker/ceph/minio/live origin the fast box lacks | Belongs to backend-gated suites, not fast tier |
| **C** | **Genuinely untested AND fast-tractable** | no test exercises it and none is needed beyond an in-process stub | **← the target of this plan** |
| **D** | **Tested but not captured** | a fast test *does* exercise it, but in a **separate binary** (`tests/c/*.c` unit harness) whose `.gcda` never lands in the `objs/nginx` lcov capture | Either drive it through the **live request path** (moves the objs number), or extend the capture to include the C-unit binaries |

Category **A vs D** is the subtle one and the reason the earlier draft was imprecise:
`impersonate/*` is dark because its test **skips at runtime** unless `geteuid()==0`
(`test_impersonation_gridmap_root.py:54` = `skipif(os.geteuid() != 0)`) — a *privilege*
reason, not a marker reason. `cred_mint.c` is dark despite a perfectly good **fast,
unmarked** C unit test (`tests/c/test_cred_mint.c`) because that test compiles
`cred_mint.o` into its **own** `test_cred_mint` binary; the coverage lane only captures
`$NGINX_SRC/objs` + `client/`, so that `.gcda` is invisible (Category D).

### 3.2 Classification signal (how to confirm before writing a test)
```bash
grep -rlEi <concept> tests/test_*.py                     # who references it
# then for each referencing file check, in order:
#   pytest.mark.serial / name matches _SLOW_MODULE_HINTS   → Cat A (marker)
#   skipif(geteuid/…) / mark.ceph / PHASE81_RUN_CEPH / docker → Cat A(runtime)/B
#   compiled as tests/c/*.c standalone binary               → Cat D
#   none of the above, zero references                      → Cat C  ← target
```

---

## 4. Gap register (top uncovered files, classified)

Ranked by uncovered lines in the `src/` baseline.

### Category A — marker-excluded or runtime-skipped (do NOT target with fast tests)
| File | Base % | Reason (marker vs runtime) |
|------|-------:|----------------------------|
| `protocols/gridftp/ev/*` (mode_e, data, xfer, cmd, dispatch, io) | 0 % | all 16 gridftp tests `serial`+`slow` (marker) |
| `auth/gssapi/gsi_mech.c` | 0 % | only ref is a `serial` GSI evil test (marker) |
| `auth/impersonate/{client,broker,broker_ops,idmap_denylist,lifecycle_broker}.c` | 0–7 % | tests run but `skipif(geteuid()!=0)` (runtime — needs the setuid broker) |
| `auth/gsi/proxy_req_sign.c`, `tpc/outbound/tpc_token.c`, `protocols/webdav/tpc_{thread,marker,marker_start,curl}.c`, `tpc/outbound/source_stream.c` | 0–35 % | TPC/delegation lanes `serial` (marker) |
| `auth/crypto/ocsp.c` | 0 % | OCSP responder round-trip; serial cert lanes |

### Category B — infra-gated (belongs to backend-gated suites, not fast tier)
| File | Base % | Needs |
|------|-------:|-------|
| `fs/backend/s3/{sd_s3_write,sd_s3_meta}.c` | 8–16 % | live S3 origin (MinIO) — `minio_s3_forward_suite` |
| `fs/backend/rados/cephfs_layout.c` | 0 % | Ceph/RADOS docker lab (`PHASE81_RUN_CEPH`) |
| `fs/backend/remote/sd_remote.c` | 46 % | remote `root://` origin backend |
| `fs/xfer/{xfer_mover_agent,stage_waiter}.c` | 0–15 % | FRM/stage backend + tape driver |
| `fs/cache/origin/pelican_register.c` | 1.8 % | live Pelican director/registry endpoint |

### Category D — tested but not captured (fix the capture, or drive live)
| File | Base % | Existing fast test (separate binary) | To move the objs number |
|------|-------:|--------------------------------------|-------------------------|
| `fs/backend/cred_mint.c` | 0 % | `tests/c/test_cred_mint.c` via `test_c_auth_units.py[cred_mint]` (fast, unmarked) | drive live via S3/WebDAV PUT with a mint CA armed (Wave 3 #7) **or** add `tests/c/` gcda to the lcov capture |

### Category C — fast-tractable targets (THE PLAN)
| File | Base % | Fast driver | Wave |
|------|-------:|-------------|------|
| `protocols/webdav/search.c` | ~~0 %~~ **95 %** | ✅ DONE `test_webdav_search.py` | 0 |
| `protocols/s3/multipart_complete_list_parts.c` | ~~0 %~~ **92 %** | ✅ DONE `test_s3_multipart.py` | 0 |
| `protocols/s3/multipart_complete_list_uploads.c` | ~~0 %~~ **86 %** | ✅ DONE `test_s3_multipart.py` | 0 |
| `observability/dashboard/api_admin_proxy.c` | 15 % | dashboard admin REST — **validation/auth/routing/degraded paths only** (see W1.1) | 1 |
| `protocols/webdav/put_body.c` | 34 % | ingest-digest verification branches over plain-HTTP WebDAV PUT | 1 |
| `fs/path/resolve_confined_ops.c` | 45 % | evil-path / symlink-escape branches (extend `test_evil_paths.py`) | 1 |
| `fs/cache/directives.c` | 38 % | `nginx -t` config-parse units (valid + rejected) | 2 |
| `fs/tier/tier_config.c` | 50 % | `nginx -t` store-URL finaliser reject cases | 2 |
| `auth/token/exchange.c` | 0 % | RFC 8693 exchange — guard/connect-fail live + TLS-stub happy path | 3 |
| `auth/s3/sts.c` | 0 % | **DEFERRED** (not live-wired) — low ROI, see W3.6 | 3 |
| `protocols/webdav/proxy_pool.c` | 3 % | **degraded only** — SHM zone never created (see W1.1) | 1 |
| `fs/vfs/vfs_io_core.c` | 50 % | branch coverage via existing data-plane | 4 |

---

## 5. The plan — prioritised waves

Each wave follows the repo's **3-test ritual** (success + error + security-negative)
and the fleet-declaration gate (`@pytest.mark.registry_server(<name>)` or a declared
fixture). Prefer extending an existing config/spec over adding a new fleet instance.
**Every subagent dispatched to help must be told: never run git-write commands, never
run pytest (single-owner fleet).**

---

### Wave 1 — pure HTTP surfaces, no new infra (highest ROI)

Drivable against the existing `main` / dashboard / S3 instances with `requests`.

#### W1.1 — Admin proxy REST → `api_admin_proxy.c` 15 %→~60 %, `proxy_pool.c` 3 %→~15 %

**⚠ Reality check (from source):** the proxy-pool SHM zone is **never created** in the
current tree. `brix_proxy_pool_configure()` (`proxy_pool.c:78`) is defined but called
from nowhere — the enabler directive `brix_webdav_proxy_dynamic` was retired in the
legacy-proxy cleanup. So `pool_table()` returns NULL and every *mutating* path lands in
the degraded branch. **This test can only assert the reachable-over-HTTP surface:
validation, auth, routing, and the degraded (404) responses.** A live pool would need the
retired wiring restored (out of scope). `proxy_pool.c` therefore only rises modestly
(the add/list/drain helpers short-circuit on NULL table); the real gain is
`api_admin_proxy.c`'s validation/routing code.

**New file:** `tests/test_admin_proxy_pool.py`. Model auth + body plumbing on
`tests/test_phase23_admin_api.py` (same `uses_lifecycle_harness`, fast). Use the
`nginx_admin_api.conf` instance (dashboard location, `brix_admin_rate_limit off;`,
`brix_admin_secret {SECRET_FILE};` — token-only auth). Declare its registry name via
`@pytest.mark.registry_server(<admin-api spec>)`.

Route prefix `ADMIN_PREFIX = "/brix/api/v1/admin/"`. Auth: `Authorization: Bearer <tok>`.

| # | Test | Request | Expect | Covers |
|---|------|---------|--------|--------|
| 1 | list empty | `GET  proxy/backends` | 200 `{"backends":[]}` | `admin_proxy_list` snapshot-of-0 |
| 2 | add valid-url, pool-disabled | `POST proxy/backends {"url":"http://127.0.0.1:8080","weight":100}` | **404 `proxy_pool_disabled`** | url-valid → `brix_proxy_pool_add`→DECLINED (`api_admin_proxy.c:158`) |
| 3 | add bad scheme | `POST … {"url":"ftp://x"}` | 400 `invalid_field` | `admin_validate_url` (`api_admin.c:378`) — runs *before* pool |
| 4 | add missing url | `POST … {"weight":5}` | 400 `missing_field` | `api_admin_proxy.c:143` |
| 5 | add bad chars/host | `POST … {"url":"http:// bad host/"}` | 400 `invalid_field` | url charset check |
| 6 | weight clamp | `POST … {"url":"http://h:9/","weight":99999}` | 404 `proxy_pool_disabled` (clamp path still taken) | `api_admin_proxy.c:153` clamp 1..1000 |
| 7 | get unknown id | `GET  proxy/backends/7` | 404 `not_found` | `admin_proxy_one` in-flight NULL table |
| 8 | drain unknown id | `POST proxy/backends/7/drain` | 404 `not_found` | `api_admin_proxy.c:232` |
| 9 | drain via GET | `GET  proxy/backends/7/drain` | 405 `method_not_allowed` | `api_admin_proxy.c:228` |
| 10 | delete unknown | `DELETE proxy/backends/7` | 404 `not_found` | `api_admin_proxy.c:252` |
| 11 | non-numeric id | `GET  proxy/backends/abc` | 400 `bad_uri` | `api_admin.c:569` |
| 12 | oversized id tail | `GET  proxy/backends/<80 chars>` | 400 `bad_uri` | `admin_parse_proxy_uri` 64-byte tail |
| 13 | no token | `GET  proxy/backends` (no Authorization) | 403 `forbidden` | `brix_admin_check_auth` fail-closed |
| 14 | wrong token | `… Bearer WRONG` | 403 `forbidden` | `admin_auth_secret_ok` CRYPTO_memcmp |
| 15 | empty body POST | `POST proxy/backends` (no body) | 400 `empty_body` | `api_admin.c:258` |
| 16 | non-object JSON | `POST … "[]"` | 400 `invalid_json` | `api_admin.c:296` |
| 17 | body > 64 KiB | `POST …` 70 KiB body | 413 `body_too_large` | `ADMIN_MAX_BODY` (`api_admin.c:269`) |
| 18 | wrong method on collection | `PUT proxy/backends` | 405 `method_not_allowed` | `admin_route_proxy` |

Error body shape is always `{"schema":…,"error":"<code>"}`; success `{"schema":…,…}`.
Assert on the `error` string, not just status. (Existing proof: `test_phase23_admin_api.py:281`
already asserts `ftp://` → 400 `invalid_field`; lines 235/242 assert 403 no/wrong token.)

**SSRF sub-case (optional 19–20):** on an instance that also sets
`brix_admin_proxy_allow <host>` (none in `tests/configs/` yet — would need a new
fragment), a POST whose URL host is not listed → **403 `host_not_allowed`**
(`api_admin_proxy.c:151`). Only add if a config is created; note it in `webdav/README.md`
§ "Dynamic backend pool".

#### W1.2 — WebDAV PUT ingest-digest verification → `put_body.c` 34 %→~65 %

The existing `test_checksum_on_write.py` (`uses_lifecycle_harness`, fast) tests checksum
**persistence**; the digest **verification** branches of
`webdav_put_verify_ingest_digest()` (mismatch/require/unsupported/encoding) are largely
dark. Drive a plain-HTTP WebDAV PUT against a write-enabled instance
(`NGINX_HTTP_WEBDAV_PORT`) with varied `Digest:` / `Content-MD5:` / `Content-Encoding:`
headers. Confirm the target instance has `brix_allow_write on` (the `main` spec anchors
on root://; use a webdav-write spec/config that sets `brix_webdav on` +
`brix_allow_write on`, e.g. the checksum-on-write config family).

Supported alg tokens (`webdav_digest_tokens`, `put_body.c`): `md5`, `sha-256`, `sha256`
(base64 value); `adler32`, `crc32c`, `crc32` (hex value). Header precedence:
`Digest:` first, else `Content-MD5:` (→ md5/base64), else NONE.

**New file:** `tests/test_webdav_put_digest.py`.

| # | Test | Headers on PUT | Expect | Branch (`webdav_put_verify_ingest_digest`) |
|---|------|----------------|--------|--------------------------------------------|
| 1 | correct md5 (b64) | `Digest: md5=<base64(md5(body))>` | 201/204 | FOUND + match → OK |
| 2 | correct sha-256 | `Digest: sha-256=<b64>` | 201/204 | alg table sha-256 path |
| 3 | correct crc32c (hex) | `Digest: crc32c=<hex>` | 201/204 | hex-decode path (`webdav_digest_value_hex`) |
| 4 | Content-MD5 fallback | `Content-MD5: <b64(md5)>` | 201/204 | `webdav_digest_select` fallback |
| 5 | wrong md5 | `Digest: md5=<b64 of WRONG>` | **400** | FOUND + mismatch → 400 |
| 6 | malformed digest value | `Digest: md5=@@notb64@@` | **400** | BAD → 400 |
| 7 | unknown alg | `Digest: whirlpool=xx` | 201/204 (skipped) | token not in table → NONE → OK |
| 8 | Content-Encoding skip | `Digest: md5=<wrong>` + `Content-Encoding: gzip` | 201/204 | encoding present → verification skipped |
| 9 | hex leading-zero eq | `Digest: crc32c=0abc…` vs `abc…` | 201/204 | `webdav_hex_norm_equal` case/zero-insensitive |
| 10 | require-digest, none sent | *(instance with `brix_webdav_require_digest on`)* PUT no digest | **400** | NONE + require → 400 |

Cases 1–9 run against a plain write instance; case 10 needs a small config fragment
adding `brix_webdav_require_digest on;` (none exists in `tests/configs/` — create
`nginx_webdav_require_digest.conf` + a fleet spec, or fold onto an existing webdav-write
config via a `{REQUIRE_DIGEST}` slot). Directives:
`brix_webdav_require_digest` (`module_commands.c:423`),
`brix_webdav_checksum_on_write` (`:416`).

#### W1.3 — Path-confinement branches → `resolve_confined_ops.c` 45 %→~65 %

Extend `tests/test_evil_paths.py` (`uses_lifecycle_harness`, fast — it runs today and
already lifts this file to 45 %). The confined-op surface is
`brix_open_confined_canon` + `brix_{rename,link,setattr,chmod,symlink,readlink,xattr,
lstat}_confined_canon`. Existing tests cover root:// read/open/write traversal + NUL +
symlink-escape; the dark branches are the **mutating** ops and the **WebDAV/S3 edges**.

Add cases driving each edge with an escaping/encoded path:
- **WebDAV** `MKCOL`, `DELETE`, `MOVE`/`COPY` (`Destination:` header) with `..`,
  URL-encoded `%2e%2e`, absolute `Destination` pointing outside the export → assert
  nothing is created/removed outside (reuse `_assert_nothing_escaped`).
- **rename/link escape**: `MOVE` a valid resource to a traversal `Destination` → 403/409,
  source untouched (`brix_rename_confined_canon` reject).
- **symlink readback**: place a symlink escaping the root, `PROPFIND`/`GET` → resolves
  confined, not followed out (`brix_readlink_confined_canon` /
  `brix_lstat_confined_canon`).
- **setattr/chmod**: WebDAV `PROPPATCH` or S3 metadata write on a traversal key →
  rejected before touching the outside path.

3-test ritual per op (valid inside-root success + traversal reject + symlink-escape
reject). This is branch-heavy — expect the biggest *branch* (not line) coverage gain.

---

### Wave 2 — config-parse unit lanes (no fleet server at all)

`objs/nginx -t` against generated conf fragments; assert accept/reject + exact `[emerg]`
needle. **Copy the harness verbatim** from `tests/test_frm_directive_pin.py:56`
(`_nginx_t(root, srv_directives)` → returns `(rc, stderr+stdout)`; stream server;
`NGINX_BIN` from settings; `[NGINX_BIN,"-t","-p",prefix,"-c",conf]`,
`capture_output=True, text=True`). For the HTTP plane use `ConfCheck.ok/.fails` from
`tests/test_cvmfs_conformance_srv_config.py:66` (monotonic `_seq` for unique conf names,
never-dialled origin `http://127.0.0.1:9`).

#### W2.4 — Cache directive parsing → `directives.c` 38 %→~75 %

**New file:** `tests/test_cache_directive_parse.py`. Directives + their setters + exact
reject strings (all `[emerg]`, so `rc != 0`):

| Directive | Accept example | Reject example | Needle in output |
|-----------|----------------|----------------|------------------|
| `brix_cache_origin_family` | `auto` / `inet` / `inet6` | `ipv7` | `must be one of: auto, inet, inet6` |
| `brix_cache_eviction_threshold` | `0.95` / `95%` | `banana` | `invalid value "banana"` |
| " | | `0` or `150%` | `is out of range` |
| " | (twice) | dup | `is duplicate` |
| `brix_cache_max_file_size` | `10m` / `1048576` | `10x` | `unknown suffix in "10x" (use k/m/g)` |
| " | | `10mZ` | `trailing garbage in` |
| " | | huge → `off_t` | `overflows off_t` |
| `brix_cache_high_watermark` | `0.9` / `90%` | `banana` | `invalid value` |
| " | | `0` / `100%` | `must be greater than 0 and less than 1.0` |
| `brix_cache_low_watermark` | `0.8` | `1.5` | `must be greater than 0 and less than 1.0` |
| `brix_cache_include_regex` | `\.root$` | `[unclosed` | `invalid pattern` |

Minimum valid stream server body (from `_nginx_t`): `brix_root on; brix_storage_backend
posix:{root}/data; brix_auth none;` + the directive under test.
**Gotcha:** `low < high` pair-ordering is **not** checked in `directives.c` — it's
enforced later in `runtime_server.c`; don't assert an ordering reject at parse time.

#### W2.5 — Tier store-URL finaliser → `tier_config.c` 50 %→~75 %

**New file:** `tests/test_tier_store_parse.py`. The 11 tier directives come from the
X-macro `BRIX_TIER_DIRECTIVES` (`src/core/config/tier_directives.h:44`); URLs store at
parse but validate in the finaliser `brix_tier_parse_store` (`tier_config.c`, `tier_fail`,
all `[emerg]`). Reject matrix on `brix_cache_store` / `brix_storage_backend`:

| Store URL under test | Needle |
|----------------------|--------|
| `""` (empty) | `empty store url` |
| `nohost` (no scheme) | `has no scheme` |
| `bogus://h:1/` | `unknown driver scheme "bogus"` |
| `root://[fe80::1/` | `unbalanced "[" in store host` |
| `root://host/` (no port, needs one) | `is missing a port` |
| `root://host:99999/` | `invalid store port` |
| `posix:/…<very long>` | `local store path too long` |

Cross-directive finaliser rejects (`runtime_server_backend.c`, `[emerg]`):
- `tape://` or `frm://` backend + no `brix_cache_store` → `is nearline and requires
  brix_cache_store`
- `brix_cache_cold_store` without hot → `requires brix_cache_store (the hot tier)`
- `brix_stage on` without `brix_stage_store` → `brix_stage on requires brix_stage_store`
- `brix_cache_slice_size 3m`? — must be 0 or a 1 MiB multiple, else
  (`server_conf_merge_security.c:487`) `must be a positive multiple of 1m`

Accept cases: model on `nginx_cache_only.conf` (`brix_storage_backend root://localhost:11094;`
+ `brix_cache_store posix:{CACHE_DIR};`) and `nginx_slice_cache_cache.conf`
(`brix_cache_slice_size 1m;`).

---

### Wave 3 — outbound clients vs a stub endpoint (one small stub server)

Copy the stub base from **`tests/guard_http_lib.py`** (`StubBackend` +
`_StubHandler`: `free_port()`, `ThreadingHTTPServer` in a daemon thread, mutable
`reply_status`, hit counter, `.stop()`). For **request assertions** copy the recording
pattern from `tests/test_phase24_mirror.py:247` (`_ShadowHandler`). For **TLS** wrap the
socket as in `tests/lib/fwd_oidc_server.py:33`
(`ctx = ssl.SSLContext(PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert,key);
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)`).

#### W3.7 — x509 credential minting → `cred_mint.c` 0 %→~70 % (Category D → drive live)

`cred_mint.c` is **already** unit-tested (`tests/c/test_cred_mint.c`, fast, unmarked) but
that gcda isn't captured (Category D). To move the **objs** number, drive the **live**
mint path: `brix_cred_mint` (`cred_mint.c:691`) is called from `vfs_cred_maybe_mint`
(`vfs_cred.c:159`) when **all** hold: (1) `brix_sd_ucred_select` DECLINED (no existing
`<key>.pem`), (2) `cap_ok` (backend can scope per-user), (3) a mint CA is armed on the
ctx. The ctx is armed only from **S3** (`protocols/s3/util.c:48`), **WebDAV GET**
(`webdav/get.c:184`), and **WebDAV PUT** (`put_setup.c`).

**Config to arm it:** `brix_storage_credential_mint_ca <ca_cert.pem> <ca_key.pem>`
(TAKE2, `http_common.c:212`; **parses+load-validates both files at `nginx -t`** — a bad
CA fails config) + optional `brix_storage_credential_mint_ttl <secs>`
(`http_common.c:219`; default 3600).

**New file:** `tests/test_cred_mint_live.py`. Generate a throwaway CA (openssl, like
`tests/c/test_cred_mint.c:36`), wire it into a webdav/S3 write config whose backend can
scope per-user, do a request as an identity with no pre-provisioned `.pem`:

| # | Test | Expect | Covers |
|---|------|--------|--------|
| 1 | first PUT/GET mints | request OK; `<cred_dir>/<key>.pem` now exists, 0600 | mint success path |
| 2 | PEM structure | 3 blocks: leaf EC P-256 cert, key, CA cert; CN encodes principal; `notAfter≈now+ttl` | `mint_serialize_pem` |
| 3 | second request reuses | same file mtime, no new `.mint-*.tmp` | `mint_cached_pem_ok` (notAfter > now+300) |
| 4 | refresh window re-mints | with `ttl` small enough that notAfter within 300 s → new mint | `BRIX_CRED_MINT_REFRESH_WINDOW` |
| 5 | atomic (no half-file) | never observe a `.mint-*.tmp` after success | `mint_write_tmp` O_EXCL+rename |
| 6 | bad CA path rejected | `nginx -t` fails | `brix_conf_set_mint_ca` load-validate |

**Alternative (Category-D fix instead of live):** teach `coverage.py`/`operator_build`
to also `lcov --directory tests/c` so the existing C-unit gcda is captured. Cheaper, but
only credits unit coverage — the live test additionally exercises `vfs_cred.c` wiring.

#### W3.8 — RFC 8693 token exchange → `exchange.c` 0 %→~50 % (guard) / ~70 % (TLS stub)

`brix_token_exchange` (`exchange.c:337`) **is** live-wired: called from
`brix_vfs_deleg_exchange` (`vfs_deleg.c:387`) in EXCHANGE delegation mode. Outbound is
**HTTPS-only** POST (`CURLOPT_PROTOCOLS_STR="https"`, `exchange.c:290`), form body
`grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=…&
subject_token_type=…access_token&audience=<a>&resource=<a>[&scope=…]`, response JSON
`access_token` (jansson; `BRIX_HAVE_JANSSON`). Directives:
`brix_backend_token_exchange_endpoint` / `_client_id` / `_client_secret`
(`http_common.c:240-259`), plus `brix_backend_delegation exchange`.

**Two tiers of test (new file `tests/test_token_exchange.py`):**
- **Guard/connect-fail (no stub, cheapest, still real coverage):** configure EXCHANGE
  mode + endpoint = a dead/closed `https://127.0.0.1:<closed>/token`, drive a backend
  request needing delegation → curl connect fails → `NGX_ERROR` → request 502/failed.
  Covers entry-guards (`exchange.c:342-349`), body build, HTTPS-pin, error mapping.
- **Happy path (TLS stub):** stand up `guard_http_lib.StubBackend` **wrapped in TLS**
  (fwd_oidc pattern) with `do_POST` returning
  `{"access_token":"EXCHANGED","token_type":"Bearer","expires_in":3600}`. Point
  `brix_backend_token_exchange_endpoint` at it; assert the backend request carries the
  exchanged token, and the recorded POST body has the RFC-8693 grant_type +
  `audience`==`resource`. (TLS is mandatory — a plain-HTTP stub is rejected before the
  request by the `https`-only pin.)

**Do NOT confuse with** `tests/test_tpc_token_exchange_staging.py` — that exercises a
*different* implementation (`webdav/tpc_cred.c` subprocess-curl), is `serial` +
`uses_lifecycle_harness`, and won't move `exchange.c`.

**LANDED (guard + connect-fail tier) — phase-92, 2026-08-02.** Delivered as a direct
C unit `tests/c/exchange_test.c` (runner `exchange`, `c_auth_units.py`) rather than the
live pytest — the plan had ruled a C unit out as "Category D (separate binary → won't
move objs)", but the phase-92 gcda-capture fix (`_coverage_link_flags`) now credits
`tests/c` gcda in the lcov lane, so a unit linking the **real** `exchange.o` *does* move
`exchange.c`. `nm` confirmed `exchange.o`'s only non-libc/curl/jansson deps are
`ngx_pnalloc` + `ngx_log_error_core` (both stubbed; a stack `ngx_log_t{.log_level=0}`
keeps `ngx_log_error()` from firing / NULL-derefing). Covers: all four entry-guards
(NULL pool / empty subject / missing endpoint / NULL out slot), the RFC-8693 form-body
build (with and without the optional `scope`), the `https`-only protocol pin, the curl
perform against a **closed loopback port** (`https://127.0.0.1:1` → immediate
ECONNREFUSED, fast+deterministic) and its `NGX_ERROR` error map, and the
security-negative that a `http://` endpoint is refused by the pin (no cleartext dial) —
`out` stays empty on every failure (no fabricated token). **Residual — TLS-stub happy
path** (`brix_tx_parse_response` success branch, ~50%→~70%): still wants a TLS-wrapped
OIDC stub returning `{"access_token":…}`; deferred to a fleet-tier test (a C unit can't
cheaply stand up a trusted-CA TLS server). Success+error+security-neg all present at the
unit tier.

#### W3.6 — STS AssumeRole → `sts.c` 0 % — **DEFERRED, low ROI (document, don't build yet)**

`brix_s3_sts_assume` (`sts.c:373`) is **call-ready but not live-wired**: its only caller
`brix_vfs_deleg_sts_cred` (`vfs_deleg.c:593`) is itself **not** called from
`brix_vfs_deleg_live_cred` (explicit `DEFERRED` note `vfs_deleg.c:569`) because (a) the
SigV4 service key pair `svc_ak`/`svc_sk` has no config source on `brix_vfs_ctx_t`, and
(b) `sd_remote` open_cred doesn't map `s3_ak/sk/session` to origin keys yet. Directives
`brix_backend_s3_sts_endpoint`/`_role` exist but region + service keys do not.

Consequence: **no live HTTP request reaches `sts.c`**, so it can't be covered the way
W3.8 covers exchange. A C unit constructing `brix_s3_sts_conf_t` by hand (endpoint →
HTTP stub returning AssumeRole XML — plain `http` is allowed here, `sts_http.c:87`) is
possible but is Category D (separate binary → won't move the objs number). **Recommend:
leave `sts.c` for when the DEFERRED wiring lands; note it here so it isn't mistaken for a
quick fast-tier win.** If pursued now, the honest form is: land the `svc_ak/sk`+region
config wiring first (unblocks live), then test exactly like W3.8.

---

### Wave 4 — branch coverage on hot data-plane files

#### W4.9 — VFS io-core branches → `vfs_io_core.c` 50 %→~65 %

Drive the already-covered functions (`brix_vfs_io_execute_read/write/pgread/readv/
writev/sync/truncate/opendir`) down their *error/partial* branches through existing
root/webdav/s3 data paths — no new infra:
- **short/partial reads**: ranged GET past EOF, zero-length range, range spanning EOF.
- **readv/writev**: multi-range WebDAV GET (`Range: bytes=0-9,20-29`) to hit the iovec
  assembly branch.
- **pgread/pgwrite**: root:// `kXR_pgread`/`kXR_pgwrite` with a mid-file offset (per-page
  CRC32c path — INVARIANT 1).
- **TLS memory-buffer vs file-backed sendfile** (INVARIANT 2): same GET over the TLS
  webdav port (`b->memory=1`) and the cleartext port (file-backed sendfile) — two
  distinct code paths through the same function.
- **truncate/sync**: WebDAV PUT with `Content-Range` that truncates, then a follow-up
  read.

These are *branch* wins on lines already counted — target the 46.8 % branch rate, not
the line rate. Reuse existing data-plane test helpers rather than new fixtures.

> **Status 2026-08-02 — DEFERRED as documented tail (not churned).** Re-assessed
> against the efficiency mandate and found net-negative to pursue now: (a) every
> candidate host (`test_conf_io_read.py`, `test_readv.py`, `test_webdav.py`) is a
> *live-fleet* differential test that self-skips without the stock xrootd toolchain
> (`L.have_official()`), so the added assertions would not even execute in the
> fast/toolchain-less tier where the coverage plan is scored; (b) the existing
> differential READ suite already straddles the read/readv/pgread framing boundaries
> across the page-boundary edge sizes (`sz_4095/4096/4097 … sz_65536`), so the target
> functions are already *line*-covered and much of the branch surface is exercised;
> (c) the residual is pure branch-% on already-line-covered functions, gated behind a
> live fleet whose flakiness is documented (`live_suite_frozen_nginx`) — a poor
> return for the churn. Left as the honest remaining coverage tail; revisit only
> inside a reviewed full-tier fleet run (§6), where the branch numbers actually count.

### Non-goals (explicitly out of fast-tier scope)
- Category A/B files. To move those, run a **full-tier** capture (§6) or a privileged
  broker subset (`geteuid()==0`) — not new fast tests.
- A live proxy pool (W1.1) — needs retired `brix_webdav_proxy_dynamic` wiring restored.
- `sts.c` happy path (W3.6) — needs the DEFERRED delegation wiring landed first.

---

## 6. Graduating the CI floor (do this before setting `COVERAGE_MIN`)

1. Run **one full-tier** instrumented capture in CI (not `--fast`) to read the true
   number — Category A code will light up (impersonate as root, serial TPC/GSI) and the
   real `src/` line-rate will exceed 67.5 %. This is the number a full-tier floor is set
   against (B-1 lesson).
2. Optionally fix Category **D**: add `tests/c/` gcda to the lcov capture so the existing
   C-unit coverage (cred_mint, token/scope units) is credited.
3. Land Wave 1–2 (no-infra), re-read fast-tier %, and set an initial **fast-tier**
   `COVERAGE_MIN` a few points under the observed fast number as a ratchet-only floor.
4. Keep the fast floor and any full-tier floor as **separate** env values — a fast-only
   gate must never assume Category A/B coverage the fast tier can't produce.

---

## 7. Progress log
- **2026-07-21** — baseline read (§2); lane bugs fixed (§1); Category-C Wave-0 landed:
  `test_webdav_search.py` (10) + ListParts/ListMultipartUploads in `test_s3_multipart.py`
  (10) → `search.c` 0→95 %, `multipart_complete_list_parts.c` 0→92 %,
  `multipart_complete_list_uploads.c` 0→86 %. All UNCOMMITTED.
- **2026-07-21 (b)** — plan made hyper-detailed from a source sweep (three Explore
  agents + direct reads): corrected the fast-tier exclusion set (only `slow`+`serial`;
  `uses_lifecycle_harness` runs), added Category **D** (tested-but-not-captured, e.g.
  `cred_mint.c`), and pinned every wave to exact endpoints/directives/reject-strings/
  fixtures. Key reality-checks recorded: proxy-pool SHM zone is never created (W1.1
  degraded-only), `sts.c` is DEFERRED/not-live-wired (W3.6 low-ROI), `exchange.c` is
  HTTPS-only (W3.8 needs a TLS stub). No tests written in this step — planning only.
- **2026-07-21 (c)** — Waves 1 & 2 (the no-infra fast wins) IMPLEMENTED + green. All UNCOMMITTED:
  - **W2.4** `tests/test_cache_directive_parse.py` (NEW, **25 passed**) — `nginx -t` units
    for `src/fs/cache/directives.c` custom setters: accept/reject/duplicate branches for
    `brix_cache_origin_family`/`_eviction_threshold`/`_max_file_size`/`_high|low_watermark`/
    `_include_regex`. Harness mirrors `test_frm_directive_pin.py:56` (stream server, no fleet).
    Reality-check: `eviction_threshold 0`/`150%` hit the `(0,1)` range guard
    ("greater than 0 and less than 1.0"), NOT the ppm out-of-range branch.
  - **W2.5** `tests/test_tier_store_parse.py` (NEW, **11 passed**) — `nginx -t` units for the
    tier store-URL finaliser (`brix_cache_store` → `brix_tier_parse_store` [emerg]) + cross-
    directive rejects (cold-without-hot, nearline-requires-cache, slice-size-1m-multiple).
    Reality-check: `brix_storage_backend` has its OWN setter ("remote origin needs host:port"),
    distinct from the cache_store finaliser wording; posix tier dirs must pre-exist (accessible).
  - **W1.1** `tests/test_phase23_admin_api.py` (EDITED, +13 proxy tests, **16 passed** `-k proxy`)
    — admin REST proxy-pool degraded/validation/routing paths (pool SHM zone never created →
    `proxy_pool_disabled`/`not_found`/`method_not_allowed`/`bad_uri`/`body_too_large`/JSON-error
    branches) via the self-contained `admin_server` lifecycle fixture. No live pool (out of scope).
  - **W1.2** `tests/test_webdav_put_digest.py` (NEW, **13 passed**) — PUT ingest-digest verify
    (`webdav_put_verify_ingest_digest`, runs on every PUT): RFC-3230 `Digest` md5/sha-256/crc32 +
    `Content-MD5` fallback commit; wrong/malformed → 400; unknown-alg + Content-Encoding skip;
    `brix_webdav_require_digest` bare-PUT 400. Lifecycle harness, `nginx_lc_checksum_on_write.conf`
    `EXTRA_DIRECTIVES` slot. Reality-check: Content-Encoding skip needs a *genuinely* gzip'd body.
  - **W1.3** `tests/test_evil_paths.py` (EDITED, MOVE/COPY escaping-`Destination` block added to
    `_webdav_evil_suite`) — `brix_rename_confined_canon`/COPY confined-canon reject; bare + same-
    authority-URL Destinations at `/../` and `/%2e%2e/`; asserts nothing lands beside the root and
    the source survives a refused MOVE. **11 passed** (10 classes fleet-gated → skip when fleet down).
- **2026-07-21 (d)** — Wave 3/4 status after source verification (NOT built — mandate: 0 mistakes):
  - **W3.7** (cred_mint live) — the live mint gate needs `cap_ok`, i.e. a leaf driver with
    `open_cred`/`staged_open_cred`/`stat_cred` (root://, webdav-http, s3) **plus** a client identity
    resolving to a derived key with no pre-provisioned `.pem` — the full GSI/token fleet dance that
    `tests/cmdscripts/user_backend_cred.py` already drives live (its P3/P4 already cover the mint-CA
    `nginx -t` parse). Reproducing that in a fast lifecycle test is high-risk. **Recommended
    mistake-proof path = the plan's Category-D alternative**: capture `tests/c/` gcda in the lcov
    lane so the existing `tests/c/test_cred_mint.c` unit coverage is credited (tooling edit, no
    fragile live test). Deferred pending that lane change.
  - **W3.8** (token exchange) — both the guard/connect-fail and TLS-stub tiers require a token-JWKS
    authenticated front + `brix_backend_delegation exchange` wiring driving a backend open (the
    `make_token.py`/SciTokens/bwrap infra `fwd_matrix_live.py` uses). Correct status/needle assertions
    there can't be made without standing up that infra — deferred to avoid fragile assertions.
  - **W3.6** (sts.c) — remains DEFERRED (not live-wired; see §5 W3.6).
  - **W4.9** (vfs_io_core branches) — additive edge-range assertions on existing data-plane tests;
    no-infra in principle but each needs empirical 206/416/200 verification against a running fleet.
    Not yet built; lowest concrete deliverable (branch-nudge only).
```
