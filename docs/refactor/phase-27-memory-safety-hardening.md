# Phase 27: Memory-Safety & Anti-Abuse Hardening

**Date:** 2026-06-12
**Author:** security / memory-safety audit
**Status:** PLAN — not yet begun
**Scope:** the module under `src/` only — no nginx-core edits (per build governance)

---

## Goal

Harden the module against two classes of failure that an **external, untrusted
peer** can provoke over the wire (`root://`, `davs://`, S3, CMS, TPC):

1. **Memory leaks** — heap, OpenSSL/curl/jansson handles, file descriptors, and
   shared-memory slots that are not released on every code path (especially
   error / early-return paths and long-lived stream sessions).
2. **Resource-exhaustion & corruption attacks** — attacker-controlled lengths
   driving oversized or integer-overflowed allocations, and unbounded
   accumulation of per-peer state (sessions, registry slots, pending queues).

The deliverable is **defensive infrastructure + a consistent discipline**, not a
one-off bug sweep: checked size arithmetic, a scoped-cleanup idiom for external
handles, eviction on the bounded registries, and — most importantly —
**automated detection** (ASAN/LSan + valgrind in CI, plus a wire-parser fuzz
harness) so regressions are caught mechanically rather than by review.

This phase **builds on** defenses the module already has (see *Current Posture*)
and makes them uniform rather than spot-applied.

---

## Threat Model

| Actor | Vector | Failure we must prevent |
|---|---|---|
| Unauthenticated stream client | `dlen` in `ClientRequestHdr`, readv segment counts, path lengths | Oversized / overflowed allocation → OOM or heap overflow |
| Authenticated-but-hostile client | Many `kXR_login` sessions, many open handles | Slot/fd exhaustion → DoS of legitimate users |
| Malicious TPC / proxy origin | Crafted `ServerResponseHdr.dlen`, GSI exchange buckets, PEM/cipher blobs | Error-path leak of OpenSSL handles + heap on every failed handshake → slow OOM |
| Hostile HTTP/S3 peer | `Content-Length`, multipart, dead-property XML, header counts | Unbounded buffering, jansson refcount leaks |
| Repeated-connection attacker | Open/close churn, failed-auth churn | Per-connection leak amplified to OOM; CPU amplification via crypto |

The unifying property: **anything whose size or count comes off the wire is
attacker-controlled** and must be (a) bounded *before* allocation, (b) computed
with overflow-checked arithmetic, and (c) freed on *every* exit path.

---

## Current Posture (what already exists — keep & generalise)

The audit found the codebase is **already disciplined in its newest paths**; the
work is to make that discipline universal.

- **Per-opcode payload cap, pre-allocation.** `src/connection/recv.c` defines a
  cap table consulted *before any allocation* — `auth → XROOTD_MAX_AUTH_PAYLOAD`
  (16 KB), `write → XROOTD_MAX_WRITE_PAYLOAD`, `prepare →
  XROOTD_MAX_PREPARE_PAYLOAD`, `readv → segments × segsize`, others →
  `path + 64`. Over-cap clients are disconnected. This is the model to extend.
- **Auth brute-force / CPU-amplification cap.** `src/auth/gsi/auth.c:357` rejects once
  `auth_fail_count >= XROOTD_MAX_AUTH_ATTEMPTS`, skipping the certreq round.
- **Body caps before `malloc` on remote responses.** `src/fs/cache/origin_response.c:49`
  (`*dlen > max_body`) and `src/tpc/io.c:115` (`*dlen > TPC_RESP_MAX_BODY`) both
  bound, allocate `dlen+1`, and free on the read-failure path. **These are the
  reference pattern.**
- **Bounded shared-memory registries.** Session registry is fixed-capacity
  (`XROOTD_SESSION_REGISTRY_SLOTS`, `src/session/registry.h:30`); manager
  registry is 128 slots (`src/manager/registry.c`), rejects-on-full, and
  increments `xrootd_registry_full_total`. No unbounded growth.
- **A rich cap vocabulary already exists** — `XROOTD_MAX_FILES`,
  `XROOTD_MAX_READV_TOTAL`, `XROOTD_READV_MAXSEGS`, `XROOTD_MAX_WALK_DEPTH`,
  `XROOTD_MAX_TOKEN_SCOPES`, `XROOTD_MAX_JWKS_KEYS`, `XROOTD_PROXY_MAX_BODY`,
  `XROOTD_MAX_CONN_POOL_BYTES`, etc. New guards should reuse this naming.
- **Log-injection is already handled** via `xrootd_sanitize_log_string()`.

So this phase is *consistency + detection*, not a rewrite.

---

## Audit Findings (gaps to close)

Evidence gathered by static inspection of the 381-file / ~87 K-LoC tree.
Severity reflects exploitability by an external peer.

| # | File:line | Issue | Sev | Guard |
|---|-----------|-------|-----|-------|
| F1 | `src/read/readv.c:79`, `:250` | `malloc(segment_count * sizeof(*ranges))` / `ngx_alloc(segment_count * …)`. `segment_count = cur_dlen / SEGSIZE` (`:204`) is bounded by `recv.c`, but the **`* sizeof` multiply has no explicit overflow/`MAXSEGS` guard at the callsite** — defense-in-depth missing. | Med | Explicit `if (segment_count > XROOTD_READV_MAXSEGS) reject;` + checked-mul helper |
| F2 | `src/tpc/gsi_outbound_exchange.c:222,271,335,404,439` | DH/cert exchange does ~5 `malloc`/`OPENSSL_malloc` + many OpenSSL handles with hand-rolled `goto round_fail/done`. Long, branchy error paths driven by a **remote origin's** buckets → high risk of handle/heap leak on any malformed bucket. | High | Scoped-cleanup idiom (W3); fuzz the bucket parser (W7) |
| F3 | `src/read/readv.c:79` (and other per-request `malloc`) | Raw `malloc`/`free` used where a **request/transient pool** would auto-reclaim on the error paths. Each manual `free` is a chance to miss one. | Med | Prefer pool-backed alloc on per-request paths (W4) |
| F4 | `src/session/registry.*`, `src/manager/registry.c` | Registries are **capacity-bounded but never time-evicted**. A peer that opens sessions/handles (or a flapping CMS server) can fill all slots → legitimate logins rejected (slot-exhaustion DoS). No `last_seen` TTL reaper on the session table. | High | TTL/LRU eviction + per-source quota (W5) |
| F5 | `src/session/registry.h:30` vs `:36` docstring | `#define XROOTD_SESSION_REGISTRY_SLOTS 1024` but the doc comment says “default 256” — **cap drift** between declared limit and documentation; risk of wrong capacity assumptions in sizing/SHM math. | Low | Reconcile + single source of truth (W5) |
| F6 | 26 files use `EVP_*`; `src/auth/gsi`, `src/tpc`, `src/auth/crypto`, `src/auth/token`, `src/s3` | OpenSSL `*_new`/`d2i_*`/`PEM_read_*`/`BIO_new` with error returns; needs per-function verification that **every** return path frees. Manual audit cannot guarantee coverage at this scale. | High | LSan/valgrind CI is the real guard (W6) + scoped idiom (W3) |
| F7 | `src/dashboard`, `src/auth/token`, `src/metrics`, `src/query`, `src/s3` (jansson, 10 files) | `json_t` ownership (borrowed `json_object_get` vs owned `json_loads`/`*_new`; stealing `json_object_set_new`) is error-prone → leak or double-decref. | Med | Ownership audit + LSan (W6); jansson cheatsheet in W3 |
| F8 | systemic: **33 files `ngx_alloc`** vs **7 files `ngx_pool_cleanup_add`** | Raw `ngx_alloc` on connection/persistent pools in the long-lived **stream path** relies on a manual `ngx_free` that a session-teardown error path can skip. | Med | Cleanup-registration discipline + lint (W4, W8) |
| F9 | `src/fs/cache/evict_candidates.c:231,237` | `realloc` growth (`list->evicted`, `list->elts`) — classic “`p = realloc(p,…)` loses the old pointer on NULL” + unbounded growth risk if the candidate set is attacker-influenced. | Med | `realloc`-safe helper + cap (W1, W2) |
| F10 | `src/connection/fd_table.c` (0–255 handles) | Confirm every error path that opens an fd into the table also releases it on session close / failed-open; an fd leaked into a slot is both a descriptor leak and a logic hazard. | Med | Audit + LSan/fd-count assertion in tests (W6) |

No file using `ngx_alloc` was found to lack *any* free — so the risk is
**error-path omission and lifetime**, not wholesale absence. That is exactly the
class automated tooling catches best.

---

## Hardening Workstreams

Ordered low-risk-infra-first so later, riskier edits land on top of detection.

### W1 — Checked size arithmetic (foundation)

New header `src/core/compat/safe_size.h` (header-only, registered in
`src/core/config/config.h` includes):

```c
/* Returns 0 and *out=product on success; non-zero on overflow. */
static ngx_inline ngx_int_t xrootd_size_mul(size_t a, size_t b, size_t *out);
static ngx_inline ngx_int_t xrootd_size_add(size_t a, size_t b, size_t *out);
/* Allocate a*b bytes from pool, NULL on overflow or OOM. */
static ngx_inline void *xrootd_palloc_array(ngx_pool_t *p, size_t n, size_t sz);
static ngx_inline void *xrootd_alloc_array(ngx_log_t *log, size_t n, size_t sz);
```

Implemented with `__builtin_mul_overflow`/`__builtin_add_overflow` (GCC/Clang;
the build already targets these). Then convert every wire-driven `n * sizeof`
and `len + 1` / `a + b` size computation (start with F1, F9) to these helpers.

### W2 — Universal "cap before allocate" for wire-driven sizes

Extend the `src/connection/recv.c` cap-table model so that **no allocation sized
by wire data happens without a preceding explicit cap check**. Concretely:

- Add an explicit `XROOTD_READV_MAXSEGS` gate at `readv.c:79`/`:250` (F1).
- Sweep the wire-length allocation inventory (Appendix A) and assert each has a
  cap *at or before* the callsite: `s3` (`Content-Length`, multipart),
  `webdav/dead_props.c` (XML value/name lengths), `query/prepare.c`
  (`cur_dlen`), `proxy/forward_*` (`total`), `cache/origin_protocol.c`
  (`total`), `mirror`, `compat/namespace_ops.c`.
- Where a cap is missing, add one reusing the `XROOTD_*_MAX_*` vocabulary and a
  `XROOTD_PROXY_METRIC_INC`/reject path mirroring `registry_full_total`.

### W3 — Scoped-cleanup idiom for external handles (OpenSSL / curl / jansson)

The TPC/GSI exchange (F2) and the 26 EVP-using files (F6) need a discipline that
makes leaks structurally hard rather than reviewer-dependent.

- Add `src/auth/crypto/scoped.h`: small `XROOTD_DEFER_*` macros (or a manual
  `cleanup:` label convention codified in `CODE STYLE`) that pair each
  `*_new` with its `*_free`, plus convenience destroyers
  (`xrootd_evp_md_free`, `xrootd_bio_free`, `xrootd_x509_stack_free`).
- A **jansson ownership cheatsheet** comment block + helper
  `xrootd_json_decref_safe()`; document borrowed (`json_object_get`,
  `json_array_get`) vs owned (`json_loads`, `*_new`, `json_pack`) and the
  stealing setters (`json_object_set_new`, `json_array_append_new`).
- Refactor `gsi_outbound_exchange.c` to a single `goto cleanup` that frees every
  handle/buffer unconditionally (init all to NULL first). This is the
  highest-value single refactor.

### W4 — Stream-path allocation lifetime

- For per-request work on a long-lived stream session, prefer a **transient
  pool** or register `ngx_pool_cleanup_add` so teardown frees automatically
  (closes F3, F8).
- Audit each raw `ngx_alloc` in `src/stream`, `src/session`, `src/cms`,
  `src/manager`, `src/handshake`, `src/read`, `src/write`, `src/tpc` for a
  guaranteed free on the **session-close** and **error-disconnect** paths.
- Where a buffer lives exactly as long as the session, attach it to the
  connection pool's cleanup chain at allocation time so there is no second place
  to remember.

### W5 — Registry / cache anti-exhaustion

- **Session registry TTL reaper** (F4): stamp `last_seen`, reap idle/expired
  slots under the existing zone mutex on insert-when-full instead of hard-reject;
  add a per-source-identity soft quota so one peer cannot occupy all slots.
- Mirror the manager registry's `registry_full_total` accounting on the session
  table so exhaustion is observable in `/metrics`.
- Reconcile the slot-count cap drift (F5): one `#define`, doc matches code.
- Confirm redirect/health caches and pending queues
  (`src/manager`, `src/upstream`, `src/proxy`) have a bound + eviction.

### W6 — Automated leak / UAF detection in CI (the keystone)

This is the guard that makes all the above *stay* fixed.

- New build target: `./configure … --with-cc-opt='-fsanitize=address,undefined
  -fno-omit-frame-pointer' --with-ld-opt='-fsanitize=address,undefined'`
  producing an ASAN+UBSan+LSan nginx. Document in `docs/03-configuration/build-guide.md`.
- Run the **full pytest suite + the CMS mesh suite** (`tests/test_cms_mesh_interop.py`)
  under it; LSan reports any leak reachable at exit, ASAN catches overflow/UAF.
- Add a **valgrind `--leak-check=full --track-fds=yes`** smoke target over a
  curated subset (auth handshakes, TPC, S3 multipart, readv) for fd-leak and
  still-reachable detection ASAN misses.
- Wire both into the OAK CI / test harness as opt-in jobs (`SANITIZE=1`
  in `manage_test_servers.sh`); gate merges on a clean LSan run.

### W7 — Wire-parser fuzz harness

The attack surface is parsers of attacker-controlled bytes. Add libFuzzer
targets (compiled standalone against the parser TUs, not full nginx):

- Framing + per-opcode dispatch (`src/connection/recv.c`, `src/handshake`).
- GSI/TPC bucket + PEM/cipher parsing (`src/tpc/gsi_outbound_*`, `src/auth/gsi`).
- Token/JWT/JWKS (`src/auth/token`), S3 SigV4 + multipart (`src/s3`), WebDAV
  XML / dead-props (`src/webdav/dead_props.c`).
- Seed corpus from the existing test fixtures; run under ASAN. Store under
  `tests/fuzz/`. Even a few CPU-minutes per target routinely surfaces the
  overflow/leak/UAF cases manual review misses.

### W8 — Allocation/free invariant linting

A cheap grep-based CI check (`tests/lint_alloc.sh`) enforcing the discipline:

- No raw `malloc`/`free` in HTTP-request handlers (must use `r->pool`).
- Every wire-driven `* sizeof` / `dlen`-based alloc has a cap check within N
  lines (heuristic; flags F1-style gaps in review).
- `ngx_alloc` in stream files is paired with `ngx_free` or
  `ngx_pool_cleanup_add` in the same function.
- Each OpenSSL `*_new` in a function has a matching `*_free` token count.

Heuristic, not sound — its job is to make the *next* F1/F2 visible in review.

---

## New Files / Helpers

| File | Purpose | Registered in |
|---|---|---|
| `src/core/compat/safe_size.h` | overflow-checked size math + array alloc (W1) | `config.h` includes |
| `src/auth/crypto/scoped.h` | OpenSSL handle destroyers + cleanup idiom (W3) | `config.h` includes |
| `tests/fuzz/*.c` + `tests/fuzz/README.md` | libFuzzer targets + corpus (W7) | standalone, not in module |
| `tests/lint_alloc.sh` | alloc/free invariant lint (W8) | CI |
| (docs) `build-guide.md` ASAN section | sanitizer build instructions (W6) | — |

No new `.c` added to the module build except possibly thin guard wrappers; most
helpers are header-only (`static ngx_inline`) so **no `./configure` is needed**
for W1/W3 — incremental `make` suffices. Sanitizer builds (W6) and fuzz targets
(W7) are separate build invocations.

---

## Sequencing & Effort

1. **W1 + W6** first — the foundation and the detector. With ASAN/LSan running
   the existing suites, every subsequent change is validated automatically.
2. **W2 + W5** — close the externally-reachable DoS gaps (F1, F4).
3. **W3** — the GSI/TPC cleanup refactor (F2), validated under W6.
4. **W4** — the broad stream-lifetime audit, guided by LSan output.
5. **W7 + W8** — ongoing/regression guards.

Effort: W1 ~½ day, W6 ~1 day (build plumbing + triaging first LSan run), W2/W5
~1–2 days each, W3 ~1 day, W4 ~2–3 days (audit-heavy), W7/W8 ~1–2 days.

---

## Verification

```bash
# W1/W3 header-only — incremental build stays clean
make -j$(nproc) && echo "build OK"

# W6 — sanitizer build + suites must be LSan-clean
./configure --with-stream --with-stream_ssl_module --with-http_ssl_module \
  --with-http_dav_module --with-threads --add-module=$REPO \
  --with-cc-opt='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  --with-ld-opt='-fsanitize=address,undefined' && make -j$(nproc)
SANITIZE=1 tests/manage_test_servers.sh restart
ASAN_OPTIONS=detect_leaks=1 PYTHONPATH=tests pytest tests/ -q   # 0 LSan reports
# CMS mesh under sanitizer too
SANITIZE=1 PYTHONPATH=tests pytest tests/test_cms_mesh_interop.py -q

# W6 — fd-leak smoke
valgrind --leak-check=full --track-fds=yes objs/nginx -t -c <conf>

# W7 — fuzz targets build & run a short pass clean
for t in tests/fuzz/fuzz_*; do "$t" -runs=200000 -max_total_time=120 corpus/; done

# W8 — invariant lint passes
tests/lint_alloc.sh   # exit 0
```

Each functional change still follows the repo rule: **3 tests — success + error
+ security-negative** (e.g. for F1: a valid readv, an over-`MAXSEGS` readv that
is rejected cleanly, and an overflow-crafted `segment_count`).

---

## Risk Assessment

- **Sanitizer build differences:** ASAN changes timing and memory layout; some
  harness readiness waits may need slack (the CMS mesh already uses active
  readiness probing — `tests/cms_mesh_lib.py:wait_ready` — so it tolerates the
  slowdown). Sanitizer build is opt-in (`SANITIZE=1`), never the default.
- **W3 GSI refactor is the riskiest edit** (touches live crypto handshakes); it
  lands *after* W6 so LSan + the existing GSI/TPC tests gate it.
- **W5 eviction must hold the zone mutex** correctly — a reaper racing the
  insert path is a UAF risk; review against the existing locking in
  `session/registry.c` / `manager/registry.c`.
- Header-only W1/W3 helpers add symbols only; no behavior change until call
  sites adopt them (grep for the new symbols should be the only diff initially).

## Rollback

W1/W3/W8 are additive (new headers + lint) — revert by removing the include and
reverting adopted call sites. W6/W7 are separate build targets / test dirs —
deleting them has zero effect on the production build. W2/W4/W5 are per-call-site
edits guarded by the 3-test rule, revertible individually.

---

## Appendix A — Wire-length allocation inventory (audit checklist for W2)

Allocations whose size derives from attacker-controlled input, to be confirmed
capped + overflow-checked:

- `src/read/readv.c:79,250` — `segment_count * sizeof` *(F1, no callsite cap)*
- `src/fs/cache/origin_response.c:60` — `*dlen+1` *(capped ✓ `max_body`)*
- `src/tpc/io.c:118` — `*dlen+1` *(capped ✓ `TPC_RESP_MAX_BODY`)*
- `src/query/prepare.c:317` — `cur_dlen+1` *(verify `MAX_PREPARE_PAYLOAD` gate)*
- `src/fs/cache/origin_protocol.c:220,321` — `malloc(total)` *(verify cap)*
- `src/proxy/forward_relay_dispatch.c:136`, `forward_rewrite_helpers.c:61,139`
  — `ngx_alloc(total/new_total)` *(verify `XROOTD_PROXY_MAX_BODY`)*
- `src/webdav/dead_props.c:129,285,321` — XML len-derived *(verify cap)*
- `src/core/compat/namespace_ops.c:114` — `list_len` *(verify source)*
- `src/fs/cache/evict_candidates.c:231,237,251` — `realloc` growth *(F9)*
- `src/tpc/gsi_outbound_exchange.c:222,271,335,404,439` — exchange buffers *(F2)*
- `src/s3/copy.c:41`, `src/auth/crypto/ocsp.c:524`, `src/write/chkpoint*.c:84,86`
  — header/DER/path-len derived *(verify caps)*

## Appendix B — External-handle hotspots (audit checklist for W3/W6)

- OpenSSL EVP/BIO/X509/EC/BN: `src/tpc/gsi_outbound_*` (densest),
  `src/auth/gsi/*`, `src/auth/crypto/*`, `src/auth/token/*`, `src/s3/auth_sigv4_*`,
  `src/auth/sss/*` — 26 files total.
- libcurl: `src/webdav/tpc*`, `src/fs/cache/origin*` (1 `curl_easy_init` site —
  verify `curl_easy_cleanup` + `curl_slist_free_all` on all returns).
- jansson: `src/dashboard`, `src/auth/token`, `src/metrics`, `src/query`, `src/s3`,
  `src/auth/gsi` — 10 files; audit borrowed-vs-owned refs.
- File descriptors: `src/connection/fd_table.c` (F10), `src/core/compat/staged_file.c`,
  `src/fs/cache`, `src/tpc/io.c`.
