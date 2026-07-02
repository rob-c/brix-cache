# Phase 47 — Operability & packaging: make nginx-xrootd easy to install, run, and operate

**Status:** IMPLEMENTED 2026-06-21 (W1–W5; W6 deferred as designed).

## Implementation notes (what actually shipped)

- **W1 — one combined `.so`.** Restructured the root `config` so the seven
  non-filter module blocks accumulate their srcs/deps/libs and emit **one**
  combined `ngx_module_name` block (`ngx_stream_xrootd_module.so`) — but **only**
  on `--add-dynamic-module`. The plan's "single block, `ngx_module_type=HTTP`"
  needed a correction: a single mixed-type block breaks the **static**
  `--add-module` build (the two STREAM modules would register into
  `HTTP_MODULES`). So the new `xrd_emit_module` helper branches on
  `$ngx_module_link` — combined block for DYNAMIC, per-block (per-type) for static.
  The HTTP AUX filter stays its own `.so`; combined srcs are deduped
  (`metrics/tracking.c` was double-listed). Proven end-to-end: static
  `ngx_modules.c` keeps STREAM modules in the stream slots; the dynamic build
  emits exactly **2 `.so`**; the formerly-cyclic symbols
  (`xrootd_dashboard_http_add`, `xrootd_proxy_pool_add`, `ngx_xrootd_shm_zone`)
  are now `T`/`T`/`B` inside the combined `.so` with zero undefined xrootd
  symbols; and `nginx -t` with the 2 `load_module` lines loads **clean** (the
  previous failure mode). RPM spec installs/ships 2 `.so` + a 2-line
  `mod-xrootd.conf` (combined first), Release bumped to -4.
- **W2 — `/healthz`.** `xrootd_health on;` in the metrics module (new
  `src/metrics/health.c`, no new `.so`). `GET /healthz` → 200 liveness JSON;
  `?verbose` adds `metrics_shm`/`worker_pid`/`nginx_version`; HEAD → 200; POST →
  405. Wired into the harness metrics block; `tests/test_health_endpoint.py` 4/4.
- **W3 — `contrib/xrootd.conf.example`** (http-context davs+s3+metrics+healthz+
  dashboard, with the top-level `stream{}` root:// block in a paste-ready header
  comment) + **`contrib/logrotate.d/nginx-xrootd`**; both RPM-installed. `nginx -t`
  on the example passes (caught + fixed a real `tpc_cafile`-is-a-file error).
- **W4 — `contrib/grafana-dashboard.json`** (12 panels) + **`prometheus-alerts.yml`**
  (8 rules), built on the verified exported families; both validated and RPM-shipped.
- **W5 — day-2 runbooks** (`troubleshooting`, `capacity-planning`,
  `certificate-rotation`, `upgrade-procedure`) registered in `docs/index.md`;
  preflight folded into `/healthz?verbose`.
- **Regression:** 15/15 S3-metrics + large-file byte-exact/checksum smoke green;
  static build clean (also surgically fixed a pre-existing `-Werror=comment`
  breakage in `src/shared/file_serve.c`).

---

**Original plan below (status: superseded by the notes above).**

**Scope:** packaging (`packaging/rpm/`, root `config`), a tiny new HTTP endpoint
(`src/metrics/`), shippable ops artifacts (`contrib/`), and docs (`docs/05-operations/`,
`docs/08-metrics-monitoring/`). **No protocol/wire changes.**
**Next free number** (46 is `phase-46-s3-write-concurrency.md`, implemented).

---

## 0. Context (why)

The protocol, auth, perf, and feature surfaces are mature (phases 30–46: root://, WebDAV,
S3, compression, impersonation, XrdAcc, FRM, native clients…). What's left to make this a
project a new HEP/WLCG site can *adopt* is **operability and setup-friendliness**, not more
features. A read-only audit surfaced one real correctness blocker and a cluster of
"last-mile" gaps:

1. **The RPM's dynamic modules cannot be loaded as a set (broken out-of-box install).**
   The build emits **8 separate `.so` modules** (root `config` has 8 `ngx_module_name`
   blocks) and the RPM writes 8 `load_module` lines (`nginx-mod-xrootd.spec:155-162`). But
   `nginx -t` fails to dlopen them together because of a **circular cross-module symbol
   cycle** — the dashboard `.so` calls `xrootd_proxy_pool_add` (defined in the WebDAV
   `.so`) while WebDAV/S3/dashboard all need `ngx_xrootd_shm_zone`
   (`src/metrics/handler.c:12`) and `xrootd_dashboard_http_add`; with `RTLD_NOW` a cross-
   `.so` cycle can't resolve (documented in `phase-42-compression.md:73-79`). Only the
   **static** `--add-module` build works today, so `dnf install nginx-mod-xrootd` + the
   shipped snippet is a hard failure for an operator.
2. **No default/example config or logrotate is installed** — the RPM ships only the
   `load_module` snippet; the operator must hand-write `nginx.conf`.
3. **No HTTP health/readiness endpoint** — there is internal *upstream* health-checking
   (`src/net/manager/health_check.c`) and SRR/metrics/dashboard, but nothing an LB or
   Kubernetes probe can hit (`/healthz`, `/ready`).
4. **No shipped Grafana dashboard / alert rules** — the README references a "ready-made"
   dashboard but none exists in-repo; `/metrics` is rich and low-cardinality but operators
   must build panels from scratch.
5. **Day-2 runbooks are missing** — day-1 docs are good (`BUILD_INSTALL.md`,
   `docs/01-getting-started/`, `docs/03-configuration/examples.md`), but there is no
   consolidated troubleshooting guide, capacity-planning, cert/token-rotation procedure, or
   upgrade/rollback note; guidance is scattered across 8+ docs.

**Already in place (do NOT re-build):** JWKS hot-reload (`src/auth/token/refresh.c`, mtime
poll) and non-disruptive CRL/X509_STORE rebuild (`src/auth/gsi`) already exist — the rotation
runbook documents them, it does not add them. Metrics (`src/metrics/`) and the dashboard
(`src/dashboard/`) are production-grade. Config-time validation (`src/core/config/helpers.c`,
~354 `ngx_conf_log_error` sites) is already strict.

---

## 1. Keystone — make the dynamic build load

nginx's `auto/module` supports **one `.so` containing many modules** via a single
space-separated `ngx_module_name="m1 m2 … m8"` block with the union of srcs (shared srcs
de-duplicated automatically; modules register by their `ngx_module_t.type` at load, so
mixed STREAM + HTTP in one `.so` is fine). Collapsing the cyclically-dependent module set
into **one `.so`** makes every cross-module reference resolve at *link time* instead of
dlopen time — the cycle disappears. The static `--add-module` path is unaffected (it
already links everything into one binary). This is the fix that turns the RPM into a
working `dnf install`.

---

## 2. Workstreams

### W1 — Dynamic-module bundling (keystone)
**Files:** root `config`, `packaging/rpm/nginx-mod-xrootd.spec`

- Restructure the root `config`: merge the 7 non-filter module blocks
  (`ngx_stream_xrootd_module`, `…cms_srv_module`, `…metrics_module`, `…srr_module`,
  `…webdav_module`, `…s3_module`, `…dashboard_module`) into **one** `ngx_module_name="…"`
  block with the **union** of `ngx_module_srcs` (each `.c` listed once — this also removes
  the current `metrics/tracking.c` double-listing), the union of `ngx_module_deps`,
  `ngx_module_incs`, and `ngx_module_libs` (`-lssl -lcrypto -lcrypt` + curl/xml2/jansson/
  krb5/codec). Keep `ngx_http_xrootd_xrdhttp_filter_module` as its **own** block (it is an
  `HTTP_AUX_FILTER` with filter-ordering needs and only `-lssl`; it's not in the cycle and
  loads after the combined `.so` via `RTLD_GLOBAL`).
- Result: the dynamic build emits **2 `.so`** (one combined + the filter); the RPM ships 2
  and writes **2** `load_module` lines (combined first). Static build (`--add-module`)
  output is identical to today.
- Update `packaging/rpm/nginx-mod-xrootd.spec` `%install`/`%files`/`mod-xrootd.conf`
  generation (lines ~136-163, 189-230) to the new `.so` set.
- **Risk:** medium — build-machinery change. Mitigation: the static path is untouched and
  remains the guaranteed fallback; the combined-`.so` pattern is standard nginx. **If** a
  mixed-type single-`.so` proves unworkable on the target nginx, fall back to splitting
  along the cycle boundary (the minimal acyclic unit is
  stream+metrics+webdav+dashboard+s3+srr+cms) or relocating the
  `xrootd_proxy_pool_add` / `xrootd_dashboard_http_add` symbols into the stream core so the
  graph is acyclic.
- **Validation:** build with `--add-dynamic-module`; `nginx -t` against the generated
  `mod-xrootd.conf` loads **clean** (the current failure mode); smoke a root:// + davs:// +
  s3:// request through the dynamic build; confirm the static build + the full pytest suite
  still pass unchanged; `ldd` / `nm -D` shows no unresolved cross-`.so` symbols.

### W2 — HTTP health/readiness endpoint
**Files:** `src/metrics/module.c` + a new `src/metrics/health.c`

- Add a `xrootd_health on;` location directive in the **metrics** module (avoids a new
  module/`.so`; reuses the lightest content-handler recipe — the SRR pattern in
  `src/srr/handler.c:22-80`: set status + `application/json`, send one `ngx_buf_t`).
- `GET /healthz` → **200** `{"status":"ok","version":"…"}` for liveness (process accepting
  connections). A `?verbose` / readiness variant additionally reports cheap, non-secret
  signals: metrics SHM mapped, export root reachable/writable, host-cert notAfter (days to
  expiry), JWKS key count. Never leak secrets.
- **Risk:** low (additive read-only endpoint). **Validation:** `curl /healthz` → 200 JSON;
  `?verbose` reports cert-expiry + roots; behaves under a stopped backend.

### W3 — Ship a default example config + logrotate
**Files:** new `contrib/`, `packaging/rpm/nginx-mod-xrootd.spec`

- Create `contrib/xrootd.conf.example` — a minimal, **heavily-commented** server serving
  `davs://` (TLS) + `s3://` from one export, with `/metrics`, `/healthz`, and the dashboard
  wired (sourced from `docs/03-configuration/examples.md`). Create
  `contrib/logrotate.d/nginx-xrootd` for the access logs.
- RPM installs `xrootd.conf.example` to `/etc/nginx/conf.d/` (as `%config(noreplace)`, named
  `.example` so it doesn't auto-activate) and the logrotate file to `/etc/logrotate.d/`.
- **Validation:** `nginx -t` on the example config passes; `rpmbuild` lists the new files.

### W4 — Grafana dashboard + Prometheus alert rules
**Files:** new `contrib/`

- `contrib/grafana-dashboard.json` — panels built on the **real** exported families:
  `xrootd_io_bytes_read/written{proto}`, `xrootd_{webdav,s3}_responses_total{status_class}`,
  `xrootd_{webdav,s3}_auth_total{result}`, the unified latency histogram,
  `xrootd_cache_hits/misses_total`, `xrootd_kv_*{zone}`, per-VO `xrootd_vo_*`. Mine
  `docs/08-metrics-monitoring/promql-examples.md`.
- `contrib/prometheus-alerts.yml` — starter alerts (5xx ratio, auth-failure spike, cache
  miss surge, error-rate, scrape-down). Ship via a small `nginx-xrootd-dashboards` noarch
  subpackage (or `%doc` under `/usr/share/nginx-xrootd/`).
- **Validation:** `promtool check rules contrib/prometheus-alerts.yml`; import the dashboard
  JSON against a live `/metrics` and confirm panels populate.

### W5 — Day-2 operability docs + light server-side preflight
**Files:** `docs/05-operations/`, `docs/index.md`

- New runbooks, registered in `docs/index.md`:
  `troubleshooting.md` (a single "X is broken → check Y" decision tree consolidating the
  scattered auth/TPC/cache/path-escape guidance), `capacity-planning.md` (worker/conn/FD
  limits, SHM-zone sizing, thread-pool tuning), `certificate-rotation.md` (documents the
  **existing** JWKS mtime-reload + CRL/X509_STORE rebuild + `nginx -s reload` semantics),
  `upgrade-procedure.md` (RPM upgrade, module-load order, rollback). Document the
  `libbz2.so.1.0` SONAME caveat so a target host without it is handled up front.
- **Server-side preflight ("doctor"):** fold into W2's `/healthz?verbose` (the runtime
  check) + a short "preflight checklist" doc; deeper `nginx -t`-time validation only if
  cheap. Keep modest — the client already has `xrddiag`.
- **Validation:** docs render; every new doc linked from `docs/index.md`; the
  troubleshooting tree cross-checked against real error strings.

### W6 — deferred S3 protocol-feature backlog — **IMPLEMENTED 2026-06-21**

All three landed (each opt-in / transparent-fallback, wire-compatible). 9 new tests + S3
(106) and WebDAV (125) regression green.

- **W6b — `renameat2(RENAME_NOREPLACE)` atomic create-if-absent.** Exclusive-rename
  variants (`xrootd_rename_beneath_excl`, `xrootd_rename_confined_canon_excl`,
  `xrootd_staged_commit_excl`) threaded through the one commit chokepoint, plus an
  impersonation `IMP_OP_RENAME_NOREPLACE` broker op. S3 `If-None-Match:*` PUT commits
  exclusively → EEXIST maps to 412; falls back to the legacy stat+rename on kernels
  without RENAME_NOREPLACE. Always-on (only adds atomicity). `tests/test_s3_create_exclusive.py`
  (incl. a concurrent single-winner race).
- **W6a — aws-chunked per-chunk SigV4 verification.** Opt-in
  `xrootd_s3_verify_chunk_signatures`. Auth now retains the seed signature + signing key +
  scope/timestamp on the request ctx (previously discarded); the (off-event-loop) decoder
  rolls the AWS4-HMAC-SHA256-PAYLOAD chain with an incremental SHA-256 and rejects a
  mismatch with 403. `tests/test_s3_chunk_signature.py` (real signed upload, tampered → 403,
  verify-off unchanged). Gotcha: the seed canonical request uses **UNSIGNED-PAYLOAD**
  (XrdClS3 convention), not the STREAMING marker.
- **W6c — ListObjects sorted-listing cache.** Opt-in `xrootd_s3_list_cache` +
  `_ttl`. **Per-worker LRU** (`src/s3/list_cache.c`), NOT SHM — the shared KV store's
  fixed key_max+val_max stride would waste memory on every slot and cap the cacheable
  listing size (a finding during implementation; the user chose the per-worker design). A
  readdir-position cursor is impossible (S3 needs lexicographic order, sorting happens after
  the full walk), so it caches the sorted result, validated by bucket-root mtime + TTL
  (bounded eventual consistency). `tests/test_s3_list_cache.py` (correctness, bounded-stale,
  mtime/TTL invalidation).

---

## 3. Non-goals

- Token/CRL hot-reload — **already implemented**; W5 only documents it.
- A bespoke production Helm chart — `k8s-tests/` already has CI-grade charts to adapt; out of scope.
- Rewriting the dashboard or metrics — they are production-grade.

## 4. Sequencing

1. **W1** first — it's the actual blocker; everything else assumes a working install. Gate
   on the dynamic `nginx -t` loading clean + the static path unchanged.
2. **W2** (health endpoint) and **W3** (example config + logrotate) — small, high-value,
   and W3's example config should reference W2's `/healthz`.
3. **W4** (Grafana + alerts) and **W5** (docs) — independent, parallelizable.
4. **W6** — only on explicit request.

## 5. Files to modify / add

| Workstream | Files |
|---|---|
| W1 | root `config` (collapse module blocks → one combined + the filter); `packaging/rpm/nginx-mod-xrootd.spec` |
| W2 | `src/metrics/module.c` + new `src/metrics/health.c` (register the new `.c` in root `config`) |
| W3 | new `contrib/xrootd.conf.example`, `contrib/logrotate.d/nginx-xrootd`; spec `%install`/`%files` |
| W4 | new `contrib/grafana-dashboard.json`, `contrib/prometheus-alerts.yml`; spec dashboards subpackage |
| W5 | new `docs/05-operations/{troubleshooting,capacity-planning,certificate-rotation,upgrade-procedure}.md` + `docs/index.md` |
| W6 (optional) | per-feature (`src/s3/aws_chunked.c`+auth, beneath/impersonate rename, `src/s3/list_objects_v2.c`) |

## 6. Expected outcome

- `dnf install nginx-mod-xrootd` → `nginx -t` loads cleanly (dynamic build fixed); a new
  operator has a working `davs://`+`s3://` gateway from the shipped example config in minutes.
- LBs / k8s get `/healthz`; operators get a Grafana dashboard + alerts and day-2 runbooks.
- Zero protocol/wire change; the full existing test suite stays green.
