# TESTING.md — running the BriX-Cache test suite on AlmaLinux 9

Everything needed to run the Python test suite (fast lane and full) on an
AlmaLinux 9 host from scratch, plus the hard-won lessons from bringing it up on
this box (`xrd1.edi.scotgrid.ac.uk`, 4 cores). Preference throughout: **distro
RPMs over pip/virtualenvs** for Python deps.

---

## TL;DR — run the fast test suite

Once the one-time setup (§1–§4) is done:

```bash
cd /root/dev/brix-cache
export TEST_NGINX_BIN=/usr/local/bin/brix-test-nginx \
       NGINX_BIN=/usr/local/bin/brix-test-nginx \
       PYTHONPATH=tests
unset TEST_OWN_FLEET                       # attach-mode: don't wipe/own the fleet

# 1. free the ports this box's live XRootD holds (see §4)
sudo systemctl stop xrootd@brix.service cmsd@brix-mgr.service

# 2. bring the fleet up once (detached; ~10–15 min on 4 cores; idle load then ~0.7)
tests/manage_test_servers.sh start-all

# 3. run the fast set — conftest attaches to the running fleet.
#    -n3 keeps the load < 8 on a 4-core box (see §5).
python -m pytest tests/ --ignore=tests/userns \
    -m "not slow and not serial" -n 3 --dist load -p no:randomly -q
```

A single file, for a quick check: `python -m pytest tests/test_readv.py -q`.

> **Parallelism vs load:** `-n` is the main load lever. On this **4-core** box use
> `-n 3` to keep the load average under 8. `-n 8` oversubscribes 4 cores ~2× and
> destabilises the box. `tests/run_suite.sh --fast` auto-computes `nproc-2` (= 2
> here), which is also safe.

---

## 1. Python dependencies — all via dnf (no venv)

Every dep is an EL9 RPM (BaseOS / AppStream / CRB / EPEL):

```bash
sudo dnf install -y epel-release      # python3-xrootd, pytest-xdist, pytest-timeout
sudo dnf install -y \
    python3-pytest \
    python3-pytest-timeout \
    python3-pytest-xdist \
    python3-cryptography \
    python3-requests \
    python3-urllib3 \
    python3-xrootd \
    python-unversioned-command        # provides /usr/bin/python (run_suite.sh calls `python`)
```

Verify they import:

```bash
python3 -c "import pytest, pytest_timeout, xdist, cryptography, requests, urllib3, XRootD; print('deps OK')"
```

**Gotchas discovered here:**
- **`python-unversioned-command` is required** — `run_suite.sh` and some helpers
  call `python`, which EL9 does not provide by default (only `python3`).
- **`python3-cryptography` on EL9 is 36.0.1** (the only RPM). The suite's
  `utils/make_proxy.py` used the cryptography-≥42 `not_valid_before_utc` API; it
  now falls back to the naive accessor so PKI/proxy generation works on 36 (fix
  in this repo).
- **`python3-xrootd`** (XRootD Python bindings, EPEL, v5.9.x) is needed by the
  fleet readiness probe and cross/differential tests.

## 2. Python ≥ 3.10 vs EL9's 3.9

The suite uses PEP 604 union syntax (`dict | None`) in annotations, which Python
3.9 evaluates at def-time and rejects — so ~33 modules would fail to import (712
collection errors). We closed this **without pip** by adding a commented
`from __future__ import annotations` (PEP 563) to the 9 modules that actually use
`X | Y` in annotations. The full suite now **collects 9764 tests with 0 union
errors** on EL9's stock Python 3.9. (Python 3.11 is an RPM, but `pytest-timeout`,
`pytest-xdist`, and the `xrootd` bindings have no `python3.11-*` RPM, so a fully
RPM 3.11 setup is not achievable — 3.9 + the `__future__` shims is the pure-RPM
path.)

## 3. XRootD tools + reference daemon (dnf)

```bash
sudo dnf install -y xrootd-client xrootd-server
```
- `xrootd-client` → `xrdcp`, `xrdfs` (tests + fleet readiness probe).
- `xrootd-server` → the `xrootd`/`cmsd` daemons the harness runs as reference /
  cluster / TPC backends.

## 4. The module under test + host setup

The fleet needs an nginx serving the BriX modules. This box uses the **RPM /
dynamic-module** path (system `/usr/sbin/nginx` 1.20.1 + the module `.so`s in
`/usr/lib64/nginx/modules`), driven the way it ships.

### 4a. Build + install the module from this checkout

The module under test **must match this checkout** (a mismatched module fails or
crashes at nginx startup). Build it with the in-tree CMake flow (see
[BUILD.md](BUILD.md)) and install the two `.so`s:

```bash
sudo dnf install -y nginx nginx-mod-stream       # system nginx + dynamic stream core
cmake -B build && cmake --build build -j$(nproc) # builds against nginx-mod-devel
sudo install -m0755 build/modules/ngx_stream_brix_module.so \
     build/modules/ngx_http_brix_xrdhttp_filter_module.so /usr/lib64/nginx/modules/
```

### 4b. nginx wrapper (`brix-test-nginx`)

The harness assumes a *static* `--add-module` nginx and never emits `load_module`
directives; and when run as root it drops workers to an unprivileged user that
cannot write the root-owned test dirs. A wrapper fixes both. Install it and point
the harness at it (already done via `TEST_NGINX_BIN`/`NGINX_BIN` in the TL;DR):

```bash
sudo tee /usr/local/bin/brix-test-nginx >/dev/null <<'EOF'
#!/usr/bin/env bash
# Drive the RPM-installed BriX dynamic module with the test harness.
set -u
REAL="${BRIX_REAL_NGINX:-/usr/sbin/nginx}"
MODDIR="${BRIX_MODULE_DIR:-/usr/lib64/nginx/modules}"
MODS="load_module ${MODDIR}/ngx_stream_module.so; load_module ${MODDIR}/ngx_stream_brix_module.so; load_module ${MODDIR}/ngx_http_brix_xrdhttp_filter_module.so;"
[ "$(id -u)" = "0" ] && MODS="${MODS} user root;"   # keep root workers (test dirs are root-owned)
args=(); gval=""
while [ $# -gt 0 ]; do
    case "$1" in
        -g) gval="${2:-}"; shift 2 ;;
        *)  args+=("$1"); shift ;;
    esac
done
exec "$REAL" -g "${MODS}${gval:+ ${gval}}" "${args[@]+"${args[@]}"}"
EOF
sudo chmod +x /usr/local/bin/brix-test-nginx
```

Load order matters: **stream core → brix stream → xrdhttp filter**. The wrapper
merges any caller `-g` (nginx allows only one).

### 4c. This is a live XRootD box — free the fleet ports

`xrd1` runs systemd-managed XRootD services. `xrootd@brix.service` (11094) and
`cmsd@brix-mgr.service` (11095) sit on the fleet's anon/GSI ports, and the
harness's `force_stop_nginx` reaps **whatever** listens on a hardcoded port list
(11094, 11095, …) — so it will SIGTERM those services. Stop them first (this box
is a test box), and restore after:

```bash
sudo systemctl stop  xrootd@brix.service cmsd@brix-mgr.service   # before testing
sudo systemctl start xrootd@brix.service cmsd@brix-mgr.service   # after
```
If a box runs XRootD you must NOT disturb, do not run the fleet on it — the
port-kill list is not env-overridable.

## 5. Running the tests

**Attach mode (§ TL;DR) is the recommended path.** You start the fleet once, then
run pytest **without** `TEST_OWN_FLEET`; `conftest` detects the listener on
`127.0.0.1:11094` and *attaches* (no wipe / start-all / stop-all). It prints
`A fleet is already listening … attaching …` when it engages.

`tests/run_suite.sh --fast` is the "own-fleet" runner (it sets `TEST_OWN_FLEET=1`
and wipes+starts each run). It works now that the crash and reference-xrootd
issues (§6) are fixed, but on 4 cores the full-suite fleet takes ~15 min to bring
up; attach mode reuses one fleet across runs.

Full suite / lanes (see the header of `tests/run_suite.sh`):
```bash
tests/run_suite.sh --fast     # <5min quick lane, -m "not slow and not serial"
tests/run_suite.sh --pr       # the PR gate (not slow, bulk + serial)
tests/run_suite.sh --nightly  # the deferred slow set
tests/run_suite.sh            # everything (4 lanes)
```

**Launching the fleet from a script/agent:** launch `start-all` truly detached
(`nohup … &` inside a short-lived shell does NOT survive it). Prefer a real
background job that outlives the launcher.

---

## 6. Hard-won lessons (what actually blocked the suite)

Ordered roughly by how much pain each caused.

### 6a. Module crash-loop under `error_log debug` — the big one
**Symptom:** with the whole fleet up (~187 nginx), system load exploded to 28+ on
4 cores; `du /var/lib/systemd/coredump` = **4.1 GB**; `coredumpctl` showed dozens
of `/usr/sbin/nginx` SIGSEGVs per 30 s.

**Root cause:** five connection-less worker-init maintenance timers
(`stage_sched`, `pending_reap`, `stage_reap`, `uring_panic`, accesslog-flush) were
armed with `ev->data = NULL`. This box's nginx is `--with-debug`, so nginx's
timer-expiry **debug log** (`ngx_event_expire_timers` → `ngx_event_ident(ev->data)`
= `((ngx_connection_t*)NULL)->fd`) dereferenced NULL and SIGSEGV'd the worker.
`stage_sched` arms for *every* worker and fires at 1 s, so **any config using
`error_log … debug` crashed ~1 s after each worker start → nginx respawned →
crash-loop → core-dump storm → load spike.** Configs at `error_log info` (rare)
never hit it.

**Diagnosis path:** `coredumpctl dump` a fresh core → `gdb` with the module's
`.so` symbols → crash at `mov 0x18(%rax),%r8d` with `rax=0` (offset 0x18 =
`ngx_connection_t.fd`) → the timer-expiry debug log → grep `src/` for
`ngx_add_timer` → the three `.data = NULL` sites.

**Fix (in this repo):** a shared dummy `ngx_connection_t { .fd = -1 }`; all five
timers now point `ev->data` at it. Files: `src/core/config/process.c`,
`src/core/aio/uring_admin.c`, `src/observability/accesslog/access_log.c`.
Validated: a debug-logging instance now survives the 1 s timer fire (0 crashes,
0 core dumps); full fleet idle load dropped from 28 → **~0.7**.

> **Which tests this affected:** `nginx_shared.conf` (the *main* fleet — root
> 11094-11097, WebDAV 8443/8444, S3 9001, metrics 9100) uses `error_log debug`,
> so the core fleet crash-looped and **most of the fast lane** saw intermittent
> resets/flakes. 22 configs use debug in total; the dedicated ones
> (`nginx_cluster_*`, `nginx_chaos_*`, `nginx_cms_test`, `nginx_proxy_*`,
> `nginx_crl*`, `nginx_root_tpc`, `nginx_s3_presigned*`, `nginx_webdav_tpc`,
> `nginx_credential_bridge`, mesh `mesh_hybrid_node_*`) mostly back `slow`/`serial`
> tests (cluster/chaos/cms/e2e/mesh).

### 6b. Reference xrootd / XrdHttp refuse to run as root
`xrootd` aborts as the superuser (`Security reasons prohibit running as
superuser`). Under a root harness the reference/upstream/TPC xrootd + XrdHttp
instances never started (each burned its 15 s readiness budget → `start-all`
looked hung). **Fix:** a `-R <user>` shim (`_ref_launch` in `tests/lib/refxrootd.sh`,
reused by `tests/lib/xrdhttp.sh`) that drops them to `nobody` and opens the dirs /
PKI they then read/write.

### 6c. Running the whole fleet as root
Necessary here (the repo is under `/root`, which is `750`, so a non-root user
can't reach it, and unprivileged nginx workers can't write the root-owned test
dirs). Consequences we had to handle: the `user root;` wrapper injection (§4b),
the xrootd `-R nobody` shim (6b), and it's *why* the debug-timer crash (6a) was
fatal rather than a clean failure.

### 6d. The combined dynamic `.so` was missing a module
The repo `config` assembled the combined dynamic module from an explicit list
that omitted `ngx_http_brix_common_module`, so the RPM/dynamic build compiled
`http_common.c` but never registered it — every unified-storage directive
(`brix_storage_backend`, `brix_export`, `brix_cache_*`) was rejected in HTTP
contexts (`"directive not allowed here"`). The **static** test build hid this.
Fixed in `config`.

### 6e. Portability / environment
- `tests/lib/pki.sh` hardcoded `cd /home/rcurrie/HEP-x/nginx-xrootd` → now derives
  the repo root from the script location.
- `utils/make_proxy.py` cryptography-≥42 API → naive-accessor fallback (§1).
- `nginx-mod-brix-cache.spec` required `voms-libs` (EL8 name) → the soname
  `libvomsapi.so.1()(64bit)` (works on EL8 `voms-libs` and EL9 `voms`). See BUILD.md.

### 6f. xrootd's thread floor
`xrd.sched mint 2 maxt 4 avlt 2` caps the **scheduler worker pool** at 4 (the only
pool that scales with request load). A functioning xrootd still spawns ~12 fixed
infrastructure threads (3 epoll pollers, 2 accept, 2 signal, 2 timer, admin,
main) with **no config knob** to reduce them — so ~16 threads/instance is the
floor; "4 threads total" is not achievable for xrootd. (The pss-proxy XrdCl pool
*is* separately bounded via `XRD_PARALLELEVTLOOP=1 XRD_WORKERTHREADS=1` — it went
90 → 18 threads.)

---

## 7. Fixes made in this repo (all committed together)

| Area | Files |
|---|---|
| **module crash** (NULL-data timers, §6a) | `src/core/config/process.c`, `src/core/aio/uring_admin.c`, `src/observability/accesslog/access_log.c` |
| combined `.so` module list (§6d) | `config` |
| reference xrootd / XrdHttp `-R nobody` (§6b) | `tests/lib/refxrootd.sh`, `tests/lib/xrdhttp.sh` |
| Python 3.9 unions (§2) | 9 `tests/test_*.py` |
| cryptography-36 / hardcoded path (§6e) | `utils/make_proxy.py`, `tests/lib/pki.sh` |
| VOMS soname (§6e) | `packaging/rpm/nginx-mod-brix-cache.spec` |
| thread caps (§6f) | `tests/configs/xrootd_*.conf`, `tests/configs/mesh/*`, nginx `thread_pool`/`worker_processes 1` in `tests/configs/*.conf` |
| configs-as-templates refactor | `tests/configs/mesh/*` (+ `tests/mesh_config.py`, `tests/lib/util.sh render_cfg`), mesh generators |
| CMake build + docs | `CMakeLists.txt`, `cmake/*`, `BUILD.md` |

---

## 8. Verified results

- **Deps:** all Python deps satisfied by RPMs; suite collects 9764 tests on 3.9.
- **Module:** HEAD-built dynamic module installed; `nginx -t` loads it;
  `xrdfs root://localhost:11094 stat /` returns a real stat.
- **Stability (the goal):** full fleet up = **187 nginx + 11 xrootd, 0 core dumps,
  1-min load ~0.7** on 4 cores (was load 28+ / 4.1 GB of core dumps before the
  §6a fix). The reduced-thread configs keep the idle fleet at ~0 CPU.
- **Fast lane:** runs in attach mode at `-n 3`; the earlier crash-induced flakes
  (§6a) clear once the module fix is installed.
