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

> **Running as root is no longer required** (§6c is superseded). The above is the
> convenient path on this box; the *faithful* one is `tests/run_suite_unprivileged.sh`
> (§5a), which runs pytest and the whole fleet as one unprivileged user. Root
> workers (via the `user root;` injection, §4b) bypass every permission check, so
> the ownership/permission suites — `test_conf_xrdcl_fs` chmod parity in
> particular — cannot pass as root no matter how the modes are set. Use §5a to
> validate anything permission- or identity-shaped.

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

> **What `user root;` costs you.** It is a workaround, not a neutral setting. It
> keeps workers as root so they can write the root-owned test dirs — but root
> **bypasses every permission check**, so the suite stops testing the authorization
> semantics it exists to verify, and `chmod(2)` parity vs stock diverges *by
> construction*: the reference xrootd REFUSES to run as root (§6b), so our side is
> root while stock stays `nobody`. It also masks failures rather than surfacing
> them — the checkpoint-recovery crash (§6g) is invisible under it.
> The injection is gated on `id -u = 0`, so running the wrapper unprivileged is a
> plain module-loading shim with no injection — which is exactly what §5a relies on.

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

### 5a. Unprivileged mode — TEST USER == SERVER USER

`tests/run_suite_unprivileged.sh` runs pytest, the nginx master+workers **and** the
reference xrootd as one unprivileged user. That single property is what makes
ownership and permission behaviour REAL instead of root-bypassed.

It is also the configuration the suite was last taken green in: aa92dc13's
burndown reached 6977 passing on a **non-root** box (its own message says so, and
its fixes are all non-root harness bugs), while noting the remote CI box runs as
root. That split is why root-only failure modes — §6g.4 and §6g.5 especially —
survived into a "green" tree: nobody had run the two postures against each other.

```bash
tests/run_suite_unprivileged.sh --fast                     # as root: sync, chown, drop
BRIX_TEST_USER=nobody tests/run_suite_unprivileged.sh --fast
BRIX_TEST_TREE=/srv/brix-test tests/run_suite_unprivileged.sh --fast
```

Two modes, auto-detected:

| invoked as | what happens |
|---|---|
| **unprivileged** | Runs in place. No sudo, no root, nothing to grant — a developer who *cannot* sudo runs exactly what root runs. |
| **root** | Clears any root-owned fleet off the fixed ports, syncs this checkout to `$BRIX_TEST_TREE` (default `/srv/brix-test`), chowns it + a per-user `TEST_ROOT` to `$BRIX_TEST_USER` (default `brixtest`), and re-execs there as that user. |

**Why a copy, not an ACL.** The checkout lives under `/root` (0750) — the original
reason §6c claimed root was necessary. Granting traversal would open a path into
root's home for a real account, and `nobody` in particular is *shared by other
daemons*, so an ACL for it would widen far beyond this suite. The sync leaves
`/root`'s 0750 untouched; `--delete` keeps the copy exact. The trade-off is honest:
you validate a copy, so the sync runs every time.

**Why a dedicated `brixtest` rather than `nobody`.** Nothing else on the box runs
as it, and it has a real home. `BRIX_TEST_USER=nobody` still works — with the
neutral copy there is no `/root` exposure either way — but `nobody`'s passwd home
is `/` and it is shared, so it is not the default. Create it once:

```bash
sudo useradd -r -m -d /var/lib/brixtest -s /bin/bash brixtest
```

Also handled, because a normal user cannot: root clears the foreign fleet first (an
unprivileged `start-all` **cannot** reap another uid's nginx → unfixable "Address
already in use"); `HOME` is redirected (nobody's home is `/`); and pytest's cache
(`--lf` needs it) plus `.pyc` are kept out of the read-only tree via
`PYTEST_ADDOPTS` + `PYTHONDONTWRITEBYTECODE`.

**What only this mode can validate:** anything keyed on identity or ownership.
`chmod(2)` requires *ownership*, not a permission bit — so no amount of opening
modes makes `test_conf_xrdcl_fs`'s chmod/stat parity pass under a root master with
`nobody` workers. Those 27 failures go to **zero** here.

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

### 6c. Running the whole fleet as root — ~~necessary~~ **SUPERSEDED, see §5a**
This section used to read "necessary here", for two stated reasons. Both are now
solved, and root is a convenience, not a requirement:

| the blocker | resolution |
|---|---|
| the repo is under `/root` (0750), so a non-root user can't reach it | `run_suite_unprivileged.sh` syncs the checkout to a neutral tree the user owns (§5a). `/root` keeps its 0750 — no ACL, no `o+x`. |
| unprivileged nginx workers can't write the root-owned test dirs | `_open_export_for_worker` (`tests/lib/nginx.sh`) opens the fleet's own exports under a root harness — the treatment `_ref_launch` already gave the reference xrootd's export. Unprivileged, the worker simply owns them. |

Consequences root still drags in, and why you should prefer §5a:

* the `user root;` wrapper injection (§4b) — root bypasses every permission check,
  so permission/identity suites are not really being tested;
* it **cannot** be applied to the reference xrootd, which refuses to run as root
  (§6b) — so our side is root, stock is `nobody`, and parity tests diverge by
  construction;
* it is why the debug-timer crash (6a) was fatal rather than a clean failure;
* it hides real defects: worker init runs as root and succeeds, while the
  *deployed* posture (root master → unprivileged workers) fails — exactly the
  checkpoint-recovery crash in §6g.

Root mode remains useful (it is faster to set up, and §5a's root path uses it to
clear the fixed ports). Just do not mistake it for validation.

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

> **XrdHttp is the exception — do NOT cap it at 4.** `tests/configs/xrootd_xrdhttp.conf`
> runs `mint 8 maxt 64 avlt 16` deliberately. XrdHttp does not serve HTTP itself:
> it **bridges** every request into the xroot layer (`XrootdBridge: … login as
> nobody`), so one in-flight HTTP GET occupies a scheduler thread *on top of* the
> fixed infrastructure threads above. At `maxt 4` the pool is exhausted before the
> bridged request ever gets a thread — TLS completes, the GET is read, and **the
> response never comes**; the client hangs to its timeout and the log shows only
> `login as nobody` / `disc`. It looks like a TLS or filesystem fault and is
> neither: `root://` on the same instance keeps working throughout, which is what
> isolates it to the bridge. A/B on identical PKI: `maxt 4` → hang, `maxt 64` →
> HTTP 200 in ~37 ms. The idle cost is negligible (the pool grows on demand), so
> the §7 thread-cap work applies to the plain-xroot reference daemons only.

### 6g. The stacked start-all blockers (root harness, post-aa92dc13)

Five defects, each **masking** the next: fixing one only revealed the following
one, and until all five were fixed the fast suite could not run *at all* — zero
tests executed. Recorded in the order they surface, because that is the order you
will hit them if any regress.

1. **`start-all` truncated the fleet, silently.** `start_krb5_tier` called
   `python3 kdc_helpers.py up` bare. `manage_test_servers.sh` runs under
   `set -euo pipefail`, so when the helper exits 3 (KDC tooling absent — this box
   has no `krb5-server`) the shell died *there*: `local rc=$?` never ran, and every
   server defined after that tier (clusters, cache, wt-sync/async, prepare) never
   started. That was the `rc=3` conftest rejected, and the cause of the
   port-9002 "Address already in use" cascade — attempt 1 left a half-built fleet
   holding fixed ports and the retry could not rebind them. Fix: `|| rc=$?`.
   **Identical footgun to `_ref_runas_user`** (fixed in aa92dc13): under `set -e`,
   *any* bare call whose non-zero status you mean to inspect kills start-all.
2. **`start_xrdhttp` hung start-all forever** (it is the last call in
   `start_all_dedicated`). `all.role server` put xrootd in clustered mode, but
   there is no `all.manager`/cmsd anywhere, so `cms_Finder` blocked on the olbd
   admin socket; `xrootd -b` never signalled ready and its parent hung on the
   daemonize pipe. Fix: drop the directive (the working reference daemons carry
   none). `all.role standalone` is **not** valid and breaks the fs layer.
3. **XrdHttp init wedged on the CA private key.** `http.cadir` pointed at the PKI
   `ca/` dir, which holds `ca.key` (0400 root, by design). XrdHttpTPC's TempCA
   `open()`s *every* file there as a certificate → `CAs / CRL generation for
   libcurl failed` → init never signals ready. Fix: `_xrdhttp_public_cadir` hands
   it a public-only view. Do **not** relax `ca.key`; GSI is unaffected (its
   `-certdir` does hash lookups, not a directory scan).
4. **Every write answered 403.** 89 of 102 `data-<name>` exports were 0755 root,
   unwritable by the `nobody` worker. Fix: `_open_export_for_worker` (§6c).
   Measured: 3751 → **6781** passing.
5. **Workers died at startup, leaving a listener with nothing behind it.**
   `brix_chkpoint_recover_root` drops a lock at the export root during worker init;
   on EACCES it returned `NGX_ERROR` → worker "fatal code 2 and cannot be
   respawned" — while the **master kept the port bound**. So the port accepts TCP
   and every request hangs: it reads as a server bug, not a failed start. Fixed in
   `src/` to skip recovery with a warning on EACCES/EPERM/EROFS (a root that
   refuses our writes cannot hold a journal it never wrote); other errnos still
   fail loudly. Tests: `tests/test_chkpoint_recover_export.py`.
   Note the config-time guard does **not** cover this: `helpers.c` validates the
   export with `access(path, W_OK)` evaluated as the **master**, so under a root
   master it passes and only the worker fails — false assurance in exactly nginx's
   default posture, and why this is invisible under §4b's `user root;`.

> **Diagnosis note.** A port that accepts TCP proves nothing here — the master
> binds before forking. `xrdfs … stat /` hanging (not refusing) is the tell; then
> `grep 'exited with fatal code' /tmp/xrd-test/logs/error.log`.

### 6h. Ceph tool link failure after a file split
`make -C client` (and the RPM, which drives it) died with `undefined reference to
sd_ceph_staged_abort / sd_ceph_enumerate / sd_ceph_open_cred / sd_ceph_conn_ioctx`.
The phase-79 file-size work split `sd_ceph.c` → `+sd_ceph_io.c +sd_ceph_cred.c
+sd_ceph_object.c` and `sd_cephfs_ro.c` → `+_dir.c +_resolve.c`. The ceph tools
link **no library** for the backend — they compile the driver TUs straight in — so
their source list is a *symbol closure*, and three recipes each kept a stale copy
of the old two-file list.

It fails only at **link** time, and only where librados headers are installed, so a
box without them never notices. Now named once as `CEPH_CORE_SRCS` /
`CEPHFS_RO_SRCS` in `client/Makefile` (the source of truth; the RPM and
`tests/ceph/run_rescue_tools.sh` follow it) — a future split is a one-line change
there. `sd_ceph_striper.c` is deliberately excluded: unreferenced, and it would add
a libradosstriper dependency.

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
| **checkpoint recovery vs unwritable export** (§6g.5) | `src/protocols/root/write/chkpoint_recover.c`, `chkpoint.h` + `tests/test_chkpoint_recover_export.py` |
| krb5 tier `set -e` fleet truncation (§6g.1) | `tests/lib/dedicated.sh` |
| XrdHttp `all.role`/cms hang + thread pool (§6g.2, §6f) | `tests/configs/xrootd_xrdhttp.conf` |
| XrdHttp public-only CA view (§6g.3) | `tests/lib/xrdhttp.sh` |
| worker-writable fleet exports (§6g.4, §6c) | `tests/lib/nginx.sh` |
| unprivileged runner (§5a) | `tests/run_suite_unprivileged.sh` |
| ceph tool source closure (§6h) | `client/Makefile`, `tests/ceph/run_rescue_tools.sh` |

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
- **`start-all`:** returns **0** on a root harness (97 nginx, 0 fatal worker
  exits) once §6g.1–5 are in. Takes ~10–15 min — it no longer aborts early at the
  krb5 tier, which used to make it look fast.
- **XrdHttp (§6f, §6g.2–3):** `XrdHttp started and ready on port 11113 (HTTP) /
  11112 (root://)`; HTTPS GET returns 200. This tier had **never** started on this
  box before (start-all always died at §6g.1 first), so both its bugs were latent,
  not regressions — and the https/httpg conformance suites could not run at all.
- **Unprivileged (§5a):** the fleet comes up owned by `brixtest`; the
  `test_conf_xrdcl_fs` chmod-parity cluster goes **27 → 0**, which is the point of
  the mode. Residual failures/errors in this lane are not yet triaged — several are
  tests hardcoding root-writable paths (e.g. `/var/log/nginx/error.log`), i.e. gaps
  in unprivileged support rather than module defects.
- **Ceph tools (§6h):** full `cmake --build build` green (was rc=2); "ceph:
  verified 3 binaries present" — the same assertion the RPM makes at build time, so
  packaging was broken and is now unblocked.
