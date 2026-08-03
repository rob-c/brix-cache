# CMS Auto-Role, Sub-Manager Supervision, and the Worker-0 Connection Gate

**Status:** Design/decision record for contributors and operators. Describes how
a brix nginx node now auto-derives its CMS cluster role (manager / sub-manager /
client), how it can act as a **sub-manager (supervisor) of a stock upstream
cmsd**, why the outbound CMS client is gated to worker 0, and how the control
plane logs prove all of the above.

Landed 2026-07-23 (validated live on `xrd1`). Supersedes the earlier
"`brix_cms_manager` must NOT point at the official cmsd" gotcha recorded in the
xrd1 cache/origin demo notes — that per-worker SID collision is now fixed
in-code.

---

## Context — the per-worker SID collision

A CMS node identity (SID) is `host:listen_port`. Every nginx worker shares the
same config, so before this change every worker opened its **own** outbound CMS
client using that **identical** SID. A stock upstream cmsd admits exactly one
connection per node identity: workers 2..N were rejected as "already logged in"
and 30-second blacklisted. In practice only `worker_processes 1` ever registered
cleanly against a stock cmsd, which made brix unusable as anything but a
single-worker leaf under the official manager.

---

## What changed — the decision

### 1. A single per-block bring-up entry point, worker-0-gated

`brix_cms_role_worker_init()` in `src/net/cms/connect.c` (declared in
`src/core/ngx_brix_module.h`) is now the one place a stream server block brings
up its CMS role. It is called for **every** stream server block from
`src/core/config/process.c` (around line 246), *before* the `common.enable`
data-path gate — so a dedicated cms-only manager/sub-manager block whose data
path is disabled still owns a role and, if it has an upstream, still starts a
client. The old ungated `ngx_brix_cms_start` call site in
`src/core/config/process_server_init.c` was removed (that file now carries only
comments pointing back to the new per-block, worker-0-gated bring-up).

The function does two things:

1. **Proof in logs** — emits exactly one NOTICE naming the derived role and how
   it was derived. Worker 0 only, since N identical lines help no one.
2. **Single upstream connection** — starts the outbound CMS client
   (`ngx_brix_cms_start`) on `ngx_worker == 0` **only**, so there is one
   connection per node identity. This removes the self-collision entirely and
   lets brix register cleanly with a stock upstream cmsd.

**Tradeoff (documented in-code):** single-connection mode disables the §7.1
pending-locate per-worker bridge (which needs the client on the worker holding
the suspended session). Aggregation — which is what a sub-manager actually needs
— works fine over the one link.

### 2. Auto role derivation

Role is derived from `(manager_capable, has_upstream)` via
`brix_cms_noderole_derive()`, where `manager_capable = (manager_mode == 1)` and
`has_upstream = (cms.addr != NULL)`:

| Directives on the block                     | Derived role     |
| ------------------------------------------- | ---------------- |
| `brix_cms_server on`, no upstream           | **manager**      |
| `brix_cms_server on` + `brix_cms_manager …` | **sub-manager**  |
| `brix_cms_manager …` only                   | **client** (leaf)|

`brix_cms_server on` auto-sets the block's `manager_mode` as a side effect: the
flag setter `brix_cms_srv_set_enable()` in `src/net/cms/server_module.c`
cross-sets `manager_mode = 1` on the same server block (only when it is still
`NGX_CONF_UNSET`, so an explicit `brix_manager_mode off` still wins). A
sub-manager logs in to its upstream with the Manager bit set and aggregates
space upward; a client registers up as a leaf.

### 3. `brix_listen_port` is the SID — and is NOT auto-derived

The CMS SID uses `brix_listen_port`, which defaults to `BRIX_DEFAULT_PORT`
(1094, defined in `src/protocols/root/protocol/opcodes.h`) and is **not**
derived from the block's `listen` directive. Every block that must have a
distinct node identity **must** set `brix_listen_port` explicitly, or their SIDs
collide.

---

## Logging — the two operator deliverables

Both are grep-able from the error log:

- **Role proof** — `grep "cmsd role:"` →
  `brix: cmsd role: this node is a {manager|sub-manager|client} (listen :PORT, upstream_manager=…, accepts_downstream=…, aggregates_up=…)`.
  Emitted once per node from `brix_cms_role_worker_init()` in
  `src/net/cms/connect.c`.

- **Action log** — `grep "cmsd-action"` → NOTICE lines from the header-only
  helper `brix_cms_log_action()` in `src/net/cms/action_log.h`:
  `brix: cmsd-action op=<login|register|load|space|status|redirect|state-probe|path-gone|have|disconnect|forward-op> peer=host:port dir=<out|in> path=… result=<ok|FAIL> detail=…`.
  `dir=out` = we initiated it (up to our manager); `dir=in` = a peer/manager
  requested it of us. Wired into `connect.c` and `recv_frame.c` (client side)
  and `server_recv_frame.c` / `server_recv_frame_handlers.c` (manager side).

---

## Why

- Gating the outbound client to worker 0 is the minimal change that makes brix's
  node identity match what a stock cmsd expects (one login per SID), turning a
  fatal self-collision into clean registration with **no protocol change**.
- Auto-deriving the role from the directives already present means operators
  don't hand-declare "manager vs sub-manager vs client"; adding
  `brix_cms_server on` to a block that also has an upstream is, by itself,
  enough to make it a supervisor.
- The two log families give the operator machine-checkable proof of both the
  role each node picked and every control-plane action, which is what the
  topology test asserts against.

---

## Deploying — configs and multi-instance recipe

### 3-tier demo (single instance, `worker_processes auto`)

Data blocks (e.g. ports 1094 and 1095) each set `brix_listen_port <port>` +
`brix_cms_manager xrd1:1213` → role **client**, register into the brix
sub-manager. The 1213 block sets `brix_cms_server on` + `brix_listen_port 1213`
+ `brix_cms_manager xrd1:11213` → role **sub-manager**, registers UP to the
official cmsd. Remember: `brix_listen_port` per block or the SIDs collide.

**Build/deploy:** this change added only headers, so no `./config` regen was
required — `bash build/build-nginx-modules.sh` rebuilds. The module load path is
`/usr/lib64/nginx/modules/` (per `/usr/share/nginx/modules/mod-xrootd.conf`),
**not** `/usr/share/nginx/modules/`.

### Multiple brix masters on one host (deeper cmsd trees)

A 4-tier tree was stood up on xrd1:
`inst3:3094 (client/data) → inst2:2213 (sub-mgr) → inst1:1213 (sub-mgr) → official:11213 (mgr)`.
Each extra instance is its own systemd unit
(`/etc/systemd/system/nginx-inst{2,3}.service`, mirroring stock `nginx.service`:
`Type=forking`, own `PIDFile`, `ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx{N}.conf`,
and an `ExecStartPre` of `nginx -t -c <thatconf>`). Gotchas:

- **`load_module ngx_stream_module.so` MUST come before the brix module.** Base
  stream is built dynamic (`--with-stream=dynamic`); otherwise the brix `.so`
  fails dlopen with `undefined symbol: ngx_stream_core_module`. An extra
  instance has its own config and cannot rely on instance 1's
  `include /usr/share/nginx/modules/*.conf`.
- Own `pid /run/nginx-instN.pid`, own `error_log /var/log/nginx/instN-error.log`,
  distinct listen ports.
- **SELinux (Enforcing):** `semanage port -a -t brix_port_t -p tcp <newport>`
  for every new listen port, or `httpd_t` can't bind it. Data dirs under
  `/data/brix/…` must be `nginx:nginx` with type `httpd_sys_rw_content_t`
  (mirror the existing cache/export). Launch via **systemd** (so it runs as
  `httpd_t`), not a manual `nginx` from an unconfined shell.
- Instances share only the module `.so` and talk over the CMS wire protocol;
  SHM/registry is per-master (independent). Each still worker-0-gates its single
  upstream connection.
- Restart a specific instance via its own systemd unit, **not**
  `nginx -s reload` of instance 1 — reload only re-execs the instance whose
  `-c` config you pass.

---

## Verification

### Proven end-to-end (live, xrd1)

The official cmsd log (`/var/log/xrootd/brix-mgr/cmsd.log`) showed
`Primary supervisor.<pid>:23@xrd1…:1213 logged in`, `system ID: xrd1…:1213`, and
a Route — i.e. the Manager-bit login was admitted as a supervisor
(= sub-manager). The brix sub-manager admitted 1094 + 1095 as clients
(`CMS server: registered …`). With `worker_processes auto` (5 workers) there
were no collisions, drops, or retries; all CMS connections were owned by the
single worker-0 PID.

**Known cosmetic issue (not a regression):** the inbound `op=load` action shows
`free_mb=0` — the `kYR_load` free-space field parses 0 for these nodes
(pre-existing). The `register` / `space` / avail path reports the real value.

### Topology test — `tests/test_cms_tier_topology.py`

Self-contained pytest (7 tests, ~1.5s) that stands up the whole 4-tier shape as
**one** cert-free brix nginx master: six stream server blocks on 127.0.0.1
(managers/sub-managers via `brix_cms_server on`; leaves via `return "";` +
`brix_cms_manager`), each a unique SID via `brix_listen_port`. After settle it
asserts purely from the error log: the role-proof lines, the
`op=register dir=in` edges (peer = child, `server:` = parent — pins each edge),
the `op=login dir=out` details (sub-manager vs leaf/client), and the worker
gate.

Gotchas baked into the test:

1. It **launch-probes** each candidate nginx for a `cmsd role:` line and picks a
   feature-capable binary. A stale static `settings.NGINX_BIN`/`objs` merely
   *parses* the directives (so a `-t`-only probe passes) but predates auto-role;
   the fresh feature lives only in the `/usr/lib64/nginx/modules/` dynamic `.so`.
2. The worker-0 gate covers only the **outbound** client — assert single-PID on
   `dir=out` login/load lines (one login per node from one worker). **Inbound**
   `dir=in` registrations land on whichever worker `accept()`ed them, so do NOT
   assert single-PID across all cms-action lines.
3. `op=login` names the **parent** dialed, not the child, so children sharing a
   parent collapse in the login lines. Verify per-child edges via the `register`
   lines; verify each parent's role-detail set via the `login` lines.
4. Repo `pytest.ini` sets a 30s per-test timeout, but fixture launch + settle is
   charged to the first test, so the module sets
   `pytestmark = pytest.mark.timeout(120)`.

Run:

```
PYTHONPATH=tests pytest tests/test_cms_tier_topology.py -v
```
