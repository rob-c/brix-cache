# Phase 40 — Per-request UNIX impersonation via a privileged I/O broker

> Status: **IMPLEMENTED + tested** (opt-in, off by default). Operator guide:
> [`docs/06-authentication/impersonation.md`](../06-authentication/impersonation.md).
> The rest of this doc is the design/tracking record; the implementation matches
> it with the deltas noted in *Implementation status* below.

## Implementation status (2026-06-15)

| Phase | What | State |
|---|---|---|
| 0 | `idmap.c` — identity → `{uid,gid,gids}` (gridmap + getpwnam + policy + TTL cache) | **done** — `tests/c/idmap_test.c` (10/10) |
| 1 | `broker.c` — privileged root broker: cap-drop to `{SETUID,SETGID}`, impersonate, confined ops (open/stat/mkdir/unlink/rmdir/rename/link/chmod/chown/truncate), `SCM_RIGHTS` fd passing, `SO_PEERCRED` gate | **done** |
| 2 | `client.c` + the seam in `src/path/beneath.c` (stream) + `src/path/resolve_confined_ops.c` (HTTP/S3 legacy confined-open) + per-request principal | **done** |
| 3 | remaining ops + `namespace_ops.c` (routes via the now-broker-aware beneath helpers) | **done**; `fs_walk` dir listing stays worker-side (read-only metadata) — noted limitation |
| 4 | `lifecycle.c` — directives (`xrootd_impersonation` + 7 companions), config-time mode validation, master broker spawn (`init_module`, FRM double-fork), worker connect (`init_process`), request hooks in `xrootd_dispatch` + WebDAV/S3 | **done** — `tests/userns/test_impersonate_config.py` (6 `nginx -t` cases) |
| 5 | hardening (cap-drop fail-closed, `SO_PEERCRED`, reserved-uid floor, bounded frames) + docs + userns tests | **done** — `tests/userns/` (27-assertion E2E) + operator guide |

**Deltas from the original plan:** the broker keeps only `{CAP_SETUID,CAP_SETGID}`
(the plan's draft list also named `CAP_CHOWN`/`CAP_FOWNER`; those are intentionally
dropped — chown-on-create is implicit under `setfsuid`, and keeping `CAP_FOWNER`
would weaken DAC). The userns test uses a **bind-mounted fake `/etc/passwd`**
instead of `nss_wrapper` (zero extra dependency). `single` mode is implemented as a
validated posture (no broker); the actual squash account is set via nginx `user`.

---

> Original plan below (kept for the rationale + security analysis).

## Context

Today this nginx-xrootd gateway does **not** impersonate per-request UNIX users:
every filesystem operation runs as the single worker uid (the nginx `user`
directive), and created files are owned by that worker (only the *group* can be
adjusted, via `xrootd_inherit_parent_group`). Authorization maps grid/token
identities to allow/deny decisions, but on-disk ownership and kernel DAC do not
reflect the real user. Sites that need genuine per-user ownership (quota,
accounting, downstream POSIX tools, multi-tenant DAC) cannot use this gateway as
a drop-in for classic XRootD's grid-mapfile + per-user I/O.

**Goal:** make namespace/metadata/open operations execute with the credentials
(uid / primary gid / supplementary gids) of the local UNIX account the
authenticated identity maps to — so files are owned by, and DAC is enforced for,
the real user — while keeping nginx workers **fully unprivileged**.

**Chosen architecture: a privileged root I/O broker.** Workers hold no
capabilities; a small root broker performs every open/metadata syscall under
`setfsuid`/`setfsgid` and returns the resulting fd via `SCM_RIGHTS`. The data
plane (`pread`/`pwrite`/`sendfile`/AIO) is untouched — it runs on the already-open
fd as the worker (DAC was enforced at open time).

This is **opt-in and off by default** (`xrootd_impersonation off`); it is a large
build and a real security-posture change (master runs as root). The current
single-uid + authz model remains the default and recommended posture for most
sites; this is for deployments that explicitly need on-disk per-user ownership.

### Why the broker design is tractable here (verified against the code)

- **The FS surface is extraordinarily concentrated.** Every confined open/metadata
  syscall funnels through ~8 helpers in `src/path/beneath.c`
  (`xrootd_open_beneath`, `xrootd_stat_beneath`/`xrootd_lstat_beneath`,
  `xrootd_mkdir_beneath`, `xrootd_unlink_beneath`, `xrootd_rename_beneath`,
  `xrootd_link_beneath`) and one core `do_openat2(rootfd, rel, RESOLVE_BENEATH)`
  call (`beneath.c:92`), plus the `xrootd_ns_*` orchestrators
  (`src/compat/namespace_ops.c`) and the dir walk (`src/compat/fs_walk.c`).
  **Swapping the *bodies* of these helpers** routes the whole module through the
  broker with no change to their callers.
- **The data plane needs no impersonation.** `pread`/`pwrite`/`preadv2`/
  `copy_file_range`/`sendfile` (inline in `src/read|write/*`, in the AIO thread
  pool `src/aio/*`, and `src/compat/copy_range.c`) all run on an **already-open
  fd**. Linux checks DAC at `open()`; an open fd is a capability. So only the open
  + namespace + metadata ops must be impersonated.
- **Proven SHM-safe privileged-helper pattern exists.** The FRM stage agent
  (`src/frm/stage.c`: `frm_agent_spawn` double-fork + socketpair + event-driven
  `frm_agent_on_reply` + `frm_agent_respawn`) is the template for spawning a
  long-lived helper that nginx never reaps (avoiding the SHM/SIGCHLD crash).
- **No identity→uid mapping exists today.** `src/acc/groups.c` calls
  `getpwnam(name)` but discards the uid (keeps group *names* for authz only);
  SSS/identity carry user/group *strings*, never numeric ids. A mapping layer is
  net-new (Phase 0).

## Architecture

```
 root master (nginx)                       per-instance ROOT broker (reparented to init)
   │  init_module (still root):             ┌───────────────────────────────────────┐
   │    fork + double-fork the broker  ───▶ │ drops to caps {SETUID,SETGID,CHOWN};   │
   │    (FRM pattern, SHM-safe)              │ opens its OWN rootfd(s) (O_PATH, root);│
   │                                         │ listens on AF_UNIX 0600 socket;        │
   ▼  drops workers to user=svc             │ accepts svc-only conns (SO_PEERCRED).  │
 worker (svc, NO caps)                       │                                        │
   │  init_process: connect() to socket ───▶│ per request:                            │
   │  set "current identity" before each op  │   map principal→{uid,gid,gids} (cache) │
   │  xrootd_open_beneath() body:            │   setgroups(gids);setfsgid;setfsuid;    │
   │    send{OPEN, principal, vo, rel, …} ──▶│   fd = openat2(rootfd, rel, BENEATH);   │
   │    recv fd via SCM_RIGHTS         ◀──── │   restore creds; sendmsg(fd or errno)  │
   │  read/write on fd locally (as svc)      └───────────────────────────────────────┘
```

- **Confinement is defence-in-depth:** the broker re-applies `RESOLVE_BENEATH`
  under *its own* rootfd, so a worker bug cannot escape the export root even
  though the worker supplies the relative path.
- **Authz stays in the worker** (the existing 3-tier gate); the broker only does
  identity→uid mapping + impersonated FS op + confinement. It trusts the worker's
  authenticated principal assertion (the worker is the TLS/GSI/token terminator),
  but enforces the *mapping policy* (deny unmapped, reserved-uid floor) itself.
- **Created files** opened `O_CREAT` under `setfsuid(uid)/setfsgid(gid)` are owned
  by the mapped user:group automatically.

## Operating modes (one directive, three postures)

A single directive `xrootd_impersonation off|single|map` (default **off**) selects
the posture, so a binary built *with* impersonation support can still be run with
**zero** added privilege. This is the security-conscious "drop-back" the design
must guarantee, not an afterthought:

| Mode | Broker? | Root? | Mapping | On-disk owner | Use when |
|---|---|---|---|---|---|
| **`off`** (default) | none | no | none | the nginx `user` (worker uid) | today's behavior; the recommended posture for most sites. The impersonation code is fully inert — no socket, no extra process, no caps. |
| **`single <user>`** (drop-back) | none (or one fixed-uid helper) | no | none — **all** identities squash to one configured limited account | that one fixed account | security-conscious admins who want a defined, uniform local identity but refuse a privileged mapping broker. No `CAP_SETUID`-to-arbitrary-uid, no grid-mapfile, no per-request mapping. Operationally ≈ `off` but makes the squash explicit and ignores any stray mapfile config. |
| **`map`** | yes (root, double-forked) | master root | per-identity grid-mapfile/`getpwnam` | the real mapped user | sites that need genuine per-user ownership/DAC. The full Phase 1–4 build. |

- `off` and `single` add **no** new attack surface and need **no** root: they are
  the first thing implemented and the permanent fallback. The privileged broker
  (`map`) is strictly opt-in.
- The mode is validated at config time: `map` requires a root master + a broker
  socket + (mapfile or `getpwnam`); `single` requires only the target user;
  `off` requires nothing. Wrong combinations fail closed at startup with a clear
  message.

## Implementation phases

Each phase is independently buildable/testable. New code lives in a new
`src/impersonate/` subtree (registered in the repo-root `config`).

### Phase 0 — Identity → (uid, gid, gids) mapping (`src/impersonate/idmap.c`)
- `xrootd_idmap_resolve(principal, vo_csv, group_csv) → {uid, gid, gids[], n, rc}`.
  Resolution order: (1) **grid-mapfile** (`xrootd_gridmap <file>`: `"<DN>" user`)
  → `getpwnam(user)`; (2) **direct** `getpwnam(principal)` for token-sub / SSS-user
  / krb5-localname; (3) **squash/deny** policy. Reuse the `getpwnam`+`getgrouplist`
  pattern already in `src/acc/groups.c:acc_resolve_unix` (verified) — but keep the
  uid/gid this time.
- Per-broker TTL cache (mirror `acc_grp_cache` in `groups.c`).
- **Policy guards:** `xrootd_idmap_min_uid <N>` (refuse uid < N), never map to 0 /
  system accounts, optional `xrootd_idmap_default_user <name>` (squash) vs **deny**
  (default). Pure unit-testable.

### Phase 1 — The broker process (`src/impersonate/broker.c`)
- Spawn at **`init_module`** (master, still root) using the FRM double-fork
  (`frm_agent_spawn` as the template) so nginx never reaps it; broker `setsid()`s
  and reparents to init. Master supervises liveness + respawn via a master-side
  `ngx_event` timer (or document systemd socket-activation as the supported alt).
- Broker drops to a **minimal capability set** `{CAP_SETUID, CAP_SETGID,
  CAP_CHOWN, CAP_FOWNER}` via the bounding set; **no `CAP_DAC_*`** (the whole
  point is that the user's own DAC applies). Optional `seccomp` syscall allow-list.
- Opens its own export `rootfd`(s) `O_PATH|O_DIRECTORY` (as root) — same as
  `process.c:159`.
- Listens on `xrootd_impersonation_socket` (AF_UNIX, mode 0600, owned by svc);
  accept only the svc uid (`SO_PEERCRED`).
- Per request: `xrootd_idmap_resolve` → `setgroups(gids)` (raw syscall) →
  `setfsgid(gid)` → `setfsuid(uid)` → `openat2(rootfd, rel, RESOLVE_BENEATH)` (or
  `mkdirat`/`unlinkat`/`renameat`/`fchmodat`/`fchownat`/`fstatat` for non-open
  ops) → **restore creds** → reply. Start single-threaded (poll loop); bound
  request size/relpath length.

### Phase 2 — Worker client + helper swap (`src/impersonate/client.c`, `src/path/beneath.c`)
- Worker connects at `init_process` (`src/config/process.c` + `src/config/http_rootfd.c`),
  keeps the fd for its lifetime, registered as an nginx event with reconnect-on-EOF
  (mirror `frm_agent_on_reply` / `frm_agent_respawn`).
- **Per-request "current identity":** the recv/dispatch loop sets a per-connection
  current principal pointer (from `ctx->identity`) *before* dispatching each op, so
  the confined helpers can read it **without** changing their signatures.
- **Swap the helper bodies** in `src/path/beneath.c`: when `xrootd_impersonation`
  is on, `xrootd_open_beneath` etc. send the op to the broker and return the
  fd/status instead of calling `do_openat2` locally; when off, the existing local
  path runs unchanged. Same for the legacy `resolve_confined_ops.c` fallback
  (or disable it under impersonation — note the old-kernel/no-openat2 caveat).
- Wire framing: reuse FRM's fixed-frame style; fd passed via `sendmsg`+`SCM_RIGHTS`.
  Synchronous round-trip from the worker's view (these helpers were already
  blocking syscalls); add a timeout and fail-closed on broker error.

### Phase 3 — Remaining ops + directory walk
- Broker ops for `STAT`/`LSTAT`/`MKDIR`/`UNLINK`/`RENAME`/`LINK`/`CHMOD`/`CHOWN`/
  `TRUNCATE`/`STATVFS`/`XATTR` and a `READDIR` (the broker `opendir`s under
  impersonation and returns entries+stat in one reply, covering
  `src/compat/fs_walk.c`'s `opendir`/`readdir`/`lstat` traversal).
- Route the `xrootd_ns_*` orchestrators (`namespace_ops.c`) and `fs_walk.c`
  through these. `fstat` on an already-open fd stays local (worker holds the fd).
- `xrootd_inherit_parent_group` (`src/path/group_policy.c`) becomes redundant for
  *ownership* (the broker now sets uid:gid on create) but can coexist for group
  policy; document the interaction.

### Phase 4 — WebDAV / S3
- Same broker; HTTP handlers reach the broker via the HTTP `rootfd`
  (`src/config/http_rootfd.c`) and the WebDAV/S3 identity (`mctx->identity`).
  Mostly free because they already call the same `*_beneath` helpers.

### Phase 5 — Hardening, config, docs, tests
- Directives (new): `xrootd_impersonation off|single|map` (default `off`),
  `xrootd_impersonation_user <name>` (for `single`),
  `xrootd_impersonation_socket <path>` (for `map`), `xrootd_gridmap <file>`,
  `xrootd_idmap_default_user <name>` (squash else deny), `xrootd_idmap_min_uid <N>`,
  `xrootd_idmap_cache_ttl <secs>`. Register in `src/stream/module.c` +
  `src/webdav/module.c`; fields in `src/types/config.h`; config-time mode
  validation (fail closed on invalid combinations).
- Capability/seccomp minimization on the broker; `SO_PEERCRED` gate; reserved-uid
  floor; bounded relpaths; audit logging of every mapping decision.
- Update `docs/06-authentication/identity-mapping.md` (the §0 "no impersonation"
  caveat becomes "optional, via the broker"); new `docs/06-authentication/impersonation.md`.

## Critical files
- **New:** `src/impersonate/idmap.c` (Phase 0), `broker.c` (Phase 1),
  `client.c` (Phase 2), `impersonate.h`, plus `src/impersonate/README.md`;
  register all in the repo-root `config` (`./configure` once).
- **Swap helper bodies (no caller changes):** `src/path/beneath.c` (the ~8
  helpers + `do_openat2`), `src/path/resolve_confined_ops.c` (legacy fallback).
- **Orchestrators routed through broker ops:** `src/compat/namespace_ops.c`,
  `src/compat/fs_walk.c`.
- **Lifecycle hooks:** `src/config/process.c` (`ngx_stream_xrootd_init_process`)
  + `src/config/http_rootfd.c` (worker connect); a new `init_module` master hook
  (broker spawn) wired in `src/config/postconfiguration.c` / the module struct.
- **Reuse patterns:** `src/frm/stage.c` (double-fork + socketpair + event reply +
  respawn), `src/acc/groups.c` (`getpwnam`/`getgrouplist`/cache), the SHM-safe
  zone contract (`src/compat/shm_slots.c`).
- **Config/directives:** `src/types/config.h`, `src/stream/module.c`,
  `src/webdav/module.c`, `src/config/server_conf.c` (init/merge).

## Verification

**Primary harness — unprivileged user namespaces (no real root, CI-friendly,
high coverage).** Ownership/DAC tests must create files owned by *other* uids and
assert kernel DAC for those uids, which normally needs root. Instead run the
whole stack inside an unprivileged user namespace (`unshare -Ur` /
`CLONE_NEWUSER` + `/proc/self/{uid,gid}_map`), which this host supports without
sudo. A new `tests/userns_impersonate_lib.py` (+ a small `unshare` launcher)
provides:
- A userns with a uid/gid map (map several outside subordinate uids → distinct
  in-ns uids; the test acts as in-ns root so the broker may `setfsuid` to any
  mapped uid — genuine impersonation, zero real privilege).
- **`nss_wrapper`** (`LD_PRELOAD` + `NSS_WRAPPER_PASSWD`/`_GROUP`) to supply fake
  passwd/group entries so `getpwnam`/`getgrouplist` resolve the test identities
  to in-ns uids/gids **without touching `/etc`**.
- A (mount-ns) private export tree so created files and their owners are
  inspectable inside the namespace.
- Tests gracefully **skip** (not fail) when userns/`nss_wrapper` are unavailable.

Coverage matrix:
- **idmap unit tests:** mapfile parse, `getpwnam` resolve, squash vs deny,
  `min_uid` floor, reserved-uid (0/system) rejection.
- **Mode `off`/`single`:** assert no broker process/socket exists, no caps held,
  and (single) every created file is owned by the one configured account.
- **Ownership E2E (`map`):** map identity → local test user; `xrdcp`/PUT a new
  file; `stat` it and assert `st_uid`/`st_gid` == the mapped user:group (not the
  worker uid). Read back: contents correct.
- **DAC enforcement E2E:** a mapped user *without* permission on a path is denied
  at open (`EACCES`) even though the worker authdb *granted* it; the same user
  *with* permission succeeds.
- **Confinement still holds:** a `..`/symlink escape still returns EXDEV/denied.
- **Concurrency:** two identities interleaved → each file owned by the correct
  uid:gid (no cross-request credential leak).
- **Resilience:** kill the broker → workers fail closed + log, master respawns.
- **Off-path regression:** `xrootd_impersonation off` → byte-identical to today;
  full existing suite (root/WebDAV/S3) green.
- **Perf:** benchmark a stat/dirlist storm and an open-heavy read workload to
  quantify the per-op broker round-trip cost.

## Security model & risks (explicit)
- **Master runs as root** (needed to spawn a privileged broker) — larger surface;
  keep the module's master-side code minimal.
- **Broker holds `CAP_SETUID`/`CAP_SETGID`** ⇒ a broker compromise is
  root-equivalent. Mitigate: tiny audited broker, no network (AF_UNIX only),
  `SO_PEERCRED` gate, seccomp allow-list, drop all other caps, validate every
  request, bounded inputs.
- **Worker compromise** is contained: a worker can only ask the broker to act
  within the export root as a **mapped, non-reserved** user — it cannot escape the
  root (broker confinement) nor become an unmapped/system uid (mapping policy +
  `min_uid` floor). This is the core least-privilege win.
- **Never impersonate uid 0 or system accounts.** Hard floor.
- **Perf:** one IPC round-trip per open/stat/mkdir/rename/unlink; the data plane is
  unaffected. Measure for metadata-heavy workloads.
- **Old kernels without `openat2`:** the broker relies on `RESOLVE_BENEATH`;
  document the minimum kernel, keep impersonation off where unavailable.
- Ship **off by default**, with the single-uid model remaining the default posture.
