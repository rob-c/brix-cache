# `src/impersonate/` — per-request UNIX impersonation (phase 40)

Optional, **off by default**. Lets the gateway run namespace/open operations as
the local UNIX account the authenticated identity maps to (so files are owned by,
and kernel DAC is enforced for, the real user) instead of the single nginx worker
uid. Plan: [`docs/refactor/phase-40-unix-impersonation.md`](../../docs/refactor/phase-40-unix-impersonation.md).
Operator guide: [`docs/06-authentication/impersonation.md`](../../docs/06-authentication/impersonation.md).

## Operating modes (`xrootd_impersonation off|single|map`)

| Mode | Broker | Root | Mapping |
|---|---|---|---|
| `off` (default) | none | no | none — single worker uid (today's behavior) |
| `single <user>` | none | no | all identities squash to one fixed account |
| `map` | root, double-forked | master root | per-identity grid-mapfile / `getpwnam` |

`off` and `single` add no privilege and need no root; `map` is strictly opt-in.

## Architecture

Workers stay **unprivileged**. In `map` mode a small **root broker**
(double-forked à la `src/frm/stage.c`, SHM-safe) performs each open/metadata
syscall under `setfsuid`/`setfsgid`/`setgroups` and returns the resulting fd to
the worker via `SCM_RIGHTS`. The data plane (`pread`/`pwrite`/`sendfile`/AIO)
runs on the already-open fd as the worker — DAC was enforced at open time, so it
needs no impersonation. The broker re-applies `openat2(RESOLVE_BENEATH)` under
its own export rootfd, so a worker bug cannot escape the export root.

```
 root master (init_module)              root broker (double-forked → init)
   spawn + create 0600 socket  ───────▶  drop caps to {SETUID,SETGID};
   open export rootfd (O_PATH)           open its own rootfd; poll() loop:
                                           recv req → idmap(principal)→{uid,gid,gids}
 worker (svc, no caps)                     → setgroups/setfsgid/setfsuid
   init_process: connect() ──────────▶    → openat2(rootfd, rel, RESOLVE_BENEATH)
   per request: set principal             → restore creds → reply (+ fd via SCM_RIGHTS)
   beneath/confined-open → send op ◀────
   read/write on returned fd (as svc)
```

## Files

| File | Role |
|---|---|
| `impersonate.h` | public types + API (modes, `xrootd_idmap_*`, broker + client) |
| `impersonate_proto.h` | fixed-size worker↔broker wire frames (`imp_req_t`/`imp_rep_t`) |
| `idmap.c` | identity → `{uid, gid, gids}` (grid-mapfile + `getpwnam` + policy + TTL cache) |
| `broker.c` | the privileged root broker: the request loop `imp_serve_one`, fd passing, and the `SO_PEERCRED` trust gate `imp_peer_allowed` (owns the `imp_base_*`/`imp_self_uid`/`allow_uid` state). *(Phase 38: split.)* |
| `broker_creds.c` | the privilege transitions: cap-drop, drop-to-service-user, setuid/setgid capset, impersonate/restore. *(Phase 38 split of `broker.c`.)* |
| `broker_ops.c` | the confined FS op dispatcher `imp_do_op` (openat2/open-parent/stat/rename/xattr under `RESOLVE_BENEATH`). *(Phase 38 split of `broker.c`.)* |
| `broker_internal.h` | Private split contract shared by `broker*.c` (the `extern` broker-state decls + prototypes). |
| `client.c` | worker-side broker client: per-request principal, op round-trips, reconnect |
| `lifecycle.c` | nginx glue: directives, mode validation, master spawn, worker connect, request hooks |

## How a request routes through it

1. After auth, the dispatcher calls `xrootd_imp_request_begin(identity)` (no-op
   unless `map`), which sets the worker's current principal.
2. The confined-FS helpers — `xrootd_*_beneath()` (`src/path/beneath.c`) and the
   legacy `xrootd_open_confined_canon()` (`src/path/resolve_confined_ops.c`, the
   HTTP/S3 path) — check `xrootd_imp_client_active()` and, when active, send the
   op to the broker instead of running the syscall locally.
3. `xrootd_imp_request_end()` clears the principal so it never leaks across the
   event loop.

## Safety invariants

- **Reserved-id floor — uid/gid < 1000 is impossible** (three independent layers,
  one authoritative test `xrootd_imp_creds_privileged()` at floor
  `XROOTD_IMP_HARD_MIN_ID`=1000): (1) the mapper **denies** any reserved primary
  uid / primary gid / supplementary gid (and clamps `xrootd_idmap_min_uid` up to
  ≥1000); (2) `imp_become()` refuses — performs **no** setfsuid — and the broker
  `_exit()`s if a reserved cred ever reaches the syscall edge; (3) `imp_do_op()`
  re-reads fsuid/fsgid and returns `EPERM` before the actual file syscall. The
  broker's `imp_become()` is the ONLY credential-change site in the codebase.
- Never resolve to **uid 0** or below `xrootd_idmap_min_uid` (default 1000).
- **Forbidden targets**: the nginx worker uid and the broker's own uid are ALWAYS
  refused as impersonation targets (config-independent — both in the mapper and in
  `imp_become`), plus name deny-lists for service accounts
  (`xrootd_idmap_forbidden_users`) and privileged groups
  (`xrootd_idmap_forbidden_groups`: sudo/wheel/docker/… — denied even at gid ≥ floor,
  across primary AND supplementary membership).
- **Minimise root**: with `xrootd_impersonation_broker_user`, the broker drops to a
  non-root service account keeping only `CAP_SETUID`/`CAP_SETGID` (nothing runs as
  root after the master-side rootfd open); workers shed
  `CAP_SETUID/SETGID/DAC_*/CHOWN/…` at startup.  Caveat: `CAP_SETUID` is inherently
  root-equivalent if the broker is exploited — the drop reduces incidental-root
  exposure, not code-exec containment.
- The broker drops to **only `{CAP_SETUID, CAP_SETGID}`** (+ `NO_NEW_PRIVS` +
  bounding-set clear) — crucially **no `CAP_DAC_OVERRIDE`**, so the impersonated
  user's own DAC applies. It fails closed if it cannot drop them.
- Broker socket is `0600`, owned by the worker uid, and `SO_PEERCRED`-gated.
- Authorization stays in the worker (the 3-tier gate); the broker only maps +
  impersonates + confines (defence in depth: it re-applies `RESOLVE_BENEATH`).
- Fails closed: an unreachable broker, a failed cap-drop, or an uncertain mapping
  all deny rather than fall back to privileged I/O.

## Tests

[`tests/userns/`](../../tests/userns/) — runs the real broker+client+idmap under
an **unprivileged user namespace** (subuid range via `newuidmap`/`newgidmap` +
a bind-mounted fake `/etc/passwd`, no `nss_wrapper`), proving ownership, DAC
enforcement, supplementary groups, confinement, deny policy, squash, and
no-credential-leak-under-concurrency without real root. Plus `nginx -t` mode
validation and an idmap unit test ([`tests/c/idmap_test.c`](../../tests/c/idmap_test.c)).
