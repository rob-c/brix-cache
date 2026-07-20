# Plan — the seccomp "spawn broker" (Option B: block arbitrary exec, allow only known helpers)

**Status:** design/plan (not implemented). Companion to the shipped Option A
(`brix_seccomp_allow_exec on`, which allowlists `execve` wholesale under enforce).
Option B is the high-assurance follow-up: keep `execve`/`execveat` **killed** in
the worker, and route the few legitimate fork+exec paths through a small, audited
broker that only ever execs an **allowlisted set of binaries**.

## Why

Under `brix_seccomp enforce`, the worker deny-set `SCMP_ACT_KILL_PROCESS`s
`execve`/`execveat` so a worker-code RCE cannot spawn a shell or tools. But a few
optional features legitimately fork+exec helpers, so today they need Option A
(allow execve entirely), which also lets a worker RCE exec *anything* (as the
unprivileged, no-caps, confined worker — contained, but not blocked).

seccomp-bpf **cannot** filter `execve` by path (no pointer deref), and seccomp
**user-notification is TOCTOU-unsafe** for `execve` (the process can swap the path
after the supervisor's check). The only sound way to allowlist *which* binary may
be exec'd is to do the exec in a **separate process that receives the request over
IPC and controls the path itself** — a spawn broker.

## The legitimate fork+exec sites to migrate (all optional, none on the hot path)

| Site | Feature | Binary |
|---|---|---|
| `src/fs/backend/frm/sd_frm_exec.c:64` | FRM **"exec"** MSS adapter only (tape://exec — a real external HSM) | operator-configured `$BRIX_FRM_STAGECMD` (drives HPSS/CTA/dCache/Enstore) |
| `src/tpc/outbound/tpc_token.c:181,215` | native-TPC OIDC token fetch | oidc-agent helper / `oidc-token` |
| `src/tpc/outbound/tpc_token_exchange.c:125` | native-TPC RFC 8693 token-exchange | `curl` |
| `src/protocols/webdav/tpc_cred_oidc.c` | WebDAV HTTP-TPC oidc-agent delegation | oidc-agent helper / `oidc-token` |
| `src/protocols/root/query/prepare_cmd.c:24` | `kXR_prepare` hook | operator-configured command |
| `src/fs/xfer/xfer_spawn.c:95` | shared mover-agent spawn helper (stage/upload movers) | (callers above) |
| `src/core/compat/subprocess.c:66` | generic capture-subprocess helper | (callers of the above) |

Note the FRM stage command and the `kXR_prepare` command are **operator-configured
paths** (not fixed binaries) — the spawn broker's allowlist must therefore admit
them from config (canonicalised at startup), not from a hardcoded table.

**The default tape/nearline backend does NOT exec.** The FRM driver is a pluggable
MSS adapter; the built-in **`stub` adapter** (`sd_frm_stub.c`, the default —
authority `exec` is required to select the exec adapter) performs recall/migrate/
purge as plain POSIX file copies (`stub_copyfile` = open/read/write/rename/unlink),
all allowlisted. So a `tape://` backend runs under strict `brix_seccomp enforce`
with NO `allow_exec` and needs nothing from the spawn broker — only a real external
HSM (the `exec` adapter) does.

(WebDAV HTTP-TPC **data transfer** uses libcurl in-process — no exec — so it is
unaffected either way.)

## Architecture

A small **unprivileged spawn broker**, modelled on the existing impersonation
broker (`src/auth/impersonate/`): double-forked, `AF_UNIX` socketpair, fixed-size
request frames, single-threaded, `SO_PEERCRED`-gated, `NO_NEW_PRIVS`.

- **Spawned before the worker installs seccomp** (so the broker's thread group
  never carries the `execve`-KILL filter). Master-spawned + double-forked (like the
  impersonation broker) is cleanest; one broker per worker, or a shared broker
  addressed by worker uid.
- **Unprivileged**: it runs as the worker's own account and needs **no
  capabilities** — it just `fork`+`execve`s the helper as that uid. (Do NOT fold
  this into the impersonation broker: that one holds `CAP_SETUID`, and exec +
  setuid in one process is a much larger surface. Keep them separate.)
- **Binary allowlist**: a fixed table of permitted absolute paths — the OIDC
  helper, `oidc-token`, `curl`, and the configured `kXR_prepare` command —
  resolved and canonicalised **once at startup**. The broker refuses anything
  else. No shell, no `PATH` search, no arg-driven path.
- **Worker keeps `execve`/`execveat` KILLED** — no `allow_exec` needed. A worker
  RCE cannot exec at all; it can only ask the broker to run a pre-approved binary.

### Wire protocol (fixed frames, à la `impersonate_proto.h`)

```
req:  { u32 op=SPAWN; u32 bin_id;              // index into the allowlist
        u32 argc; u32 argv_len; u32 env_len;   // bounded (e.g. argv<=64, blob<=64KiB)
        // followed by NUL-joined argv + env blobs;
        // stdin/stdout/stderr fds passed via SCM_RIGHTS }
rep:  { i32 status;                            // waitpid status, or -errno
        // stdout may be streamed back on the passed fd, or relayed }
```

The worker marshals argv/env, passes the stdin/stdout fds (or a pipe) via
`SCM_RIGHTS`, and blocks on the reply. The broker validates `bin_id`, `fork`s,
`dup2`s the fds, `execve`s `allowlist[bin_id]` with the (sanitised) argv/env, and
returns the `waitpid` status.

### Client seam

`brix_spawn_run(bin_id, argv, env, in_fd, out_fd) -> status` — a thin client that
sends the frame and awaits the reply. The five call sites above call this instead
of `fork`+`execve` directly. `src/core/compat/subprocess.c` is the natural home for
the client so its existing callers migrate with minimal churn.

## Security properties

- Worker RCE: **cannot exec anything** (execve killed) — strictly stronger than
  Option A. It can only request an allowlisted binary with bounded argv/env.
- No TOCTOU: the broker holds the canonical path; the worker never supplies it.
- Broker is tiny, audited, AF_UNIX-only, `SO_PEERCRED`-gated, fixed-frame,
  single-threaded, `NO_NEW_PRIVS`, **no capabilities** (unlike the impersonation
  broker).
- env is sanitised broker-side to a minimal controlled set (mirrors the existing
  `tpc_token.c` "minimal controlled environment" comment).

## Phasing

1. **Broker + client + protocol + allowlist**, spawned and wired, with ONE call
   site migrated (`prepare_cmd.c` — simplest: fixed binary, no streamed output) and
   an end-to-end test (kXR_prepare under `brix_seccomp enforce` WITHOUT
   `allow_exec` → works via the broker; a non-allowlisted binary → refused).
2. **Migrate the streaming/token sites** (`tpc_token_exchange.c` curl with captured
   stdout, `tpc_token.c` / `tpc_cred_oidc.c` oidc-agent) — this is the real work:
   fd-passing for curl's output and the oidc-agent UNIX-socket helper.
3. **Flip the posture**: once every exec routes through the broker, make
   `execve`-KILL the norm for enforce and treat `brix_seccomp_allow_exec` as a
   legacy escape hatch (or remove it).

## Effort & risk

- Effort: **~the size of the impersonation broker** — a new broker + client + wire
  protocol + allowlist + rewiring 5 call sites + unit/e2e tests. Most patterns
  (double-fork, socketpair, SCM_RIGHTS, fixed frames, peercred gate) are already in
  `src/auth/impersonate/` to copy.
- Risk: moderate. The fiddly bits are (a) streaming `curl`'s stdout back (fd-passing
  vs pipe relay), (b) the oidc-agent UNIX-socket helper's own fd handling, and (c)
  broker lifecycle/reaping across worker restart and reload.

## Open decisions

1. **Shared broker vs per-worker.** Per-worker is simpler to reason about
   (`SO_PEERCRED` == that worker); shared is fewer processes. Recommend per-worker,
   mirroring how the impersonation socket is `0600`-owned by the worker uid.
2. **Streaming vs capture.** For `curl` token-exchange the output is small (a JSON
   token) — a captured pipe relayed in the reply frame is simplest. Only reach for
   `SCM_RIGHTS` fd-passing if a large-output exec appears.
3. **Reuse subprocess.c** as the client home (yes — its callers are exactly the
   sites to migrate).
