# admin — the unix control-socket transport shared by every admin plane

## Overview

An operator control socket is a **transport plus a verb table**, and only the
verb table is interesting. This subsystem owns the transport half exactly once,
so each admin plane contributes nothing but its verbs.

Two planes use it today:

- **root session admin** (`../../protocols/root/session/admin_socket.c`) —
  the `XrdXrootdAdmin` analogue behind `brix_admin_socket`: `list`, `disc`,
  `msg`, `pause`, `cont`, `abort` over the live root:// session table.
- **CMS cluster admin** (`../cms/cms_admin.c`) — the `cmsd` admin analogue
  behind `brix_cms_admin_socket`: `nodes`, `drain`, `undrain`, `forget`,
  `reset` over the SHM node registry (`../manager/registry.h`).

The two planes have **different scopes and that is deliberate**. Sessions are
per-worker, so the session socket is per-worker too (worker 0 gets `<path>`,
worker *n* gets `<path>.<n>`, and each answers only for its own connections).
The node registry is SHM, so the CMS plane is node-wide: any worker's socket
sees and mutates the same registry. The transport creates a per-worker path in
both cases — it is the verb table's data, not the transport, that decides
whether the answer is worker-local.

## Files

| File | Responsibility |
|---|---|
| `admin_unix.h` | The verb-agnostic contract: `brix_admin_reply_t` (the reply arena), `brix_admin_verb_t` + the `BRIX_ADMIN_VERB()` initialiser, `brix_admin_unix_t` (the per-plane descriptor: label, verb table, opaque user data), and the two entry points `brix_admin_unix_listen()` / `brix_admin_reply_set()`. Carries the caps `BRIX_ADMIN_REPLY_MAX` (64 KiB) and `BRIX_ADMIN_CMD_MAX` (512 B). |
| `admin_unix.c` | The whole transport: bind (`unlink` stale path, `chmod 0600`), the I/O-vtable wiring a bare `ngx_get_connection()` leaves NULL, accept, newline framing, oversized-line refusal, verb match and dispatch, and the `NGX_AGAIN`-safe reply flush. |

## The verb-match rule

A verb is matched against the **whole** command line, never as a prefix:

- a bare verb (`wants_args == 0`) matches only when the line is exactly its
  name — `nodesx` is an unknown command, not `nodes`;
- an operand verb (`wants_args == 1`) requires name + a space + at least one
  operand byte — `drain` alone is an unknown command, and `cont` can never be
  reached by a prefix of `continue`.

That rule is not a nicety. Prefix matching would make one plane's verb table
reachable from a shorter spelling of another's, and would turn a truncated
operand into a *successful* mutation of the wrong target.

## The reply arena

`brix_admin_reply_t` keeps the allocation (`buf`, `cap`) separate from the
answer (`out`, `len`) so a long-body verb — ROOT `list`, CMS `nodes` — can
reserve header room, fill the body forwards, then repoint `out` *backwards*
over the finished header instead of memmoving up to 64 KiB of body. Handlers
that answer a fixed string call `brix_admin_reply_set()` and never touch the
arena at all.

## The privilege boundary, and the audit divergence

The socket is created mode **0600**: filesystem permission is the entire
authorization model, exactly as in stock XRootD. There is no in-band
authentication, and none of the verbs re-check anything.

Each plane audits its own mutations, and the format deliberately **diverges**
from the HTTP admin API's. `../../observability/dashboard/api_admin.c` hash-
chains its audit records (SHA-256, P90-28.2) because that surface is
network-reachable and a tamper claim is meaningful there. The socket's audit
lines carry the same fields *unchained*: a principal who can open a 0600 path
can also rewrite the log, so a chain would assert an integrity property the
threat model does not support. `admin_audit()` is in any case not reusable
here — it needs an `ngx_http_request_t` and the dashboard loc conf that holds
the chain state.

## Testing

- `tests/test_admin_socket.py` — the root session verb table, and the 0600 mode.
- `tests/test_phase115_cms_admin_socket.py` — the CMS verb table over a live
  two-node registry, plus the transport-level negatives that only a *second*
  plane can express: the two verb tables must be disjoint, no verb may be
  reachable by a prefix, and the registry must be byte-identical after every
  refused command.
