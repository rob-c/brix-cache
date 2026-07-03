# tpc/common — Protocol-neutral third-party-copy (TPC) core

## Overview

This subsystem is the **shared, transport-agnostic spine** for third-party copy
(TPC) in nginx-xrootd. A third-party copy is a server-to-server transfer
initiated by a client that never touches the bytes itself: the client tells one
gateway to pull a file from (or push it to) a remote origin. The module
implements two completely separate TPC transports — native XRootD pull
(`src/tpc/`, driven by a write-mode `kXR_open` carrying `tpc.src=...`) and WebDAV
HTTP-TPC (`src/protocols/webdav/tpc*.c`, driven by the `COPY` method with
`Source:`/`Credential:` headers). Rather than duplicate authorization,
credential parsing, transfer bookkeeping, and metrics across both transports,
those four concerns are factored into this `common/` directory so both go
through **one API with identical semantics**.

Nothing in `tpc/common` moves file data or speaks any wire protocol. It is pure
support code answering four questions: "may this identity perform this copy?"
(`auth.c`); "what kind of credential did the peer hand us and is it usable?"
(`credential.c`); "record / advance / finish this in-flight transfer in a
cross-process table so the dashboard can show it" (`registry.c` + `progress.c`);
and "bump the unified Prometheus TPC counters" (`metrics.c`). The
protocol-neutral data model that ties them together lives in `transfer.h`.

In the request lifecycle this code sits **inside** the TPC handlers, not at the
edge. For native pull, `read/open_request.c` calls `brix_tpc_check_authz()`
when it sees `tpc.src=` on an open, `tpc/tpc_token.c` parses the bearer
credential via `brix_tpc_credential_parse()`, `tpc/launch.c` registers the
transfer with `brix_tpc_registry_add()`, `tpc/source.c` advances it with
`brix_tpc_progress_emit()`, and `tpc/done.c` emits stream-side counters via
`brix_tpc_metric_transfer()`. For WebDAV `COPY`, `webdav/tpc.c` gates with
`brix_tpc_check_authz()`, `webdav/tpc_cred.c` parses the `Credential:` header,
`webdav/tpc.c`/`tpc_thread.c` register the transfer, `webdav/tpc_curl.c` and
`tpc_marker.c` advance progress, and all three emit
`brix_tpc_metric_transfer()` at start / per-marker / completion.

The single cross-process registry is published once at post-configuration time
by **both** transports (`config/postconfiguration.c` and `webdav/postconfig.c`,
both calling `brix_tpc_registry_configure()`) and consumed read-only by the
dashboard (`dashboard/api.c::dashboard_build_tpc_registry`, via
`brix_tpc_registry_snapshot()`).

## Files

| File | Responsibility |
|---|---|
| `transfer.h` | The protocol-neutral data model. Defines `brix_tpc_transfer_t` (one in-flight copy) plus the small integer enums every other file keys off: protocol (`BRIX_TPC_PROTO_STREAM`=1 / `_WEBDAV`=2), direction (`_DIR_PULL`=1 / `_DIR_PUSH`=2), state (`_STATE_PENDING`/`_ACTIVE`/`_DONE`/`_ERROR` = 1..4), and the fixed registry sizing constants (`_REGISTRY_SLOTS`=1024, `_SRC_URL_MAX`/`_DST_PATH_MAX`=1024). Header-only; no `.c`. |
| `auth.h` / `auth.c` | `brix_tpc_check_authz()` — fail-closed gate deciding whether an `brix_identity_t` may initiate a TPC for a given (src, dst) pair. Rejects S3 SigV4 identities outright, then checks WLCG token scope (read on source, write on destination) via `brix_identity_check_token_scope()`. File-private `brix_tpc_check_scope_path()` does the per-path NUL-terminate-and-check. |
| `credential.h` / `credential.c` | The `brix_tpc_credential_t` model plus `brix_tpc_credential_parse()` (classify a raw credential string as none/proxy/token, optionally guided by a `hint`, after trimming and `Bearer `/`-----BEGIN` sniffing), `brix_tpc_credential_validate()` (non-empty + expiry check), and `brix_tpc_credential_type_name()`. |
| `registry.h` / `registry.c` | The cross-process transfer registry: a fixed `BRIX_TPC_REGISTRY_SLOTS`-entry table in an nginx shared-memory zone (`brix_tpc_transfers`), guarded by an `ngx_shmtx_t`. Exposes `_configure` (post-config wiring), `_add`, `_update`, `_remove`, `_find`, and `_snapshot` (lock-held copy-out for the dashboard). Owns the slot-internal storage backing the source URL and destination path strings. |
| `progress.c` | `brix_tpc_progress_emit()` — thin convenience wrapper that forwards a byte/state update to `brix_tpc_registry_update()`. The `bytes_total` argument is currently ignored (`(void) bytes_total;`); total is fixed at add time. Declared in `registry.h`. |
| `metrics.h` / `metrics.c` | `brix_tpc_metric_transfer()` — the single low-cardinality call site both transports use to record TPC outcomes. Maps the neutral (protocol, direction, event) triple onto the unified counter API `brix_metric_tpc()` in `../../metrics/unified.h`. Defines the `BRIX_TPC_METRIC_STARTED`/`_SUCCESS`/`_ERROR` event codes (1/2/3). |

## Key types & data structures

- **`brix_tpc_transfer_t`** (`transfer.h`) — the canonical record of one
  in-flight copy: `id`, `protocol`, `direction`, `src_url`, `dst_path`,
  `bytes_total`, `bytes_done`, `started_at`, `updated_at`, `state`. Its
  `ngx_str_t` members are **not owner-managed by the caller**: callers may pass
  stack- or request-pool-backed strings to `brix_tpc_registry_add()`, and the
  registry copies them into slot-owned fixed buffers before publishing (see the
  contract comment in `transfer.h:24-30`).

- **`brix_tpc_credential_t`** (`credential.h`) — a tagged record: a `type`
  discriminator (`NONE`/`PROXY`/`TOKEN`) plus `proxy_pem`, `bearer`, an optional
  resolved `identity`, and an optional `expires_at`. Only the string field
  matching `type` is meaningful.

- **`brix_tpc_registry_entry_t`** (`registry.c`, file-private) — one table
  slot: an `in_use` flag, an embedded `brix_tpc_transfer_t`, and the two inline
  character buffers (`src_url_data[1024]`, `dst_path_data[1024]`) that back the
  transfer's `ngx_str_t` members. The whole table
  (`brix_tpc_registry_table_t`) is a leading `ngx_shmtx_sh_t lock` followed by
  the `slots[1024]` array, allocated in shared memory.

- **`brix_tpc_transfer_snapshot_t`** (`registry.h`) — a flattened,
  self-contained copy of a transfer returned by
  `brix_tpc_registry_snapshot()`. Unlike `brix_tpc_transfer_t` it embeds
  `char[]` arrays (not `ngx_str_t`), so a consumer such as the dashboard can read
  it after the registry lock is released without dangling into shared memory.

## Control & data flow

This subsystem is **called into**, never an entry point itself. Execution enters
from the two TPC transports plus one post-config hook and one read-only consumer:

1. **Post-config wiring (once per cycle).** Both
   `../../config/postconfiguration.c:198` and `../../webdav/postconfig.c:144`
   call `brix_tpc_registry_configure(cf)`, which reserves the
   `brix_tpc_transfers` shared-memory zone against `ngx_stream_brix_module`.
   Calling it from both paths is idempotent — `ngx_shared_memory_add()` returns
   the same zone and the `shm_init` callback creates the `ngx_shmtx_t` once.

2. **Native XRootD pull** (`../README.md`, files `../*.c`): on a write-mode
   `kXR_open` carrying `tpc.src=`, `../read/open_request.c:160` gates with
   `brix_tpc_check_authz()`; `../tpc_token.c:84` parses the bearer credential
   through `brix_tpc_credential_parse()`; `../launch.c:176` registers via
   `brix_tpc_registry_add()`; `../source.c:208` advances with
   `brix_tpc_progress_emit()`; and `../done.c` emits
   `brix_tpc_metric_transfer(BRIX_TPC_PROTO_STREAM, ...)`.

3. **WebDAV HTTP-TPC** (`../../webdav/tpc.c` and siblings): on `COPY`,
   `webdav/tpc.c:63` gates with `brix_tpc_check_authz()`; `webdav/tpc_cred.c:57`
   parses the `Credential:` header; `webdav/tpc.c:99` / `tpc_thread.c:72`
   register via `brix_tpc_registry_add()`; `webdav/tpc_curl.c:273` and
   `tpc_marker.c:177` advance progress; and `tpc.c`/`tpc_thread.c`/`tpc_marker.c`
   emit `brix_tpc_metric_transfer(BRIX_TPC_PROTO_WEBDAV, ...)` at start,
   per-marker, and completion.

4. **Read-only consumer:** `../../dashboard/api.c:443` calls
   `brix_tpc_registry_snapshot()` to render the live transfer table as JSON.

Call-outs from this subsystem are deliberately narrow: `auth.c` →
`../../types/identity.h` (`brix_identity_check_token_scope`,
`BRIX_AUTHN_S3KEY`); `metrics.c` → `../../metrics/unified.h`
(`brix_metric_tpc`, `BRIX_PROTO_*`, `BRIX_ERR_NONE`/`_OTHER`);
`registry.c` → `../../ngx_brix_module.h` for the `ngx_stream_brix_module`
descriptor used to scope the shared-memory zone.

## Invariants, security & gotchas

- **Fail-closed authorization.** `brix_tpc_check_authz()` returns access only on
  explicit `NGX_OK`. S3 SigV4 identities (`BRIX_AUTHN_S3KEY`) are rejected
  before any scope check (`auth.c:69-73`) — SigV4 and WLCG tokens are distinct
  auth domains and never share logic. Source path requires **read** scope
  (`auth.c:75`, `need_write=0`), destination requires **write** scope
  (`auth.c:79`, `need_write=1`). A NULL/empty path is
  treated as "no path constraint to check" and passes (`auth.c:34-36`): callers
  must not rely on this gate to confine paths — kernel confinement
  (`../../path/beneath.c`, `RESOLVE_BENEATH`) is the path authority, not this
  gate.

- **Path-length guard before stack copy.** `brix_tpc_check_scope_path()` copies
  the wire path into a `char[PATH_MAX]` to NUL-terminate it for the scope check;
  an over-length path is rejected (`NGX_DECLINED`) rather than truncated
  (`auth.c:38-42`).

- **Credential parsing is trim-then-sniff-then-hint.** Leading/trailing
  whitespace and CR/LF are trimmed first (`credential.c:140-147`). A `Bearer `
  prefix or `-----BEGIN` marker then classifies the credential even when no
  `hint` is given; the `hint` forces a type when the raw form is ambiguous. The
  literal `none` and the empty string both resolve to
  `BRIX_TPC_CREDENTIAL_NONE`, which `validate()` accepts (anonymous /
  unauthenticated copy) (`credential.c:149-152`). An unrecognized non-empty form
  is `NGX_DECLINED` (`credential.c:183-185`).

- **Credential ownership depends on `pool`.** `brix_tpc_credential_parse()`
  copies into a NUL-terminated pool allocation when `pool != NULL`, but
  **aliases the caller's buffer** (no copy, no NUL terminator) when `pool == NULL`
  (`brix_tpc_copy_credential_str`, `credential.c:44-57`). Callers that pass
  `NULL` must keep the source buffer alive for the credential's lifetime and must
  not assume NUL termination.

- **The registry is cross-process shared memory, lock-guarded.** All mutating
  operations (`_add`/`_update`/`_remove`/`_snapshot`) take
  `brix_tpc_registry_mutex` (`ngx_shmtx_t`) around the slot scan.
  `brix_tpc_registry_find()` is the one **unlocked** reader — it returns a raw
  pointer into shared memory and is only safe for same-worker, short-lived
  inspection; concurrent/cross-worker consumers (the dashboard) must use
  `_snapshot()`, which copies under the lock into self-contained
  `brix_tpc_transfer_snapshot_t` rows.

- **Slot storage owns the strings.** `brix_tpc_registry_add()` deep-copies
  `src_url`/`dst_path` into the slot's inline buffers and repoints the stored
  transfer's `ngx_str_t` at them, truncating to `..._MAX - 1` and NUL-terminating
  (`registry.c:208-215`, via `brix_tpc_registry_copy_str`). Never publish a
  transfer expecting the caller's string
  pointers to survive — they will not.

- **Bounded, never-blocking, fail-soft.** The table is a fixed
  `BRIX_TPC_REGISTRY_SLOTS` (1024) entries; a full table logs a warning and
  returns id `0` (`registry.c:189-193`) rather than allocating or blocking — the
  copy still proceeds, it simply will not appear in the dashboard. `id == 0` is
  the sentinel for "not registered" and short-circuits `_update`/`_remove`
  (`registry.c:193-195`, `:234-236`).

- **ID generation is best-effort-unique, not cryptographic.** IDs mix
  `ngx_time() << 32`, `ngx_pid << 16`, and a per-worker sequence counter, forcing
  away from `0` (`brix_tpc_registry_next_id`, `registry.c:112-123`). They are
  stable handles for the dashboard, not security tokens.

- **Metric labels stay low-cardinality.** `brix_tpc_metric_transfer()` reduces
  every outcome to a (protocol, is_push, error-class) tuple before calling
  `brix_metric_tpc()` — no paths, URLs, or DNs ever reach a metric. Only
  `_SUCCESS` (→ `BRIX_ERR_NONE`) and `_ERROR` (→ `BRIX_ERR_OTHER`) touch
  counters; `_STARTED` is currently debug-log only (`metrics.c:25-38`).

- **Build registration.** These files are registered in the module's top-level
  `config` source list — both the stream and HTTP `NGX_ADDON_SRCS`/`DEPS` blocks
  reference `src/tpc/common/*` (`config:115-119`, `:218-222`, `:327-331`,
  `:671-672`). Adding a new `.c` here requires editing the top-level `config`,
  not `src/core/config/config.h`.

## Entry points / extending

- **Add a credential type** (e.g. a SciToken-flavored variant): extend
  `brix_tpc_credential_type_t` and the `brix_tpc_credential_t` fields in
  `credential.h`, add a sniff branch + a `_validate()` arm + a name in
  `credential.c`, then teach the two callers (`webdav/tpc_cred.c`,
  `tpc/tpc_token.c`) to pass the right `hint`.

- **Add a transfer field** the dashboard should show: add it to
  `brix_tpc_transfer_t` (`transfer.h`) **and** the flattened
  `brix_tpc_transfer_snapshot_t` (`registry.h`), copy it in
  `brix_tpc_registry_snapshot()`, and render it in
  `dashboard/api.c::dashboard_build_tpc_registry`.

- **Add a TPC metric dimension:** prefer extending the unified counter
  (`../../metrics/unified.h`, `brix_metric_tpc`) and mapping to it inside
  `brix_tpc_metric_transfer()`; do not add a high-cardinality label.

- **Wire a new transport into the registry:** call
  `brix_tpc_registry_configure()` from its post-config hook, `_add()` at start,
  `brix_tpc_progress_emit()` during transfer, `_remove()` (or a terminal
  `_update()` to `_STATE_DONE`/`_ERROR`) at finish, and
  `brix_tpc_metric_transfer()` for counters — using the neutral
  `BRIX_TPC_PROTO_*`/`_DIR_*`/`_STATE_*` constants from `transfer.h`.

## See also

- `../README.md` — native XRootD destination-side pull TPC (the stream transport
  that consumes this core: `connect.c`, `launch.c`, `source.c`, `done.c`,
  `tpc_token.c`, `key_registry.c`).
- `../../webdav/` — WebDAV `COPY` HTTP-TPC (the HTTP transport; `tpc.c`,
  `tpc_cred.c`, `tpc_marker.c`, `tpc_thread.c`, `tpc_curl.c`).
- `../../types/` — `identity.h` (`brix_identity_t`,
  `brix_identity_check_token_scope`, `BRIX_AUTHN_*`) used by `auth.c`.
- `../../metrics/` — `unified.h` (`brix_metric_tpc`) backing `metrics.c`.
- `../../path/` — `beneath.c` / `RESOLVE_BENEATH` confinement, the real path
  authority (TPC authz here is scope-only).
- `../../dashboard/` — `api.c`, the read-only consumer of the registry snapshot.
- `../../../README.md` — master subsystem index.
