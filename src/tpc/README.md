# tpc — Native XRootD third-party-copy (destination-side pull)

## Overview

This subsystem implements **native XRootD third-party copy (TPC)** for the
`root://` stream protocol: a client issues a write-mode `kXR_open` whose opaque
query carries `tpc.src=root://origin//path` (plus `tpc.key`, `tpc.org`,
`tpc.lfn`, `tpc.token_mode`, ...), and *this* gateway becomes the **destination**
that opens a fresh outbound XRootD client connection to the remote source,
streams the file in, writes it to the local export, and only then completes the
copy. The client never touches the bytes — that is the defining property of a
third-party copy. WebDAV HTTP-TPC (the `COPY` method with `Source:`/`Credential:`
headers) is an entirely separate transport living in `../webdav/` (`tpc*.c`);
the two share only the protocol-neutral core in [`common/`](common/README.md).

TPC enters from the stream open path (`../read/open_request.c`) and, crucially,
is driven in **two phases keyed off `kXR_sync`**. Phase one — `kXR_open` —
validates the source, performs the SSRF preflight, creates and confines the local
destination file, generates/echoes the rendezvous `tpc.key`, and returns an open
handle immediately (`engine/launch.c::brix_tpc_prepare_pull`). Phase two — driven by
`kXR_sync` (`../write/sync.c`): the **first** sync *arms* the transfer
(`ctx->tpc_armed`), the **second** sync *fires* it
(`engine/launch.c::brix_tpc_start_pull`), posting the blocking pull to the nginx
thread pool. This arm/flush handshake matches `xrdcp`/`gfal` TPC semantics and
lets the client control exactly when staging-to-final commit happens.

The actual fetch is blocking socket I/O and therefore **must not run on the
event loop**. It executes inside a detached `ngx_thread_task` worker
(`outbound/thread.c` → `outbound/connect.c` → `outbound/bootstrap.c`/`gsi/gsi_outbound_*`/`outbound/tpc_token.c` →
`outbound/source.c`), and only the completion callback (`engine/done.c`) runs back on the event
loop to frame and queue the deferred `kXR_open` response. Because the worker
runs off-loop, all code under `#if (NGX_THREADS)` uses `malloc`/`free` and raw
`send`/`recv`/`write` — **never** `ngx_palloc`, which is not thread-safe here;
only `engine/launch.c` and `engine/done.c` (event-thread code) may touch `c->pool`.

A second responsibility lives here: the **SHM TPC key registry**
(`engine/key_registry.c`/`.h`), a cross-worker shared-memory table of in-flight
rendezvous keys with TTL expiry. On the *source* side of a transfer it lets one
worker register a key and another worker validate/consume it when the
destination reconnects with `tpc.org`+`tpc.key` — the "SHM key registry,
cross-process, zero-copy" rendezvous referenced in the architecture invariants.

## Files

Phase-67 layout: `engine/` = event-loop orchestration (opaque parse, open-path
launch, completion handoff, SHM key registry, disabled-build stubs);
`outbound/` = the blocking source-session client pipeline run on the thread
pool; `gsi/` = the outbound GSI/ztn handshake kernel; `common/` = the
protocol-neutral spine shared with WebDAV HTTP-TPC.

| File | Responsibility |
|---|---|
| `engine/tpc_internal.h` | Shared types (`brix_tpc_params_t`, `brix_tpc_pull_t`), wire constants (`TPC_CHUNK_SIZE`=1 MiB, `TPC_IO_TIMEOUT_SEC`=60, `TPC_CONNECT_TIMEOUT_SEC`=5, `TPC_RESP_MAX_BODY`), and all cross-file function declarations. |
| `engine/parse.c` | (event thread) Parse the `tpc.*` opaque query into `brix_tpc_params_t`; decompose `root://host[:port]//path` (and IPv6 `[...]`, bare host, LFN) into `src_host`/`src_port`/`src_path`. Clears all fields on partial-parse failure to block bypass. |
| `engine/launch.c` | (event thread) Entry points. `brix_tpc_prepare_pull`/`brix_tpc_launch_pull`: SSRF preflight → confined destination open → fhandle + file metadata → key gen/register → send open response. `brix_tpc_start_pull`: build the `brix_tpc_pull_t` task, register the shared transfer, post to the thread pool. |
| `outbound/thread.c` | (thread pool) Worker orchestrator: `connect → bootstrap → tpc_pull_from_source`, updating the shared transfer registry state at each step. |
| `outbound/connect.c` | (thread pool) DNS resolve (`getaddrinfo`), per-candidate SSRF policy check, non-blocking TCP connect with `poll()` timeout. Also `brix_tpc_check_src_policy` — the event-thread SSRF preflight used before destination creation. |
| `outbound/bootstrap.c` | (thread pool) Anonymous outbound XRootD session: handshake → `kXR_protocol` → `kXR_login` (user `xrd`, `kXR_ver005`); on `kXR_authmore` delegates to the credentialed finish path. |
| `gsi/gsi_outbound_finish.c` | (thread pool) Auth-method selection from the server's login `&P=` parameter block: prefer WLCG JWT (`ztn`) when a token is available, fall back to GSI (`gsi`) when the server also allows it and a cert is configured. |
| `gsi/gsi_outbound_common.c` | (thread pool) WLCG token (`ztn`) outbound auth + wire helpers `tpc_put_u32`, `tpc_send_kxr_auth`; reads the bearer file via the token subsystem. |
| `gsi/gsi_outbound_certreq.c` | (thread pool) GSI round 1: load cert chain + key PEM, validate, send `kXGC_certreq`, expect `kXR_authmore`. |
| `gsi/gsi_outbound_exchange.c` | (thread pool) GSI rounds: Diffie-Hellman key exchange, derive shared secret, encrypt and send the cert chain (`kXGC_cert`), optional server-cert verification against the configured CA store. |
| `outbound/tpc_token.c` | (thread pool) Delegated OAuth2/OIDC token fetch for source auth: `oidc-agent` mode (fork/exec helper or `oidc-token`) and `token-exchange` mode (RFC 8693 via `curl`); validates the fetched token. |
| `outbound/source.c` | (thread pool) The pull itself: remote `kXR_open` (with `?tpc.key=&tpc.org=`), `kXR_read` loop in `TPC_CHUNK_SIZE` chunks (accumulating `kXR_oksofar`/`kXR_ok`), EINTR-safe writes to `dst_fd`, `fsync`, best-effort `kXR_close`. |
| `outbound/io.c` | (thread pool) Blocking socket primitives: `tpc_send_all`, `tpc_recv_response` (parses `ServerResponseHdr` + `malloc`s the body, capped at `TPC_RESP_MAX_BODY`); routes through `SSL_read`/`SSL_write` once `tls.c` upgraded the socket. |
| `outbound/tls.c` | (thread pool) `tpc_start_tls()` — blocking client TLS handshake on the connected pull socket after the source answers `kXR_protocol` with `kXR_gotoTLS`; stores the negotiated `SSL` on the pull task so `io.c` carries every later frame over TLS. |
| `engine/done.c` | (event thread) Completion callback: restore the deferred request, finalize file metadata, frame & queue the `kXR_open`/`kXR_sync` success response (embedding `tpc.key` for `xrdcp`) or error; on connection-closed-in-flight, unlink the partial file and free the handle. |
| `engine/key_registry.c` / `.h` | SHM rendezvous-key table (256 slots, 60 s TTL): configure zone, generate/register/validate/consume/remove keys under a spinlock across workers. |
| `engine/noop.c` | Build-time-disabled fallback: stub implementations of every public entry point returning `kXR_Unsupported`/`-1` when native TPC is compiled out. Not in the default source list (threads are mandatory). |
| `common/` | Protocol-neutral TPC spine shared with WebDAV TPC — authz, credential parsing, transfer registry, metrics, progress. Has its own [`common/README.md`](common/README.md). |

## Key types & data structures

- **`brix_tpc_params_t`** (`tpc_internal.h`) — parsed `tpc.*` opaque fields:
  raw `src`/`dst`, decomposed `src_host`/`src_port`/`src_path`, `key`, `org`,
  `lfn`, `stage`, `token_mode`, plus a `has_*` flag per field. Produced by
  `parse.c`, consumed by `launch.c`.
- **`brix_tpc_pull_t`** (`tpc_internal.h`) — the per-pull task context,
  heap-allocated inside the `ngx_thread_task` in `start_pull`, populated from the
  `brix_file_t` slot, and freed implicitly with the pool after `done.c`
  consumes the result. Carries the connection/ctx/conf back-refs, the deferred
  `streamid`, source coordinates, `tpc_key`/`tpc_org`, `token_mode` +
  `delegated_token` + `token_scope`, `dst_path`/`dst_fd`/`fhandle_idx`,
  `reply_kind` (`BRIX_TPC_REPLY_OPEN`/`_SYNC`), `transfer_id`, and the
  out-params `result`/`xrd_error`/`bytes_written`/`err_msg`.
- **`brix_tpc_key_table_t` / `brix_tpc_key_entry_t`** (`key_registry.h`) —
  the SHM rendezvous table: `BRIX_TPC_KEY_SLOTS` (256) fixed entries, each a
  128-byte key + absolute-ms `expiry` + `in_use`, guarded by an
  `ngx_shmtx_sh_t` spinlock so all workers share one key namespace.
- **`brix_tpc_transfer_t`** (`common/transfer.h`) — the protocol-neutral
  in-flight-transfer record threaded through the shared registry/metrics; this
  subsystem tags it `BRIX_TPC_PROTO_STREAM` / `BRIX_TPC_DIR_PULL` and walks
  it through the `PENDING → ACTIVE → DONE/ERROR` states.

## Control & data flow

**Entry.** `kXR_open` with a `tpc.src=` opaque → `../read/open_request.c` calls
`brix_tpc_parse_opaque()` (`parse.c`) then `brix_tpc_launch_pull()`
(`launch.c`). The open path also consumes a presented `tpc.key` via the SHM
registry (`brix_tpc_key_consume`) on the source side. `kXR_sync`
(`../write/sync.c`) drives the two-phase arm/flush, the second sync calling
`brix_tpc_start_pull()`.

**Calls out to:**
- [`../path/`](../path/README.md) — destination open is confined via
  `brix_open_beneath(conf->rootfd, ...)` against the per-worker root fd
  (`RESOLVE_BENEATH`); `launch.c` strips the `root_canon` prefix to pass the
  *logical* path so the root is not doubled.
- [`../aio/`](../aio/README.md) — the thread→event-loop handoff reuses the same
  `brix_aio_restore_request` / `brix_aio_resume` machinery; the connection
  enters `XRD_ST_AIO` while the pull runs.
- [`../read/`](../read/README.md) / [`../write/`](../write/README.md) — open
  request decode and the `kXR_sync` arm/flush trigger.
- [`../compat/`](../compat/README.md) — `net_target` SSRF policy
  (`brix_net_target_check_addr`/`_dns`) and `shm_slots` expiry helpers.
- [`../token/`](../token/README.md) — bearer-file reads and OAuth2 access-token
  JSON parsing for delegated source auth.
- [`../session/`](../session/README.md) — handle publish for bound sessions
  (`brix_session_handle_publish`).
- [`common/`](common/README.md) — credential validate, transfer registry
  add/update/remove, metrics, progress emit.

**Returns** by framing a `kXR_ok` `ServerOpenBody` (fhandle + optional statbuf,
with `tpc.key` appended for client extraction) or `kXR_*` error in `done.c`, then
`brix_queue_response` + `brix_aio_resume`.

## Invariants, security & gotchas

- **Confinement is mandatory.** The destination file is opened only through
  `brix_open_beneath(conf->rootfd, dst_logical, ...)`. `launch.c` deliberately
  strips the `root_canon` prefix from the authz/logging path before passing it to
  `openat2`, because passing the absolute path would double the root and fail
  with `ENOENT` (`launch.c:230-252`). Never add a raw `open` on a client path.
- **SSRF defense is two-stage.** `brix_tpc_check_src_policy` (event thread)
  rejects the source *before* the destination file is created; `connect.c`
  re-checks **every** resolved `addrinfo` candidate against the same
  `allow_local`/`allow_private` policy at connect time, closing the
  resolve-time/connect-time TOCTOU gap.
- **Parse fails closed.** `parse.c` zeroes the whole struct up front and, on any
  src-spec parse failure, clears `src_host`/`src_path`/`src_port` entirely so a
  partially-parsed source can never reach `connect()` (`parse.c:222-239`). Port
  is validated to 1–65535.
- **Off-loop allocation discipline.** Everything in the thread-pool files
  (`thread.c`, `connect.c`, `bootstrap.c`, `source.c`, `io.c`, `gsi_outbound_*`,
  `tpc_token.c`) uses `malloc`/`free` and raw socket syscalls — `ngx_palloc` is
  not thread-safe here. Only `launch.c`/`done.c` may use `c->pool`.
- **Body-size cap.** `tpc_recv_response` rejects any response whose `dlen >
  TPC_RESP_MAX_BODY` before allocating, bounding a hostile source's memory
  influence (`io.c:114`).
- **Peer-response tolerance.** `source.c` accepts both the minimal 4-byte
  fhandle reply and the full `ServerOpenBody`, and accumulates `kXR_oksofar`
  frames per `kXR_read` until the terminal `kXR_ok` — required for interop with
  reference XRootD origins.
- **Single-use rendezvous keys.** `key_registry.c::brix_tpc_key_consume`
  removes the key on a successful match (replay protection); `_validate` only
  checks presence. Both lazy-expire stale entries during the scan. Slot
  exhaustion silently drops a register — callers tolerate this.
- **Connection-closed cleanup.** If the client disconnects mid-pull,
  `done.c::brix_aio_restore_request` fails and the callback unlinks the
  partial destination file, closes `dst_fd`, frees the fhandle slot, and marks
  the shared transfer `ERROR` — no half-written files are left exposed.
- **GSI is hand-rolled.** `gsi_outbound_exchange.c` implements the DH key
  exchange and `kXGS_cert` payload assembly directly against OpenSSL rather than
  via a GSSAPI library; server-cert verification (with
  `X509_V_FLAG_ALLOW_PROXY_CERTS`) is only performed when `conf->gsi_store` is
  configured.
- **Subprocess token fetch.** `tpc_token.c` fork/execs `oidc-token`/`curl`; it
  uses an end-of-options `--` terminator before the endpoint URL and avoids
  `access()`-before-`execve` TOCTOU. The RFC 8693 body is written to a `mkstemp`
  temp file that is `unlink`ed on every exit path.

## Entry points / extending

- **Add a `tpc.*` opaque parameter:** extend `brix_tpc_params_t` + its `has_*`
  flag (`tpc_internal.h`), add a key match in `tpc_parse_token` (`parse.c`),
  carry it onto the `brix_file_t` in `brix_tpc_prepare_pull` and onto
  `brix_tpc_pull_t` in `brix_tpc_start_pull` (`launch.c`), then act on it in
  the worker.
- **Add a source auth method:** detect it from the login `&P=` block in
  `tpc_outbound_finish_login` (`gsi_outbound_finish.c`) and add the handler
  alongside `tpc_outbound_ztn` / `tpc_outbound_gsi`.
- **Add a token-delegation mode:** add a `ngx_strcmp` branch in
  `tpc_fetch_delegated_token` (`tpc_token.c`) and a fetch helper next to
  `tpc_token_oidc_agent` / `tpc_token_rfc8693`.
- **Tune the rendezvous TTL/slots:** `BRIX_TPC_KEY_TTL_MS` /
  `BRIX_TPC_KEY_SLOTS` (`key_registry.h`); the runtime TTL override is the
  `brix_tpc_key_ttl` directive.

## See also

- [`common/README.md`](common/README.md) — shared TPC authz/credential/registry/metrics core.
- [`../webdav/README.md`](../webdav/README.md) — the other TPC transport (HTTP `COPY`).
- [`../path/README.md`](../path/README.md) — `RESOLVE_BENEATH` confinement.
- [`../aio/README.md`](../aio/README.md) — thread-pool / event-loop handoff pattern.
- [`../read/README.md`](../read/README.md) · [`../write/README.md`](../write/README.md) — open decode and `kXR_sync` arm/flush trigger.
- [`../token/README.md`](../token/README.md) — bearer files and OAuth2 token parsing.
- [`../README.md`](../README.md) — master subsystem index.
