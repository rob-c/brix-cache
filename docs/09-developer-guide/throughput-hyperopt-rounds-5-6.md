# Throughput hyper-optimization — rounds 5–6 (sendfile fd-resolver, chunked pgread streaming, reuseport scatter + §1.4 bind migration)

2026-09-01/02. The engineering record for the round-5/6 "out-perform xrootd
with a clear margin" work. Round 5 (sendfile fd-resolver, PGREAD MAXIOV 512,
the confused-deputy open-fstat fix) is summarized at the end; round 6 is the
multi-worker story: why `reuseport` silently disabled response offloading, and
the cross-worker kXR_bind migration (§1.4) that fixes it.

## The scoreboard (loopback, 8 GiB page-cache-resident file, xrdcp v5.9)

One production config — `worker_processes 4;` + `listen ... reuseport;` — wins
every axis simultaneously:

| axis                    | brix vs stock xrootd 5.9          |
|-------------------------|-----------------------------------|
| single-stream xrdcp     | **+42–65%**                       |
| xrdcp -S4 (substreams)  | parity (client CRC-bound), 100% offload |
| 4 concurrent clients    | **+25% best / +17% mean**         |
| server CPU per byte     | **−23%**                          |

The -S4 axis is client-bound: xrdcp's own CRC32c verification saturates before
either server does, so "parity at lower server CPU" is the winning shape there.

## Round 6a — §1.3 chunked pgread streaming

`pgread_encode.c` streams a large kXR_pgread as chunked kXR_oksofar frames
instead of materializing the full response; `BRIX_PGREAD_MAXIOV` 64→512 cut
the syscall census for an 8 GiB transfer from 32,768 preadv calls to 4,096.

## Round 6b — the reuseport/-S4 regression that wasn't a regression

Post-refactor `-S4` dropped −18% vs xrootd. Root cause was **not** the pgreads
refactor (a 1-worker control run with the same binary hit parity+): with
`listen ... reuseport` the kernel hashes each of a client's TCP connections to
a worker **independently**, so a kXR_bind secondary routinely lands on a
different worker than the session's primary. The §1.1 response-offload conn
map is per-worker — the primary's worker must own the secondary's socket to
push response frames — so a scattered bind silently fell back to inline
primary responses. Measured offload rates: reuseport ≈60%, no-reuseport
4-worker ≈88%, 1-worker 100%. The tradeoff before §1.4: reuseport wins
multi-client accept spreading but loses single-client substream offload.

## Round 6c — §1.4 cross-worker bind migration

`src/protocols/root/session/bind_migrate.{h,c}` (+ hooks in `bind.c`,
`handler.c` `brix_conn_adopt_attach`, `process.c`/`module_definition.c`
init wiring, `registry.{h,c}` `owner_worker`).

Mechanism: the master creates one AF_UNIX SOCK_SEQPACKET socketpair per worker
pre-fork (init_module — the last pre-fork hook; SCM_RIGHTS needs an fd that
exists in both processes). At kXR_bind time, if the SHM session registry says
the sessid's owner (`brix_session_owner_worker`) is another worker, the
accepting worker sends the secondary's fd + {magic, listening index, sessid,
streamid} to the owner's channel and abandons the connection **without writing
a byte** (the handler returns NGX_ERROR → quiet local close; the SCM_RIGHTS
copy keeps the socket alive). The owner adopts: fabricates the
ngx_connection_t exactly as ngx_event_accept would (I/O vtable, pool, log,
peer/local sockaddrs, connection number), fabricates the stream session as
ngx_stream_init_connection would (conf from the listening addr, module ctx
array, variables), attaches the brix ctx through the same accept-path helpers
(`brix_conn_adopt_attach` = conn_init_ctx + conn_apply_srv_conf +
conn_begin_session), stamps the bind streamid, and runs the shared
`brix_bind_attach` core — pathid assignment, offload registration, and the
kXR_ok reply all happen on the owning worker. Offload rate under 4-worker
reuseport: 100% (4095/4096 measured).

Safety gates (each refusal degrades to the pre-§1.4 inline behavior):

- **Frame boundary**: the recv loop reads exact per-frame byte counts, so at
  the bind boundary no userspace bytes are buffered; pipelined client bytes
  sit in the kernel socket buffer and travel with the fd.
- **TLS never migrates** (`c->ssl != NULL` declines — SSL state cannot cross
  processes). Cleartext secondaries under a TLS-primary session still can.
- **Queued replies never reorder** (`ctx->out.count != 0` declines).
- **Single worker / over-cap (64) / channel EAGAIN / sendmsg failure**: decline.
- Adopt validates magic, listening index bounds, `naddrs == 1`, and closes the
  fd on any failure — the client sees EOF on the secondary and degrades to
  control-stream I/O.

Tests: `tests/test_bind_migration.py` — a dedicated 2-worker reuseport
instance (the shared fleet is 1-worker and cannot scatter): 12 scattered
bind+tagged-read rounds all offload (P(false pass) = 2⁻¹² without migration —
verified: the test FAILS against a pre-migration binary), unknown-sessid
refusal, and kXR_open refused on 8 scattered secondaries (an adopted
connection inherits the bound-stream capability restriction).

## Round 5 (context) — sendfile fd-resolver + MAXIOV + open-fstat fix

- `read_sendfile.c`: `read_sendfile_serve_fd` fd-resolver; driver-backed
  handles ask `driver->read_sendfile_fd` (posix serves; cache/partial decline).
- The confused-deputy open-fstat fix in `open_resolved_file_open.c`:
  populate the handle snapshot via `fh->sd_obj.driver->fstat` (the ADOPTED
  object's driver), never `sd->driver` — a cache COMPLETE hit adopts the
  store's posix obj, and the instance's fstat misread it as size 0, which the
  sendfile clamp then trusted (0-byte serves). Same obj-keyed-slot rule as the
  storage-driver N–P wave. The fd-identity capture (real st_dev for the
  published-handle table + the special-file EINVAL gate) lives in
  `brix_open_capture_fd_identity`.

## Operational note

`worker_processes 1` remains a valid deployment (migration self-disables); the
recommended config for throughput is 4 workers + reuseport. On reload the
master closes the previous generation's channel fds before creating the new
ones; cache-manager/loader processes skip channel arming (`ngx_worker` out of
range).
