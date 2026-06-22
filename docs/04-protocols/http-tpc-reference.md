# TPC: nginx-xrootd vs official xrootd

A concrete side-by-side of where nginx-xrootd's third-party copy support
matches the official XRootD implementation, where it diverges, and why. Read
this before writing TPC-related tests or integrating with WLCG FTS.

## Executive summary

- nginx-xrootd implements two practical TPC paths:
  - native destination-side XRootD pull and source rendezvous implemented in
    `src/tpc/` (root:// sources).
  - HTTP/WebDAV TPC implemented in `src/webdav/tpc*.c` with libcurl-based
    pull/push, TransferHeader handling, OAuth2/OIDC delegation, performance
    markers, and optional multi-stream Range GET.
- Official xrootd (`XrdHttpTpc`) provides a full-featured HTTP(S) TPC handler
  built on libcurl multi/pipelining with perf markers, monitoring, CA/CRL
  integration, multi‑stream transfers, and richer auth/delegation wiring.
- Key remaining gaps in nginx-xrootd vs official xrootd: upstream-style
  in-server TPC integration, richer timeout/retry semantics, production TPC
  monitoring hooks, more configurable SSRF policy, and native root TPC edge
  cases such as TLS-upgraded origins and multihop delegation.

## Where to read the implementations

- nginx-xrootd (module):
  - native TPC: [src/tpc/](../../src/tpc/)
    - `src/tpc/launch.c`, `src/tpc/thread.c`, `src/tpc/source.c`,
      `src/tpc/bootstrap.c`, `src/tpc/connect.c`, `src/tpc/tpc_internal.h`
  - HTTP/WebDAV TPC glue: [src/webdav/tpc.c](../../src/webdav/tpc.c),
    [src/webdav/tpc_curl.c](../../src/webdav/tpc_curl.c),
    `src/webdav/tpc_cred.c` (OAuth2/OIDC token handling),
    `src/webdav/tpc_cred_parse.c` (token parsing),
    `src/webdav/tpc_marker.c` (perf-marker generation),
    `src/webdav/tpc_thread.c` (async transfer threading)

- official xrootd (reference): key code is in the `XrdHttpTpc` plugin
  (example files under a reference tree used for earlier comparisons):
  - `/tmp/xrootd-src/src/XrdHttpTpc/` (e.g. `XrdHttpTpcTPC.cc`,
    `XrdHttpTpcUtils.cc`, `XrdHttpTpcMultistream.cc`) and monitoring in
    `/tmp/xrootd-src/src/XrdXrootd/XrdXrootdTpcMon.cc`.

Note: reference xrootd files above are external to this workspace; the
module source links above point into this repository.

## Detailed differences (by topic)

### 1) Entry points & scope

- nginx-xrootd:
  - native TPC is destination‑pull for `root://` style sources. The code
    allocates a local temp file, posts a worker task to an nginx thread pool,
    then performs synchronous XRootD opcode exchanges over a TCP socket
    implemented in `src/tpc/`.
  - HTTP/WebDAV COPY uses the WebDAV module's `tpc.c` and libcurl transfer
    helper code in `tpc_curl.c`. Long transfers run off the event loop, and
    marker mode streams a 202 response while a thread-pool task performs the
    transfer.
- official xrootd:
  - supports the full HTTP TPC lifecycle: redirection to disk servers, disk
    server multistream pulls/pushes, and both push/pull flows implemented
    inside the server using libcurl multi APIs.

Implication: nginx-xrootd is pragmatic and compact; official xrootd integrates
TPC deeply into its HTTP stack and avoids external helpers.

### 2) Supported source schemes

- nginx-xrootd: native TPC: `root://` only; WebDAV TPC: `https://` via curl.
- official xrootd: HTTP(S) TPC (native multi‑stream), supports disk-server
  redirection semantics and additional schemes handled by its OSS layer.

### 3) Authentication & delegation

- nginx-xrootd:
  - native TPC supports the source/destination rendezvous key flow and can
    complete ztn or GSI after `kXR_authmore` when configured. TLS-upgraded
    origins and multihop delegation remain narrower than upstream.
  - WebDAV TPC collects `TransferHeader*`, can use configured cert/key/CA
    material, and supports `Credential: oidc-agent` and
    `Credential: token-exchange` via `src/webdav/tpc_cred.c` and
    `src/webdav/tpc_cred_parse.c`.
- official xrootd:
  - supports TransferHeader and credential forwarding, integrates
    authz→opaque CGI mapping and can include client-supplied authz in the
    remote PUT/GET when requested. Also includes CA/CRL handling callbacks.

To reach fuller parity: expand native TPC credential edge cases and keep
credential forwarding locked behind explicit policy checks.

### 4) SSRF / address policy

- nginx-xrootd: has an explicit SSRF guard rejecting loopback (127/8, ::1)
  and IPv6 link-local addresses in `src/tpc/connect.c::tpc_addr_is_prohibited()`.
  RFC1918 private ranges are intentionally allowed.
- official xrootd: uses libcurl socket callbacks to reject local/private
  addresses by configuration (`allow_private` / `allow_local`).

Parity note: official xrootd provides more runtime configurability for these
policies — adding similar config flags in nginx-xrootd is advised.

### 5) Concurrency & I/O model

- nginx-xrootd:
  - native TPC uses blocking sockets inside an nginx thread‑pool task. That
    is simple and robust but incurs task dispatch and blocking overhead.
  - WebDAV TPC uses libcurl from worker/helper paths. Multi-stream pull uses
    `curl_multi` with Range GET and `pwrite`, but it is still not integrated
    into nginx's event loop the way upstream XrdHttpTpc is integrated into the
    XRootD HTTP stack. Some credential exchange modes use subprocess helpers.
- official xrootd:
  - HTTP TPC uses libcurl multi APIs with a multi‑handle, multi‑stream
    scheduling layer (`XrdHttpTpcMultistream.cc`), pipelining, and careful
    buffer management to drive parallel transfers without blocking server
    threads.

This is one of the largest practical differences: nginx-xrootd has practical
multi-stream support, but official xrootd's TPC engine is more deeply integrated
with its HTTP/TPC scheduler and monitoring model.

### 6) Chunking, perf markers & client experience

- nginx-xrootd: native TPC streams raw XRootD read responses into the file.
  IMPLEMENTED: perf‑marker multipart streaming for HTTP/WebDAV TPC COPYs is now
  implemented in `src/webdav/tpc_marker.c` (202 Accepted + chunked WLCG
  Performance-Marker blocks, including per-stripe markers for multi-stream
  pulls).
- official xrootd: emits periodic "Perf Marker" chunks (see
  `XrdHttpTpcTPC.cc`) to inform clients of progress during long transfers;
  it also supports returning an early 202 + chunked response and continuing
  the transfer asynchronously while the client receives periodic updates.

### 7) Timeout, retry and error semantics

- nginx-xrootd: uses simple socket-level timeouts per TPC connect/read and
  best-effort remote close; error detail is logged but retry policies are
  minimal.
- official xrootd: has configurable initial and idle timeouts, multi-handle
  failure propagation, and more nuanced rules about how to abort and notify
  the client (including status relaying from origin to client).

### 8) Commit/atomic semantics

- Both implement the safe pattern of writing to a temp file and linking/renaming
  into place on success. nginx-xrootd uses `tmp_path` + `rename/link` logic in
  `src/webdav/tpc.c` and the native TPC launcher stages a local file and then
  returns the open response once the pull finishes (see `src/tpc/done.c`).

### 9) Monitoring and metrics

- nginx-xrootd: simple counters in WebDAV (pull started/success/fail) exist
  but there is no TPC-level streaming JSON monitor comparable to xrootd's
  `XrdXrootdTpcMon` tracking per-transfer metrics and reporting JSON to a
  dedicated stream.
- official xrootd: integrated TPC monitoring and JSON lines export used by
  operations dashboards.


## Parity roadmap — concrete tasks

Below are prioritized tasks to bring nginx-xrootd's TPC feature set closer
to the official xrootd behaviour. Each item contains a short implementation
note and an estimated effort (Small / Medium / Large).

1) Tighten HTTP TPC integration and scheduling (Large)
   - Reduce remaining helper/thread/process dependencies where practical.
   - Align multi-stream scheduling, block sizing, and pipelining controls more
     closely with `XrdHttpTpcMultistream.cc`.
   - Keep the existing opensocket/closesocket callbacks for SSRF pinning and
     packet marking.
   - Benefit: better throughput predictability and easier operational tuning.

2) Expand perf-marker compatibility and tests (Small to Medium)
   - 202 + chunked WLCG Performance-Marker streaming is implemented in
     `src/webdav/tpc_marker.c`; add compatibility tests against clients that
     depend on upstream marker timing and final-marker details.

3) Credential delegation hardening (Small to Medium)
   - WebDAV `TransferHeader*`, `Credential: oidc-agent`, and
     `Credential: token-exchange` support exist. Continue hardening explicit
     policy checks, logging, and failure modes.
   - For native `root://` pulls, expand tests around ztn/GSI after
     `kXR_authmore`, TLS-upgraded origins, and multihop delegation.

4) Make SSRF policy configurable (Small)
   - Add nginx directives to permit/deny private or local IPs per-site.
   - Map to socket callback/`tpc_addr_is_prohibited()` behavior.

5) Add TPC monitoring (Small → Medium)
   - Emit JSON lines to a monitoring stream or expose per-transfer metrics
     for Prometheus similar to `XrdXrootdTpcMon`.

6) Improve timeouts, retries, and error propagation (Small → Medium)
   - Add configurable `first_timeout` and `idle_timeout` and propagate origin
     HTTP/XRootD error codes to the client where appropriate.

7) Tests and CI (Small)
   - Add integration tests under `tests/`:
     - authenticated source pull for native ztn/GSI and WebDAV OIDC modes,
     - SSRF attempts (loopback, link-local) should be rejected,
     - multi-stream throughput test (compare single vs multi stream),
     - perf-marker observation tests for chunked responses.

Estimated order: 1 → 2 → 3 → 5 → 6 → 4 → 7, but you may reorder based on
priority (e.g., implement SSRF configurability early for safety).

## Suggested nginx config directives

Add a small set of `xrootd_webdav_tpc_*` directives to make behavior tunable:

- `xrootd_webdav_tpc_enable on|off` — enable internal HTTP TPC.
- `xrootd_webdav_tpc_block_size <bytes>` — block size for multi-stream pulls.
- `xrootd_webdav_tpc_max_streams <N>` — cap streams per transfer.
- `xrootd_webdav_tpc_marker_interval <sec>` — perf marker interval.
- `xrootd_webdav_tpc_allow_local on|off` — control loopback/link-local.
- `xrootd_webdav_tpc_allow_private on|off` — allow RFC1918 private ranges.
- `xrootd_webdav_tpc_cacert <path>` / `xrootd_webdav_tpc_cert` / `tpc_key` — CA/cred options.

These map directly to the knobs used in the official `XrdHttpTpc` module.

## Tests to validate parity

- Auth-required origin test: start origins requiring XRootD ztn/GSI and WebDAV
  OIDC/token-exchange credentials, then verify successful and negative paths.
- SSRF negative tests: try `tpc.src=root://127.0.0.1//...` and link-local
  addresses — module should reject these as in `connect.c`.
- Multi-stream throughput test: compare current single-threaded pull vs the
  new libcurl multi implementation across concurrency sweep (use existing
  `tests/load_test.py` harness interleaving mode).
- Perf-marker test: send a client COPY that expects periodic perf markers
  and assert markers are received at configurable intervals.

## Notes & caveats

- Native `root://` TPC and HTTP TPC are different beasts: native uses raw
  XRootD opcodes and must preserve wire semantics; HTTP TPC is built on
  HTTP/WebDAV semantics (multi‑stream, chunked responses). Consider keeping
  both codepaths but sharing helper abstractions (config, metrics, SSRF
  policy) to reduce duplication.
- Security: credential delegation is a significant security surface. Existing
  delegation paths must remain locked behind explicit configuration and
  validated against policy (allowed hosts, token expiry, scope checks).

## Next steps

1. Prioritize the remaining gaps: monitoring, retry/error semantics, SSRF
   configurability, and native TPC credential edge cases.
2. Add compatibility tests against official `XrdHttpTpc` behavior for markers,
   multistream, delegation, and error propagation.
3. Iterate on hardening, especially CRL/CA policy, token expiry, and transfer
   observability.
