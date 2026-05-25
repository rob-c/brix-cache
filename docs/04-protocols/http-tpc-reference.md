# TPC: nginx-xrootd vs official xrootd

A concrete side-by-side of where nginx-xrootd's third-party copy support matches the official XRootD implementation, where it diverges, and why. Read this before writing TPC-related tests or integrating with WLCG FTS.
provides a practical roadmap to expand the module to approach parity.

## Executive summary

- nginx-xrootd implements two practical TPC paths:
  - native destination‑side XRootD pull implemented in `src/tpc/` (root:// sources).
  - HTTP/WebDAV TPC implemented in `src/webdav/tpc*.c` — implemented as a curl
    helper (`fork`/`exec`) that downloads into a temp file.
- Official xrootd (`XrdHttpTpc`) provides a full-featured HTTP(S) TPC handler
  built on libcurl multi/pipelining with perf markers, monitoring, CA/CRL
  integration, multi‑stream transfers, and richer auth/delegation wiring.
- Key gaps in nginx‑xrootd vs official xrootd: integrated libcurl multi, perf
  markers and chunked responses, multi‑stream parallelism, credential
  delegation support, richer timeout/retry semantics, and production TPC
  monitoring hooks.

## Where to read the implementations

- nginx-xrootd (module):
  - native TPC: [src/tpc/](src/tpc/)
    - `src/tpc/launch.c`, `src/tpc/thread.c`, `src/tpc/source.c`,
      `src/tpc/bootstrap.c`, `src/tpc/connect.c`, `src/tpc/tpc_internal.h`
  - HTTP/WebDAV TPC glue: [src/webdav/tpc.c](src/webdav/tpc.c),
    [src/webdav/tpc_curl.c](src/webdav/tpc_curl.c)

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
  - HTTP/WebDAV COPY (client→server) uses `webdav` module `tpc.c` and when
    performing an HTTPS pull it calls an external `curl` binary (`tpc_curl.c`).
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
  - native TPC bootstraps with an anonymous `kXR_login` in `bootstrap.c` and
    fails if source requires authentication. `tpc.key` is appended to the
    source open query if provided and passed verbatim to the origin.
  - WebDAV TPC rejects credential delegation (requires `Credential: none`)
    and uses `curl` arguments for cert/key when configured server‑side.
- official xrootd:
  - supports TransferHeader and credential forwarding, integrates
    authz→opaque CGI mapping and can include client-supplied authz in the
    remote PUT/GET when requested. Also includes CA/CRL handling callbacks.

To reach parity: implement controlled credential forwarding for HTTP TPC
and enable non‑anonymous bootstrap paths (native and HTTP), ensuring secure
validation and policy checks (see parity tasks below).

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
  - WebDAV TPC uses `fork` + external `curl`, blocking the parent until
    child exits.
- official xrootd:
  - HTTP TPC uses libcurl multi APIs with a multi‑handle, multi‑stream
    scheduling layer (`XrdHttpTpcMultistream.cc`), pipelining, and careful
    buffer management to drive parallel transfers without blocking server
    threads.

This is one of the largest practical gaps: matching official throughput and
scalability requires an integrated multi‑stream, nonblocking HTTP engine.

### 6) Chunking, perf markers & client experience

- nginx-xrootd: native TPC streams raw XRootD read responses into the file;
  there is no server→client perf‑marker multipart stream for long-running
  COPYs. WebDAV TPC (curl) gives no structured perf‑markers back to the
  client beyond curl's exit status.
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

1) Integrate HTTP TPC directly using libcurl multi (Large)
   - Replace the external `curl` helper (`src/webdav/tpc_curl.c`) with an
     internal libcurl multi-based implementation similar to
     `XrdHttpTpcMultistream.cc`.
   - Implement opensocket and closesocket callbacks to reuse the module's
     SSRF and packet-marking logic.
   - Add a multi-stream scheduler, block-size and pipelining multiplier
     config (e.g. `xrootd_tpc_block_size`, `xrootd_tpc_streams`).
   - Benefit: parallel, nonblocking transfers with much higher throughput.

2) Add perf-marker and chunked early response support (Medium)
   - Implement server-side 202 + chunked multipart behavior to send periodic
     performance markers to the client while the transfer proceeds.
   - Mirror `SendPerfMarker()` semantics from official code to support
     monitoring clients.

3) Credential delegation & TransferHeader support (Medium)
   - Implement `TransferHeader*` mapping in WebDAV TPC and allow controlled
     forwarding of client `Authorization` or explicit transfer headers.
   - For native `root://` pulls, add a secure path to perform non-anonymous
     `kXR_login` when the module is configured to forward credentials or when
     a validated `tpc.key` is present.

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
     - authenticated source pull (expect failure until delegation implemented),
     - SSRF attempts (loopback, link-local) should be rejected,
     - multi-stream throughput test (compare single vs multi stream),
     - perf-marker observation tests for chunked responses.

Estimated order: 1 → 2 → 3 → 5 → 6 → 4 → 7, but you may reorder based on
priority (e.g., implement SSRF configurability early for safety).

## Suggested nginx config directives

Add a small set of `xrootd_webdav_tpc_*` directives to make behavior tunable:

- `xrootd_webdav_tpc_enable on|off` — enable internal HTTP TPC.
- `xrootd_webdav_tpc_block_size <bytes>` — block size for multi-stream pulls.
- `xrootd_webdav_tpc_streams <N>` — streams per transfer.
- `xrootd_webdav_tpc_marker_period <sec>` — perf marker interval.
- `xrootd_webdav_tpc_allow_local on|off` — control loopback/link-local.
- `xrootd_webdav_tpc_allow_private on|off` — allow RFC1918 private ranges.
- `xrootd_webdav_tpc_cacert <path>` / `xrootd_webdav_tpc_cert` / `tpc_key` — CA/cred options.

These map directly to the knobs used in the official `XrdHttpTpc` module.

## Tests to validate parity

- Auth-required origin test: start an origin requiring XRootD login, attempt
  an nginx-xrootd native TPC pull (should fail until delegation is added).
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
- Security: credential delegation is a significant security surface. Any
  delegation design must be locked behind explicit configuration and
  validated against policy (allowed hosts, token expiry, scope checks).

## Next steps

1. Review this doc and pick an initial target (e.g., internal libcurl multi
   TPC or SSRF configurability). 2. I can implement the chosen item and add
   tests and CI. 3. Iterate on hardening (CRL, perf markers, monitoring).

If you want, I can start by implementing the internal libcurl multi HTTP TPC
or add SSRF flags and the small tests first — which would you prefer?
