# TPC: BriX-Cache vs official xrootd

A concrete side-by-side of where BriX-Cache's third-party copy support
matches the official XRootD implementation, where it diverges, and why. Read
this before writing TPC-related tests or integrating with WLCG FTS.

## What TPC is

Third-party copy moves bytes **directly between two storage endpoints** while a
client only orchestrates. The payload never flows through the client — it just
sends control requests and watches for completion.

```text
        ┌──────────┐   1. "copy SRC → DST"   ┌──────────────┐
        │  client  │ ───────────────────────▶│ destination  │
        │  (FTS,   │                          │ (this server)│
        │  gfal…)  │◀────── 4. result ────────│              │
        └──────────┘                          └──────┬───────┘
                                                     │ 2. pull
              data path bypasses the client          │    bytes
                                                     ▼
                                              ┌──────────────┐
                                              │   source     │
                                              │  (origin)    │
                                              └──────────────┘
                                       3. bulk data: SRC ──▶ DST only
```

Two transports carry this in BriX-Cache:

```text
  NATIVE root:// pull (src/tpc/)            HTTP/WebDAV COPY (src/protocols/webdav/tpc*.c)
  ───────────────────────────────          ─────────────────────────────────────
  client ── kXR_open(tpc.stage) ─▶ DST      client ── COPY + Source: hdr ─▶ DST
  DST    ── rendezvous key ──────▶ SRC      DST    ── libcurl GET ────────▶ SRC
  DST    ◀═ raw XRootD reads ═════ SRC      DST    ◀═ Range GET streams ═══ SRC
  DST    ── kXR_open response ───▶ client   DST    ── 202 + perf-markers ─▶ client
         (blocking task, 1 stream)                 (multi-stream curl, markers)
```

## Executive summary

- BriX-Cache implements two practical TPC paths:
  - native destination-side XRootD pull and source rendezvous implemented in
    `src/tpc/` (root:// sources).
  - HTTP/WebDAV TPC implemented in `src/protocols/webdav/tpc*.c` with libcurl-based
    pull/push, TransferHeader handling, OAuth2/OIDC delegation, performance
    markers, and optional multi-stream Range GET.
- Official xrootd (`XrdHttpTpc`) provides a full-featured HTTP(S) TPC handler
  built on libcurl multi/pipelining with perf markers, monitoring, CA/CRL
  integration, multi‑stream transfers, and richer auth/delegation wiring.
- Key remaining gaps in BriX-Cache vs official xrootd: upstream-style
  in-server TPC integration, richer timeout/retry semantics, production TPC
  monitoring hooks and more configurable SSRF policy (native root TPC pulls
  now follow redirects and run multi-stream: `brix_tpc_max_hops`,
  `brix_tpc_streams`).

## Where to read the implementations

- BriX-Cache (module):
  - native TPC: [src/tpc/](../../src/tpc/)
    - `src/tpc/engine/launch.c`, `src/tpc/outbound/thread.c`, `src/tpc/outbound/source.c`,
      `src/tpc/outbound/bootstrap.c`, `src/tpc/outbound/connect.c`, `src/tpc/engine/tpc_internal.h`
  - HTTP/WebDAV TPC glue: [src/protocols/webdav/tpc.c](../../src/protocols/webdav/tpc.c),
    [src/protocols/webdav/tpc_curl.c](../../src/protocols/webdav/tpc_curl.c),
    `src/protocols/webdav/tpc_cred.c` (OAuth2/OIDC token handling),
    `src/protocols/webdav/tpc_cred_parse.c` (token parsing),
    `src/protocols/webdav/tpc_marker.c` (perf-marker generation),
    `src/protocols/webdav/tpc_thread.c` (async transfer threading)

- official xrootd (reference): key code is in the `XrdHttpTpc` plugin
  (example files under a reference tree used for earlier comparisons):
  - `/tmp/brix-src/src/XrdHttpTpc/` (e.g. `XrdHttpTpcTPC.cc`,
    `XrdHttpTpcUtils.cc`, `XrdHttpTpcMultistream.cc`) and monitoring in
    `/tmp/brix-src/src/XrdXrootd/XrdXrootdTpcMon.cc`.

Note: reference xrootd files above are external to this workspace; the
module source links above point into this repository.

## Detailed differences (by topic)

### 1) Entry points & scope

- BriX-Cache:
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

Implication: BriX-Cache is pragmatic and compact; official xrootd integrates
TPC deeply into its HTTP stack and avoids external helpers.

### 2) Supported source schemes

- BriX-Cache: native TPC: `root://` only; WebDAV TPC: `https://` via curl.
- official xrootd: HTTP(S) TPC (native multi‑stream), supports disk-server
  redirection semantics and additional schemes handled by its OSS layer.

### 3) Authentication & delegation

- BriX-Cache:
  - native TPC supports the source/destination rendezvous key flow and can
    complete ztn or GSI after `kXR_authmore` when configured, follows source
    redirects up to `brix_tpc_max_hops`, and pulls over up to `brix_tpc_streams`
    bound sub-streams when the client sends `tpc.str`.
  - WebDAV TPC collects `TransferHeader*`, can use configured cert/key/CA
    material, and supports `Credential: oidc-agent` and
    `Credential: token-exchange` via `src/protocols/webdav/tpc_cred.c` and
    `src/protocols/webdav/tpc_cred_parse.c`.
- official xrootd:
  - supports TransferHeader and credential forwarding, integrates
    authz→opaque CGI mapping and can include client-supplied authz in the
    remote PUT/GET when requested. Also includes CA/CRL handling callbacks.

To reach fuller parity: expand native TPC credential edge cases and keep
credential forwarding locked behind explicit policy checks.

### 4) SSRF / address policy

TPC pull is an SSRF primitive: the destination server dials the source
authority named in the request. BriX-Cache defends this with **two independent
layers**, both enforced ahead of any outbound connection and both shared,
byte-for-byte, between the native `root://` plane and the WebDAV COPY plane:

**Layer 1 — address RANGE gate (default-on).** An explicit SSRF guard rejects
loopback (127/8, ::1) and IPv6 link-local addresses in
`src/tpc/outbound/connect.c::tpc_addr_is_prohibited()`. Loopback/link-local are
opened only with `…_tpc_allow_local on`; RFC-1918 private ranges are allowed by
default and closed with `…_tpc_allow_private off`. Refusals read `… prohibited`.

**Layer 2 — source-host NAMING allowlist (default-off, opt-in).** When enabled,
a pull may only name an *allowlisted* source authority — an exact host or, with
a leading `.`, a domain suffix (case-insensitive; the bare apex does not match a
`.suffix` rule — the host must be strictly longer). This is strictly stricter
than Layer 1: it fires *first*, so a non-allowlisted host is refused even when
the range gate would have permitted it (e.g. an RFC-1918 address). The verdict
core is the pure `brix_tpc_source_guard_check()` in
`src/tpc/common/egress_guard.c`, shared so the two planes can never disagree:

- native `root://`: enforced in
  `src/tpc/engine/launch_prepare.c::tpc_prepare_check_preconditions()`; refuses
  with `kXR_NotAuthorized` + `TPC source host not permitted: <host>`.
- WebDAV COPY: enforced in
  `src/protocols/webdav/tpc.c::webdav_tpc_source_guard()`; refuses with
  `403 Forbidden`.

Both refusals emit a `signal=tpc_egress` guard-audit line (banned by the
`[xrootd-guard-tpc_egress]` fail2ban jail) and bump the label-less
`brix_stream_tpc_egress_refused_total` metric. Directives:

- native: `brix_tpc_source_guard on|off`, `brix_tpc_source_allow <host> […]`
- WebDAV: `brix_webdav_tpc_source_guard on|off`,
  `brix_webdav_tpc_source_allow <host> […]`

The allow directive is repeatable and space-separated; a custom setter appends
*every* argument (the stock `ngx_conf_set_str_array_slot` keeps only the first,
silently dropping the rest — an allowlist footgun this codebase has hit before).

official xrootd uses libcurl socket callbacks to reject local/private addresses
by configuration (`allow_private` / `allow_local`); it has no equivalent of the
Layer-2 naming allowlist.

**Layer 3 — identity matrix (default-off, opt-in; 2.0 F18).** Layers 1 and 2 ask
*which host* a leg may talk to. Layer 3 asks *who is asking, how they proved it,
and which local paths they may touch* — the stock `ofs.tpc` grammar, in BriX
spelling. It sits INSIDE the host plane: a matrix rule can only narrow what
Layers 1–2 already permitted, never widen it.

| BriX | stock `ofs.tpc` | what it decides |
|---|---|---|
| `brix_tpc_allow_identity <dn\|group\|host\|vo> <pattern>` | `allow dn/group/host/vo` | whose credential may open a TPC leg |
| `brix_tpc_require <all\|client\|dest> <auth>[,<auth>…]` | `require {all\|client\|dest} <auth>` | which authentication method a party must have used |
| `brix_tpc_restrict <path>` | `restrict <path>` | which local paths a leg may touch |
| `brix_tpc_oids on\|off` | `oids` | whether object-id paths are usable in a TPC leg |

Four facts an operator has to know before adopting it:

1. **Stage order is a security order** — `oids` → `allow` → `require` →
   `restrict`, evaluated in that order at one choke point per plane
   (`tpc_matrix_gate()` in `src/protocols/root/read/open_tpc.c`, covering all
   four native roles before any dial; `webdav_tpc_matrix_gate()` in
   `src/protocols/webdav/tpc.c`). The verdict core is the pure
   `brix_tpc_matrix_check()` in `src/tpc/common/identity_matrix.c`, shared so the
   two planes can never disagree — the same arrangement as the Layer-2 guard.
2. **Every stage is default-PERMIT when unconfigured and fail-CLOSED once
   configured.** A site that never writes these directives sees no behaviour
   change at all; a site that writes one rule has *denied everything that rule
   does not name*, including an anonymous or unauthenticated subject. `oids` is
   the one exception: it is default-DENY, matching stock.
3. **The party is read off the wire, not asserted.** A native TPC leg carrying
   `tpc.org` was opened by the peer SERVER and presents the *server's*
   credential (party `dest`); a leg without `tpc.org` was opened by the
   initiating CLIENT (party `client`). `require dest gsi` is therefore not
   satisfiable by a client credential — which is exactly the point of the
   distinction. On the WebDAV plane the requester is always the client party.
4. **`restrict` is narrower than stock.** The prefix match is
   component-aware, so `/data` admits `/data/x` but never `/database`. It runs
   on the same cleaned logical path an `open()` would use — traversal is already
   refused before the matrix sees it. **On the WebDAV plane that path is the
   request URI**, so a prefix written on a `location` must include the location's
   own prefix: under `location /restrict/`, the rule that confines a COPY to
   `/restrict/allowed/…` is `brix_tpc_restrict /restrict/allowed`, not
   `brix_tpc_restrict /allowed`. A prefix that omits it matches nothing and — the
   stage being fail-closed — refuses every COPY on that location.

Both callers of the HTTP gate are covered: a COPY *pull* (`Source:`) and a COPY
*push* (`Destination:` + `Credential:`) both pass through
`webdav_tpc_authorize()`, so the same rule governs the object arriving and the
object leaving.

Refusals name the directive that denied the leg and nothing else — no DN, VO,
group, host or path is echoed back — and account through the existing TPC
error paths rather than a new metric family.

### 5) Concurrency & I/O model

- BriX-Cache:
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

This is one of the largest practical differences: BriX-Cache has practical
multi-stream support, but official xrootd's TPC engine is more deeply integrated
with its HTTP/TPC scheduler and monitoring model.

### 6) Chunking, perf markers & client experience

- BriX-Cache: native TPC streams raw XRootD read responses into the file.
  IMPLEMENTED: perf‑marker multipart streaming for HTTP/WebDAV TPC COPYs is now
  implemented in `src/protocols/webdav/tpc_marker.c` (202 Accepted + chunked WLCG
  Performance-Marker blocks, including per-stripe markers for multi-stream
  pulls).
- official xrootd: emits periodic "Perf Marker" chunks (see
  `XrdHttpTpcTPC.cc`) to inform clients of progress during long transfers;
  it also supports returning an early 202 + chunked response and continuing
  the transfer asynchronously while the client receives periodic updates.

### 7) Timeout, retry and error semantics

- BriX-Cache: uses simple socket-level timeouts per TPC connect/read and
  best-effort remote close; error detail is logged but retry policies are
  minimal.
- official xrootd: has configurable initial and idle timeouts, multi-handle
  failure propagation, and more nuanced rules about how to abort and notify
  the client (including status relaying from origin to client).

### 8) Commit/atomic semantics

- Both implement the safe pattern of writing to a temp file and linking/renaming
  into place on success. BriX-Cache uses `tmp_path` + `rename/link` logic in
  `src/protocols/webdav/tpc.c` and the native TPC launcher stages a local file and then
  returns the open response once the pull finishes (see `src/tpc/engine/done.c`).
- **Completion gate before the commit (BriX-Cache only).** Staging alone does not
  say the *whole* file arrived: "curl stopped without an error" is also what a
  chunked source that dies mid-body, a truncating middlebox, or a corrupting one
  produce. Two opt-in directives close that, mirroring the native pair
  `brix_tpc_require_source_size` / `brix_tpc_verify_checksum`:
  - `brix_webdav_tpc_require_source_size on|off` (default off)
  - `brix_webdav_tpc_verify_checksum <alg>` (default unset; any algorithm
    `brix_checksum_parse` accepts — `adler32`, `crc32`, `crc32c`, `md5`, `sha1`,
    `sha256`, `crc64`, `crc64nvme`, `zcrc32` — validated at config parse time, so
    a typo is `[emerg]` rather than a silently disabled gate)

  When either is on, `webdav_tpc_verify_pulled()`
  (`src/protocols/webdav/tpc_verify.c`) issues one HEAD against the source —
  carrying `Want-Digest: <alg>` when the checksum half is on — over the same
  secured handle configuration the pull used (TLS pin, rebind guard, client
  credential, transfer headers). The declared `Content-Length` is compared with
  the staged temp's size (a disagreement is unambiguous truncation and always
  refuses; a source that declares *no* length refuses only under
  `require_source_size`), then the returned RFC-3230 `Digest` is recomputed over
  the temp through a confined `brix_vfs_open_fd()`. The checksum half is
  fail-closed: no `Digest`, an unparseable one, an algorithm brix cannot compute,
  or a mismatch all refuse. Refusals are `502`; every pull tier already treats
  that as a failed transfer, so the staged temp is aborted and nothing is
  published. The gate hangs off `webdav_tpc_run_curl_pull()` and the multi-stream
  Range driver, which between them cover all three tiers (202-marker, thread-pool,
  synchronous) exactly once. Push is unaffected — both gates are pull concepts.
  Tests: `tests/test_webdav_tpc_completion_gate.py`.

### 9) Monitoring and metrics

- BriX-Cache: simple counters in WebDAV (pull started/success/fail) exist
  but there is no TPC-level streaming JSON monitor comparable to xrootd's
  `XrdXrootdTpcMon` tracking per-transfer metrics and reporting JSON to a
  dedicated stream.
- official xrootd: integrated TPC monitoring and JSON lines export used by
  operations dashboards.


## Parity roadmap — concrete tasks

Below are prioritized tasks to bring BriX-Cache's TPC feature set closer
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
     `src/protocols/webdav/tpc_marker.c`; add compatibility tests against clients that
     depend on upstream marker timing and final-marker details.

3) Credential delegation hardening (Small to Medium)
   - WebDAV `TransferHeader*`, `Credential: oidc-agent`, and
     `Credential: token-exchange` support exist. Continue hardening explicit
     policy checks, logging, and failure modes.
   - For native `root://` pulls, expand tests around ztn/GSI after
     `kXR_authmore` against production sources (TLS upgrade, multihop and
     multi-stream are covered by `tests/test_release20_tpc_*.py`).

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

## Configuration directives (as implemented)

The `brix_webdav_tpc_*` family is registered in
`src/protocols/webdav/directives_tpc.h`; every name below is real and listed in
[`directives.md`](../03-configuration/directives.md). (An earlier draft of this
section proposed `brix_webdav_tpc_enable`, `brix_webdav_tpc_block_size`,
`brix_webdav_tpc_cacert` and `brix_webdav_tpc_source_guard/_source_allow`; none
of those spellings exists — use the names here.)

- `brix_webdav_tpc on|off` — enable HTTP TPC (COPY with `Source:`/`Destination:`).
- `brix_webdav_tpc_max_streams <N>` — cap streams per transfer.
- `brix_webdav_tpc_marker_interval <sec>` — perf-marker interval.
- `brix_webdav_tpc_xfr <N>` — explicit concurrent-transfer cap (the `ofs.tpc
  xfr` analog): a new `COPY` beyond `N` in-flight transfers is refused with
  `503`. Counts live in-use registry slots (an abandoned transfer is reaped
  first, so it never permanently counts). `0` (default) = bound only by the
  compile-time registry slot ceiling.
- `brix_webdav_tpc_timeout <time>`, `brix_webdav_tpc_low_speed_bytes <n>` /
  `brix_webdav_tpc_low_speed_secs <n>` — overall and stall timeouts on the
  pull leg.
- `brix_webdav_tpc_curl <path>` — the curl binary the pull leg execs.
- `brix_tpc_allow_local on|off` / `brix_tpc_allow_private on|off` — loopback,
  link-local and RFC1918 source ranges (SSRF Layer 1).
- `brix_tpc_source_guard on|off` + `brix_tpc_source_allow <host> […]` — source-host
  naming allowlist (SSRF Layer 2; see §4), shared with native root:// TPC.
- `brix_tpc_allow_identity <dn|group|host|vo> <pattern>` (repeatable),
  `brix_tpc_require <all|client|dest> <auth>[,<auth>…]`,
  `brix_tpc_restrict <path>` (repeatable) and `brix_tpc_oids on|off` — the
  `ofs.tpc` identity matrix (Layer 3; see §4), also shared with native
  root:// TPC. All four are unset by default and each is fail-closed once
  written; `brix_tpc_oids` is default-deny.
- `brix_webdav_tpc_cafile <path>` / `brix_webdav_tpc_cadir <dir>` /
  `brix_webdav_tpc_cert` / `brix_webdav_tpc_key` — CA and credential material
  for the source connection.
- `brix_webdav_tpc_credential_forward on|off` — forward the requester's
  per-user proxy or bearer to the source (default on, opportunistic).
- `brix_tpc_require_source_size on|off` + `brix_tpc_verify_checksum <alg>` —
  pull completion gate (size + RFC-3230 digest; see §8), unified with the
  stream-plane spellings in phase 101. No `XrdHttpTpc` equivalent.

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
