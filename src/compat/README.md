# compat — Cross-protocol shared primitives (checksums, HTTP, paths, filesystem, SSRF)

## Overview

`src/compat` is the module's library of **protocol-neutral building blocks**: small, focused helpers that the three protocol front-ends (`root://` stream, WebDAV/HTTP, S3 REST) plus the cluster/proxy/TPC machinery all share so they cannot drift apart. Nothing here owns a request lifecycle or a wire dialect; each file does one job — compute a CRC32c, parse a Range header, write a request body to an fd, build an Allow header, resolve a URL host against an SSRF policy — and does it identically for every caller. The directory's reason to exist is the project's core rule: *use helpers, never reimplement path/auth/metrics/framing* (see the root `CLAUDE.md`). When a checksum, error-code mapping, or path-confinement decision needs to change, it changes here once.

Despite the historical name "compat", this is not a thin compatibility shim over nginx — it is the de-duplication layer. Earlier files such as `cors.c`, `io.c`, `http_protocol_vars.c`, `kxr_errno.c`, and `result_mapper.c` have been **folded into the surviving consolidated files** (e.g. `error_mapping.c` now carries the errno→kXR, errno→HTTP, and namespace-status→HTTP maps that three separate files used to). `result_mapper.h` survives only as a back-compat alias header whose two prototypes are now defined in `error_mapping.c`.

These helpers sit *below* the protocol handlers in every request lifecycle. A WebDAV `GET` calls `xrootd_http_parse_range` → `xrootd_http_set_file_headers` → `xrootd_http_send_file_range`; an S3 `ListObjectsV2` calls `xrootd_fs_walk` + `xrootd_http_chain_appendf` + `xrootd_xml_write_text_element`; a native `kXR_Qcksum` calls `xrootd_integrity_get_fd` → `xrootd_checksum_hex_fd`; every mutating op (`rm`, `mkdir`, `mv`, WebDAV `MKCOL`/`DELETE`/`MOVE`, S3 `PutObject`/`DeleteObjects`) routes through `xrootd_ns_*` in `namespace_ops.c`. Outbound transfers (native TPC, WebDAV HTTP-TPC) gate on `net_target.c`'s SSRF policy.

Two invariants make this directory load-bearing for security: (1) every namespace mutation and staged write here re-resolves the client path under the export root with the kernel's `openat2(RESOLVE_BENEATH)` API (via `../path/beneath.h`) — confinement is enforced at the syscall, not assumed from an upstream check; and (2) all outbound network targets pass a DNS-rebind-safe SSRF classifier before any byte is sent.

## Files

### Checksums & hex

| File | Responsibility |
|---|---|
| `crc32c.c` / `crc32c.h` | CRC-32c (Castagnoli) engine: SSE4.2 hardware (`_mm_crc32_u64`), a 3-way-parallel hardware path for large buffers (≥768 B, Mark-Adler GF(2) recombination), and a bit-by-bit software fallback. `xrootd_crc32c_extend/_value/_copy_value`. Backs pgread/pgwrite per-page CRC (Invariant #1) and TPC copy-with-checksum. |
| `checksum.c` / `checksum.h` | Multi-algorithm file checksum: `xrootd_checksum_alg_t` (adler32/crc32/crc32c via zlib+crc32c; md5/sha1/sha256 via OpenSSL EVP). Parse names, classify u32-vs-digest, compute from an fd (64 KB `pread` loop, EINTR-safe), emit hex. Entry point `xrootd_checksum_hex_name_fd`. |
| `integrity_info.c` / `integrity_info.h` | Checksum **cache + policy** layer over `checksum.c`: reads/writes a `user.XrdCks.<alg>` xattr keyed by mtime+size (stale on change), formats RFC-3230 HTTP `Digest` values, invalidates by fd or path after writes. Shared by kXR_Qcksum, XrdHttp Want-Digest, dirlist dcksm, S3 ETag. |
| `hex.c` / `hex.h` | Nibble↔char and byte-array→hex string. NOTE: `xrootd_hex_encode` emits **lowercase** hex; `xrootd_hex_nibble` emits **uppercase** (used by `xml.c` `%XX` control-escaping). |
| `crypto.c` / `crypto.h` | Worker-lifecycle OpenSSL HMAC-SHA256 + SHA-256 singletons. `EVP_MAC`/`EVP_MD` fetched once at `init_process`, freed at `exit_process`; per-call cost is just a CTX alloc. Used by GSI `kXR_sigver` and S3 SigV4. |

### HTTP request/response helpers

| File | Responsibility |
|---|---|
| `http_headers.c` / `http_headers.h` | Case-insensitive `headers_in` lookup, `Authorization: Bearer` extraction, control-char validation, whitespace-trimmed value compare, response/request header insertion (`set_header`/`_str`/`_num`), and the canonical handler-rc→HTTP-status mapper `xrootd_http_effective_status` (keeps WebDAV/S3 metric buckets aligned). |
| `http_body.c` / `http_body.h` | nginx request-body chain (`request_body->bufs`, mixed memory + spooled-to-file): summarise byte count/layout, write whole body to an fd (`copy_file_range` for file bufs, `pwrite` for memory), read all into one pool buffer, gzip/deflate **inflate**-to-fd, and the `ngx_http_read_client_request_body` dispatch wrapper. |
| `http_file_response.c` / `http_file_response.h` | File-backed serving for WebDAV GET & S3 GET/HEAD: ETag/Content-Range header construction, the standard status+length+type+ETag block (`set_file_headers`), single-range send (`send_file_range`, sets `last_buf`, optional fd pool-cleanup), and multi-range chain append (`chain_append_file_range`). Uses nginx sendfile — see gotcha below. |
| `http_conditionals.c` / `http_conditionals.h` | RFC 7232 conditionals: `If-Match`/`If-None-Match` (with `*` wildcard and weak-ETag equivalence), `If-Modified-Since`, and WebDAV `Overwrite: F`. Returns 304 / 412 / NGX_OK. |
| `http_query.c` / `http_query.h` | Bounded `?key=value` scanner over `r->args` (one `ngx_str_t`): case policy, percent-decode, `+`→space, NUL-reject, truncation, bare-flag detection. `xrootd_http_query_get`/`_has`. Drives S3 ListObjectsV2 / multipart query parsing. |
| `http_xml.c` / `http_xml.h` | Incremental XML response chain builder (`chain_appendf`/`vappendf`, stack tmp[2048] → pool overflow), single-buffer XML send, and a protocol-agnostic `<Error><Code><Message>` sender (S3 + REST). |
| `range.c` / `range.h` | Single-range RFC 7233 `bytes=` parser (`xrootd_http_range_t`: present + satisfiable). Thin facade over `range_vector.c` in single-range mode. |
| `range_vector.c` / `range_vector.h` | Multi-range parse/normalise/validate + contiguous-run coalescing. Shared by XrdHttp multipart byteranges, single-range HTTP, and native `kXR_readv` I/O coalescing. |
| `uri.c` / `uri.h` | RFC 3986 percent-decode (nginx-lenient: malformed `%` passes verbatim) and percent-encode (uppercase hex, configurable `safe_extra`). The encoder feeds S3 SigV4 canonicalisation. |
| `xml.c` / `xml.h` | XML escaping (`& < > " '`, optional `&apos;` and control-char `%XX`), `<name>escaped</name>` element builder with name validation, and WebDAV `<lockinfo>` parsing via **libxml2** (`XML_PARSE_NONET|NOERROR|NOWARNING`, `XML_PARSE_NO_XXE` when available). `xrootd_xml_backend_name()` returns `"libxml2"`. |
| `etag.c` / `etag.h` | RFC 7232 ETag string from mtime+size, strong or `W/`-weak (`XROOTD_ETAG_WEAK`), matching XrdHttp's `"%lx-%llx"` convention. |
| `protocol_caps.c` / `protocol_caps.h` | Shared HTTP-operation descriptor (`xrootd_http_operation_t`: name, method, metric slot, access-op, capability flags) plus method→op lookup and flag-filtered `Allow` / `Access-Control-Allow-Methods` builder. WebDAV & S3 keep their own tables; these helpers just search/format. |

### Filesystem & namespace mutation

| File | Responsibility |
|---|---|
| `namespace_ops.c` / `namespace_ops.h` | **The mandatory mutation gateway.** `xrootd_ns_delete/_mkdir/_rename/_local_copy` over already-resolved paths, each opening a `RESOLVE_BENEATH` rootfd and routing every stat/open/unlink/mkdir/rename through `../path/beneath.h`. Neutral `xrootd_ns_status_t` result; recursive-vs-empty, overwrite, staged-commit, xattr-preserve policies. INVARIANT: protocol handlers MUST use these, not raw `*_beneath` calls. |
| `fs_walk.c` / `fs_walk.h` | Directory traversal: dot-entry check, path join, empty-dir probe, options-driven recursive `xrootd_fs_walk` (depth/hidden/files-vs-dirs/cross-device), and confined recursive `xrootd_fs_remove_tree_confined` (unlinks/rmdir via beneath API). Backs dirlist, PROPFIND collections, S3 ListObjects, recursive DELETE/MOVE. |
| `fs_usage.c` / `fs_usage.h` | `statvfs(2)` → total/free/available/used bytes + occupancy ppm (`xrootd_fs_usage_t`). For Prometheus, PROPFIND quota, and `kXR_query` space. |
| `staged_file.c` / `staged_file.h` | Crash-safe atomic write lifecycle: `open` a unique `O_EXCL` temp under the confined root → write → `commit` (atomic rename) or `abort` (close+unlink). All three phases go through `RESOLVE_BENEATH`. Used by S3 PUT, WebDAV PUT/COPY. |
| `tmp_path.c` / `tmp_path.h` | Uniform temp name `<base>.xrd-tmp.<pid>.<random>` — one glob (`*.xrd-tmp.*`) cleans orphans from every subsystem. |
| `copy_range.c` / `copy_range.h` | `copy_file_range(2)` zero-copy with `pread`/`pwrite` 256 KB fallback on `EXDEV/ENOSYS/EOPNOTSUPP/EINVAL/EPERM`. **Blocking** — thread-pool/post-accept only. Backs kXR_clone, kXR_chkpoint, ns local copy, HTTP body→fd. |
| `path.c` / `path.h` | `XROOTD_PATH_MAX`/`_MIN` constants and `xrootd_http_resolve_path`: validates depth + rejects `.`/`..` components, then produces the lexical `root_canon`+`decoded_path` join for ACL/logging. Does NO existence check and NO `realpath` — real confinement happens at the op via RESOLVE_BENEATH. Returns 0 or an HTTP status (400/403/414). |

### Networking, async, time, logging, SHM

| File | Responsibility |
|---|---|
| `net_target.c` / `net_target.h` | Outbound URL parser + **SSRF guard** for native TPC, WebDAV HTTP-TPC, future S3 remote-copy. Zero-copy URL split (scheme/host/port/path, IPv6 literals), per-address prohibited-range classification (loopback/link-local/RFC-1918/ULA, v4-mapped), blocking DNS check, and `check_dns_pin` which validates *every* resolved address and returns the first to pin (closes the DNS-rebind TOCTOU). `xrootd_net_host_chars_valid` blocks CRLF/scheme injection into redirect strings. DNS calls are **thread-only**. |
| `async_job.c` / `async_job.h` | Minimal background-job lifecycle (`xrootd_async_job_t`): init + register cleanup + idempotent `cleanup_once` (finalized flag). Prevents double-finalize/double-free across TPC threads, PUT body callbacks, Qckscan. Relies on nginx's single-threaded completion model for the guard. |
| `error_mapping.c` / `error_mapping.h` | Unified status translation (consolidates the old kxr_errno/http_errno/result_mapper): errno→kXR (`xrootd_kxr_from_errno`), ns-status→kXR, errno→HTTP, ns-status→HTTP. `EXDEV`/`ELOOP` (RESOLVE_BENEATH escapes) map to `kXR_NotAuthorized`/403 — never 500. |
| `result_mapper.h` | Back-compat alias header — declares `xrootd_http_map_ns_status`/`xrootd_http_map_errno` (defined in `error_mapping.c`). |
| `err_strings.h` | Lowercase canonical errno→message strings (`xrootd_kxr_err_string`) that conformance tests assert, avoiding `strerror` case drift (e.g. "permission denied" not "Permission denied"). |
| `time.c` / `time.h` | `xrootd_format_iso8601` — UTC `YYYY-MM-DDThh:mm:ss.000Z` via `gmtime_r` for stat/logs/S3 LastModified/HTTP dates. |
| `log.c` / `log.h` | `xrootd_log_safe_path` — sanitises a wire path (escapes control/quote/non-ASCII via `xrootd_sanitize_log_string`, defined in `../path/path.c`) before logging with a one-`%s` format. |
| `shm_slots.h` | Inline SHM-slot helpers: `slot_expired` (msec compare) and `remember_free_slot` (first-candidate-wins). For TPC key registry, cache origin slots. |

## Key types & data structures

- **`xrootd_checksum_alg_t`** (`checksum.h`) — adler32 / crc32 / crc32c / md5 / sha1 / sha256; classified u32 vs digest to pick the fast path and the hex width.
- **`xrootd_integrity_info_t` / `xrootd_integrity_opts_t`** (`integrity_info.h`) — checksum result (alg, name, hex, `from_cache`) and cache policy (allow/update xattr cache, require regular file).
- **`xrootd_ns_result_t` / `xrootd_ns_status_t`** (`namespace_ops.h`) — protocol-neutral mutation outcome (`existed`/`created`/`was_dir` + `sys_errno`) and its status enum, mapped to kXR or HTTP by `error_mapping.c`. Plus `xrootd_ns_delete_opts_t` / `_copy_opts_t`.
- **`xrootd_staged_file_t`** (`staged_file.h`) — fd + `active` flag + `tmp_path` for the atomic open→commit/abort lifecycle.
- **`xrootd_http_range_t`** (`range.h`) and **`xrootd_byte_range_t` / `xrootd_range_vector_opts_t`** (`range_vector.h`) — single- and multi-range descriptors plus parser policy.
- **`xrootd_http_operation_t` / `xrootd_proto_op_flags_t`** (`protocol_caps.h`) — per-method descriptor and READ/WRITE/LIST/TPC/LOCK/ASYNC_BODY capability bits.
- **`xrootd_net_target_t` / `xrootd_net_target_policy_t`** (`net_target.h`) — zero-copy parsed URL (fields point into the original buffer) and SSRF allow/deny policy.
- **`xrootd_http_body_summary_t`** (`http_body.h`) — total bytes + `has_memory`/`has_spooled` flags.
- **`xrootd_fs_walk_entry_t` / `_options_t` / `xrootd_fs_walk_pt`** (`fs_walk.h`) — per-entry callback payload and traversal options.
- **`xrootd_fs_usage_t`** (`fs_usage.h`) — computed byte totals + occupancy ppm.
- **`xrootd_async_job_t`** (`async_job.h`) — background-job lifecycle with idempotent cleanup.

## Control & data flow

Execution always **enters from a caller above** — a protocol handler or a subsystem — never on its own:

- **WebDAV** (`../webdav/`): GET → `range.c` → `http_file_response.c`; PUT → `http_body.c` (+ `staged_file.c`, `tmp_path.c`); PROPFIND → `fs_walk.c` + `http_xml.c` + `xml.c` + `etag.c`; MKCOL/DELETE/MOVE/COPY → `namespace_ops.c`; LOCK → `xml.c`; conditionals → `http_conditionals.c`; method routing/Allow → `protocol_caps.c`.
- **S3** (`../s3/`): SigV4 → `crypto.c` + `uri.c`; key resolve → `path.c`; list → `fs_walk.c` + `http_xml.c`; get → `range.c`/`range_vector.c` + `http_file_response.c`; put/copy → `http_body.c` + `staged_file.c` + `namespace_ops.c`; errors → `http_xml.c`.
- **Native stream** (`../read/`, `../write/`, `../query/`, `../fattr/`): checksums → `checksum.c`/`crc32c.c`/`integrity_info.c`; readv coalescing → `range_vector.c`; clone/chkpoint/copy → `copy_range.c`; mutations → `namespace_ops.c`; space → `fs_usage.c`.
- **TPC / proxy / CMS** (`../tpc/`, `../proxy/`, `../cms/`): outbound target validation → `net_target.c`; background job teardown → `async_job.c`; SHM slot bookkeeping → `shm_slots.h`.

What this directory **calls out to**: the filesystem helpers depend on the kernel-confinement primitives in [`../path/beneath.h`](../path/README.md) (`xrootd_*_beneath`, `xrootd_beneath_open_root`, `xrootd_beneath_strip_root`) and on [`../fattr`](../fattr/README.md) xattr key constants; `copy_range.c` and the body/checksum loops are **blocking** and run under the [`../aio`](../aio/README.md) thread pool; status mappings feed the response framing in [`../response`](../response/README.md) and the counters in [`../metrics`](../metrics/README.md). It depends on nginx core/HTTP, OpenSSL, zlib, and libxml2.

## Invariants, security & gotchas

- **Kernel confinement is enforced here, at the op.** `namespace_ops.c`, `staged_file.c`, and `fs_walk.c`'s `remove_tree` open a `RESOLVE_BENEATH` rootfd and route every mutating syscall through it; a path that does not strip cleanly under `root_canon` is refused with `EXDEV` (`namespace_ops.c:67`, `staged_file.c:91`) rather than touched raw. `path.c` deliberately does **no** `realpath` and **no** existence check (`path.c:1-14`) — it only rejects `.`/`..` and builds the lexical join; confinement is the kernel's job at the actual op.
- **Documented non-beneath sites are intentional, not gaps.** `namespace_ops.c:427` (copy on already-confined fds), the xattr copies (`namespace_ops.c:463`), and `fs_walk.c:264`'s readdir loop each carry an inline justification: they act on fds already opened beneath, or on kernel-supplied dirent names with `lstat` (no `..`, final symlink not followed). The mutations they drive still go through the beneath API.
- **`EXDEV`/`ELOOP` are auth failures, never server errors.** Both `error_mapping.c` (`:42`, `:117`) and `namespace_ops.c`'s `errno_to_ns_status` (`:88`) map a blocked traversal / escaping-symlink to `kXR_NotAuthorized` / 403 — a forbidden op, not a 500.
- **SSRF + DNS-rebind.** Every outbound transfer must pass `net_target.c`. `check_dns_pin` validates *all* resolved addresses (so a multi-A record can't smuggle a private address) and pins the first permitted one, closing the re-resolution TOCTOU (`net_target.c:402`). `xrootd_net_host_chars_valid` blocks CRLF/scheme injection into redirect/registration strings. DNS resolution is **blocking — thread-only** (`net_target.h:88`).
- **Blocking calls must stay off the event loop.** `copy_range.c` (`copy_range.h:26`), the `pread`/`pwrite` loops in `http_body.c`/`checksum.c`, statvfs/xattr syscalls, and `net_target` DNS all block; callers must invoke them from a thread-pool task or post-accept context, never an nginx handler directly.
- **TLS vs cleartext buffers.** `http_file_response.c` builds nginx **file-backed** buffers for the sendfile path. GOTCHA (from project memory): this is nginx's native sendfile, not the custom XRootD data plane — mixing it with custom S3/VFS reads needs care in `../webdav/get.c` to avoid double-send/buffer conflicts. Per Invariant #2, TLS responses must be memory-backed (`b->memory=1`); cleartext uses file-backed + sendfile — never mix.
- **Fail-closed auth helpers.** `http_headers.c` Bearer extraction returns `NGX_DECLINED`/`NGX_ERROR` unless the scheme and a non-empty token are both present; `http_conditionals.c` returns 412 when `If-Match` is set but the resource is absent. SigV4 and WLCG token logic never share code (Invariant #6) — `crypto.c` only provides the primitives.
- **CRC32c value is wire-stable across paths.** The serial, 3-way-parallel, and software CRC32c implementations are bit-identical (`crc32c.c:230`); the 3-way path is a pure scheduling win and only engages at ≥768 B (`crc32c.c:451`). pgread/pgwrite per-page CRC depends on this (Invariant #1).
- **Integrity xattr cache is mtime+size-keyed and advisory.** A stored `user.XrdCks.<alg>` value is treated as a miss if the file's current mtime/size differ (`integrity_info.c:87`); write/truncate/rename paths must call `xrootd_integrity_invalidate_fd/_path`. Errors are ignored by design.
- **`ngx_str_t` is not NUL-terminated**; these helpers honour `.len` throughout (header lookups, query scan, range parse). `net_target_t` fields point into the *original* URL buffer — keep it alive while the struct is used (`net_target.h:28`).
- **Hex case asymmetry.** `xrootd_hex_encode` is lowercase (checksums/ETags); `xrootd_hex_nibble` is uppercase (`xml.c` `%XX`). Don't assume one casing.
- **XML backend.** Despite the header mentioning a fallback scanner, `xml.c` compiles **only** the libxml2 path; the build depends on libxml2 and `xrootd_xml_backend_name()` always returns `"libxml2"`.

## Entry points / extending

- **New checksum algorithm:** add the enum in `checksum.h`, the name/EVP/u32 branches in `checksum.c`, and the name to `s_algorithms[]` in `integrity_info.c` (so the xattr cache invalidates it).
- **New shared HTTP helper:** add it to the relevant `http_*.c`/`.h` pair (headers, body, file-response, conditionals, query, xml) — keep the WHAT/WHY/HOW block; both WebDAV and S3 should be able to call it without protocol knowledge.
- **New mutating filesystem op:** extend `namespace_ops.c` (`xrootd_ns_*`) so all three protocols share confinement + errno mapping; never add a raw `*_beneath` call in a protocol handler (`namespace_ops.h:61` invariant).
- **New outbound-transfer feature:** parse with `xrootd_net_target_parse`, then gate with `xrootd_net_target_check_dns_pin` from a thread; reuse `xrootd_net_target_policy_t` rather than re-implementing range checks.
- **New status mapping:** add the case to the appropriate section of `error_mapping.c` (errno→kXR, errno→HTTP, ns→HTTP) — one place, every protocol.
- **New `.c`/`.h` in this directory:** register it in the top-level `config` source list (nginx addon `ngx_addon_srcs`); incremental builds use `make -j$(nproc)`, a new file requires re-running `./configure`.

## See also

- [`../path/README.md`](../path/README.md) — `beneath.h` RESOLVE_BENEATH confinement, canonicalisation, ACL/authdb (this directory's confinement backend).
- [`../aio/README.md`](../aio/README.md) — thread-pool offload for the blocking calls here.
- [`../read/README.md`](../read/README.md), [`../write/README.md`](../write/README.md) — native opcode bodies that consume these checksum/copy/mutation helpers.
- [`../webdav/README.md`](../webdav/README.md), [`../s3/README.md`](../s3/README.md) — the two HTTP front-ends that drive the `http_*` / `range` / `xml` / `staged_file` helpers.
- [`../fattr/README.md`](../fattr/README.md) — xattr key constants used by `integrity_info.c` / `namespace_ops.c`.
- [`../query/README.md`](../query/README.md), [`../tpc/README.md`](../tpc/README.md), [`../metrics/README.md`](../metrics/README.md) — callers of checksum, `net_target`, and `fs_usage`.
- [`../README.md`](../README.md) — master subsystem index.
