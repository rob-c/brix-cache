# compat — Cross-protocol shared primitives (checksums, paths, filesystem, SSRF)

## Overview

`src/core/compat` is the module's library of **protocol-neutral building blocks**: small, focused helpers that the three protocol front-ends (`root://` stream, WebDAV/HTTP, S3 REST) plus the cluster/proxy/TPC machinery all share so they cannot drift apart. Nothing here owns a request lifecycle or a wire dialect; each file does one job — compute a CRC32c, parse a Range header, mutate the namespace under kernel confinement, resolve a URL host against an SSRF policy — and does it identically for every caller. The directory's reason to exist is the project's core rule: *use helpers, never reimplement path/auth/metrics/framing* (see the root `CLAUDE.md`). When a checksum, error-code mapping, or path-confinement decision needs to change, it changes here once.

Despite the historical name "compat", this is not a thin compatibility shim over nginx — it is the de-duplication layer. Earlier files such as `cors.c`, `io.c`, `http_protocol_vars.c`, `kxr_errno.c`, and `result_mapper.c` have been **folded into the surviving consolidated files** (e.g. `error_mapping.c` now carries the errno→kXR, errno→HTTP, and namespace-status→HTTP maps that three separate files used to). `result_mapper.h` survives only as a back-compat alias header whose two prototypes are now defined in `error_mapping.c`.

**The HTTP-semantics cluster moved out (2026-07-02):** `http_headers`, `http_body`, `http_file_response`, `http_conditionals`, `http_query`, `http_xml`, `http_compress`, and `etag` now live in [`../http`](../http/README.md) — they are security-load-bearing HTTP request/response semantics, not portability glue, and deserve to be discoverable by name. What remains here is the genuinely protocol-neutral layer: checksums, namespace mutation, path/range/URI/XML primitives, SSRF, time/log/SHM utilities.

These helpers sit *below* the protocol handlers in every request lifecycle. A WebDAV `GET` calls `brix_http_parse_range` (`range.c`) before the serve pipeline in `core/http` takes over; an S3 `ListObjectsV2` calls `brix_fs_walk` + `brix_xml_write_text_element`; a native `kXR_Qcksum` calls `brix_integrity_get_fd` → `brix_checksum_hex_fd`; every mutating op (`rm`, `mkdir`, `mv`, WebDAV `MKCOL`/`DELETE`/`MOVE`, S3 `PutObject`/`DeleteObjects`) routes through `brix_ns_*` in `namespace_ops.c`. Outbound transfers (native TPC, WebDAV HTTP-TPC) gate on `net_target.c`'s SSRF policy.

Two invariants make this directory load-bearing for security: (1) every namespace mutation and staged write here re-resolves the client path under the export root with the kernel's `openat2(RESOLVE_BENEATH)` API (via `../path/beneath.h`) — confinement is enforced at the syscall, not assumed from an upstream check; and (2) all outbound network targets pass a DNS-rebind-safe SSRF classifier before any byte is sent.

## Files

### Checksums & hex

| File | Responsibility |
|---|---|
| `crc32c.c` / `crc32c.h` | CRC-32c (Castagnoli) engine: SSE4.2 hardware (`_mm_crc32_u64`), a 3-way-parallel hardware path for large buffers (≥768 B, Mark-Adler GF(2) recombination), and a bit-by-bit software fallback. `brix_crc32c_extend/_value/_copy_value`. Backs pgread/pgwrite per-page CRC (Invariant #1) and TPC copy-with-checksum. |
| `crc64.c` / `crc64.h` | CRC-64 engine for two variants: **XZ** (`crc64` — poly 0x42F0E1EBA9EA3693) and **NVME** (`crc64nvme` — AWS `x-amz-checksum-crc64nvme`, poly 0xAD93D23594C93659); both reflected, init/xorout all-FF. 256-entry reflected table per variant (load-time constructor), `brix_crc64_extend/_value`, plus `brix_crc64_combine` (zlib-style GF(2) combine) for S3 multipart FULL_OBJECT. ngx-free; built into libxrdproto for the client. No hardware path (x86 baseline has no CRC64 instruction). |
| `checksum.c` / `checksum.h` | Multi-algorithm file checksum: `brix_checksum_alg_t` (adler32/crc32/crc32c via zlib+crc32c; crc64/crc64nvme via crc64.c; md5/sha1/sha256 via OpenSSL EVP). Parse names (incl. the `crc64xz` alias → `crc64`), classify u32 / u64 / digest width, compute from an fd (64 KB `pread` loop, EINTR-safe), emit hex (8 / 16 / digest chars). Entry point `brix_checksum_hex_name_fd`. |
| `integrity_info.c` / `integrity_info.h` | Checksum **cache + policy** layer over `checksum.c`: reads/writes a `user.XrdCks.<alg>` xattr keyed by mtime+size (stale on change) — the fd-keyed cache routes through the VFS xattr seam (`brix_vfs_f{get,set,remove}xattr`); the `.cks` sidecar fallback is a separate below-seam store. Formats RFC-3230 HTTP `Digest` values, invalidates by fd (`brix_integrity_invalidate_fd`) or path (`brix_integrity_invalidate_path(log, root_canon, path)`) after writes; a `no_compute` (cache-only) opt declines on a miss for latency-sensitive read paths (S3 GET/HEAD echo). Shared by kXR_Qcksum, XrdHttp Want-Digest, dirlist dcksm, S3 ETag + crc64nvme. |
| `hex.c` / `hex.h` | Nibble↔char and byte-array→hex string. NOTE: `brix_hex_encode` emits **lowercase** hex; `brix_hex_nibble` emits **uppercase** (used by `xml.c` `%XX` control-escaping). |
| `crypto.c` / `crypto.h` | Worker-lifecycle OpenSSL HMAC-SHA256 + SHA-256 singletons. `EVP_MAC`/`EVP_MD` fetched once at `init_process`, freed at `exit_process`; per-call cost is just a CTX alloc. Used by GSI `kXR_sigver` and S3 SigV4. |

### HTTP-adjacent primitives

The request/response-semantics files (`http_*`, `etag`) live in [`../http`](../http/README.md). These remain here because they serve non-HTTP planes too:

| File | Responsibility |
|---|---|
| `range.c` / `range.h` | Single-range RFC 7233 `bytes=` parser (`brix_http_range_t`: present + satisfiable). Thin facade over `range_vector.c` in single-range mode. |
| `range_vector.c` / `range_vector.h` | Multi-range parse/normalise/validate + contiguous-run coalescing. Shared by XrdHttp multipart byteranges, single-range HTTP, and native `kXR_readv` I/O coalescing. |
| `uri.c` / `uri.h` | RFC 3986 percent-decode (nginx-lenient: malformed `%` passes verbatim) and percent-encode (uppercase hex, configurable `safe_extra`). The encoder feeds S3 SigV4 canonicalisation. |
| `xml.c` / `xml.h` | XML escaping (`& < > " '`, optional `&apos;` and control-char `%XX`), `<name>escaped</name>` element builder with name validation, and WebDAV `<lockinfo>` parsing via **libxml2** (`XML_PARSE_NONET|NOERROR|NOWARNING`, `XML_PARSE_NO_XXE` when available). `brix_xml_backend_name()` returns `"libxml2"`. |
| `protocol_caps.c` / `protocol_caps.h` | Shared HTTP-operation descriptor (`brix_http_operation_t`: name, method, metric slot, access-op, capability flags) plus method→op lookup and flag-filtered `Allow` / `Access-Control-Allow-Methods` builder. WebDAV & S3 keep their own tables; these helpers just search/format. |

### Filesystem & namespace mutation

| File | Responsibility |
|---|---|
| `namespace_ops.c` / `namespace_ops.h` | **The mandatory mutation gateway.** `brix_ns_delete/_mkdir/_rename/_local_copy` over already-resolved paths, each opening a `RESOLVE_BENEATH` rootfd and routing every stat/open/unlink/mkdir/rename through `../path/beneath.h`. Neutral `brix_ns_status_t` result; recursive-vs-empty, overwrite, staged-commit, xattr-preserve policies. INVARIANT: protocol handlers MUST use these, not raw `*_beneath` calls. |
| `fs_walk.c` / `fs_walk.h` | Directory traversal: dot-entry check, path join, empty-dir probe, options-driven recursive `brix_fs_walk` (depth/hidden/files-vs-dirs/cross-device), and confined recursive `brix_fs_remove_tree_confined` (unlinks/rmdir via beneath API). Backs dirlist, PROPFIND collections, S3 ListObjects, recursive DELETE/MOVE. |
| `fs_usage.c` / `fs_usage.h` | `statvfs(2)` → total/free/available/used bytes + occupancy ppm (`brix_fs_usage_t`). For Prometheus, PROPFIND quota, and `kXR_query` space. |
| `staged_file.c` / `staged_file.h` | Crash-safe atomic write lifecycle: `open` a unique `O_EXCL` temp under the confined root → write → `commit` or `abort` (close+unlink). `brix_commit_staged` is **backend-aware**: a POSIX final takes `rename(2)` (same-FS) or copy-then-rename (cross-device EXDEV); a **non-POSIX final export** (e.g. pblock) is published by streaming the partial INTO the backend via its driver `staged_*` state machine (`commit_staged_to_backend`, resolved by `brix_vfs_backend_resolve_for_path`) — the cross-filesystem atomic commit behind `upload_resume`/POSC on a pblock export. Used by S3 PUT, WebDAV PUT/COPY, and root:// close. |
| `tmp_path.c` / `tmp_path.h` | Uniform temp name `<base>.xrd-tmp.<pid>.<random>` — one glob (`*.xrd-tmp.*`) cleans orphans from every subsystem. |
| `copy_range.c` / `copy_range.h` | `copy_file_range(2)` zero-copy with `pread`/`pwrite` 256 KB fallback on `EXDEV/ENOSYS/EOPNOTSUPP/EINVAL/EPERM`. **Blocking** — thread-pool/post-accept only. Backs kXR_clone, kXR_chkpoint, ns local copy, HTTP body→fd. |
| `path.c` / `path.h` | `BRIX_PATH_MAX`/`_MIN` constants and `brix_http_resolve_path`: validates depth + rejects `.`/`..` components, then produces the lexical `root_canon`+`decoded_path` join for ACL/logging. Does NO existence check and NO `realpath` — real confinement happens at the op via RESOLVE_BENEATH. Returns 0 or an HTTP status (400/403/414). |

### Networking, async, time, logging, SHM

| File | Responsibility |
|---|---|
| `net_target.c` / `net_target.h` | Outbound URL parser + **SSRF guard** for native TPC, WebDAV HTTP-TPC, future S3 remote-copy. Zero-copy URL split (scheme/host/port/path, IPv6 literals), per-address prohibited-range classification (loopback/link-local/RFC-1918/ULA, v4-mapped), blocking DNS check, and `check_dns_pin` which validates *every* resolved address and returns the first to pin (closes the DNS-rebind TOCTOU). `brix_net_host_chars_valid` blocks CRLF/scheme injection into redirect strings. DNS calls are **thread-only**. |
| `async_job.c` / `async_job.h` | Minimal background-job lifecycle (`brix_async_job_t`): init + register cleanup + idempotent `cleanup_once` (finalized flag). Prevents double-finalize/double-free across TPC threads, PUT body callbacks, Qckscan. Relies on nginx's single-threaded completion model for the guard. |
| `error_mapping.c` / `error_mapping.h` | Unified status translation (consolidates the old kxr_errno/http_errno/result_mapper): errno→kXR (`brix_kxr_from_errno`), ns-status→kXR, errno→HTTP, ns-status→HTTP. `EXDEV`/`ELOOP` (RESOLVE_BENEATH escapes) map to `kXR_NotAuthorized`/403 — never 500. |
| `result_mapper.h` | Back-compat alias header — declares `brix_http_map_ns_status`/`brix_http_map_errno` (defined in `error_mapping.c`). |
| `err_strings.h` | Lowercase canonical errno→message strings (`brix_kxr_err_string`) that conformance tests assert, avoiding `strerror` case drift (e.g. "permission denied" not "Permission denied"). |
| `time.c` / `time.h` | `brix_format_iso8601` — UTC `YYYY-MM-DDThh:mm:ss.000Z` via `gmtime_r` for stat/logs/S3 LastModified/HTTP dates. |
| `log.c` / `log.h` | `brix_log_safe_path` — sanitises a wire path (escapes control/quote/non-ASCII via `brix_sanitize_log_string`, defined in `../path/path.c`) before logging with a one-`%s` format. |
| `shm_slots.h` | Inline SHM-slot helpers: `slot_expired` (msec compare) and `remember_free_slot` (first-candidate-wins). For TPC key registry, cache origin slots. |

## Key types & data structures

- **`brix_checksum_alg_t`** (`checksum.h`) — adler32 / crc32 / crc32c / crc64 / crc64nvme / md5 / sha1 / sha256; classified u32 (8 hex) vs u64 (16 hex) vs digest to pick the compute path and the hex width.
- **`brix_integrity_info_t` / `brix_integrity_opts_t`** (`integrity_info.h`) — checksum result (alg, name, hex, `from_cache`) and cache policy (allow/update xattr cache, require regular file).
- **`brix_ns_result_t` / `brix_ns_status_t`** (`namespace_ops.h`) — protocol-neutral mutation outcome (`existed`/`created`/`was_dir` + `sys_errno`) and its status enum, mapped to kXR or HTTP by `error_mapping.c`. Plus `brix_ns_delete_opts_t` / `_copy_opts_t`.
- **`brix_staged_file_t`** (`staged_file.h`) — fd + `active` flag + `tmp_path` for the atomic open→commit/abort lifecycle.
- **`brix_http_range_t`** (`range.h`) and **`brix_byte_range_t` / `brix_range_vector_opts_t`** (`range_vector.h`) — single- and multi-range descriptors plus parser policy.
- **`brix_http_operation_t` / `brix_proto_op_flags_t`** (`protocol_caps.h`) — per-method descriptor and READ/WRITE/LIST/TPC/LOCK/ASYNC_BODY capability bits.
- **`brix_net_target_t` / `brix_net_target_policy_t`** (`net_target.h`) — zero-copy parsed URL (fields point into the original buffer) and SSRF allow/deny policy.
- **`brix_fs_walk_entry_t` / `_options_t` / `brix_fs_walk_pt`** (`fs_walk.h`) — per-entry callback payload and traversal options.
- **`brix_fs_usage_t`** (`fs_usage.h`) — computed byte totals + occupancy ppm.
- **`brix_async_job_t`** (`async_job.h`) — background-job lifecycle with idempotent cleanup.

## Control & data flow

Execution always **enters from a caller above** — a protocol handler or a subsystem — never on its own:

- **WebDAV** (`../../protocols/webdav/`): GET → `range.c` (then `../http` + `protocols/shared` for the send); PUT staging → `staged_file.c` + `tmp_path.c`; PROPFIND → `fs_walk.c` + `xml.c`; MKCOL/DELETE/MOVE/COPY → `namespace_ops.c`; LOCK → `xml.c`; method routing/Allow → `protocol_caps.c`. Request/response semantics (headers, body, conditionals, ETag) → [`../http`](../http/README.md).
- **S3** (`../../protocols/s3/`): SigV4 → `crypto.c` + `uri.c`; key resolve → `path.c`; list → `fs_walk.c`; get → `range.c`/`range_vector.c`; put/copy → `staged_file.c` + `namespace_ops.c`. Request/response semantics → [`../http`](../http/README.md).
- **Native stream** (`../read/`, `../write/`, `../query/`, `../fattr/`): checksums → `checksum.c`/`crc32c.c`/`integrity_info.c`; readv coalescing → `range_vector.c`; clone/chkpoint/copy → `copy_range.c`; mutations → `namespace_ops.c`; space → `fs_usage.c`.
- **TPC / proxy / CMS** (`../tpc/`, `../proxy/`, `../cms/`): outbound target validation → `net_target.c`; background job teardown → `async_job.c`; SHM slot bookkeeping → `shm_slots.h`.

What this directory **calls out to**: the filesystem helpers depend on the kernel-confinement primitives in [`../path/beneath.h`](../../fs/path/README.md) (`brix_*_beneath`, `brix_beneath_open_root`, `brix_beneath_strip_root`) and on [`../fattr`](../../protocols/root/fattr/README.md) xattr key constants; `copy_range.c` and the body/checksum loops are **blocking** and run under the [`../aio`](../aio/README.md) thread pool; status mappings feed the response framing in [`../response`](../../protocols/root/response/README.md) and the counters in [`../metrics`](../../observability/metrics/README.md). It depends on nginx core/HTTP, OpenSSL, zlib, and libxml2.

## Invariants, security & gotchas

- **Kernel confinement is enforced here, at the op.** `namespace_ops.c`, `staged_file.c`, and `fs_walk.c`'s `remove_tree` open a `RESOLVE_BENEATH` rootfd and route every mutating syscall through it; a path that does not strip cleanly under `root_canon` is refused with `EXDEV` (`namespace_ops.c:67`, `staged_file.c:91`) rather than touched raw. `path.c` deliberately does **no** `realpath` and **no** existence check (`path.c:1-14`) — it only rejects `.`/`..` and builds the lexical join; confinement is the kernel's job at the actual op.
- **Documented non-beneath sites are intentional, not gaps.** `namespace_ops.c:427` (copy on already-confined fds), the xattr copies (`namespace_ops.c:463`), and `fs_walk.c:264`'s readdir loop each carry an inline justification: they act on fds already opened beneath, or on kernel-supplied dirent names with `lstat` (no `..`, final symlink not followed). The mutations they drive still go through the beneath API.
- **`EXDEV`/`ELOOP` are auth failures, never server errors.** Both `error_mapping.c` (`:42`, `:117`) and `namespace_ops.c`'s `errno_to_ns_status` (`:88`) map a blocked traversal / escaping-symlink to `kXR_NotAuthorized` / 403 — a forbidden op, not a 500.
- **SSRF + DNS-rebind.** Every outbound transfer must pass `net_target.c`. `check_dns_pin` validates *all* resolved addresses (so a multi-A record can't smuggle a private address) and pins the first permitted one, closing the re-resolution TOCTOU (`net_target.c:402`). `brix_net_host_chars_valid` blocks CRLF/scheme injection into redirect/registration strings. DNS resolution is **blocking — thread-only** (`net_target.h:88`).
- **Blocking calls must stay off the event loop.** `copy_range.c` (`copy_range.h:26`), the `pread`/`pwrite` loops in `checksum.c` (and `../http/http_body.c`), statvfs/xattr syscalls, and `net_target` DNS all block; callers must invoke them from a thread-pool task or post-accept context, never an nginx handler directly.
- **Fail-closed auth primitives.** SigV4 and WLCG token logic never share code (Invariant #6) — `crypto.c` only provides the primitives. The fail-closed Bearer/conditional helpers live in [`../http`](../http/README.md).
- **CRC32c value is wire-stable across paths.** The serial, 3-way-parallel, and software CRC32c implementations are bit-identical (`crc32c.c:230`); the 3-way path is a pure scheduling win and only engages at ≥768 B (`crc32c.c:451`). pgread/pgwrite per-page CRC depends on this (Invariant #1).
- **Integrity xattr cache is mtime+size-keyed and advisory.** A stored `user.XrdCks.<alg>` value is treated as a miss if the file's current mtime/size differ (`integrity_info.c:87`); write/truncate/rename paths must call `brix_integrity_invalidate_fd` (preferred — fd-keyed, VFS-routed) or `brix_integrity_invalidate_path(log, root_canon, path)` (path-keyed; the `root_canon` arg routes the removal through the VFS xattr seam). Errors are ignored by design.
- **`ngx_str_t` is not NUL-terminated**; these helpers honour `.len` throughout (header lookups, query scan, range parse). `net_target_t` fields point into the *original* URL buffer — keep it alive while the struct is used (`net_target.h:28`).
- **Hex case asymmetry.** `brix_hex_encode` is lowercase (checksums/ETags); `brix_hex_nibble` is uppercase (`xml.c` `%XX`). Don't assume one casing.
- **XML backend.** Despite the header mentioning a fallback scanner, `xml.c` compiles **only** the libxml2 path; the build depends on libxml2 and `brix_xml_backend_name()` always returns `"libxml2"`.

## Entry points / extending

- **New checksum algorithm:** add the enum in `checksum.h`, the name/EVP/u32 branches in `checksum.c`, and the name to `s_algorithms[]` in `integrity_info.c` (so the xattr cache invalidates it).
- **New shared HTTP helper:** goes in [`../http`](../http/README.md), not here.
- **New mutating filesystem op:** extend `namespace_ops.c` (`brix_ns_*`) so all three protocols share confinement + errno mapping; never add a raw `*_beneath` call in a protocol handler (`namespace_ops.h:61` invariant).
- **New outbound-transfer feature:** parse with `brix_net_target_parse`, then gate with `brix_net_target_check_dns_pin` from a thread; reuse `brix_net_target_policy_t` rather than re-implementing range checks.
- **New status mapping:** add the case to the appropriate section of `error_mapping.c` (errno→kXR, errno→HTTP, ns→HTTP) — one place, every protocol.
- **New `.c`/`.h` in this directory:** register it in the top-level `config` source list (nginx addon `ngx_addon_srcs`); incremental builds use `make -j$(nproc)`, a new file requires re-running `./configure`.

## See also

- [`../path/README.md`](../../fs/path/README.md) — `beneath.h` RESOLVE_BENEATH confinement, canonicalisation, ACL/authdb (this directory's confinement backend).
- [`../aio/README.md`](../aio/README.md) — thread-pool offload for the blocking calls here.
- [`../read/README.md`](../../protocols/root/read/README.md), [`../write/README.md`](../../protocols/root/write/README.md) — native opcode bodies that consume these checksum/copy/mutation helpers.
- [`../webdav/README.md`](../../protocols/webdav/README.md), [`../s3/README.md`](../../protocols/s3/README.md) — the two HTTP front-ends that drive the `http_*` / `range` / `xml` / `staged_file` helpers.
- [`../fattr/README.md`](../../protocols/root/fattr/README.md) — xattr key constants used by `integrity_info.c` / `namespace_ops.c`.
- [`../query/README.md`](../../protocols/root/query/README.md), [`../tpc/README.md`](../../tpc/README.md), [`../metrics/README.md`](../../observability/metrics/README.md) — callers of checksum, `net_target`, and `fs_usage`.
- [`../README.md`](../README.md) — master subsystem index.
