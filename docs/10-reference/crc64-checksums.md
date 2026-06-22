# CRC64 checksum support

This gateway exposes **CRC-64** checksums across every protocol surface (root://,
WebDAV/XrdHttp, S3) and in the native client. Stock XRootD ships **no** crc64
calculator (only a length convention: `crc64` = 8 bytes / 16 hex), so the names and
polynomials below are this gateway's de-facto convention — documented here so peers
and operators are not surprised.

## Variants

| Name | Algorithm | Normal poly | Reflected poly | `check("123456789")` |
|---|---|---|---|---|
| `crc64` (alias `crc64xz`) | CRC-64/XZ (a.k.a. GO-ECMA) | `0x42F0E1EBA9EA3693` | `0xC96C5795D7870F42` | `0x995DC9BBDF1939FA` |
| `crc64nvme` | CRC-64/NVME (Rocksoft; AWS S3) | `0xAD93D23594C93659` | `0x9A6C9329AC4BC9B5` | `0xAE8B14860A799888` |

Both are reflected with init = xorout = `0xFFFFFFFFFFFFFFFF`. The engine is a single
parameterized, table-driven kernel (`src/compat/crc64.c`, also built into
`libxrdproto` for the client); there is no hardware path because the x86 baseline has
no CRC64 instruction.

> **Important:** the generic `crc64` here is **CRC-64/XZ**, while `crc64nvme` is the
> **different** CRC-64/NVME polynomial that AWS S3 mandates. They are not
> interchangeable. Pick the name that matches your peer.

## Encoding differs by surface

The raw 64-bit value is the same; only the on-the-wire encoding changes, and that is
handled at the protocol edge — never in the kernel.

| Surface | How requested | How returned | Encoding |
|---|---|---|---|
| root:// (`kXR_query` Qcksum) | algo name `crc64` / `crc64nvme` | `"<algo> <hex>"` | 16 lowercase hex |
| root:// `kXR_query` Qconfig `chksum` | — | advertises `adler32,crc32c,crc64,crc64nvme,md5,sha1,sha256` | — |
| root:// Qckscan (tree scan) | algo prefix | `"<algo> <hex>  <logical>"` lines | 16 lowercase hex |
| WebDAV / XrdHttp | `Want-Digest: crc64` (or `?xrd.want.cksum=`) | `Digest: crc64=<hex>` | 16 lowercase hex |
| S3 | `x-amz-checksum-crc64nvme` (PUT) | `x-amz-checksum-crc64nvme` + `x-amz-checksum-type: FULL_OBJECT` | **base64 of 8 big-endian bytes** |

CRC64 is **not** folded over the streaming response body the way adler32 is (the
WebDAV streaming digest path stays adler32-only); it is always computed from the file
descriptor, so a Want-Digest of `crc64` is served via the fd/HEAD path.

## S3 behaviour (AWS compatibility)

AWS SDK/CLI enable CRC64NVME integrity by default (since late 2024).

- **PutObject** — if the client sends `x-amz-checksum-crc64nvme`, the server verifies
  it against the stored object; a mismatch returns **HTTP 400 `BadDigest`** and the
  object is **not** kept. On success (or when no checksum was sent) the value is
  echoed back. (The streaming `x-amz-trailer` / `aws-chunked` trailer form is not yet
  parsed — only a checksum sent as a normal request header is verified.)
- **GET / HEAD** — echo `x-amz-checksum-crc64nvme` **from the xattr cache only**, so
  the read path never pays a full-file recompute. Objects uploaded through the gateway
  are cached at upload time; objects created out-of-band simply omit the header (as
  AWS does when no checksum was stored).
- **Multipart** — `CompleteMultipartUpload` returns the FULL_OBJECT
  `<ChecksumCRC64NVME>` (+ `<ChecksumType>FULL_OBJECT</ChecksumType>` and the header).
  Because parts are reassembled into a single object, the whole-object value is
  computed directly on the result. (A zlib-style 64-bit `xrootd_crc64_combine` is also
  provided and unit-tested for callers that keep parts separate.)

## Caching

Computed values are cached in the `user.XrdCks.crc64` / `user.XrdCks.crc64nvme`
extended attributes (keyed by mtime+size, invalidated on write) via the shared
`integrity_info` layer — the same cache used by adler32/crc32c/digests.

## Native client

`xrdcrc64 <local-path | root://host//path>` prints `<hex> <path>` using CRC-64/XZ
(mirrors `xrdcrc32c` / `xrdadler32`). For the NVME variant over the wire, request the
`crc64nvme` algorithm name (e.g. via `xrdcp --cksum crc64nvme:...`).

## Implementation map

- Engine: `src/compat/crc64.{c,h}` (+ `shared/xrdproto/Makefile`, root `config`).
- Spine: `src/compat/checksum.{c,h}` (enum, `is_u64`, `xrootd_checksum_u64_fd`, hex),
  `src/compat/checksum_core.c` (`xrootd_cksum_u64_fd`), `src/compat/integrity_info.*`.
- root://: `src/query/config.c`, `src/query/checksum_ckscan_*.c`.
- WebDAV: `src/webdav/xrdhttp.c` (inherits via the fd-based Digest path).
- S3: `src/s3/util.c`, `object.c`, `put.c`, `handler.c` (CORS),
  `multipart_complete_body.c`, `s3.h`.
- Client: `client/lib/checksum.c`, `client/apps/xrdcrc64.c`.
- Tests: `tests/unit/test_crc64.c` (kernel + combine), `tests/test_crc64.py`
  (S3 / WebDAV / root:// end-to-end).
