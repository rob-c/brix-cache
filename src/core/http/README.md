# http — Shared HTTP request/response semantics (headers, body, conditionals, ETag)

## Overview

`src/core/http` is the single home of the module's **protocol-neutral HTTP
semantics**: the helpers that decide what an HTTP request *means* — which
header selects a representation, whether a precondition passes, what ETag a
resource carries, how a request body reaches an fd — shared by every HTTP
front-end (WebDAV, S3, dashboard, metrics, SRR) so their behaviour cannot
drift apart.

This directory was split out of [`../compat`](../compat/README.md)
(2026-07-02) because the name "compat" told an auditor *portability glue —
skim it*, when these files are in fact **security-load-bearing**: precondition
evaluation gates overwrites (`If-None-Match: *` exclusive create), Bearer
extraction is an auth boundary, and header-value validation is the
response-splitting defence. The split makes the audit-critical shared HTTP
surface discoverable by name — and gives new cross-protocol HTTP logic an
obvious home, so it does not grow as a private copy inside one protocol
handler again.

The rule is unchanged from compat: nothing here owns a request lifecycle or a
wire dialect. Each file does one job identically for every caller. When
conditional-request or ETag behaviour needs to change, it changes here once.

## Files

| File | Responsibility |
|---|---|
| `http_headers.c` / `http_headers.h` | Case-insensitive `headers_in` lookup, `Authorization: Bearer` extraction, control-char validation, whitespace-trimmed value compare, response/request header insertion (`set_header`/`_str`/`_num`), and the canonical handler-rc→HTTP-status mapper `brix_http_effective_status` (keeps WebDAV/S3 metric buckets aligned). |
| `http_body.c` / `http_body.h` | nginx request-body chain (`request_body->bufs`, mixed memory + spooled-to-file): summarise byte count/layout, write whole body to an fd (`copy_file_range` for file bufs, `pwrite` for memory), read all into one pool buffer, gzip/deflate **inflate**-to-fd, and the `ngx_http_read_client_request_body` dispatch wrapper. |
| `http_file_response.c` / `http_file_response.h` | File-backed serving for WebDAV GET & S3 GET/HEAD: ETag/Content-Range header construction, the standard status+length+type+ETag block (`set_file_headers`), single-range send (`send_file_range`, sets `last_buf`, optional fd pool-cleanup), and multi-range chain append (`chain_append_file_range`). Uses nginx sendfile — see gotcha below. |
| `http_conditionals.c` / `http_conditionals.h` | RFC 7232/9110 conditionals. `brix_http_eval_preconditions` is the full §13.2.2 evaluator (If-Match → If-Unmodified-Since → If-None-Match → If-Modified-Since precedence; `BRIX_HTTP_COND_READ` selects 304-for-GET vs 412-for-write outcomes, `_TIME` enables the date headers) — S3 GET/HEAD and conditional PUT route through it. `brix_http_check_etag_preconditions` is the ETag-only WebDAV-write subset; plus If-Modified-Since and WebDAV `Overwrite: F`. |
| `http_query.c` / `http_query.h` | Bounded `?key=value` scanner over `r->args` (one `ngx_str_t`): case policy, percent-decode, `+`→space, NUL-reject, truncation, bare-flag detection. `brix_http_query_get`/`_has`. Drives S3 ListObjectsV2 / multipart query parsing and the S3 `response-*` header overrides. |
| `http_xml.c` / `http_xml.h` | Incremental XML response chain builder (`chain_appendf`/`vappendf`, stack tmp[2048] → pool overflow), single-buffer XML send, and a protocol-agnostic `<Error><Code><Message>` sender (S3 + REST). |
| `http_compress.c` / `http_compress.h` | Negotiated response compression over the codec seam (`../compat/codec_core.h`): Accept-Encoding parse + encode-to-chain for compressible GET responses. |
| `etag.c` / `etag.h` | RFC 7232 ETag string from mtime+size, strong or `W/`-weak (`BRIX_ETAG_WEAK`), matching XrdHttp's `"%lx-%llx"` convention. Every synthetic validator in the module comes from here. |

## Boundary — what stays in `../compat`

Multi-plane primitives that HTTP merely *also* uses remain in compat:
`range.c`/`range_vector.c` (multi-range engine is shared with native
`kXR_readv` coalescing), `uri.c` (percent-codec feeds S3 SigV4
canonicalisation), `xml.c` (generic XML escaping/parsing, also WebDAV
`<lockinfo>`), `protocol_caps.c` (method descriptor tables), and everything
non-HTTP (checksums, namespace ops, SSRF guard, …).

## Control & data flow

Callers are the HTTP front-ends and HTTP-facing subsystems only:
- **WebDAV** (`protocols/webdav/`): GET → `http_file_response.c` (via
  `protocols/shared/file_serve.c`); PUT → `http_body.c` + `http_conditionals.c`;
  PROPFIND → `http_xml.c` + `etag.c`; COPY/MOVE preconditions →
  `http_conditionals.c`.
- **S3** (`protocols/s3/`): GET/HEAD conditionals + conditional PUT →
  `brix_http_eval_preconditions`; list/error XML → `http_xml.c`; put/copy →
  `http_body.c`; query overrides → `http_query.c`.
- **Observability & other HTTP surfaces** (`observability/dashboard/`,
  `metrics/`, `srr`, `net/ratelimit/ratelimit_http.c`,
  `net/mirror/http_mirror.c`, `fs/scan/scan_http.c`): header
  lookup/insertion + status mapping.

The stream (`root://`) plane has no `ngx_http_request_t` and takes nothing
from here except protocol-neutral constants (`etag.h`'s string builder;
`write_compress.c` borrows `BRIX_DECODE_MAX_RATIO` from `http_body.h`).

## Invariants, security & gotchas

- **Fail-closed auth helpers.** Bearer extraction returns
  `NGX_DECLINED`/`NGX_ERROR` unless the scheme and a non-empty token are both
  present; `If-Match` with an absent resource is 412.
- **One precondition evaluator.** Protocol handlers must not read
  `r->headers_in.if_match`/`if_none_match` and decide for themselves — they
  call `brix_http_eval_preconditions` (or the WebDAV subset) so RFC 9110
  precedence and the 304/412 split stay uniform. Guarded by
  `tests/test_cross_protocol_shared_helpers.py` and
  `tools/ci/check_http_helper_reimpl.sh`.
- **Header values are attacker input.** Anything copied into a response
  header goes through the control-byte check (`brix_http_str_has_ctl`) —
  that is the response-splitting defence (see S3 `response-*` overrides).
- **TLS vs cleartext buffers.** `http_file_response.c` builds file-backed
  buffers for the sendfile path; TLS responses must be memory-backed
  (`b->memory=1`) per module Invariant #2 — never mix.
- **Blocking calls stay off the event loop.** The `pread`/`pwrite` loops in
  `http_body.c` block; call them from a thread-pool task or post-accept
  context only.
- **`ngx_str_t` is not NUL-terminated**; these helpers honour `.len`
  throughout.

## Entry points / extending

- **New shared HTTP helper:** add it to the relevant `http_*.c`/`.h` pair —
  keep the WHAT/WHY/HOW block; every HTTP front-end should be able to call it
  without protocol knowledge. New `.c` files register in the top-level
  `config` and require re-running `./configure`.
- **New conditional-request behaviour:** extend
  `brix_http_eval_preconditions` (flags), never a protocol-local evaluator.

## See also

- [`../compat/README.md`](../compat/README.md) — the remaining
  protocol-neutral primitives (checksums, namespace ops, SSRF, ranges, XML).
- [`../../protocols/shared/README.md`](../../protocols/shared/README.md) —
  the cross-HTTP-protocol serve pipeline built on these helpers.
- [`../../protocols/webdav/README.md`](../../protocols/webdav/README.md),
  [`../../protocols/s3/README.md`](../../protocols/s3/README.md) — the two
  main HTTP front-ends.
