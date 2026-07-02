# Implementation Plan Audit

## Overview

This document used to describe the obvious missing features in the XRootD
stream, WebDAV HTTP, and S3 REST modules. The current tree has since absorbed
those changes through the phase work documented in `docs/FEATURE_GAPS.md` and
the phase-specific implementation notes.

This file now records the audited implementation state and the regression
guards that keep the previously proposed work from drifting out of the source
tree.

## Current Status

| Area | Proposed Work | Current Implementation | Status |
|------|---------------|------------------------|--------|
| Stream | Dispatch `kXR_Stat`, `kXR_Statx`, `kXR_Locate`, and `kXR_Clone`. | `src/handshake/dispatch_read.c` routes these opcodes to `src/read/stat.c`, `src/read/statx.c`, `src/read/locate.c`, and `src/read/clone.c`. | Complete |
| Stream | Preserve `pgread`/`pgwrite` framing and CRC32c invariants. | `src/read/pgread.c` and `src/write/pgwrite.c` use page CRC32c helpers and `kXR_status` progress replies. | Complete |
| Stream | Implement checkpoint corner cases. | `src/write/chkpoint.c` handles checkpoint lifecycle and abandoned checkpoint recovery. `src/write/chkpoint_xeq.c` handles checkpointed write execution. | Complete |
| Native TPC | Add shared registry/auth/progress/metric plumbing. | `src/tpc/common/` centralizes TPC credentials, authorization, registry updates, progress emission, and metrics; native paths still use the SHM key registry. | Complete |
| WebDAV | Verify proxy certificates before proxy handling. | `src/protocols/webdav/access.c` runs `webdav_verify_proxy_cert()` before delegating upstream proxy requests to `webdav_proxy_handler()`. | Complete |
| WebDAV | Verify bearer tokens and scope-check mutating methods. | `src/protocols/webdav/access.c` verifies bearer tokens and calls `webdav_check_token_write_scope()` for write operations; token scopes are evaluated through the shared identity/scope helpers. | Complete |
| WebDAV | Add CORS headers to every WebDAV response. | `src/protocols/webdav/access.c` calls `webdav_add_cors_headers()` for each enabled WebDAV request, including preflight requests. | Complete |
| WebDAV | Account method metrics consistently. | `src/protocols/webdav/dispatch.c` wraps method returns with `webdav_metrics_return()`, and `src/protocols/webdav/metrics.c` feeds the unified metrics layer. | Complete |
| S3 | Keep SigV4 auth separate from WebDAV bearer-token auth. | S3 auth is split across `src/protocols/s3/auth_sigv4_*.c`; `src/protocols/s3/handler.c` uses `s3_verify_sigv4()` and does not call WebDAV token validation. | Complete |
| S3 | Cover multipart abort, complete, list, and copy sub-operations. | Multipart handling is split across `src/protocols/s3/multipart_*.c` and wired from `src/protocols/s3/handler.c`. | Complete |
| All | Add security-negative and observability coverage. | Protocol-specific suites cover negative auth paths; `tests/test_cross_protocol_shared_helpers.py` now includes a static implementation-plan guard. | Complete |

## Implementation Notes

- Stream filesystem paths must use the stream path resolver and VFS/confined
  helpers already present in `src/path/` and `src/fs/`; WebDAV resolver helpers
  are only for HTTP request handling.
- New module source files are registered in the repository's top-level
  `config` file. Generated nginx Makefiles are never edited.
- WebDAV proxy requests intentionally pass through the common access phase
  first. That keeps cert/token auth, write gating, CORS, and request metrics in
  one place before proxy transport is selected.
- S3 SigV4 authentication remains protocol-local. WLCG/WebDAV bearer-token
  helpers are not shared with the S3 auth path.

## Regression Guard

The implementation-plan closure is enforced by
`tests/test_cross_protocol_shared_helpers.py::test_implementation_plan_feature_gaps_are_closed`.
That test checks the opcode dispatch, page CRC/status framing markers, WebDAV
auth/CORS/scope/metrics hooks, S3 SigV4 separation, and multipart operation
wiring without starting nginx.

## Verification Checklist

- Run `PYTHONPATH=tests pytest tests/test_cross_protocol_shared_helpers.py -v`
  after edits that touch shared helper wiring or protocol dispatch.
- Run the relevant protocol suite for behavioral changes:
  `tests/test_metrics.py`, `tests/test_webdav_metrics.py`,
  `tests/test_s3_metrics.py`, and any stream opcode-specific tests touched by
  the change.
- Run `./configure --with-stream --with-http_ssl_module --with-http_dav_module --with-threads --add-module=$REPO`
  only when adding source files, config blocks, or configure options; otherwise
  use an incremental build.
