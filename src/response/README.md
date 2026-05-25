# response - XRootD response framing helpers

Low-level building blocks used by every handler to construct wire responses.

| File | Exports |
|------|---------|
| `basic.c` | `xrootd_build_resp_hdr` - fill a `ServerResponseHdr` with streamid, status, and body length |
| `basic.c` | `xrootd_send_ok` / `xrootd_send_error` - convenience wrappers for the common cases |
| `control.c` | `xrootd_send_redirect` - build a kXR_redirect response with host:port |
| `control.c` | `xrootd_send_wait` - build a kXR_wait async-retry response |
| `crc32c.c` | `xrootd_crc32c` - wire-facing CRC32C API delegated to `src/compat/crc32c.c` |
| `status.c` | `xrootd_send_pgwrite_status` / `xrootd_send_pgread_status` - kXR_status frames with CRC32c |

Nothing in this directory performs any I/O or touches the connection directly;
all functions return a buffer or call `xrootd_queue_response` from
`connection/write_helpers.c`.
