# `src/ssi/` — minimal XrdSsi unary request/response service

## Overview

A minimal `XrdSsi`-style **unary RPC** service carried over the ordinary
`root://` file protocol. A client opens an SSI resource path (`/.ssi/<service>`),
writes the request bytes (`kXR_write`), reads the response (`kXR_read`), and closes
— a single request→response exchange dispatched to a compiled-in service handler.

It exists for **wire parity** with `XrdSsi`'s common unary case without requiring a
C++ plugin ABI: services are built in (the reference one is `echo`). Streaming
responses, alerts, and session multiplexing are explicit **non-goals**.

The transport is the unmodified XRootD open/write/read/close path: an SSI handle is
a *virtual* handle that carries no real fd. The read/write hooks are clean
early-returns keyed on `ctx->files[idx].ssi`, so the normal file data path is
**byte-for-byte unchanged for every non-SSI handle**.

## Flow

1. `kXR_open` of a path under `/.ssi/` (when `xrootd_ssi on`) → `xrootd_ssi_open()`
   binds a virtual handle and replies `kXR_ok` + fhandle.
2. `kXR_write` → `xrootd_ssi_write()` appends to the request buffer (capped at
   `XROOTD_SSI_REQ_MAX`, 1 MiB).
3. First `kXR_read` → `xrootd_ssi_read()` dispatches the accumulated request to the
   named service via `xrootd_ssi_invoke()`, then serves the response bytes.

## Files

| File | Responsibility |
|---|---|
| `ssi.h` | Public types (`xrootd_ssi_req_t`, the per-handle state), the `/.ssi/` prefix + 1 MiB request cap, and the API: `xrootd_ssi_match` / `_open` / `_write` / `_read` / `_invoke`. |
| `ssi.c` | Resource-path matching, the open/write/read hooks, and the built-in service dispatch (`echo` returns the request verbatim). |

## See also

- `../connection/fd_table.h` — the virtual-handle slot the SSI state hangs off.
- `../read/open_request.c` — the `kXR_open` interception that routes SSI paths here.
