# `src/fs/cache/origin/` — origin transport + Pelican advertisement for the read-through cache

## Overview

This directory holds what remains of the cache's **origin-transport layer** after
phase-64 §14 retired the legacy per-scheme origin model. The cache no longer
dispatches per-URL-scheme transports from a `brix_cache_origin` directive —
**one fill path** stages bytes from the export's registered storage backend
(`brix_storage_backend`, resolved by `../open_or_fill.c` and pumped through the
cstore spine in `../fetch.c`). Remote origins are therefore ordinary **source
storage drivers**: `root://` → `src/fs/backend/xroot/`, `s3://` →
`src/fs/backend/s3/`, HTTP(S)/WebDAV → `src/fs/backend/http/`.

What stays here is the **server-side transport implementation those drivers
inject**, plus the Pelican federation **publisher** role:

Everything here runs in an **nginx thread-pool worker** (blocking libcurl I/O
with timeouts), never on the event loop; completion resumes the client back on
the single-threaded loop via the shared fill-done path.

## Files

| File | Responsibility |
|---|---|
| `transport.h` | The parsed-origin-URL type + origin-digest type and `brix_cache_origin_url_parse()` (borrowed-view parse, copies nothing). Consumed by the checksum-on-fill integration (`../verify.h`); the historical per-scheme transport vtable it once declared is retired. |
| `s3_transport.c` / `.h` (+ `s3_transport_setup.c`, `s3_transport_internal.h`) | The **server-side libcurl implementation of `brix_s3_transport_t`** (`src/fs/backend/s3/sd_s3_transport.h`) — one synchronous request + response accessors — injected into the shared `sd_s3` and `sd_http` drivers so the same driver code runs over the server's HTTP stack and the native clients'. `s3_transport_setup.c` carries the operator policy + per-thread curl-handle lifecycle. |
| `pelican_register.c` / `.h` | Pelican-federation **publisher**: when `brix_cache_advertise on`, a per-worker timer POSTs a signed `OriginAdvertiseV2` (short-lived ES256 advertise JWT minted by `src/auth/token/jwt_sign.c`) to the Director's `registerCache` endpoint on a ≥60 s cadence so the Director redirects clients here. |

## Invariants

- **Thread-pool only.** No transport call touches the event loop; all I/O is
  blocking with explicit timeouts.
- **Checksum at the edge.** Transports report the origin's *advertised* digest;
  the actual verification lives once in `../verify.c`, never in a transport.
- **Borrowed URL views.** `brix_cache_origin_url_parse()` copies nothing; the
  parsed `ngx_str_t` views point into the caller's storage.
- **Registration prerequisite.** `pelican_register.c` assumes the cache's public
  key is already registered with the federation registry — that handshake is an
  out-of-band operator step, not performed here.

## See also

- `../README.md` — the cache subsystem overview (fill engine, write-through).
- `src/fs/backend/README.md` — the storage-driver seam the remote-origin drivers
  (`xroot/`, `s3/`, `http/`, `remote/`) register under.
- [`docs/refactor/phase-64-fully-tiered-composable-storage.md`](../../../../docs/refactor/phase-64-fully-tiered-composable-storage.md)
  §14 — the legacy cache-origin removal this layout reflects.
