# `src/fs/cache/origin/` — pluggable origin transports for the read-through cache

## Overview

This directory holds the **origin-transport seam** for the read-through cache
(`src/fs/cache/`). The cache's fill engine (`../fetch.c`, `../slice_fill.c`) knows how
to stage bytes into a local `.part` file, verify a checksum, and atomically
publish — but it must not know *where* those bytes come from. That "where" is a
driver vtable (`xrootd_cache_transport_t`, declared in `transport.h`) selected from
the origin URL scheme. A driver only has to (a) stream a byte range to a local fd
and (b) report the origin's advertised content digest; the single fill engine and
the single checksum-on-fill integration (`../verify.c`) then work identically for
every protocol. This mirrors the storage-driver seam in `src/fs/backend/sd.h`.

The native XRootD origin client (`root://` / `roots://`) lives one level up in
`../origin_protocol.c` / `../io.c`; this directory adds the **HTTP-family** drivers
that reach origins the XRootD wire protocol cannot: XrdHttp, dCache, plain object
stores, and Pelican/OSDF federations.

Everything here runs in an **nginx thread-pool worker** (blocking libcurl /
socket I/O with timeouts), never on the event loop; completion resumes the client
back on the single-threaded loop via the shared fill-done path.

## Files

| File | Responsibility |
|---|---|
| `transport.h` | The driver seam: `xrootd_cache_transport_t` vtable, capability bits (`XROOTD_CACHE_CAP_*`), the parsed-URL type, origin-digest type, `xrootd_cache_origin_url_parse()`, and `xrootd_cache_transport_for(scheme)`. |
| `http_transport.c` / `.h` | HTTP(S)/WebDAV driver (libcurl). Ranged GET streamed straight to the `.part` fd; captures the RFC 3230 `Digest` header (solicited via `Want-Digest`). Bearer auth from the configured cache credential and/or the forwarded client token. |
| `pelican.c` / `.h` | Pelican-federation **consumer** transport: discover the federation Director (`.well-known/pelican-configuration`), then GET the object through the Director's HTTP 307 with redirect-following (built on `http_transport.c`). |
| `pelican_register.c` / `.h` | Pelican-federation **publisher**: a per-worker timer that POSTs a signed `OriginAdvertiseV2` (short-lived ES256 advertise JWT) to the Director's `registerCache` endpoint so the Director redirects clients here. Re-advertises on a ~1-minute cadence. |

## Invariants

- **Thread-pool only.** No driver call touches the event loop; all I/O is blocking
  with explicit timeouts.
- **Capability-gated steps.** A driver advertises what it supports in `caps`; the
  engine skips unsupported steps (an origin that cannot report a checksum yields no
  digest and the best-effort verify policy commits the fill unverified — it never
  fabricates one).
- **Checksum at the edge.** Drivers report the origin's *advertised* digest; the
  actual verification lives once in `../verify.c`, not in any transport.
- **Borrowed URL views.** `xrootd_cache_origin_url_parse()` copies nothing; the
  parsed `ngx_str_t` views point into the caller's storage.
- **Registration prerequisite.** `pelican_register.c` assumes the cache's public
  key is already registered with the federation registry — that handshake is an
  out-of-band operator step, not performed here.

## See also

- `../README.md` — the cache subsystem overview (fill engine, write-through).
- [`docs/02-concepts/`](../../../docs/02-concepts/) and the Pelican design notes
  referenced inline in `pelican.c` / `pelican_register.c`.
