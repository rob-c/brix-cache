# `src/protocols/dig/` — XrdDig-style remote diagnostics

## Overview

An `XrdDig`-style handler that gives operators **read-only, authorization-gated
HTTP access to a whitelist of server-side files** (config, logs, …) without a shell
on the box. Requests under `/.well-known/dig/<export>/<rel>` are routed here from
the WebDAV dispatch when the feature is enabled (`xrootd_webdav_dig on`).

The handler is **fail-closed by construction** — every layer denies by default:

1. **Default off** — disabled, the handler declines and the request takes the
   normal 404 path.
2. **Read-only** — only `GET`/`HEAD`; any other method → 405.
3. **Confinement** — every open goes through the kernel
   `openat2(RESOLVE_BENEATH)` primitive (`xrootd_open_beneath`) anchored at the
   export's realpath, so `../` and symlink escapes are impossible regardless of the
   requested relative path. Export dirs are realpath'd at config time (the BENEATH
   anchors).
4. **Authorization** — a principal→export allow-file. An anonymous principal, an
   unset/unreadable allow-file, or no matching rule all DENY (403). The principal
   is the token subject if present, else the GSI DN.

## Files

| File | Responsibility |
|---|---|
| `dig.h` | Public contract: the URI prefix (`/.well-known/dig/`) and the `xrootd_dig_handle()` entry point. The export type and prototype are shared via `webdav.h` (the config setter lives with the WebDAV directives). |
| `dig.c` | The handler and all of its enforcement: principal resolution, allow-file authorization, method/confinement checks, and the confined open+serve. |

## See also

- `../path/beneath.h` — the `RESOLVE_BENEATH` confined-open primitive.
- `../webdav/README.md` — the HTTP dispatch that routes the dig prefix here.
