# webdav/util — WebDAV URI decoding and XML escaping helpers

## Overview

This is the smallest WebDAV leaf subsystem: two thin, protocol-aware adapters that
sit between the WebDAV method handlers (`../`) and the all-protocol shared
implementations in `../../compat/`. It holds no state, allocates almost nothing of
its own, and exists purely to translate the generic compat primitives into the
*nginx HTTP* dialect that WebDAV handlers expect — specifically nginx status codes
(`NGX_OK`, `NGX_HTTP_BAD_REQUEST`, …) and nginx request-pool allocation
(`ngx_pnalloc`).

`uri.c` handles two inbound-path concerns. `webdav_urldecode()` percent-decodes a
request URI or a `Destination` header path into a caller-supplied buffer, mapping
the compat decoder's numeric result codes onto nginx HTTP error codes and
*rejecting embedded NUL bytes* (a security requirement — a NUL would otherwise
truncate the string before path confinement runs).
`webdav_destination_extract_path()` strips the optional `scheme://authority` prefix
from a WebDAV `Destination` header (RFC 4918 §8.3 allows both the absolute-URI and
path-only forms), returning a zero-copy pointer into the original buffer at the
start of the path component.

`xml.c` handles the outbound concern. `webdav_escape_xml_text()` escapes
filesystem paths, lock-owner strings, and metadata before they are embedded as XML
text in response bodies (PROPFIND Multi-Status, LOCK, HEAD/property output,
SEARCH, dead-property storage). Without escaping, a filename containing `&` or `<`
would corrupt the XML structure — i.e. an XML-injection / response-corruption bug.

These helpers run on the HTTP request path only. `uri.c` is invoked during path
resolution (`../path.c`) and by the COPY/MOVE handlers (`../copy.c`, `../move.c`);
`xml.c` is invoked by every handler that emits an XML body. Both `.c` files are
registered in the top-level `config` build script (sources around lines 563–564,
headers around 228–229).

## Files

| File | Responsibility |
|------|----------------|
| `uri.c` | `webdav_urldecode()` — percent-decode URI/Destination paths with NUL rejection, mapping compat codes to nginx HTTP codes; `webdav_destination_extract_path()` — zero-copy strip of `scheme://authority` from a `Destination` header. |
| `uri.h` | Prototypes + WHAT/WHY/HOW contract for the two URI helpers (return semantics, RFC 4918 §8.3 note). |
| `xml.c` | `webdav_escape_xml_text()` — escape XML-special chars and percent-encode control bytes, allocating the result from the nginx request pool. |
| `xml.h` | Prototype + contract for the XML-escape helper (pool ownership, NULL-on-failure semantics). |

> Historical note: safe-path log formatting (`xrootd_log_safe_path`) is **not**
> here — it was promoted to the all-protocol shared helper in
> `../../compat/log.{c,h}` (reached via `../webdav.h`), and the former
> `webdav/util/logging.{c,h}` back-compat stubs were removed once all callers
> resolved to the compat header.

## Key types & data structures

This subsystem defines no types of its own. It consumes constants and signatures
from `../../compat/`:

- **`xrootd_http_urldecode()` result codes** (`../../compat/uri.h`):
  `XROOTD_URLDECODE_OK` (0), `XROOTD_URLDECODE_OVERFLOW` (1),
  `XROOTD_URLDECODE_NUL_BYTE` (2), `XROOTD_URLDECODE_BADARG` (3). `uri.c` maps
  these to `NGX_OK` / `414` / `400` / `500` respectively (BADARG and any unknown
  code fall into the `default` 500 case).
- **`XROOTD_URLDECODE_REJECT_NUL`** (`0x01`) — the flag `webdav_urldecode()`
  always passes so that `%00` yields `NUL_BYTE` (→ 400) instead of a silent
  truncation.
- **`XROOTD_XML_ESCAPE_CONTROL_PERCENT`** (`0x02`) — the flag
  `webdav_escape_xml_text()` always passes so control bytes (`< 0x20`, `0x7f`) are
  rendered as `%XX` rather than left raw (they have no standard XML entity name).
  Note: with this flag set (and `XROOTD_XML_ESCAPE_APOS_ENTITY` unset) `'` is
  escaped as `&#39;`.

## Control & data flow

**Entry — inbound (`uri.c`):**
- `../path.c` (`webdav` path resolution) calls `webdav_urldecode(r->uri.data,
  r->uri.len, …)` to decode the request URI before it is canonicalised and
  confined beneath the export root.
- `../copy.c` and `../move.c` call `webdav_destination_extract_path()` on the
  `Destination` header, then `webdav_urldecode()` on the extracted span, to obtain
  the decoded destination path for the COPY/MOVE.

**Entry — outbound (`xml.c`):**
- `../propfind.c`, `../lock.c`, `../methods_basic.c` (HEAD/property output),
  `../search.c`, and `../dead_props.c` call `webdav_escape_xml_text(r->pool, …)`
  when building XML response bodies.

**Calls out to:**
- `../../compat/uri.c` (`xrootd_http_urldecode`) — the actual RFC 3986 decoder.
- `../../compat/xml.c` (`xrootd_xml_escaped_len`, `xrootd_xml_escape`) — the
  actual two-pass escaper (length pre-sizing, then escape into the sized buffer).

The decoded/escaped output then flows on into the rest of the WebDAV lifecycle:
the decoded path goes through kernel confinement in `../../path/` (see
`../../path/README.md`, `beneath.c` / RESOLVE_BENEATH) before any syscall; the
escaped XML is written into response chains by the calling method handler.

## Invariants, security & gotchas

- **NUL-byte rejection is load-bearing, not cosmetic.** `webdav_urldecode()` always
  passes `XROOTD_URLDECODE_REJECT_NUL` (`uri.c:46-47`). A `%00` in a path must fail
  the request with `400`, never silently truncate — a truncated string would be
  confined/matched against the *wrong* path. This is the WebDAV analogue of the
  "always confine client paths" invariant.
- **Never leak raw compat codes.** `webdav_urldecode()` returns only nginx HTTP
  codes; the `switch` in `uri.c:46-53` is the single translation point. `BADARG`
  and any future/unknown compat code deliberately fall through to `500` — fail
  closed, do not treat an unrecognised code as success.
- **`webdav_destination_extract_path()` is zero-copy.** `*path_out` points *into*
  `dest_data` (`uri.c:79`); it does not allocate and does not NUL-terminate.
  Callers must respect `*path_len_out` and must not free or mutate it independently
  of the source buffer. An empty result (`p >= end`) returns `400` (`uri.c:75-77`).
- **Scheme detection requires `://`.** The prefix is only stripped when a `:` is
  found *and* the next two bytes are `//` (`uri.c:66-67`); otherwise the input is
  treated as a path-only `Destination`. The `scheme_end + 2 < end` bound guards
  against reading past the buffer on truncated input.
- **XML escaping prevents response-body injection.** Any filesystem path,
  lock-owner name, or metadata value placed in an XML body MUST go through
  `webdav_escape_xml_text()` first; skipping it lets a crafted filename break the
  Multi-Status / LOCK XML structure.
- **Pool ownership, not malloc.** `webdav_escape_xml_text()` allocates with
  `ngx_pnalloc(pool, …)` (`xml.c:68`) so the buffer is freed automatically at
  request teardown — never `free()` it. It returns `NULL` on NULL `pool`/`src`,
  OOM, or escaper failure (`xml.c:61-78`); callers must treat `NULL` as an error,
  not as an empty string.
- **`src` for `webdav_escape_xml_text()` must be a C string.** Length is computed
  via `strlen()` (`xml.c:65`); this helper is for NUL-terminated input, unlike the
  length-explicit URI helpers.
- **Two-pass sizing is exact.** The buffer is sized via `xrootd_xml_escaped_len()`
  and then `xrootd_xml_escape()` is called with `escaped_len + 1` capacity
  (`xml.c:66-75`); a non-zero return from the escaper (overflow/badarg) is treated
  as failure → `NULL`.

## Entry points / extending

- **Add a new WebDAV URI/Destination transform:** put it in `uri.c`/`uri.h`,
  follow the existing pattern — delegate the byte-level work to a `../../compat/`
  primitive and only do the nginx-code / pool adaptation here. Register any new
  `.c` in the top-level `config` (`NGX_ADDON_SRCS`, alongside the existing
  `src/protocols/webdav/util/uri.c`) and the header in the headers list.
- **Add a new response-body escaper (e.g. JSON):** mirror `xml.c` — add the flag
  handling to `../../compat/xml.c` (or the relevant compat module) and keep the
  pool-allocating, NULL-on-failure wrapper here so callers stay protocol-clean.
- **Do not** add stateful or I/O-performing code here; this layer is intentionally
  pure transformation. Anything touching the filesystem belongs in `../../fs/` or
  `../../path/`.

## See also

- `../README.md` — WebDAV method-handler subsystem (callers: `path.c`, `copy.c`,
  `move.c`, `propfind.c`, `lock.c`, `methods_basic.c`, `search.c`, `dead_props.c`).
- `../../compat/uri.h` / `../../compat/xml.h` — the all-protocol decode/escape
  implementations this subsystem wraps; `../../compat/log.{c,h}` — where the
  former safe-path log helper now lives.
- `../../path/README.md` — path canonicalisation and RESOLVE_BENEATH confinement
  that consumes the decoded path.
- `../../README.md` — master subsystem index.
