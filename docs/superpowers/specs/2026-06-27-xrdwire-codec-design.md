# xrdwire — a shared per-opcode XRootD wire codec

**Date:** 2026-06-27
**Status:** Approved (design) — implementing incrementally
**Author:** brainstorming session (Rob Currie + Claude)

## Problem

The nginx module (`src/`) and the native client (`client/`) both implement the
full XRootD wire protocol, in opposite directions: the client *builds* request
bodies and *parses* response bodies; the server *parses* request bodies and
*builds* response bodies. The binary **struct layouts** are already shared
(`src/protocol/wire_core_requests.h` etc.), and three opcodes (`pgio`,
`vendor_ext`, `fattr_codec`) already have paired pack/unpack codecs in
`libxrdproto`. But the *marshalling logic* for the other ~35 opcodes — the
`htonl`/`ntohl` and fixed-offset field population — is hand-written twice, spread
across ~40 server files and ~12 client `ops_*` files. The two copies must agree
on every offset; that implicit "must match" contract is the single largest
remaining source of cross-component duplication and the classic wire-bug class.

## Goal

One shared, round-trip-tested codec per opcode in `libxrdproto`, with both sides
rewritten to call it. Success metrics:

1. **Kill duplication** — the per-opcode marshalling exists once.
2. **Anti-drift** — the offset contract is one explicit definition.
3. **Testability** — every opcode is `pack → unpack == identity` plus golden
   byte-vector verified, with no server/client process running.

Non-goals: changing the wire format; merging the I/O loops; touching auth/ACL
logic. The codec never touches a socket, `ngx_`, or the client's blocking-poll
machinery — that per-side mechanism is irreducible.

## Architecture

Generalize the `vendor_ext` template (decoded struct + `pack`/`unpack` over a
fixed big-endian buffer, ngx-free) to every opcode.

Per opcode `<op>`:

```c
typedef struct { /* opcode-specific fixed fields, host byte order */ } xrdw_<op>_req_t;
int xrdw_<op>_req_pack  (const xrdw_<op>_req_t *r, uint8_t body[16]);   /* client */
int xrdw_<op>_req_unpack(const uint8_t body[16], xrdw_<op>_req_t *r);   /* server */
/* responses where the body is fixed-layout (not a raw byte/stream payload): */
int xrdw_<op>_rsp_pack  (const xrdw_<op>_rsp_t *r, uint8_t *out, size_t cap);
ssize_t xrdw_<op>_rsp_unpack(const uint8_t *in, size_t len, xrdw_<op>_rsp_t *r);
```

The request codec operates on the 16-byte `body` region of `ClientRequestHdr`
(streamid/requestid/dlen stay with the shared `frame_hdr.h`). The variable tail
(path, payload, dirlist entries, stat-string) is appended/consumed by the caller
— the codec owns only the fixed-offset fields.

### Files (grouped by family, under `src/protocol/codec/`)

- `wire_codec.h` — umbrella header (declares all structs + functions; re-exports
  the existing `pgio` / `vendor_ext` / `fattr_codec`).
- `wire_codec_file.c` — open, close, read, readv, write, writev, sync, truncate,
  pgread, pgwrite, clone.
- `wire_codec_meta.c` — stat, statx, dirlist, locate, query, fattr.
- `wire_codec_ns.c` — mkdir, mv, rm, rmdir, chmod, set, setattr, symlink,
  readlink, link.
- `wire_codec_session.c` — login, auth, protocol, ping, bind, endsess, sigver,
  prepare, chkpoint.

Pure C, `-DXRDPROTO_NO_NGX`-clean. Built into `libxrdproto` (client links it) and
into the module via `./config` (build-in-place, same as every other shared unit).

### Error handling

`pack` returns the number of fixed bytes written (always 16 for a request body)
or `<0` on a bad argument. `unpack` returns `0` / a positive consumed-length on
success and `<0` on a truncated/malformed fixed region — bounds-checked like
`zip_kernel`. Codes are a small neutral set (`XRDW_OK`, `XRDW_ETRUNC`,
`XRDW_EINVAL`); each side maps them onto `kXR_*` / `XRDC_*` at the edge.

## Test harness

`src/protocol/codec/wire_codec_unittest.c` — standalone `gcc` (no nginx), like
`zip_dir_unittest`:

1. **Round-trip:** for every opcode, populate a struct, `pack`, `unpack`, assert
   field-equality.
2. **Golden vectors:** byte arrays captured from real XRootD (xrdcp/xrdfs wire
   traces) — `unpack` must yield the expected struct and `pack` must reproduce
   the exact bytes. This is what proves wire-compat and answers the
   "lone-consumer-per-direction" objection: the test is the second consumer.

## Migration (incremental)

1. Land `wire_codec.h` + one family file + the unittest + build wiring. Zero
   behavior change (nothing calls it yet). Standalone test green.
2. Migrate **one opcode at a time**: replace the server's inline parse with
   `unpack`, the client's inline build with `pack`; build module + client; run
   the existing protocol-conformance suite between each opcode. Remove the old
   inline marshalling only once its codec path is green.
3. Fold `pgio` / `vendor_ext` / `fattr_codec` under `wire_codec.h` (reference;
   no rewrite — they already fit the pattern).

Order of waves: meta → ns → session → file (file last; it overlaps the perf-
sensitive hot path and the already-shared `pgio`).

## Risks

- **Hot-path opcodes** (read/write/pgread/pgwrite): the codec must be
  zero-overhead (fixed-offset copies, no allocation) — same cost as today's
  inline code. Validate with the existing perf/load tests before/after.
- **Response bodies vary** (raw bytes, ASCII stat strings, dirlist streams):
  only fixed-layout response bodies get a codec; streamed/raw bodies stay at the
  edge (the codec covers the framing, not the payload).
- **Big blast radius**: mitigated by one-opcode-at-a-time migration with the
  conformance suite as the gate, and by landing the codec+tests before any
  migration.

## Build wiring checklist (per new .c)

- add to `./config` `NGX_ADDON_SRCS` (module);
- add to `shared/xrdproto/Makefile` (`PROTO_CODEC` var + object + rule, append to
  `OBJS`);
- `./configure` once (new source), then `make`.
