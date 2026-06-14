# fattr — XRootD `kXR_fattr` extended-attribute operations

## Overview

This subsystem implements the XRootD `kXR_fattr` opcode, which lets `root://`
clients read, write, delete, and enumerate *extended attributes* (xattrs) on
exported files. XRootD attributes map directly onto the POSIX `user.` xattr
namespace: a client-visible name such as `mykey` is stored on disk under the
kernel key `user.U.mykey` and reported back to the client as `U.mykey`. The
`user.U.` prefix (`XROOTD_FATTR_XKEY_PFX`) namespaces our managed attributes so
listing never leaks unrelated `user.*` xattrs written by other tools.

`kXR_fattr` is a single wire opcode carrying one of four sub-codes — `Get`,
`Set`, `Del`, `List` — each of which corresponds to a POSIX syscall family
(`getxattr`, `setxattr`, `removexattr`, `listxattr`, plus the `f*`/handle
variants). The subsystem is reached only from the **stream** (`root://`) path;
WebDAV and S3 do not expose xattrs. There is no AIO offload here: xattr syscalls
are cheap metadata operations executed inline on the event-loop thread, then a
single response frame is built and sent.

A request can target a file two ways: by an **open file handle** (the 1-byte
`fhandle` index into `ctx->files[]`, used with `f*xattr` syscalls) or by **path**
(used with path-based syscalls). The dispatcher decides which based on the wire
framing (see Control & data flow). Path-targeted requests are confined under the
export root before any syscall runs, and a list-recurse local extension lets a
directory target enumerate attributes across its whole subtree.

Where it sits in the lifecycle: `handshake/dispatch_read.c` routes `kXR_fattr`
to `xrootd_handle_fattr()` (this subsystem) after login/auth has completed. The
dispatcher validates parameters, resolves the target, runs the auth gate for
path requests, and fans out to the per-sub-code handlers. Each handler reports
per-attribute results and increments the `XROOTD_OP_FATTR` metric slot.

## Files

| File | Responsibility |
|------|----------------|
| `ngx_xrootd_fattr.h` | Internal API: the `xrootd_fattr_entry_t` parsed-attribute struct, key-prefix constants (`XROOTD_FATTR_XKEY_PFX`, `XROOTD_FATTR_RESP_PFX`), and prototypes for every handler/helper below. |
| `dispatch.c` | `xrootd_handle_fattr()` — the single entry point. Validates `subcode`/`numattr`/write-permission, resolves file-handle vs path target, confines + auth-gates path targets, copies and parses the name vector, then routes to `fattr_get`/`fattr_set`/`fattr_del`/`fattr_list`. |
| `helpers.c` | Shared plumbing: `fattr_errno_to_xrd()` (errno→kXR), `fattr_set_rc()` (write per-attribute status in place, big-endian), `fattr_parse_nvec()` (parse the request name vector into `attrs[]`), `fattr_send_vector_status()` (build/send the Set/Del status frame). |
| `get.c` | `fattr_get()` — `kXR_fattrGet`. Two-phase read (size query then buffered read) of each named attribute via `getxattr`/`fgetxattr`; builds the value-vector (`vvec`) response: per-attr 4-byte big-endian length + raw bytes. |
| `set.c` | `fattr_set()` — `kXR_fattrSet`. Parses the value vector (4-byte BE length + bytes per attribute) with signed-length safety checks, applies each via `setxattr`/`fsetxattr`, honoring `kXR_fa_isNew` → `XATTR_CREATE`. |
| `del.c` | `fattr_del()` — `kXR_fattrDel`. Removes each named attribute via `removexattr`/`fremovexattr`, recording per-attribute status; partial success is valid. |
| `list.c` | `fattr_list()` — `kXR_fattrList`. Enumerates `user.U.*` names via `listxattr`/`flistxattr`, strips the `user.` prefix; with `kXR_fa_aData` also appends values; with the `kXR_fa_recurse` local extension on a directory target, walks the subtree emitting `relpath:U.name\0` entries. |

## Key types & data structures

- **`xrootd_fattr_entry_t`** (`ngx_xrootd_fattr.h`) — the parsed view of one
  name-vector entry, one per requested attribute (stack array sized
  `kXR_faMaxVars` = 16). Fields:
  - `rc_ptr` — pointer **back into the request copy** (`nvec_copy`) where this
    entry's 2-byte status slot lives. Handlers overwrite this slot in place so
    the status response reuses the original wire frame without rebuilding it.
  - `name` / `nlen` — the client attribute name (a slice of `nvec_copy`).
  - `xkey[512]` — the full `user.U.<name>` kernel key built by
    `fattr_parse_nvec()` (the only buffer actually passed to syscalls).
  - `value` / `vlen` — value bytes for Get results (`vlen == -1`/`0` means
    none).
  - `errcode` — per-attribute kXR status (0 = success), mirrored into `rc_ptr`.

- **`fattr_recurse_ctx_t`** (`list.c`, file-local) — accumulator for the
  `kXR_fa_recurse` directory walk: output `buf`/`cap`/`len` plus `root_len` so
  emitted paths are relative to the target directory.

- **Wire constants** (`src/protocol/opcodes.h`, `src/protocol/flags.h`):
  `kXR_fattrDel/Get/List/Set` (sub-codes 0–3, `kXR_fattrMaxSC` = 3);
  `kXR_faMaxVars` = 16, `kXR_faMaxNlen` = 248, `kXR_faMaxVlen` = 65536;
  option flags `kXR_fa_isNew` (0x01), `kXR_fa_aData` (0x10), and the local
  extension `kXR_fa_recurse` (0x20).

## Control & data flow

**Entry.** `handshake/dispatch_read.c` maps `kXR_fattr` to
`xrootd_handle_fattr(ctx, c, conf)`. The wire header is read as a
`ClientFattrRequest` from `ctx->hdr_buf`; the post-header payload is `ctx->payload`
with length `ctx->cur_dlen`.

**Target resolution (in `dispatch.c`):**
1. `subcode > kXR_fattrMaxSC` → `kXR_ArgInvalid`. `List` requires `numattr == 0`;
   all others require `1..kXR_faMaxVars`.
2. `Set`/`Del` require `conf->common.allow_write`, else `kXR_fsReadOnly`
   (fail-closed write gate — checked **before** any path/auth work).
3. Target selection:
   - **No payload** (`cur_dlen == 0`): only valid for `List`; uses the
     `fhandle[0]` index into `ctx->files[]` (must be open).
   - **Payload begins with `0x00`**: file-handle form — `fhandle[0]` selects the
     fd, any trailing bytes are the argument vector.
   - **Otherwise**: path form — `xrootd_extract_path()` extracts the request
     path, `xrootd_beneath_full_path()` (see [../path/README.md](../path/README.md))
     joins it under `conf->common.root_canon`, `xrootd_auth_gate()`
     (`XROOTD_AUTH_UPDATE` for Set/Del else `XROOTD_AUTH_READ`) authorizes it,
     and a probe `xrootd_open_beneath()` confirms the path is confined before any
     xattr syscall.
4. The argument vector is copied into a pool buffer (`nvec_copy`) and parsed by
   `fattr_parse_nvec()`; the value vector (`vvec`) for Set is whatever follows
   the name vector.

**Fan-out.** `List` → `fattr_list()`. Otherwise the parsed `attrs[]` go to
`fattr_get`/`fattr_set`/`fattr_del`. Each handler records per-attribute results
in `attrs[]`, then:
- Get builds its own response (header + name vector + per-attr value vector) and
  calls `xrootd_send_ok()`.
- Set/Del call `fattr_send_vector_status()` (header byte = error count, then the
  in-place-updated name vector).
- List builds a NUL-separated name (and optional value) buffer.

**Calls out to:** `../path/` (path extraction, confinement, auth gate),
`../metrics/` (`XROOTD_OP_OK`/`XROOTD_OP_ERR` on slot `XROOTD_OP_FATTR`), the
shared response framer `xrootd_send_ok()`/`xrootd_send_error()`, and the kernel
`<sys/xattr.h>` syscalls directly. It reads file descriptors from
`ctx->files[]` (see [../connection/README.md](../connection/README.md) /
`fd_table.c`). It does **not** use [../aio/README.md](../aio/README.md) — xattr
ops run inline.

## Invariants, security & gotchas

- **Path confinement is mandatory and explicit.** Path-form requests never call
  raw `*xattr` on the client path until `xrootd_open_beneath()` has succeeded
  against `conf->rootfd` (RESOLVE_BENEATH); the canonical full path from
  `xrootd_beneath_full_path()` is what the syscalls use (`dispatch.c:101-126`).
  The recurse walk (`list.c`) operates only inside the already-confined target
  directory.
- **Write gate is fail-closed and runs first.** `kXR_fattrSet`/`kXR_fattrDel`
  are rejected with `kXR_fsReadOnly` when `allow_write` is unset
  (`dispatch.c:43-49`), before path resolution — consistent with the global
  invariant that write permission is checked before anything else.
- **In-place status slots.** `fattr_parse_nvec()` points each
  `attrs[i].rc_ptr` back into the *copied* request buffer; `fattr_set_rc()`
  overwrites that 2-byte slot (big-endian via `htons`) so the response reuses the
  original frame. The request payload is copied first
  (`dispatch.c:152-156`) precisely so this in-place mutation is safe.
- **Signed wire lengths must be widened carefully.** `fattr_set()` reads the
  4-byte value length, casts to `int32_t`, and rejects negatives **before**
  converting to `size_t` (`set.c:46-54`) — the classic "negative length becomes
  huge `size_t`" overflow trap. Lengths are also capped at `kXR_faMaxVlen`.
- **Per-attribute partial success.** Get/Set/Del never abort on the first
  failed attribute; each gets its own kXR status and the response header carries
  an error count. `fattr_errno_to_xrd()` maps `ENODATA → kXR_AttrNotFound` and
  `ERANGE → kXR_ArgTooLong`, delegating everything else to the shared
  `xrootd_kxr_from_errno()`.
- **xattr-unsupported filesystems degrade, not error.** `fattr_list()` treats
  `ENOTSUP`/`EOPNOTSUPP` as an empty result (`list.c:219-223`) rather than a
  protocol error.
- **`kXR_fa_recurse` is a LOCAL EXTENSION** (flag 0x20, not in upstream XRootD),
  only honored for path-form directory targets. It is bounded by
  `FATTR_RECURSE_MAX_DEPTH` (16), per-dir list buffer
  `FATTR_RECURSE_XLIST_BUF` (8 KiB), and total response cap
  `FATTR_RECURSE_RESP_CAP` (256 KiB); dotfiles are skipped and only regular
  files contribute entries.
- **Listing is namespace-filtered.** Only keys beginning with `user.U.` are
  returned, with the leading `user.` (5 bytes) stripped so clients see `U.name`.
  Unmanaged `user.*` xattrs are invisible to clients.
- **Stale doc note (corrected here):** earlier docs claimed handle requests are
  serviced via a `/proc/self/fd/N` path. They are not — handle requests use the
  `f*xattr` syscall family directly (`get.c`, `set.c`, `del.c`, `list.c`).
- **`kXR_fattrMkPath`** is mentioned in the header comment but is **not**
  consulted by the dispatcher; the only option flags acted on are
  `kXR_fa_isNew`, `kXR_fa_aData`, and `kXR_fa_recurse`.

## Entry points / extending

- **Add a new sub-code:** define it in `src/protocol/opcodes.h`, bump
  `kXR_fattrMaxSC`, add a `case` in the `switch` in `xrootd_handle_fattr()`
  (`dispatch.c`), implement the handler in a new `.c` file plus a prototype in
  `ngx_xrootd_fattr.h`, register the file in the top-level `config` script (the
  module's `ngx_module_srcs` / `NGX_ADDON_SRCS` list), then `./configure` + `make`.
- **Add a new option flag:** define it in `src/protocol/flags.h` and branch on
  `options &` your flag in the relevant handler (mirror how
  `kXR_fa_isNew`/`kXR_fa_aData`/`kXR_fa_recurse` are handled).
- **Reuse, don't reimplement:** use `fattr_parse_nvec()`,
  `fattr_set_rc()`, `fattr_errno_to_xrd()`, and `fattr_send_vector_status()`
  rather than open-coding name-vector parsing or status framing.

## See also

- [../path/README.md](../path/README.md) — path extraction, `xrootd_beneath_full_path`, `xrootd_open_beneath`, and `xrootd_auth_gate` confinement/authorization.
- [../handshake/README.md](../handshake/README.md) — opcode dispatch that routes `kXR_fattr` here.
- [../connection/README.md](../connection/README.md) — `ctx->files[]` fd table backing handle-form requests.
- [../metrics/README.md](../metrics/README.md) — the `XROOTD_OP_FATTR` counter slot.
- [../protocol/README.md](../protocol/README.md) — `ClientFattrRequest`, sub-code and flag constants.
- [../README.md](../README.md) — master subsystem index.
