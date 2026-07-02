# `root://` Binary Wire Protocol — Official XRootD vs. nginx-xrootd

> Part of the [XRootD vs nginx-xrootd comparison set](./README.md).

This document compares the **official XRootD C++** server with the **nginx-xrootd**
stream module at the level of the `root://` *binary wire protocol*: the initial
handshake, `kXR_protocol`/TLS negotiation, `kXR_login`/`kXR_auth`, the universal
framing, and the per-opcode coverage and framing-parity of every `kXR_*` request
code.

Every claim below is grounded in source. The official side cites
`/tmp/xrootd-src/src/XProtocol/XProtocol.hh` (the opcode and struct definitions)
and `XrdXrootd/XrdXrootdProtocol.cc` / `XrdXrootdXeq.cc` (the `do_*` handlers).
The nginx-xrootd side cites this repository's `src/` tree. Where a behaviour was
already verified by the conformance / interop suites, this doc **reuses** the
facts from the companion documents rather than re-deriving them:

- [`../conformance-findings.md`](../conformance-findings.md) — 22 fixed wire divergences vs. the spec + stock tools.
- [`../gohep-interop-findings.md`](../gohep-interop-findings.md) — three bugs an independent Go client exposed.
- [`../xrootd-implementations.md`](../xrootd-implementations.md) — the five-implementation code-level comparison.

---

## Scope

In scope: the `root://` (and `roots://` = TLS) binary protocol only — framing,
handshake, version/TLS/capability negotiation, login + auth handoff, and the
request-opcode surface. The crypto internals of GSI/token/SSS handshakes, the
HTTP/WebDAV/S3 planes, and CMS clustering are covered by their own comparison
documents and are referenced here only where they affect wire behaviour.

"Official XRootD" means the reference C++ implementation in `/tmp/xrootd-src`
(protocol string `5.2.0`, `kXR_PROTOCOLVERSION 0x00000520`,
`XProtocol.hh:70-76`). "nginx-xrootd" / "this module" means the server in
`src/` (the native client in `client/` is mentioned only where the two ends must
agree on the wire).

---

## In official XRootD

The protocol is **defined** by `XProtocol/XProtocol.hh` and **served** by
`XrdXrootd/`. The connection lifecycle in the reference:

1. A pooled `XrdProtocol` (`XrdXrootdProtocol`) is matched to the link; its
   `Process()` (`XrdXrootdProtocol.cc:368`) drives a **continuation** state
   machine — a partial socket read stashes state and reschedules via the `Resume`
   member-function pointer rather than blocking (`XrdXrootdProtocol.hh:589`,
   confirmed in [`../xrootd-implementations.md`](../xrootd-implementations.md) §1).
2. Before login, only `kXR_protocol`, `kXR_login`, and `kXR_bind` are accepted —
   a strict pre-login gate (`XrdXrootdProtocol.cc:472-474, 515`).
3. After login, `Process2()` dispatches the full opcode set through a deliberately
   split `switch` "to help the compiler" (`XrdXrootdProtocol.cc:439`); each opcode
   has a `do_*()` handler in `XrdXrootdXeq.cc` (and the Pgrw/FAttr/ChkPnt
   companions). The complete confirmed handler set:
   `do_Auth, do_Bind, do_ChkPnt, do_Chmod, do_CKsum, do_Clone, do_Close,
   do_Dirlist, do_Endsess, do_FAttr, do_gpFile, do_Locate, do_Login, do_Mkdir,
   do_Mv, do_Open, do_PgRead, do_PgWrite, do_Ping, do_Prepare, do_Protocol,
   do_Qconf, do_Query, do_Read, do_ReadV, do_Rm, do_Rmdir, do_Set, do_Stat,
   do_Statx, do_Sync, do_Truncate, do_Write, do_WriteV` (grep of `XrdXrootdXeq*.cc`).
   `kXR_sigver` is special-cased in `Process2` to `ProcSig()`
   (`XrdXrootdProtocol.cc:411, 616`), *not* a `do_*` handler — it is a request
   *prefix*, not a standalone request.

The request opcode enum is `XRequestTypes` (`XProtocol.hh:111-147`),
`kXR_1stRequest = kXR_auth = 3000 … kXR_clone = 3032`, terminated by
`kXR_REQFENCE`. There are **no opcodes above `kXR_clone` (3032)** in the official
protocol.

---

## In nginx-xrootd

The module registers as an `NGX_STREAM_MODULE` and runs the protocol **on nginx's
event loop**, single-threaded per worker — the only event-loop reimplementation in
the field ([`../xrootd-implementations.md`](../xrootd-implementations.md) §1). The
recv path is a byte-accumulating state machine
(`HANDSHAKE(20B) → REQ_HEADER(24B) → REQ_PAYLOAD(dlen) → dispatch`) with suspend
states that return to the loop immediately; blocking work (file I/O, DH keygen) is
exiled to a thread pool / per-worker keypool.

The opcode constants live in `src/protocols/root/protocol/opcodes.h`; the flag/error/status
constants in `src/protocols/root/protocol/flags.h`; the wire structs in `src/protocols/root/protocol/`
(`wire_core_requests.h` et al.). Dispatch is a four-stage cascade in
`src/protocols/root/handshake/dispatch.c`, each stage returning `XROOTD_DISPATCH_CONTINUE` if the
opcode is not its own:

| Stage | File | Opcodes |
|---|---|---|
| pre-dispatch | `dispatch.c` | pending-sigver verify + signing-level enforcement |
| session | `dispatch_session.c` | `protocol, login, auth, ping, set, endsess, bind` |
| read | `dispatch_read.c` | `stat, open(read), read, close, dirlist, readv, query, prepare, pgread, locate, statx, fattr, clone, readlink` |
| write | `dispatch_write.c` | `write, pgwrite, sync, truncate, mkdir, rm, writev, rmdir, mv, chmod, chkpoint, setattr, symlink, link` |
| signing | `dispatch_signing.c` | `sigver` (inspects every request; must run last) |

Proxy mode (`conf->proxy_enable`) re-routes all post-login filesystem opcodes to
an upstream after the **`auth_done`** gate (`dispatch.c:71` — fail-closed, see the
[auth-gate memory](../../../09-developer-guide/) note). An unrecognized opcode
returns `kXR_InvalidRequest` (3006), matching the reference at
`XrdXrootdProtocol.cc:608` (this was conformance fix #4 — we previously returned
`kXR_Unsupported`/3013; `conformance-findings.md` row 4).

This module also defines **four vendor extension opcodes above the official fence**
(`kXR_setattr/symlink/readlink/link` = 3500-3503, `opcodes.h:92-95`) — see
[Extensions](#extensions-and-known-divergences).

---

## Handshake, login, and TLS negotiation

### Universal framing — agreement

Both sides use the identical, byte-stable framing (network byte order
throughout):

- **Client request header, 24 bytes:** `streamid[2] | requestid[2] | body[16] |
  dlen[4]`. Official `struct ClientRequestHdr` (`XProtocol.hh:157-162`); ours
  `XRD_REQUEST_HDR_LEN 24` (`opcodes.h:30`), parsed in `src/protocols/root/connection/recv.c`.
- **Server response header, 8 bytes:** `streamid[2] | status[2] | dlen[4]`.
  Official `struct ServerResponseHeader` (`XProtocol.hh:955-959`); ours
  `XRD_RESPONSE_HDR_LEN 8` (`opcodes.h:31`).
- **`streamid` is opaque** — echoed as raw bytes, never byte-swapped, on both
  sides (confirmed for all five implementations in
  [`../xrootd-implementations.md`](../xrootd-implementations.md) §2).
- Response status codes agree: `kXR_ok=0`, `kXR_oksofar=4000`, `kXR_attn=4001`,
  `kXR_authmore=4002`, `kXR_error=4003`, `kXR_redirect=4004`, `kXR_wait=4005`,
  `kXR_waitresp=4006`, `kXR_status=4007` (official `XResponseType`,
  `XProtocol.hh:940-951`; ours `flags.h`/`opcodes.h:106-137`).
- Error-response body is `errnum[4] + NUL-terminated errmsg` on both sides
  (official `ServerResponseBody_Error`, `XProtocol.hh:1072-1075`); error codes
  `kXR_ArgInvalid=3000 … kXR_TimerExpired=3035` agree (`XProtocol.hh:1031-1069`;
  ours `opcodes.h:148-177`, a subset — see the opcode table notes).

### Initial 20-byte handshake

The client sends `struct ClientInitHandShake` = five 32-bit words
(`XProtocol.hh:84-90`); the canonical hello is `{0,0,0,4,2012}` where
`2012 = 0x000007dc` is the historical magic.

- **Official validation is loose**: the real gate is "first three words zero,
  fourth word == 4" with the magic word historical
  (`XrdXrootdProtocol.cc:311-325`, per
  [`../xrootd-implementations.md`](../xrootd-implementations.md) §3).
- **nginx-xrootd validates `fourth==4 && fifth==ROOTD_PQ(2012)`**
  (`src/protocols/root/handshake/client_hello.c:66`, `ROOTD_PQ` defined `opcodes.h`). Slightly
  stricter than the reference (it also requires the magic), but a conformant
  client always sends it, so this is interoperable.

### Handshake reply

Both reply with a `ServerResponseHeader` (streamid `{0,0}`, status `kXR_ok`,
`dlen=8`) followed by an 8-byte body = `protover[4] | msgval[4]`:

| | protover | msgval (server role) |
|---|---|---|
| Official | `kXR_PROTOCOLVERSION` (`0x00000520`, 5.2.0) | `kXR_DataServer`=1 / `kXR_LBalServer`=0 |
| nginx-xrootd | `kXR_PROTOCOLVERSION` (`0x00000520`) | always `kXR_DataServer`=1 |

 nginx-xrootd source: `client_hello.c:84-87` writes `htonl(kXR_PROTOCOLVERSION)`
then `htonl(kXR_DataServer)`. It always advertises **DataServer** in the
handshake; *manager/redirector* status is advertised later via the
`kXR_protocol` flags, not here. The conformance suite confirms the handshake
reply (`protover 0x520`, DataServer) as conformant
([`../conformance-findings.md`](../conformance-findings.md) "What the suites
confirm").

### `kXR_protocol` and TLS negotiation

The client sends `ClientProtocolRequest` carrying `clientpv[4]`, a `flags` byte,
and an `expect` byte (`XProtocol.hh:589-614`). The request flags:

`kXR_secreqs=0x01` (return security requirements), `kXR_ableTLS=0x02`
(TLS-capable), `kXR_wantTLS=0x04` (switch to TLS now), `kXR_bifreqs=0x08`.

The server reply (`ServerResponseBody_Protocol`, `XProtocol.hh:1233-1237`) is
`pval[4] | flags[4]` plus an optional `secreq` trailer. The capability flags
(`XProtocol.hh:1192-1229`):

| flag | value | meaning |
|---|---|---|
| `kXR_isServer` | `0x00000001` | serves files |
| `kXR_isManager` | `0x00000002` | redirector/manager |
| `kXR_haveTLS` | `0x80000000` | TLS available |
| `kXR_gotoTLS` | `0x40000000` | upgrade to TLS now |
| `kXR_tlsLogin/tlsData/tlsSess/...` | `0x0?000000` | which phases require TLS |

**nginx-xrootd** (`src/protocols/root/session/protocol.c`):

- Builds `pval = htonl(kXR_PROTOCOLVERSION)` and a `flags` bitmask
  (`protocol.c:116-132`): always `kXR_isServer`; `kXR_isManager` when
  `manager_map`/`manager_mode` is configured (and `kXR_attrSuper`/`kXR_attrVirtRdr`
  in the corresponding modes); and `kXR_haveTLS | kXR_gotoTLS | kXR_tlsLogin` when
  it offers TLS.
- **TLS negotiation**: `offer_tls` is true when `conf->tls && tls_ctx` and the
  client set `kXR_ableTLS | kXR_wantTLS` (`protocol.c:80-83`). If the client
  *demands* TLS (`kXR_wantTLS`) but the server has none configured, the request is
  rejected. When offering, it sets `ctx->tls_pending=1` so the connection upgrades
  via `ngx_ssl_create_connection` after the reply. This matches the reference's
  `kXR_ableTLS/wantTLS ↔ haveTLS/gotoTLS/tlsLogin` model
  ([`../xrootd-implementations.md`](../xrootd-implementations.md) §3 table).
- **SecurityInfo trailer**: when the client sets `kXR_secreqs`, the server appends
  a trailer (`protocol.c:94-200`): a 4-byte SecurityInfo header, one 8-byte entry
  per enabled auth plugin (sss/ztn/gsi order), and a
  `ServerResponseReqs_Protocol` whose `seclvl` byte = `conf->security_level`
  (matching official `kXR_secNone..kXR_secPedantic` = 0..4, `XProtocol.hh:1173-1177`).

The conformance suite confirms `kXR_protocol` flags as conformant
([`../conformance-findings.md`](../conformance-findings.md)).

### `kXR_login`

Official `ClientLoginRequest` (`XProtocol.hh:422-432`): `pid[4]`, `username[8]`,
`ability2`, `ability`, `capver[1]` (async bit `0x80` OR'd with the protocol
version in the low 6 bits — `XLoginCapVer`/`XLoginVersion`, `XProtocol.hh:404-420`),
`reserved2`. The reply (`ServerResponseBody_Login`, `XProtocol.hh:1081-1084`) is a
**16-byte sessid** plus an optional `sec[]` blob.

**nginx-xrootd** (`src/protocols/root/session/login.c`):

- Parses username/PID from the 8-byte field; **rejects non-printable usernames**
  (`login.c:82`), which is stricter than the reference but defensible
  ([`../xrootd-implementations.md`](../xrootd-implementations.md) §4).
- Generates a 16-byte `sessid` and sets `logged_in=1` (the session id is *not*
  crypto-grade, noted in source).
- **Anonymous nuance**: when `conf->auth == XROOTD_AUTH_NONE`, login completes in
  one round-trip and the reply body is **the sessid only** (no `sec[]` blob,
  `login.c:113-124`), and `auth_done=1` is set immediately. This empty-body anon
  reply is the nuance flagged in the conformance docs and verified there (16-byte
  login sessid confirmed conformant).
- When auth is configured, the body is `sessid + "&P=..."` parameter block
  (`login.c:140-214`) advertising the required plugin(s) — e.g.
  `&P=ztn,v:10000&P=gsi,v:<ver>,c:ssl,ca:<hash>`, `&P=sss,...`, `&P=krb5,...`,
  `&P=unix`, `&P=host`, `&P=pwd,...`. `auth_done` stays 0, forcing a `kXR_auth`
  follow-up (mirrors the reference setting `XRD_LOGGEDIN|XRD_NEED_AUTH`).

### `kXR_auth`

Official `ClientAuthRequest` (`XProtocol.hh:168-174`) carries a 4-byte `credtype`
and a credential blob; `do_Auth()` runs the chosen `XrdSecProtocol` and replies
`kXR_authmore` for additional rounds or `kXR_ok` on success. nginx-xrootd's
handler is `xrootd_handle_auth` in `src/auth/gsi/auth.c`, which drives GSI / token /
SSS / krb5 to completion (multi-round via `kXR_authmore`), then sets
`auth_done=1`. The crypto details (GSI buckets, DH, IV/`#ivlen`, digest
negotiation) are out of scope here and covered in
[`../xrootd-implementations.md`](../xrootd-implementations.md) §5; the *framing*
(`credtype`, `kXR_authmore` rounds) agrees.

---

## Opcode coverage

Every `kXR_*` request opcode in the official enum (`XProtocol.hh:111-147`), with
the official handler, our handler file, implementation status, and framing/semantic
parity notes. Our handler files are confirmed by grep over `src/` and the dispatch
tables in `src/protocols/root/handshake/dispatch_*.c`.

| # | Opcode | Official handler | nginx-xrootd handler | Impl? | Framing / semantics parity |
|---|--------|------------------|----------------------|-------|----------------------------|
| 3000 | `kXR_auth` | `do_Auth` | `gsi/auth.c` (`handle_auth`) | yes | `credtype[4]`, multi-round `kXR_authmore`; GSI/token/SSS/krb5. |
| 3001 | `kXR_query` | `do_Query`/`do_Qconf`/`do_Qfh`/`do_Qspace`/`do_Qxattr`/`do_CKsum` | `query/dispatch.c` (`handle_query`) | yes | `infotype` subcodes. Qconfig returns **bare `value\n`** (fix #6), `pio_max`→bare int (fix #12), checksum trims trailing NUL/CR/LF (fix #16). |
| 3002 | `kXR_chmod` | `do_Chmod` | `write/chmod.c` (`handle_chmod`) | yes | `mode[2]` (`XOpenRequestMode` perm bits). Write-gated. |
| 3003 | `kXR_close` | `do_Close` | `read/close.c` (`handle_close`) | yes | `fhandle[4]`. POSC-disconnect handling differs (documented xfail, see conformance). |
| 3004 | `kXR_dirlist` | `do_Dirlist`/`do_DirStat` | `dirlist/handler.c` (`handle_dirlist`) | yes | `options[1]` (`kXR_dstat` etc). Consults `manager_map` (fix #2/bug #2); hides internal `.nginx-xrootd*` artifacts (fix #9). |
| 3005 | `kXR_gpfile` | `do_gpFile` | — (none) | **no** | Falls through → `kXR_InvalidRequest`. Reference struct is itself marked "all wrong; correct when implemented" (`XProtocol.hh:360`). |
| 3006 | `kXR_protocol` | `do_Protocol` | `session/protocol.c` (`handle_protocol`) | yes | `pval+flags` + optional secreq trailer; full TLS negotiation. |
| 3007 | `kXR_login` | `do_Login` | `session/login.c` (`handle_login`) | yes | 16-byte sessid; anon empty-body / `&P=` blob. |
| 3008 | `kXR_mkdir` | `do_Mkdir` | `write/mkdir.c` (`handle_mkdir`) | yes | `options[1]` (`kXR_mkdirpath`) + `mode[2]`. Existing path → `kXR_ItExists` (fix #11); trailing slash normalized (fix #19); `mkpath` idempotent. |
| 3009 | `kXR_mv` | `do_Mv` | `write/mv.c` (`handle_mv`) | yes | `arg1len[2]` then `src dst`. Dest parent chain auto-created (fix #14). |
| 3010 | `kXR_open` | `do_Open` | `read/open_request.c` (`handle_open`) | yes | `mode+options+optiont`. Reply is a **bare 4-byte fhandle** unless `kXR_retstat`/`kXR_compress` (fix #7). `open(new)` on existing → `kXR_ItExists` (fix #20); parent auto-create gated on `kXR_mkpath\|kXR_async` (fix #21). |
| 3011 | `kXR_ping` | `do_Ping` | `session/lifecycle.c` (`handle_ping`) | yes | Empty body → empty `kXR_ok` (confirmed conformant). |
| 3012 | `kXR_chkpoint` | `do_ChkPnt`/`do_ChkPntXeq` | `write/chkpoint.c` (`handle_chkpoint`) | yes | `fhandle[4]` + `opcode` (`kXR_ckpBegin/Commit/Query/Rollback/Xeq`). Write-gated. |
| 3013 | `kXR_read` | `do_Read`/`do_ReadAll` | `read/read.c` (`handle_read`) | yes | `fhandle+offset+rlen`, optional `read_args` (pathid). Raw data stream; `kXR_oksofar` chunking. |
| 3014 | `kXR_rm` | `do_Rm` | `write/rm.c` (`handle_rm`) | yes | **Non-recursive** unlink/rmdir (fix #18 — was recursive data-loss). Write-gated. |
| 3015 | `kXR_rmdir` | `do_Rmdir` | `write/rmdir.c` (`handle_rmdir`) | yes | Empty→ok, non-empty→`ENOTEMPTY`/`kXR_ItExists`. |
| 3016 | `kXR_sync` | `do_Sync` | `write/sync.c` (`handle_sync`) | yes | `fhandle[4]` → fsync. Write-gated. |
| 3017 | `kXR_stat` | `do_Stat` | `read/stat.c` (`handle_stat`) | yes | `id size flags mtime`; full `StatGen` flags incl. `kXR_writable`/`kXR_xset` (fix #10). vfs option → 6-field statvfs (fix #8). Consults `manager_map` (bug #2/#3). |
| 3018 | `kXR_set` | `do_Set` | `query/set.c` (`handle_set`) | yes | `modifier` byte; server-side config option. |
| 3019 | `kXR_write` | `do_Write`/`do_WriteAll` | `write/write.c` (`handle_write`) | yes | `fhandle+offset+pathid`; payload = data. Write-gated. (Pipelined recv, see memory note.) |
| 3020 | `kXR_fattr` | `do_FAttr` | `fattr/dispatch.c` (`handle_fattr`) | yes | `fhandle+subcode+numattr+options` (`kXR_fattrDel/Get/List/Set`). |
| 3021 | `kXR_prepare` | `do_Prepare` | `query/prepare.c` (`handle_prepare`) | yes | `options+prty+port+optionX`; tape staging / cancel (FRM). |
| 3022 | `kXR_statx` | `do_Statx` | `read/statx.c` (`handle_statx`) | yes | **1 flag byte per path** (fix #5), **newline-separated** request paths; missing path → `kXR_error`/`kXR_NotFound` (fix #17). |
| 3023 | `kXR_endsess` | `do_Endsess` | `session/lifecycle.c` (`handle_endsess`) | yes | `sessid[16]`; **session-scoped** termination (endsess fix — was de-authing current conn regardless of sessid). |
| 3024 | `kXR_bind` | `do_Bind` | `session/bind.c` (`handle_bind`) | yes | `sessid[16]` → reply `substreamid`; secondary data channel / parallel streams. |
| 3025 | `kXR_readv` | `do_ReadV`/`do_DirStat` | `read/readv.c` (`handle_readv`) | yes | `pathid` + `read_list[]`; per-segment `readahead_list` framing (coalesced `preadv`, ≤64 iovecs). |
| 3026 | `kXR_pgwrite` | `do_PgWrite`/`do_PgWIO` | `write/pgwrite.c` (`handle_pgwrite`) | yes | `fhandle+offset+pathid+reqflags`; per-page CRC32c, `kXR_ChkSumErr` on mismatch. Write-gated. |
| 3027 | `kXR_locate` | `do_Locate` | `read/locate.c` (`handle_locate`) | yes | `options[2]`; host:port replica list. Consults `manager_map`. |
| 3028 | `kXR_truncate` | `do_Truncate` | `write/truncate.c` (`handle_truncate`) | yes | `fhandle+offset` (by handle or by path). Write-gated. |
| 3029 | `kXR_sigver` | `ProcSig` (not a `do_*`) | `session/signing.c` (`handle_sigver`) | yes | Request **prefix**: **no response on success** (fix #1/bug #1); `expectrid+version+flags+seqno+crypto`; HMAC-SHA256, monotonic seqno, `kXR_SigVerErr` on failure. |
| 3030 | `kXR_pgread` | `do_PgRead`/`do_PgRIO` | `read/pgread.c` (`handle_pgread`) | yes | `fhandle+offset+rlen`; `kXR_status(4007)` framing + per-page CRC32c; gapped in-place `preadv` layout. |
| 3031 | `kXR_writev` | `do_WriteV`/`do_WriteVec` | `write/writev.c` (`handle_writev`) | yes | `options` + `write_list[]`; optional `doSync`. All fhandles validated before any write. Write-gated. |
| 3032 | `kXR_clone` | `do_Clone` | `read/clone.c` (`handle_clone`) | yes | `dst fhandle` + `clone_list[]` (32-byte items); server-side range copy (v5.2.0). |

**Coverage summary:** of the 33 official request opcodes (3000-3032), nginx-xrootd
implements **32**; the only gap is `kXR_gpfile` (3005), whose reference struct is
itself flagged as unfinished (`XProtocol.hh:360`) and which falls through to a
conformant `kXR_InvalidRequest`.

> "Implemented = yes" means the opcode is dispatched and produces a
> protocol-correct response for its documented framing. It does **not** claim
> byte-for-byte parity on every option of every op; the conformance suites
> ([`../conformance-findings.md`](../conformance-findings.md)) pin the specific
> option-level behaviours, and the fix references in the table point at the exact
> divergences that were found and corrected. Any option not yet exercised by the
> suites is "not verified" rather than "guaranteed identical."

---

## Extensions and known divergences

### Vendor POSIX extension opcodes (3500-3503)

This module defines **four opcodes above the official `kXR_clone` fence**
(`src/protocols/root/protocol/opcodes.h:92-95`, handlers in `src/protocols/root/write/ext_ops.c`):

| # | Opcode | Purpose |
|---|--------|---------|
| 3500 | `kXR_setattr` | set mtime/atime (utimens) and/or owner (chown) on a path |
| 3501 | `kXR_symlink` | create a symbolic link |
| 3502 | `kXR_readlink` | read a symlink target (dispatched in the *read* table) |
| 3503 | `kXR_link` | create a hard link |

These are **capability-negotiated** (advertised via `kXR_Qconfig "xrdfs.ext"`):
the native client emits them only when the server advertises support, so a stock
XRootD client never sends them and a stock server never receives them
(`ext_ops.c` header block). They exist for POSIX completeness so the FUSE driver
can honour `cp -p`, `touch -d`, `chown`, and `ln`/`ln -s`. Wire formats live in
`src/protocols/root/protocol/wire_vendor_ext.h`; `kXR_setattr`'s payload is a 44-byte big-endian
attribute prefix + NUL-terminated path. The official protocol has **no equivalent
wire ops** — these are a strict, opt-in superset, not a divergence in the
overlapping surface.

### `kXR_statNoFollow` (vendor stat option)

`flags.h:179` defines `kXR_statNoFollow 0x40` as a **vendor-local** option bit on
`kXR_stat`: when set, the server `lstat`s the final component so a symlink
describes itself rather than its target (`read/stat.c:316-319`,
`path/beneath.c:147`). This is a local option flag (not a new opcode); a stock
client never sets it.

### Conformance fixes already made

The 22 wire divergences found by the conformance / interop suites and corrected
are catalogued in [`../conformance-findings.md`](../conformance-findings.md) and
[`../gohep-interop-findings.md`](../gohep-interop-findings.md). The ones most
relevant to wire framing/semantics (cross-referenced in the opcode table above):

- **sigver no-response on success** — `kXR_sigver` is a request *prefix*; the
  server sends no frame on success (bug #1). Verified against go-hep *and* the
  official client at `security_level ≥ 2`.
- **4-byte open fhandle** — non-`retstat` `kXR_open` returns a bare 4-byte handle,
  not a 12-byte `ServerOpenBody` (fix #7). This also exposed and fixed a
  write-through-cache regression that had over-specified the old 12-byte reply.
- **statx 1-byte flags, newline-separated request** (fix #5); missing path →
  `kXR_NotFound` (fix #17).
- **Qconfig bare values** / `pio_max` bare int / checksum trailing-NUL trim
  (fixes #6, #12, #16).
- **mkdir `kXR_ItExists` on existing path** (fix #11); trailing-slash normalize
  (fix #19); **open(new) `kXR_ItExists`** (fix #20); parent auto-create gated on
  `kXR_mkpath|kXR_async` (fix #21).
- **stat full `StatGen` flags** incl. `kXR_writable`/`kXR_xset` (fix #10); 6-field
  statvfs (fix #8).
- **rm non-recursive** (fix #18 — previously recursive, a data-loss bug).
- **unknown opcode → `kXR_InvalidRequest`** (3006), not `kXR_Unsupported` (fix #4).
- **stat/dirlist consult `manager_map`** and root `/` prefix matches children
  (bugs #2, #3).

### Other observed differences

- **Reported version**: both advertise `0x520` (5.2.0). (For context, go-hep is
  frozen at 3.1 and dCache at 5.0 — see
  [`../xrootd-implementations.md`](../xrootd-implementations.md) §3.)
- **Handshake strictness**: the reference accepts any fifth word; we require the
  `2012` magic (`client_hello.c:66`). Interoperable for conformant clients.
- **Username strictness**: we reject non-printable usernames at login; the
  reference does not (`login.c:82`).
- **POSC on disconnect**: we remove the un-closed partial immediately (correct
  Persist-On-Successful-Close intent); stock keeps it pending a reconnect window.
  Documented as a defensible semantic difference (xfail), not a bug
  ([`../conformance-findings.md`](../conformance-findings.md)).

---

## End-user view

What `xrdcp` / `xrdfs` operations map to which opcodes, and what a user can or
cannot do against this module:

| User command | Opcodes exercised | Works against nginx-xrootd? |
|---|---|---|
| `xrdcp root://h//f /tmp/f` (download) | `protocol, login[, auth, sigver], stat, open(read), read`/`pgread`/`readv`, `close` | Yes — byte-identical to stock (conformance "What the suites confirm"). |
| `xrdcp /tmp/f root://h//f` (upload) | `protocol, login[, auth], open(new\|async), write`/`pgwrite`, `sync`, `close` | Yes — parent dir auto-created via `kXR_async` (fix #13/#21). |
| `xrdfs h ls` / `ls -l` | `dirlist` (+`dstat`) | Yes (internal artifacts hidden, fix #9). |
| `xrdfs h stat` / `statvfs` | `stat` (vfs option) | Yes — full flags + 6-field statvfs (fixes #8/#10). |
| `xrdfs h locate` | `locate` | Yes (consults `manager_map`). |
| `xrdfs h query config\|checksum` | `query` (Qconfig/Qcksum) | Yes — bare-value format, multi-algo cksum (fixes #6/#12/#16). |
| `xrdfs h mkdir\|rmdir\|rm\|mv\|truncate\|chmod` | `mkdir, rmdir, rm, mv, truncate, chmod` | Yes — reference-aligned EEXIST/ENOTEMPTY/non-recursive semantics. |
| `xrdfs h cat\|tail` | `open(read), read, close` | Yes. |
| `xrdfs h prepare` | `prepare` | Yes (FRM tape staging). |
| FUSE `cp -p` / `touch -d` / `chown` / `ln[-s]` | `setattr`/`symlink`/`link`/`readlink` (3500-3503) | Yes **only** via the native client/FUSE after capability negotiation; **not** with a stock client. |
| `kXR_gpfile` (get/put-file legacy) | `gpfile` (3005) | **No** — returns `kXR_InvalidRequest` (also unfinished in the reference). |

In short: the full read/write/metadata surface a stock `xrdcp`/`xrdfs` user
relies on works against this module, with reference-aligned semantics verified
differentially against stock tools and two independent clients. The only
user-visible gaps are `kXR_gpfile` (effectively dead in the reference too) and the
vendor extensions, which require this project's own client.

---

## Parity summary

- **Framing**: byte-identical (24-byte request header, 8-byte response header,
  opaque streamid, network byte order, error/status body layout). No divergence.
- **Handshake**: identical 20-byte hello and 8-byte reply; both advertise
  `0x520`/DataServer. We validate slightly more strictly (require the `2012`
  magic).
- **`kXR_protocol` + TLS**: full `ableTLS/wantTLS ↔ haveTLS/gotoTLS/tlsLogin`
  negotiation; SecurityInfo trailer with `seclvl`. Parity confirmed by the
  conformance suite.
- **Login/auth**: 16-byte sessid, `&P=` plugin advertisement, anon empty-body,
  `kXR_auth`/`kXR_authmore` rounds — all aligned.
- **Opcodes**: 32 of 33 official request opcodes implemented (only `kXR_gpfile`
  absent, itself unfinished upstream); 22 historical divergences found and fixed,
  each pinned by a guarding test.
- **Beyond the reference**: paged I/O (`pgread`/`pgwrite` + `kXR_status` +
  per-page CRC32c) and `readv` — features only this module and the C++ reference
  implement among the reimplementations
  ([`../xrootd-implementations.md`](../xrootd-implementations.md) §6) — plus four
  opt-in vendor POSIX extension opcodes.

**Bottom line:** on the `root://` binary wire protocol, nginx-xrootd is a
**conformant, near-complete reimplementation** of official XRootD, differentially
verified against the stock server/tools and two independent clients, with a small,
explicitly opt-in vendor superset and one dead-opcode gap.

---

## Source references

**Official XRootD** (`/tmp/xrootd-src/src/`):

- `XProtocol/XProtocol.hh` — opcode enum `XRequestTypes:111-147`; request structs
  `:157-925`; handshake structs `:84-98`; protocol flags/TLS bits `:589-614,
  1192-1229`; login structs `:404-432, 1081-1084`; response codes/structs
  `:940-1075, 1233-1322`; error codes `:1031-1069`; version defines `:70-76`.
- `XrdXrootd/XrdXrootdProtocol.cc` — `Process()` `:368`; pre-login gate / dispatch
  `:411, 439, 472-474, 515, 608`; handshake validation `:311-325`; `ProcSig()`
  `:616`.
- `XrdXrootd/XrdXrootdXeq.cc` (+ `XrdXrootdXeqPgrw.cc`, `XrdXrootdXeqFAttr.cc`,
  `XrdXrootdXeqChkPnt.cc`) — the `do_*` handlers enumerated in
  [In official XRootD](#in-official-xrootd).

**nginx-xrootd** (`/home/rcurrie/HEP-x/nginx-xrootd/src/`):

- `protocol/opcodes.h` — opcode/version/size constants (request ids `:44-95`,
  responses `:106-137`, errors `:148-177`).
- `protocol/flags.h` — status/option flags incl. `kXR_statNoFollow:179`.
- `handshake/client_hello.c` — initial handshake (`:66` validation, `:84-87`
  reply).
- `handshake/dispatch.c` + `dispatch_session.c` / `dispatch_read.c` /
  `dispatch_write.c` / `dispatch_signing.c` — the dispatch cascade.
- `session/protocol.c` (`:80-200`) — `kXR_protocol`/TLS/SecurityInfo.
- `session/login.c` (`:82-214`) — `kXR_login`, anon empty-body, `&P=` blob.
- `session/lifecycle.c` — `kXR_ping`, `kXR_endsess`. `session/bind.c` —
  `kXR_bind`. `session/signing.c` (`:75-140`) — `kXR_sigver` no-response.
- `gsi/auth.c` — `kXR_auth`. `query/dispatch.c`, `query/prepare.c`,
  `query/set.c` — query/prepare/set. `read/{stat,statx,open_request,read,close,
  readv,pgread,locate,clone}.c`, `dirlist/handler.c`, `fattr/dispatch.c` — read
  plane. `write/{write,writev,pgwrite,sync,truncate,mkdir,rm,rmdir,mv,chmod,
  chkpoint,ext_ops}.c` — write plane.
- `protocol/wire_vendor_ext.h`, `compat/vendor_ext.h` — vendor extension wire
  formats.

**Companion comparison docs** (verified facts reused here):
[`../conformance-findings.md`](../conformance-findings.md),
[`../gohep-interop-findings.md`](../gohep-interop-findings.md),
[`../xrootd-implementations.md`](../xrootd-implementations.md).
