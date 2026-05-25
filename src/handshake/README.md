# Handshake Sources

These files cover request entry into the native XRootD stream module:

- `client_hello.c`: validates the initial 20-byte XRootD client handshake
- `dispatch.c`: request entrypoint and category ordering
- `dispatch_session.c`: pre-auth/session lifecycle opcodes
- `dispatch_read.c`: authenticated read-side and metadata opcodes
- `dispatch_write.c`: authenticated mutating opcodes
- `dispatch_signing.c`: `kXR_sigver` request routing
- `policy.c`: login/auth/write gates used by the routing table
- `sigver.c`: verifies pending `kXR_sigver` state before routing the covered request
- `handshake.h`: Public handshake types and cross-file prototypes

The request-specific handlers live in `src/session/`, `src/read/`,
`src/write/`, `src/query/`, `src/fattr/`, and related operation directories.

## Data flow

Every request reaches this directory via `connection/recv.c` after the header
bytes are fully accumulated.  The call chain for a typical authenticated read
request looks like:

```
connection/recv.c: ngx_stream_xrootd_recv()
    └─ handshake/dispatch.c: xrootd_dispatch()
           ├─ [if sigver_pending] handshake/sigver.c: xrootd_verify_sigver()
           ├─ handshake/dispatch_session.c: xrootd_dispatch_session_opcode()
           │       handles: kXR_protocol, kXR_login, kXR_auth, kXR_ping,
           │                kXR_set, kXR_endsess, kXR_bind
           │       returns XROOTD_DISPATCH_CONTINUE if not its opcode
           ├─ handshake/dispatch_read.c: xrootd_dispatch_read_opcode()
           │       handles: kXR_stat, kXR_open, kXR_read, kXR_close,
           │                kXR_dirlist, kXR_readv, kXR_query, kXR_prepare,
           │                kXR_pgread, kXR_locate, kXR_statx, kXR_fattr, kXR_clone
           │       calls xrootd_dispatch_require_auth() before each handler
           │       returns XROOTD_DISPATCH_CONTINUE if not its opcode
           ├─ handshake/dispatch_write.c: xrootd_dispatch_write_opcode()
           │       handles: kXR_write, kXR_pgwrite, kXR_writev, kXR_sync,
           │                kXR_truncate, kXR_mkdir, kXR_rm, kXR_rmdir,
           │                kXR_mv, kXR_chmod, kXR_chkpoint
           │       calls require_auth + require_write before each handler
           └─ handshake/dispatch_signing.c: xrootd_dispatch_signing_opcode()
                   handles: kXR_sigver
```

`XROOTD_DISPATCH_CONTINUE` is `NGX_DECLINED`.  Each sub-dispatcher returns
it to pass the request to the next level.  An unrecognised opcode falls
through all dispatchers and gets `kXR_Unsupported`.

`handshake/policy.c` provides the three gates (`require_auth`,
`require_write`, `require_login`) that every sub-dispatcher calls before
routing to the actual handler.
