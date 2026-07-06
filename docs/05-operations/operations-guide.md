# Supported operations

Every XRootD operation the module handles — command-line examples, Python client snippets, and the constraints you'll hit in production.

If you want the higher-level "what does `xrdcp` usually do to the server?" view,
see [xrdcp-interactions.md](../04-protocols/xrootd-client-interaction.md). If you want the design
trade-offs behind some of the odd-looking behavior, see [quirks.md](../10-reference/quirks.md).

---

## Operation families at a glance

Most XRootD requests fall into one of two shapes: path-based requests that name
a file directly, and handle-based requests that use the small file handle
returned by `kXR_open`.

```text
connection setup
    |
    v
kXR_protocol -> kXR_login -> optional kXR_auth
    |
    +-- path-based metadata and namespace operations
    |       |
    |       +-- kXR_stat / kXR_statx / kXR_dirlist / kXR_locate
    |       +-- kXR_mkdir / kXR_rm / kXR_rmdir / kXR_mv / kXR_chmod
    |       +-- kXR_prepare / kXR_query / kXR_fattr
    |
    +-- open-file operations
            |
            v
        kXR_open(path, flags)
            |
            v
        handle byte stored in ctx->files[]
            |
            +-- reads:  kXR_read / kXR_pgread / kXR_readv
            +-- writes: kXR_write / kXR_pgwrite / kXR_writev
            +-- sync/stat-by-handle
            |
            v
        kXR_close(handle)
```

The distinction matters for authorization and performance. Path-based requests
resolve and check a path each time. Handle-based I/O inherits the open-time
decision and reuses cached file state until `kXR_close` or disconnect.

```text
path request:
    request path -> resolve -> ACL/scope check -> syscall -> response

handle request:
    handle -> ctx->files[handle] -> cached fd/path/size -> I/O -> response
```

---

## Connection and session

These operations happen at the start of every connection, before any file access.

### Handshake + `kXR_protocol`

The XRootD client sends a 20-byte binary handshake when it first connects, then immediately sends a `kXR_protocol` request to negotiate capabilities. The module handles both automatically — clients and servers do this without any user-level configuration.

When `brix_manager_map` mappings are configured the server sets the `kXR_isManager` capability bit in the `kXR_protocol` response so clients know the server may return redirects.

### `kXR_login`

After the protocol handshake, the client sends its username. For anonymous servers, the module accepts any username. For GSI servers, the login response triggers the certificate exchange. For token servers, the login response advertises the `ztn` bearer-token security protocol.

### `kXR_ping`

A liveness check. Clients occasionally send pings to verify the server is still up. The module replies immediately with `kXR_ok`.

### `kXR_sigver` — request signature verification

When GSI authentication is active, the client may precede sensitive requests with a `kXR_sigver` packet carrying an HMAC-SHA256 of the following request header (and optionally its payload). The server verifies the HMAC using the session signing key derived from the GSI Diffie-Hellman shared secret (`SHA-256(DH_secret)`).

Verification rules:
- **Signing key**: derived during GSI handshake; `signing_active` flag gates all checks.
- **HMAC input**: `seqno(8B big-endian) || 24-byte request header [|| payload if `kXR_nodata` not set]`.
- **Replay protection**: the sequence number must strictly increase across the session.
- **RSA path**: if the `kXR_rsaKey` crypto flag is set, the asymmetric signature is accepted without verification (the HMAC path covers the common case).
- **Non-GSI sessions**: `kXR_sigver` is accepted without verification; token and anonymous sessions do not derive a signing key.

Mismatched HMACs are rejected with `kXR_NotAuthorized`.

Security-level enforcement is configured with
`brix_security_level none|compatible|standard|intense|pedantic`. When a GSI
session has an active signing key, `handshake/sigver.c` mirrors XRootD's
request-protection table and rejects unsigned opcodes that require a preceding
valid `kXR_sigver`. The `pedantic` level also advertises `kXR_secOData` and
rejects payload-bearing signed requests that set `kXR_nodata`.

### `kXR_endsess`

The client signals it is done with the session. The module closes all open file handles and acknowledges. The client then closes the TCP connection.

---

## Sub-pages

- [Read operations](read.md) — kXR_stat, kXR_open, kXR_read, kXR_pgread, kXR_readv, kXR_dirlist, kXR_locate
- [Write operations](write.md) — kXR_open (write), kXR_write, kXR_pgwrite, kXR_truncate, kXR_sync
- [Management and queries](management.md) — filesystem management, queries, prepare, unsupported opcodes, limits, auth notes
