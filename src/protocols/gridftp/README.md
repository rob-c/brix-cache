# GridFTP / FTP Gateway

A self-contained nginx STREAM module (phase-82) that terminates an RFC 959 FTP
control channel — including the gsiftp GSI dialect (RFC 2228 AUTH GSSAPI, GFD.020
MODE E / DCAU / PROT) — and bridges STOR/RETR/LIST/SIZE/MKD/DELE to the VFS
storage seam (`brix_vfs_*`), confining every path through
`brix_http_resolve_path()`. Enabled per stream server block with `brix_gridftp
on` + `brix_gridftp_export <dir>`; writes are off unless
`brix_gridftp_allow_write on`. Further directives cover the storage backend and
credential, PASV port range, strict ALLO-size checking, write verification, and
the GSI cert/key/CA material.

Files in this directory:

- `ftp_gateway.h` — the module's public surface: the per-server conf struct
  (`ngx_stream_brix_ftp_srv_conf_t`), the module descriptor extern, and the
  stream connection handler entry point `brix_ftp_ev_handler()`.
- `ftp_module.c` — module descriptor, conf create/merge, directive setters,
  export-root canonicalisation (realpath confinement root), and GSI context
  construction. Note: the GSI TLS context is a plain OpenSSL `SSL_CTX`, not
  `ngx_ssl_create()` — the mem-BIO GSSAPI engine drives handshakes on a bare
  SSL with no nginx connection attached, and nginx's callbacks would deref
  missing ex-data and crash mid-handshake.
- `ftp_dc_sec.h` / `ftp_dc_sec.c` — the data-channel GSI security boundary for
  DCAU A / PROT P: present the delegated user proxy (not the host cert) on the
  data SSL, apply the TLS policy (1.2 cap, abrupt-EOF tolerance), and
  post-handshake PKIX-verify the peer's RFC 3820 chain while pinning its
  end-entity DN to the control-channel identity.
- `ftp_eblock.h` — header-only MODE E extended-block codec (17-byte
  descriptor/count/offset header, EOF/EOD flags) plus the committed-range
  overlap guard: blocks arrive out of order across parallel data connections,
  and a block overlapping an already-committed range is corruption or a
  deliberate overwrite and must fail the transfer.

The actual protocol engine lives in `ev/` — the non-blocking, event-driven
state machine split by concern (command dispatch, replies, data-channel I/O,
MODE E reassembly, TLS/security glue, path handling, transfers). This top
directory owns the module/config skeleton and the shared security/framing
primitives the engine consumes. The control-channel GSSAPI accept engine itself
is `src/auth/gssapi/gsi_mech.c`.
