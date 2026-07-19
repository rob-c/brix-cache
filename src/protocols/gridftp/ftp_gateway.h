#ifndef BRIX_GRIDFTP_GATEWAY_H
#define BRIX_GRIDFTP_GATEWAY_H

/*
 * gridftp/ftp_gateway.h — GridFTP / FTP control-channel gateway (phase-82 P82.1).
 *
 * A self-contained nginx STREAM module that terminates an RFC 959 FTP control
 * channel and bridges STOR/RETR/LIST/SIZE/MKD/DELE to the VFS storage seam
 * (brix_vfs_*), confining every path through brix_http_resolve_path().  This is
 * the cleartext vertical slice: no RFC 2228 GSI security layer yet (AUTH GSSAPI
 * is advertised absent), PASV-only passive data channel, TYPE I transfers.
 *
 * Directive: brix_gridftp on;              (inside a stream server {} block)
 * Required:  brix_gridftp_export <dir>;    (the exported filesystem tree root)
 * Optional:  brix_gridftp_allow_write on;  (permit STOR/MKD/DELE; default off)
 *
 * Scope note (POC): the control + passive-data dialogue runs synchronously on a
 * blocking socket inside the worker for a single client at a time.  This proves
 * the VFS round-trip end to end; the production form is the event-driven state
 * machine described in docs/refactor/phase-82-gridftp-gateway.md §5.
 */

#include "core/ngx_brix_module.h"
#include "fs/backend/sd.h"                 /* enum brix_cred_mode (deleg_mode) */

#include <openssl/x509.h>

/* Per-server-block config for the GridFTP gateway module. */
typedef struct {
    ngx_flag_t   enable;                 /* brix_gridftp on|off               */
    ngx_str_t    export;                 /* brix_gridftp_export <dir> (raw)   */
    ngx_flag_t   allow_write;            /* brix_gridftp_allow_write on|off   */
    ngx_str_t    storage_backend;        /* brix_gridftp_storage_backend      */
                                         /*   ("" = posix, "pblock", ...)     */
    ngx_str_t    storage_credential;     /* brix_gridftp_storage_credential:   */
                                         /*   name of a brix_credential block  */
                                         /*   supplying the s3:// backend's     */
                                         /*   SigV4 keys (unset for posix/pblock) */
    ngx_flag_t   verify_write;           /* brix_gridftp_verify_write on|off:  */
                                         /*   read each STOR back through the  */
                                         /*   driver and CRC-check it (default */
                                         /*   off — doubles read I/O). STORAGE- */
                                         /*   persistence check, not wire: CKSM */
                                         /*   is the client-side wire check.   */
    char         root_canon[PATH_MAX];   /* realpath(export); confinement root */

    /* Passive-mode data-port range (brix_gridftp_pasv_port_range <lo> <hi>).
     * Deployment knob for firewalled sites: an FTP data connection lands on a
     * server-chosen port the peer must reach, so behind a firewall the admin
     * must pin PASV/EPSV to a pre-opened range (globus GLOBUS_TCP_PORT_RANGE /
     * vsftpd pasv_min_port..pasv_max_port). 0/0 (default) = ephemeral: the
     * kernel picks any port, which is un-firewallable on the hostile networks
     * this must deploy into. Both inclusive, 1..65535, lo <= hi. */
    ngx_int_t    pasv_port_lo;
    ngx_int_t    pasv_port_hi;

    /* brix_gridftp_require_allo_size on|off (default off): in stream-mode STOR a
     * bare data-channel close is the only completion signal, so a mid-flight
     * truncation is indistinguishable from a complete transfer. When on, a STOR
     * preceded by ALLO <size> must deliver exactly <size> bytes or it fails 550
     * (never a truncated object committed as complete). Off by default because
     * RFC 959 permits ALLO as an advisory reservation, so strict equality is
     * opt-in for deployments whose clients (globus-url-copy/FTS) send the exact
     * file size. A STOR with no preceding ALLO is unaffected either way. */
    ngx_flag_t   require_allo_size;

    /* Per-request backend delegation: forward the gsiftp client's control-channel-
     * delegated X.509 proxy to the storage backend so the upstream authenticates
     * AS the user (legacy gsiftp → xrootd gateway). Resolved at merge — default
     * PASSTHROUGH (a full proxy is presented unmodified, as with root:///WebDAV);
     * overridable via `mode` on the named brix_credential block. Only enforced on
     * proxy-capable backends (xroot/s3); posix/pblock stay on SELECT. */
    enum brix_cred_mode deleg_mode;

    /* RFC 2228 GSI security layer (phase-82 P82.3) — gsiftp:// support. */
    ngx_flag_t   gsi;                    /* brix_gridftp_gsi: enable AUTH GSSAPI */
    ngx_str_t    certificate;            /* brix_gridftp_certificate <pem>    */
    ngx_str_t    certificate_key;        /* brix_gridftp_certificate_key <pem> */
    ngx_str_t    trusted_ca;             /* brix_gridftp_trusted_ca <dir|file> */
    ngx_ssl_t   *tls_ctx;                /* host cert/key ctx (built at config) */
    X509_STORE  *ca_store;               /* client-proxy trust store (config)  */
} ngx_stream_brix_ftp_srv_conf_t;

/* Module descriptor, defined in ftp_module.c. */
extern ngx_module_t  ngx_stream_brix_ftp_module;

/* Stream connection handler (ev/ftp_ev_io.c): the non-blocking STREAM engine
 * that drives the whole RFC 959 / GFD.020 dialogue for brix_gridftp. */
void brix_ftp_ev_handler(ngx_stream_session_t *s);

#endif /* BRIX_GRIDFTP_GATEWAY_H */
