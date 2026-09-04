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
    brix_shared_conf_t common;             /* export/storage/auth policy */
    ngx_flag_t   enable;                 /* brix_gridftp on|off               */

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
    ngx_ssl_t   *tls_ctx;                /* host cert/key ctx (built at config) */
    X509_STORE  *ca_store;               /* client-proxy trust store (config)  */

    /* VO authorization on the gateway (phase-92): `brix_gridftp_require_vo
     * <path> <vo>` appends a longest-prefix VO ACL rule (brix_vo_rule_t), the
     * same rule shape and matcher the HTTP/root planes use. Finalized against
     * root_canon at merge (rule .path → .resolved); NULL/empty ⇒ allow-all, so
     * an export with no require_vo is unaffected. Every namespace/transfer verb
     * is gated in one place (brix_ftp_ev_resolve): a resolved path covered by a
     * rule is served only when the client's VOMS VO CSV lists the required VO. */
    /* VOMS attribute carry (phase-92): when a VO ACL rule is in force, the
     * client's VOMS FQANs must be lifted off its GSI proxy into the session
     * identity so an authorized VO can *satisfy* a rule (not merely be denied).
     * `brix_gridftp_vomsdir <dir>` (per-VO LSC trust) and
     * `brix_gridftp_voms_cert_dir <dir>` (VOMS signing-CA trust) mirror the
     * WebDAV plane's brix_webdav_vomsdir / brix_webdav_voms_cert_dir. Both empty
     * ⇒ no carry (a proxy's VOMS AC is ignored), so a require_vo export stays
     * fail-closed (deny-until-VOMS-carry). */
} ngx_stream_brix_ftp_srv_conf_t;

/* Module descriptor, defined in ftp_module.c. */
extern ngx_module_t  ngx_stream_brix_ftp_module;

/* Stream connection handler (ev/ftp_ev_io.c): the non-blocking STREAM engine
 * that drives the whole RFC 959 / GFD.020 dialogue for brix_gridftp. */
void brix_ftp_ev_handler(ngx_stream_session_t *s);

#endif /* BRIX_GRIDFTP_GATEWAY_H */
