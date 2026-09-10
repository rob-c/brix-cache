#include "cache_internal.h"
#include "protocols/root/connection/netconnect.h"   /* shared outbound connect/I/O hardening */
#include "core/compat/af_policy.h"        /* brix_af_policy_t origin family policy */
#include "net/dns/dns.h"                  /* brix_dns_resolve_sync: the one DNS path */


#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <openssl/err.h>

/* brix_cache_origin_close — free everything an origin connection holds (SSL,
 * SSL_CTX, socket fd) and NULL the pointers; symmetric with origin_connect and
 * called on every error path. Order matters: SSL shutdown before free, SSL_CTX
 * before the fd close, fd last, so the SSL layer never dangles. */

void
brix_cache_origin_close(brix_cache_origin_conn_t *oc)
{
    if (oc->ssl != NULL) {
        SSL_shutdown(oc->ssl);
        SSL_free(oc->ssl);
        oc->ssl = NULL;
    }

    if (oc->ssl_ctx != NULL) {
        SSL_CTX_free(oc->ssl_ctx);
        oc->ssl_ctx = NULL;
    }

    if (oc->fd >= 0) {
        close(oc->fd);
        oc->fd = -1;
    }
}

/* origin_tls_load_verify — load the origin's CA trust anchor into ssl_ctx,
 * choosing CAfile vs CApath by stat(). WHAT: brix_trusted_ca (synth->trusted_ca)
 * may be a single PEM bundle OR a hashed CA directory (grid-security style); the
 * two OpenSSL slots are not interchangeable, so a directory passed as CAfile
 * silently loads nothing and the peer verify then falls back to the system store.
 * WHY: the origin CA is operator-configured (e->origin_ca_dir → synth->trusted_ca)
 * and is usually a directory. HOW: stat → S_ISDIR ? CApath : CAfile; empty trust
 * anchor → system default paths. Returns 0 on a usable store, -1 on load failure. */
static int
origin_tls_load_verify(SSL_CTX *ctx, const ngx_str_t *ca)
{
    if (ca == NULL || ca->len == 0 || ca->data == NULL) {
        (void) SSL_CTX_set_default_verify_paths(ctx);
        return 0;
    }
    {
        char        path[PATH_MAX];
        size_t      n = ca->len < sizeof(path) - 1 ? ca->len : sizeof(path) - 1;
        struct stat st;
        int         is_dir;
        int         ok;

        ngx_memcpy(path, ca->data, n);
        path[n] = '\0';

        is_dir = (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
        ok = is_dir
            ? SSL_CTX_load_verify_locations(ctx, NULL, path)
            : SSL_CTX_load_verify_locations(ctx, path, NULL);
        return ok == 1 ? 0 : -1;
    }
}

/* brix_cache_origin_tls_upgrade — perform a blocking client TLS handshake over
 * the ALREADY-CONNECTED origin fd (oc->fd), storing the negotiated SSL on oc->ssl
 * so every subsequent frame rides TLS via the io.c SSL_read/SSL_write path.
 *
 * WHAT: build a per-connection SSL_CTX (peer verify against synth->trusted_ca,
 *       CAfile-or-CApath), bind the expected hostname + SNI, and SSL_connect.
 * WHY:  a stock XRootD `roots://` origin negotiates kXR_protocol over CLEARTEXT
 *       and then advertises kXR_gotoTLS; the client must upgrade THIS fd in place
 *       before kXR_login/auth. The same helper also serves any TLS-from-connect
 *       caller (call it right after connect). Runs on a blocking fill worker, so
 *       it uses a synchronous SSL_connect rather than nginx's async handshake.
 * HOW:  SSL_CTX_new(TLS_client) → SSL_VERIFY_PEER → origin_tls_load_verify →
 *       SSL_set1_host + SNI (MITM: chain-only would accept any CA-valid cert) →
 *       SSL_set_fd(oc->fd) → SSL_connect. On failure t's error is set; any partly
 *       built oc->ssl/oc->ssl_ctx stay attached to oc for the caller's
 *       brix_cache_origin_close to release (same contract as connect_addr).
 * Returns 0 with oc->ssl live, -1 on failure (t error set). */
int
brix_cache_origin_tls_upgrade(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const ngx_str_t *host)
{
    oc->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (oc->ssl_ctx == NULL) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin TLS context failed");
        return -1;
    }
    SSL_CTX_set_min_proto_version(oc->ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(oc->ssl_ctx, SSL_VERIFY_PEER, NULL);

    if (origin_tls_load_verify(oc->ssl_ctx,
                               &t->conf->common.trusted_ca) != 0) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin CA load failed");
        return -1;
    }

    oc->ssl = SSL_new(oc->ssl_ctx);
    if (oc->ssl == NULL) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin TLS allocation failed");
        return -1;
    }

    /*
     * Verify the presented cert is actually FOR this host: SSL_VERIFY_PEER only
     * checks the chain, not the name, so without SSL_set1_host an on-path attacker
     * with ANY CA-valid cert could impersonate the origin. Fold the name check
     * into the handshake verification and set SNI so the origin serves the right
     * cert.
     */
    if (host != NULL && host->len > 0 && host->data != NULL) {
        char   vhost[256];
        size_t hl = host->len < sizeof(vhost) - 1
                    ? host->len : sizeof(vhost) - 1;

        ngx_memcpy(vhost, host->data, hl);
        vhost[hl] = '\0';
        SSL_set_hostflags(oc->ssl, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
        if (SSL_set1_host(oc->ssl, vhost) != 1) {
            brix_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin TLS host-verify setup failed");
            return -1;
        }
        (void) SSL_set_tlsext_host_name(oc->ssl, vhost);
    }
    SSL_set_fd(oc->ssl, oc->fd);

    if (SSL_connect(oc->ssl) != 1) {
        char ebuf[160];

        ERR_error_string_n(ERR_get_error(), ebuf, sizeof(ebuf));
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0,
            "brix: cache origin TLS handshake failed: %s", ebuf);
        brix_cache_set_error(t, kXR_TLSRequired, 0,
                               "cache origin TLS handshake failed");
        return -1;
    }
    return 0;
}

/* brix_cache_origin_connect_addr — resolve through the phase-116 DNS driver
 * (brix_dns_resolve_sync: never getaddrinfo here), try each answer with a
 * non-blocking poll-timeout connect (avoids the ~2min TCP retransmit stall), set
 * SO_RCVTIMEO/SO_SNDTIMEO. TLS is NOT engaged here for a root:// origin: a stock
 * XRootD `roots://` peer does the kXR_protocol exchange over CLEARTEXT and then
 * advertises kXR_gotoTLS, so brix_cache_origin_bootstrap upgrades the fd in place
 * (brix_cache_origin_tls_upgrade) after the protocol reply. Runs in a blocking
 * fill thread-pool worker, so it uses poll() rather than the event loop;
 * BRIX_CACHE_IO_TIMEOUT bounds an unreachable peer. */
int
brix_cache_origin_connect_addr(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const ngx_str_t *host, uint16_t portnum)
{
    brix_dns_addr_t  addrs[BRIX_DNS_MAX_ADDRS];
    char             reason[BRIX_DNS_ERROR_LEN];
    ngx_uint_t       fam, n, i;

    oc->fd = -1;
    oc->ssl_ctx = NULL;
    oc->ssl = NULL;

    if (host == NULL || host->len == 0 || host->data == NULL
        || portnum == 0)
    {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin address not configured");
        return -1;
    }

    fam = (t->conf != NULL)
          ? t->conf->cache_origin_family : (ngx_uint_t) BRIX_AF_AUTO;
    if (fam == NGX_CONF_UNSET_UINT) {
        fam = (ngx_uint_t) BRIX_AF_AUTO;     /* AUTO tries every family */
    }

    /* phase-116: resolve through the one brix DNS path (literal, per-worker
     * cache, the export's brix_resolver, then libc) under the export's
     * policy; a registry-built origin carries the policy on its synthetic
     * conf, an unconfigured one resolves the way libc reads resolv.conf. */
    n = brix_dns_resolve_sync(t->conf != NULL ? t->conf->common.dns.policy
                                              : NULL,
                              (const char *) host->data, portnum,
                              (brix_af_policy_t) fam, SOCK_STREAM, addrs,
                              BRIX_DNS_MAX_ADDRS, reason, sizeof(reason));
    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, ngx_cycle->log, 0,
                      "brix cache origin \"%V\": DNS resolution failed: %s",
                      host, reason);
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin DNS resolution failed");
        return -1;
    }

    for (i = 0; i < n; i++) {
        int  fd;

        fd = socket(addrs[i].ss.ss_family, SOCK_STREAM, 0);
        if (fd < 0) {
            continue;
        }

        brix_apply_socket_io_timeouts(fd, BRIX_CACHE_IO_TIMEOUT);

        if (brix_connect_fd_deadline(fd, (struct sockaddr *) &addrs[i].ss,
                                       addrs[i].len,
                                       BRIX_CACHE_IO_TIMEOUT * 1000) == 0)
        {
            oc->fd = fd;
            /* TLS is deferred: the root:// bootstrap negotiates kXR_protocol
             * over cleartext and upgrades on the origin's kXR_gotoTLS advert.
             * See brix_cache_origin_tls_upgrade + brix_cache_origin_bootstrap. */
            return 0;
        }

        close(fd);
    }

    brix_cache_set_syserror(t, kXR_ServerError, "cache origin connect failed");
    return -1;
}

/* brix_cache_origin_connect — thin wrapper: connect_addr using the configured
 * cache_origin host/port. 0 on success (with TLS if configured), -1 on error. */
int
brix_cache_origin_connect(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc)
{
    return brix_cache_origin_connect_addr(t, oc,
                                            &t->conf->cache_origin_host,
                                            t->conf->cache_origin_port);
}
