#ifndef BRIX_CORE_HTTP_KTLS_H
#define BRIX_CORE_HTTP_KTLS_H

/*
 * core/http/ktls.h — enable kernel-TLS (kTLS) on an nginx http_ssl context.
 *
 * WHAT: brix_http_ktls_enable_ctx() sets SSL_OP_ENABLE_KTLS on a server's
 *       already-built OpenSSL SSL_CTX so that HTTPS responses sendfile(2) over
 *       kernel-TLS (the kernel encrypts the records in place) and request bodies
 *       decrypt in-kernel — cutting the userspace SSL_write/memmove crypto that
 *       dominates the TLS data path.
 *
 * WHY:  The HTTP plane (WebDAV, S3) serves files through nginx's native output
 *       chain, which already uses sendfile; once the SSL_CTX is kTLS-opted,
 *       ngx_linux_sendfile()/recv use kTLS automatically with NO handler change.
 *       This is the HTTP twin of the root:// stream path's SSL_OP_ENABLE_KTLS
 *       (src/protocols/root/session/tls_config.c).
 *
 * HOW:  Runtime-safe. SSL_OP_ENABLE_KTLS is a transparent no-op when the
 *       negotiated cipher or the running kernel cannot offload — OpenSSL then
 *       falls back to userspace TLS. Each protocol calls this from its own
 *       postconfiguration server loop for the servers it owns (proper layering:
 *       this helper only touches the SSL_CTX it is handed).
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <openssl/ssl.h>

static inline void
brix_http_ktls_enable_ctx(SSL_CTX *ctx, ngx_log_t *log, ngx_str_t *server_name)
{
#ifdef SSL_OP_ENABLE_KTLS
    if (ctx == NULL) {
        return;
    }
    SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "brix: kernel-TLS (kTLS) requested on SSL context for server "
                  "%V (brix_ktls on) - engages per-connection when the "
                  "negotiated cipher is kTLS-offloadable, else userspace TLS",
                  server_name);
#else
    (void) ctx;
    (void) log;
    (void) server_name;
#endif
}

#endif /* BRIX_CORE_HTTP_KTLS_H */
