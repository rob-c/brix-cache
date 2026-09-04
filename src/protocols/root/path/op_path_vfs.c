/* Session-to-VFS delegation and monitoring binding for root:// operations. */
#include "core/ngx_brix_module.h"
#include "protocols/root/path/op_path.h"
#include "fs/vfs/vfs.h"
#include "protocols/shared/deleg_wire.h"
#include "auth/krb5/deleg_capture.h"
#include "auth/protbind/protbind.h"

#if (BRIX_HAVE_KRB5)
/* ---- op_path_backend_host --------------------------------------------------
 *
 * WHAT: Extract the bare host from a "root://host:port" storage-backend URL as a
 *       borrowed view into `url` — handling the "roots://" scheme, bracketed IPv6
 *       ([::1]:port), and an optional trailing "/path". Empty view when absent.
 *
 * WHY:  §5.7 krb5 EXCHANGE. The modern brix_storage_backend grammar parses the
 *       driver host lazily in the sd_xroot factory, so conf->cache_origin_host is
 *       empty on a plain root:// export; the delegated-TGT origin SPN derivation
 *       (brix_krb5_deleg_origin_spn) needs the host, recovered from the URL here.
 *       The derived SPN is only a fallback — the origin's advertised "&P=krb5,<spn>"
 *       wins at auth time — but a non-empty host is required for the bind to run.
 *
 * HOW:  Strip the scheme prefix, then take the bracketed IPv6 body or the token up
 *       to the first ':' or '/'. A borrowed view (no allocation); the bytes live on
 *       the config and outlive the op. */
static ngx_str_t
op_path_backend_host(const ngx_str_t *url)
{
    ngx_str_t  h = { 0, NULL };
    u_char    *p, *end, *stop, *rb;

    if (url == NULL || url->len == 0) {
        return h;
    }
    p   = url->data;
    end = url->data + url->len;

    if ((size_t) (end - p) > sizeof("roots://") - 1
        && ngx_strncmp(p, "roots://", sizeof("roots://") - 1) == 0)
    {
        p += sizeof("roots://") - 1;
    } else if ((size_t) (end - p) > sizeof("root://") - 1
        && ngx_strncmp(p, "root://", sizeof("root://") - 1) == 0)
    {
        p += sizeof("root://") - 1;
    }

    if (p < end && *p == '[') {                 /* [IPv6]:port */
        rb = ngx_strlchr(p, end, ']');
        if (rb == NULL) {
            return h;
        }
        h.data = p + 1;
        h.len  = (size_t) (rb - (p + 1));
        return h;
    }

    stop = p;                                   /* host ends at ':' or '/' */
    while (stop < end && *stop != ':' && *stop != '/') {
        stop++;
    }
    h.data = p;
    h.len  = (size_t) (stop - p);
    return h;
}
#endif

static void
op_path_bind_authz(brix_ctx_t *ctx, ngx_stream_brix_srv_conf_t *conf,
    brix_vfs_ctx_t *vctx)
{
    const char *peer;
    const char *host;

    if (conf == NULL) {
        return;
    }
    peer = ctx->login.peer_ip;
    if (conf->common.acc.resolve_hosts && ctx->session != NULL) {
        host = brix_protbind_peer_host_cached(ctx, ctx->session->connection);
        if (host != NULL) {
            peer = host;
        }
    }
    brix_vfs_ctx_bind_authz(vctx, conf->authdb_rules, conf->common.vo_rules,
        conf->common.acc.tables, conf->common.acc.format, peer,
        (brix_authz_backstop_mode_t) conf->common.authz_backstop);
}

void
brix_root_vfs_ctx_init(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, brix_vfs_ctx_t *vctx,
    const char *resolved_path)
{
    brix_vfs_ctx_init(vctx, c->pool, c->log, BRIX_PROTO_ROOT,
        conf->common.root_canon, NULL,
        brix_vfs_policy_from_write_enable(conf->common.allow_write),
        0 /* is_tls */, ctx->identity, resolved_path);
    vctx->rootfd = conf->rootfd;
    brix_root_vfs_bind_session(ctx, conf, vctx);
}

/* ---- brix_root_vfs_bind_session ----------------------------------------------
 *
 * WHAT: Bind the session's captured raw bearer JWT onto a cred-bound VFS ctx for
 *       backend PASSTHROUGH. See op_path.h for the full contract.
 *
 * WHY:  Lets a remote-backed root:// export authenticate the backend leg AS the
 *       inbound user. Two forwardable credentials ride the GSI login: the raw
 *       bearer JWT (ctx->bearer_token) and — when the client opts in and the DN
 *       is proven (phase-70 §5.1, gsi_promote_fullproxy) — a full x509 proxy
 *       (ctx->deleg_proxy_pem, chain + private key) for backend PASSTHROUGH.
 *
 * HOW:  No-op on the default SELECT export. Otherwise wraps whichever
 *       credential(s) the session captured as ngx_str_t (bytes owned by the
 *       session ctx, outliving the op) and hands them to brix_vfs_deleg_bind on
 *       the VFS ctx's pool. The full proxy is forwarded only in PASSTHROUGH
 *       mode — the only strategy that replays the user's own credential
 *       verbatim. If neither credential is present, nothing is bound. */
void
brix_root_vfs_bind_session(brix_ctx_t *ctx,
                             ngx_stream_brix_srv_conf_t *conf,
                             brix_vfs_ctx_t *vctx)
{
    ngx_str_t         bearer;
    const ngx_str_t  *bearer_arg = NULL;
    const ngx_str_t  *proxy_arg = NULL;

    if (ctx == NULL || vctx == NULL) {
        return;
    }

    /* phase-110 W3: every VFS ctx the session builds folds into the session's
     * I/O monitor (context.h) — this is the root plane's ONE per-session
     * post-init hook, called at all 14 ctx-build sites, which is what makes
     * the stream $brix_* surface complete by construction rather than by
     * remembering each site. Unconditional and before the delegation
     * early-return: monitoring does not depend on the credential mode. The
     * monitor is embedded in the pcalloc'd per-connection ctx, so this is an
     * event-loop-allocated target the offload thread may scalar-write. */
    vctx->io_monitor = &ctx->io_monitor;
    /* phase-110 W7: the client address for the JSON access log's `remote`.
     * ctx->peer_ip is an already-NUL-terminated cstr (populated for authdb HOST
     * rules), so this is a borrow, not an alloc — safe on any thread. */
    if (ctx->login.peer_ip[0] != '\0') {
        vctx->peer = ctx->login.peer_ip;
    }

    op_path_bind_authz(ctx, conf, vctx);

    if (conf == NULL || conf->common.backend_delegation == BRIX_CRED_SELECT) {
        return;
    }

    bearer.data = (u_char *) ctx->bearer_token;
    bearer.len  = ngx_strlen(ctx->bearer_token);
    if (bearer.len > 0) {
        /* Backend audience gate (phase-70 §5.2 / P90-70.9): a bearer forwarded
         * verbatim must name the backend in its aud — on refusal nothing is
         * bound and the service-cred policy applies. */
        bearer_arg = brix_proto_deleg_gate_bearer(&bearer, &conf->common,
                                                  vctx->log);
    }

    /* A full proxy is a PASSTHROUGH-only credential: it is presented to the
     * upstream unmodified, so it makes sense only when the resolved mode replays
     * the user's own credential. */
    if (ctx->deleg_proxy_pem.len > 0
        && (enum brix_cred_mode) conf->common.backend_delegation
               == BRIX_CRED_PASSTHROUGH)
    {
        proxy_arg = &ctx->deleg_proxy_pem;
    }

    /* Phase 70 §5.7: an inbound-captured forwarded TGT (ctx->krb5.ccache) binds
     * as a krb5 EXCHANGE credential so the origin leg re-authenticates AS the
     * user over GSSAPI. The origin service principal is derived from the
     * configured origin host + the gateway realm; independent of the bearer/proxy
     * binding, and it allocates its own live-cred bag (like the STS/SSS stamps),
     * so it must run before the no-bearer/no-proxy early return. */
#if (BRIX_HAVE_KRB5)
    {
        ngx_str_t  cc;
        ngx_str_t  spn;
        ngx_str_t  origin_host = conf->cache_origin_host;

        /* The modern "brix_storage_backend root://host:port" grammar parses the
         * origin host lazily in the driver factory (sd_xroot), so on a plain
         * root:// export conf->cache_origin_host is empty here — only the legacy
         * tier grammar fills it. Recover the host from the backend URL so the
         * delegated-TGT origin SPN can still be derived; without it the krb5
         * EXCHANGE bind would silently no-op and the origin leg would fall back
         * to the (absent) service credential. */
        if (origin_host.len == 0) {
            origin_host = op_path_backend_host(&conf->common.storage_backend);
        }

        cc.data = (u_char *) ctx->krb5.ccache;
        cc.len  = ngx_strlen(ctx->krb5.ccache);

        if (brix_krb5_deleg_origin_spn(&cc, conf->common.backend_krb5_forwardable,
                &origin_host, &conf->krb5.principal,
                vctx->pool, &spn) == NGX_OK)
        {
            brix_vfs_deleg_set_krb5(vctx,
                (enum brix_cred_mode) conf->common.backend_delegation, &cc, &spn);
        }
    }
#endif

    if (bearer_arg == NULL && proxy_arg == NULL) {
        return;
    }

    (void) brix_vfs_deleg_bind(vctx->pool, vctx,
        (enum brix_cred_mode) conf->common.backend_delegation,
        bearer_arg, proxy_arg);

    brix_proto_deleg_stamp_conf(vctx, &conf->common);

    /* P90-70.4: stamp the server's GSI trust store so the VFS deleg gate
     * re-runs the RFC-3820 chain-trust check on the pushed proxy before
     * materialising it (gsi_promote_fullproxy only DN-matches the push).
     * Depth 0 = OpenSSL default, matching the root:// login verify. */
    brix_vfs_deleg_set_ca_store(vctx, conf->gsi_store, 0);
}
