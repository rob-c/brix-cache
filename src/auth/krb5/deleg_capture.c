#include "auth/krb5/deleg_capture.h"
#include "auth/krb5/capture.h"
#include "auth/krb5/carry.h"
#include "auth/krb5/forward.h"                        /* origin_princ_from_host */
#include "auth/gsi/gsi_core.h"                        /* brix_gbuf */
#include "protocols/root/response/response.h"         /* build_resp_hdr, send_error */
#include "protocols/root/connection/write_helpers.h"  /* brix_queue_response */
#include "protocols/root/protocol/opcodes.h"          /* XRD_RESPONSE_HDR_LEN, kXR_authmore */

#include <string.h>

/*
 * deleg_capture.c — inbound XrdSeckrb5 forwarded-TGT delegation-capture state
 * machine (phase-70 §5.7). See deleg_capture.h for the contract and the WHAT/WHY.
 */

/* ------------------------------------------------------------------ *
 * Always-compiled seams (no krb5/GSSAPI): the gate, the round-2 payload framing,
 * the fwdtgt continuation wire, and the request-time origin-SPN derivation.
 * ------------------------------------------------------------------ */

int
brix_krb5_deleg_wanted(ngx_stream_brix_srv_conf_t *conf)
{
    return conf != NULL && conf->krb5.delegate == 1;
}

ngx_int_t
brix_krb5_deleg_credbytes(const u_char *payload, size_t dlen,
    const u_char **cred, size_t *credlen)
{
    size_t off;

    if (payload == NULL || cred == NULL || credlen == NULL
        || dlen <= 4 || ngx_strncmp(payload, "krb5", 4) != 0)
    {
        return NGX_ERROR;
    }

    /* The official XrdSeckrb5 client NUL-terminates the "krb5" prefix; the native
     * client emits a bare "krb5". A KRB_CRED begins with its ASN.1 APPLICATION
     * tag (0x76), never 0x00, so skipping the optional NUL cannot truncate it.
     * dlen > 4 guarantees payload[4] is in-bounds; a body-less "krb5\0" then
     * skips to off == 5 and fails the emptiness check below. */
    off = 4;
    if (payload[4] == '\0') {
        off = 5;
    }

    if (dlen <= off) {
        return NGX_ERROR;
    }

    *cred = payload + off;
    *credlen = dlen - off;
    return NGX_OK;
}

ngx_int_t
brix_krb5_send_fwdtgt(brix_ctx_t *ctx, ngx_connection_t *c)
{
    brix_gbuf  g;
    u_char    *buf;
    size_t     total;

    brix_gbuf_init(&g);
    brix_gbuf_raw(&g, "krb5", 5);      /* protocol name + NUL */
    brix_gbuf_raw(&g, "fwdtgt", 7);    /* forward-TGT continuation marker + NUL */
    brix_gbuf_end(&g);

    if (g.err) {
        brix_gbuf_free(&g);
        return brix_send_error(ctx, c, kXR_NoMemory, "krb5: out of memory");
    }

    total = XRD_RESPONSE_HDR_LEN + g.len;
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        brix_gbuf_free(&g);
        return brix_send_error(ctx, c, kXR_NoMemory, "krb5: out of memory");
    }

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_authmore,
                          (uint32_t) g.len, (ServerResponseHdr *) buf);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, g.p, g.len);
    brix_gbuf_free(&g);

    ngx_log_debug0(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: krb5 round 1 -> fwdtgt (delegation requested)");
    return brix_queue_response(ctx, c, buf, total);
}

ngx_int_t
brix_krb5_deleg_origin_spn(const ngx_str_t *ccache, int forwardable,
    const ngx_str_t *origin_host, const ngx_str_t *gateway_princ,
    ngx_pool_t *pool, ngx_str_t *out_spn)
{
    char    host[256];
    char    gwp[512];
    u_char *spn;
    size_t  spnlen;

    if (ccache == NULL || ccache->len == 0 || !forwardable
        || origin_host == NULL || origin_host->len == 0
        || origin_host->len >= sizeof(host)
        || gateway_princ == NULL || gateway_princ->len == 0
        || gateway_princ->len >= sizeof(gwp))
    {
        return NGX_DECLINED;            /* a gate is unmet — nothing to bind */
    }

    ngx_memcpy(host, origin_host->data, origin_host->len);
    host[origin_host->len] = '\0';
    ngx_memcpy(gwp, gateway_princ->data, gateway_princ->len);
    gwp[gateway_princ->len] = '\0';

    spn = ngx_pnalloc(pool, 512);
    if (spn == NULL) {
        return NGX_ERROR;
    }

    if (brix_krb5_origin_princ_from_host(host, gwp, (char *) spn, 512) != NGX_OK) {
        return NGX_ERROR;              /* fail closed — do not bind a bad SPN */
    }

    spnlen = ngx_strlen(spn);
    if (spnlen == 0) {
        return NGX_ERROR;
    }

    out_spn->data = spn;
    out_spn->len = spnlen;
    return NGX_OK;
}

#if (BRIX_HAVE_KRB5)

#include <krb5.h>
#include <gssapi/gssapi.h>
#include <stdlib.h>
#include <unistd.h>

/* Pool-cleanup payload: enough to reach the parked handles + ccache at close. */
typedef struct {
    brix_ctx_t   *ctx;
    krb5_context  kctx;
} brix_krb5_deleg_cleanup_t;

void
brix_krb5_deleg_release(brix_ctx_t *ctx, krb5_context kctx)
{
    if (ctx->krb5.auth_ctx != NULL) {
        krb5_auth_con_free(kctx, (krb5_auth_context) ctx->krb5.auth_ctx);
        ctx->krb5.auth_ctx = NULL;
    }
    if (ctx->krb5.client != NULL) {
        krb5_free_principal(kctx, (krb5_principal) ctx->krb5.client);
        ctx->krb5.client = NULL;
    }
    ctx->krb5.round = 0;
}

/* Connection-close teardown: release any parked round-1 handles and unlink the
 * captured forwarded-TGT ccache (it is a per-connection 0600 temp). */
static void
brix_krb5_deleg_cleanup(void *data)
{
    brix_krb5_deleg_cleanup_t *cl = data;

    brix_krb5_deleg_release(cl->ctx, cl->kctx);

    if (cl->ctx->krb5.ccache[0] != '\0') {
        (void) unlink(cl->ctx->krb5.ccache);
        cl->ctx->krb5.ccache[0] = '\0';
    }
}

ngx_int_t
brix_krb5_deleg_park(brix_ctx_t *ctx, ngx_connection_t *c, krb5_context kctx,
    krb5_auth_context auth_ctx, krb5_principal client, const char *cname)
{
    krb5_principal              cli_copy = NULL;
    ngx_pool_cleanup_t         *cln;
    brix_krb5_deleg_cleanup_t  *cl;

    if (krb5_copy_principal(kctx, client, &cli_copy) != 0) {
        return NGX_ERROR;
    }

    cln = ngx_pool_cleanup_add(c->pool, sizeof(*cl));
    if (cln == NULL) {
        krb5_free_principal(kctx, cli_copy);
        return NGX_ERROR;
    }

    ctx->krb5.auth_ctx = auth_ctx;
    ctx->krb5.client   = cli_copy;
    ctx->krb5.round    = 1;
    ngx_cpystrn((u_char *) ctx->krb5.cname, (u_char *) cname,
                sizeof(ctx->krb5.cname));

    cl = cln->data;
    cl->ctx  = ctx;
    cl->kctx = kctx;
    cln->handler = brix_krb5_deleg_cleanup;
    return NGX_OK;
}

/* Create a fresh 0600 temp file to back the captured forwarded-TGT ccache. Honors
 * $TMPDIR, defaulting to /tmp; mkstemp() guarantees O_EXCL + mode 0600. */
static ngx_int_t
brix_krb5_deleg_mkccache(ngx_connection_t *c, char *path, size_t pathlen)
{
    const char *dir = getenv("TMPDIR");
    u_char     *end;
    int         fd;

    if (dir == NULL || dir[0] == '\0') {
        dir = "/tmp";
    }

    end = ngx_snprintf((u_char *) path, pathlen, "%s/brix-krb5-fwd-XXXXXX", dir);
    if ((size_t) (end - (u_char *) path) >= pathlen) {
        return NGX_ERROR;
    }
    *end = '\0';

    fd = mkstemp(path);
    if (fd < 0) {
        ngx_log_error(NGX_LOG_ERR, c->log, ngx_errno,
                      "brix: krb5 fwdtgt: cannot create temp ccache");
        return NGX_ERROR;
    }
    (void) close(fd);   /* libkrb5 rewrites the FILE by name, keeping mode 0600 */
    return NGX_OK;
}

/* Release the capture entry's output handles (its private MEMORY ccache + the
 * imported GSS cred) once the forwarded TGT has been serialised to the FILE. */
static void
brix_krb5_capture_out_release(krb5_context kctx, void *gss_cred, void *cap_cc)
{
    OM_uint32     min;
    gss_cred_id_t cred = gss_cred;

    if (cred != GSS_C_NO_CREDENTIAL) {
        (void) gss_release_cred(&min, &cred);
    }
    if (cap_cc != NULL) {
        krb5_cc_destroy(kctx, (krb5_ccache) cap_cc);
    }
}

/* The serialising core of round 2: decode the KRB_CRED, run the production
 * capture, and export the forwarded TGT to a 0600 FILE ccache at *path. Split
 * from the entry so each stays within the CCN ceiling; the entry owns handle
 * release regardless of the outcome here. */
static ngx_int_t
brix_krb5_capture_do(brix_ctx_t *ctx, ngx_connection_t *c, krb5_context kctx,
    void **gss_cred, void **cap_cc, char *path, size_t pathlen)
{
    const u_char *cred;
    size_t        credlen;

    if (brix_krb5_deleg_credbytes(ctx->recv.payload, ctx->recv.cur_dlen,
                                  &cred, &credlen) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                      "brix: krb5 fwdtgt round 2: malformed forwarded credential");
        return NGX_ERROR;
    }

    if (brix_krb5_capture_fwd_cred(kctx, ctx->krb5.auth_ctx, ctx->krb5.client,
                                   cred, credlen, gss_cred, cap_cc, c->log)
            != NGX_OK)
    {
        return NGX_ERROR;   /* capture already logged the krb5 detail */
    }

    if (brix_krb5_deleg_mkccache(c, path, pathlen) != NGX_OK) {
        return NGX_ERROR;
    }

    if (brix_krb5_cred_to_ccache(*gss_cred, path, c->log) != NGX_OK) {
        (void) unlink(path);
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_krb5_deleg_capture(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf)
{
    krb5_context  kctx = conf->krb5.context;
    void         *gss_cred = NULL;
    void         *cap_cc = NULL;
    char          path[1024];
    ngx_int_t     rc;

    if (ctx->krb5.round != 1 || ctx->krb5.auth_ctx == NULL
        || ctx->krb5.client == NULL || kctx == NULL)
    {
        return NGX_ERROR;
    }

    rc = brix_krb5_capture_do(ctx, c, kctx, &gss_cred, &cap_cc,
                              path, sizeof(path));

    /* The round-1 handles have done their job on both paths — release them and
     * drop the round state; likewise the capture entry's output handles. */
    brix_krb5_capture_out_release(kctx, gss_cred, cap_cc);
    brix_krb5_deleg_release(ctx, kctx);

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_cpystrn((u_char *) ctx->krb5.ccache, (u_char *) path,
                sizeof(ctx->krb5.ccache));

    /* Operator-visible confirmation the inbound leg completed: the mapped identity
     * only (cname is already logged by the session grant), never the TGT bytes. */
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: krb5 delegation captured forwarded TGT for \"%s\"",
                  ctx->krb5.cname);
    return NGX_OK;
}

#endif /* BRIX_HAVE_KRB5 */
