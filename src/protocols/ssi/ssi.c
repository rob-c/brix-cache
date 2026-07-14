/*
 * ssi.c — byte-exact XrdSsi-over-xroot engine glue (§7). See ssi.h.
 *
 * The open/query/read hooks are clean early-returns keyed on
 * ctx->files[idx].ssi, so the normal data path is unchanged for non-SSI handles.
 * Wire decode/encode lives in ssi_rrinfo (golden-validated) and ssi_reply. The
 * responder machinery, async deferral, and the kXR_write accumulation/dispatch
 * path live in ssi_dispatch.c (this file calls brix_ssi_dispatch on the
 * write-until-read path); the service dispatch uses the native responder
 * interface in ssi_service.
 */

#include "core/ngx_brix_module.h"   /* master header: ngx + tunables + config + types */
#include "ssi.h"
#include "ssi_internal.h"
#include "ssi_rrinfo.h"
#include "ssi_reply.h"
#include "ssi_service.h"
#include "provider.h"
#include "session.h"
#include "registry.h"
#include "deliver.h"
#include "protocols/ssi/svc_cta/cta_service.h"
#include "protocols/root/connection/fd_table.h"
#include "protocols/root/response/response.h"
#include "core/compat/error_mapping.h"   /* brix_kxr_from_errno */
#include "protocols/root/protocol/opcodes.h"
#include "protocols/root/protocol/wire_core_requests.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int
brix_ssi_match(ngx_stream_brix_srv_conf_t *conf, const char *path,
                 const char **service, size_t *service_len)
{
    const char *svc;
    size_t      n;

    if (conf == NULL || !conf->ssi_enable || path == NULL) {
        return 0;
    }
    if (ngx_strncmp(path, BRIX_SSI_PREFIX, BRIX_SSI_PREFIX_LEN) != 0) {
        return 0;
    }
    svc = path + BRIX_SSI_PREFIX_LEN;
    n = 0;
    while (svc[n] != '\0' && svc[n] != '/' && svc[n] != '?') {
        n++;
    }
    if (n == 0 || n >= 64) {
        return 0;
    }
    *service     = svc;
    *service_len = n;
    return 1;
}

/* ---- Gate + configure the CTA tape service during SSI open ----
 *
 * WHAT: For service name "cta", verifies `brix_ssi_service cta;` is enabled and
 * pushes the journal path + executor backend down to the service. Returns 1 when
 * the open may proceed (either non-CTA, or CTA enabled + configured); returns 0
 * after sending a kXR_NotFound error and stashing its status in *out_rc.
 *
 * WHY: The CTA service exposes a storage-control surface that must stay dark
 * unless explicitly enabled; isolating the gate keeps brix_ssi_open a flat
 * early-return sequence and confines the temporary journal buffer to one scope.
 *
 * HOW: 1) Non-"cta" services short-circuit to proceed. 2) Reject when conf is
 * absent or ssi_cta_enable is off — indistinguishable from an unknown service.
 * 3) Copy the journal directive into a null-terminated buffer (bounded) and
 * apply it with the executor flag.
 */
static int
ssi_open_cta_gate(brix_ctx_t *ctx, ngx_connection_t *c,
                  ngx_stream_brix_srv_conf_t *conf, const char *svc,
                  ngx_int_t *out_rc)
{
    char   jbuf[1024];
    size_t jlen;

    if (ngx_strcmp(svc, "cta") != 0) {
        return 1;
    }
    if (conf == NULL || !conf->ssi_cta_enable) {
        *out_rc = brix_send_error(ctx, c, kXR_NotFound, "unknown SSI service");
        return 0;
    }
    jlen = conf->ssi_cta_journal.len;
    if (jlen >= sizeof(jbuf)) {
        jlen = sizeof(jbuf) - 1;
    }
    ngx_memcpy(jbuf, conf->ssi_cta_journal.data, jlen);
    jbuf[jlen] = '\0';
    brix_ssi_cta_configure(jbuf, conf->ssi_cta_executor == 1);
    return 1;
}

/* ---- Build and queue the byte-exact SSI open reply ----
 *
 * WHAT: Assembles the response header + 12-byte ServerOpenBody (carrying the file
 * handle in fhandle[0]), optionally followed by a synthesized StatInfo string,
 * and queues it. Returns the queue result, or a kXR_NoMemory error status if the
 * response buffer cannot be allocated.
 *
 * WHY: The libXrdSsi client opens with kXR_retstat and refuses the reply unless a
 * StatInfo string follows the ServerOpenBody. Keeping the exact layout (header,
 * then body, then optional "id size flags mtime\0") in one helper preserves the
 * wire contract while shrinking the orchestrator.
 *
 * HOW: 1) Zero the body and stamp the handle index. 2) When want_stat, format a
 * plausible stat (id 0, size 0, read+write flags, mtime now) matching the
 * open-path format and grow bodylen by its NUL-terminated length. 3) Allocate the
 * header+body(+stat) buffer, build the header for the current streamid, copy the
 * body, append the stat string when present, and queue.
 */
static ngx_int_t
ssi_open_send_reply(brix_ctx_t *ctx, ngx_connection_t *c, int idx, int want_stat)
{
    ServerOpenBody  body;
    char            statbuf[128];
    size_t          total, bodylen;
    u_char         *buf;

    ngx_memzero(&body, sizeof(body));
    body.fhandle[0] = (u_char) idx;
    bodylen = sizeof(ServerOpenBody);

    statbuf[0] = '\0';
    if (want_stat) {
        ngx_snprintf((u_char *) statbuf, sizeof(statbuf), "%d %d %d %T%Z",
                     0, 0, kXR_readable | kXR_writable, ngx_time());
        bodylen += ngx_strlen(statbuf) + 1;
    }

    total = XRD_RESPONSE_HDR_LEN + bodylen;
    buf   = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return brix_send_error(ctx, c, kXR_NoMemory, "ssi resp");
    }
    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok, (uint32_t) bodylen,
                          (ServerResponseHdr *) buf);
    ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, sizeof(ServerOpenBody));
    if (want_stat) {
        size_t slen = ngx_strlen(statbuf) + 1;
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
                   statbuf, slen);
    }

    return brix_queue_response(ctx, c, buf, total);
}

ngx_int_t
brix_ssi_open(brix_ctx_t *ctx, ngx_connection_t *c,
                const char *service, size_t service_len, uint16_t options)
{
    ngx_connection_t      *conn = c;
    brix_ssi_session_t  *sess;
    brix_ssi_provider_t  prov;
    char                   svc[64];
    int                    idx, devnull;
    ngx_int_t              gate_rc;
    int                    want_stat = (options & kXR_retstat) ? 1 : 0;

    ngx_stream_brix_srv_conf_t *conf = ngx_stream_get_module_srv_conf(
        (ngx_stream_session_t *) c->data, ngx_stream_brix_module);

    ngx_memcpy(svc, service, service_len);
    svc[service_len] = '\0';

    if (!brix_ssi_provider_lookup(svc, &prov)) {
        return brix_send_error(ctx, c, kXR_NotFound, "unknown SSI service");
    }

    if (!ssi_open_cta_gate(ctx, c, conf, svc, &gate_rc)) {
        return gate_rc;
    }

    idx = brix_alloc_fhandle(ctx);
    if (idx < 0) {
        return brix_send_error(ctx, c, kXR_ServerError, "too many open files");
    }

    /* A real (harmless) fd keeps the slot "in use" so close()/free work via the
     * normal path; all I/O is intercepted on ctx->files[idx].ssi first. */
    devnull = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (devnull < 0) {
        brix_free_fhandle(ctx, idx);
        return brix_send_error(ctx, c, kXR_ServerError, "ssi open");
    }

    sess = brix_ssi_session_create(conn->pool, service, service_len, &prov);
    if (sess == NULL) {
        close(devnull);
        brix_free_fhandle(ctx, idx);
        return brix_send_error(ctx, c, kXR_NoMemory, "ssi alloc");
    }
    /* Key the registry by the session's own address (unique per live session)
     * so async completions resolve THIS session, not whichever handle shares the
     * connection. The generation check catches a recycled address. */
    sess->conn_id = (uintptr_t) sess;
    if (conf != NULL) {
        sess->max_inflight = (int) conf->ssi_max_inflight;
        sess->request_max  = conf->ssi_request_max;
        sess->response_max = conf->ssi_response_max;
    }
    brix_ssi_registry_add(sess->conn_id, sess);

    ctx->files[idx].fd         = devnull;
    ctx->files[idx].ssi        = sess;     /* now a session, not a req */
    ctx->files[idx].readable   = 1;
    ctx->files[idx].writable   = 1;
    ctx->files[idx].is_regular = 0;

    return ssi_open_send_reply(ctx, c, idx, want_stat);
}

ngx_int_t
brix_ssi_query(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
                 const unsigned char *body, size_t body_len)
{
    brix_ssi_session_t *sess = ctx->files[idx].ssi;
    brix_ssi_req_t     *rq;
    int                   cmd;
    uint32_t              id, size;
    u_char               *buf;
    size_t                total;

    if (body_len < BRIX_SSI_RRINFO_LEN) {
        return brix_send_error(ctx, c, kXR_ArgInvalid, "short SSI control");
    }
    brix_ssi_rrinfo_decode(body, &cmd, &id, &size);

    if (cmd == BRIX_SSI_CMD_CAN) {
        brix_ssi_session_drop(sess, id);
        return brix_send_ok(ctx, c, NULL, 0);
    }

    /* response-wait (Rwt). For the synchronous core the response is ready once
     * the request write completed; if the reqId is unknown or no response is
     * pending yet, treat as a protocol error. */
    rq = brix_ssi_session_req(sess, id, 0);
    if (rq == NULL || !rq->responded) {
        return brix_send_error(ctx, c, kXR_InvalidRequest,
                                 "no SSI response pending");
    }

    if (rq->error) {
        BRIX_SRV_METRIC_INC(ctx, ssi_errors_total);
        return brix_send_error(ctx, c,
                                 rq->err_code ? rq->err_code : kXR_ServerError,
                                 rq->err_text[0] ? rq->err_text : "SSI error");
    }

    /*
     * Streaming response: reply pendResp with metadata only (no inline data);
     * the client pulls the body via kXR_read (GetResp maps pendResp -> isStream).
     * Unary response: reply fullResp with the data inline.
     */
    if (rq->streaming) {
        total = brix_ssi_reply_len(rq->meta_len, 0);
        buf = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            return brix_send_error(ctx, c, kXR_NoMemory, "ssi reply");
        }
        brix_ssi_reply_build(BRIX_SSI_ATTN_PEND, rq->meta, rq->meta_len,
                               NULL, 0, buf);
        return brix_send_ok(ctx, c, buf, total);
    }

    total = brix_ssi_reply_len(rq->meta_len, rq->resp.len);
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return brix_send_error(ctx, c, kXR_NoMemory, "ssi reply");
    }
    brix_ssi_reply_build(BRIX_SSI_ATTN_FULL, rq->meta, rq->meta_len,
                           rq->resp.data, rq->resp.len, buf);
    return brix_send_ok(ctx, c, buf, total);
}

ngx_int_t
brix_ssi_read(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
                uint64_t offset, uint32_t rlen)
{
    brix_ssi_session_t *sess = ctx->files[idx].ssi;
    brix_ssi_req_t     *rq;
    unsigned char         off8[8];
    int                   cmd;
    uint32_t              id, size;
    size_t                avail, n;

    /* The SSI read offset field is a big-endian XrdSsiRRInfo; re-serialize the
     * decoded 64-bit offset back to its 8 wire bytes and decode the reqId. */
    off8[0] = (u_char) (offset >> 56); off8[1] = (u_char) (offset >> 48);
    off8[2] = (u_char) (offset >> 40); off8[3] = (u_char) (offset >> 32);
    off8[4] = (u_char) (offset >> 24); off8[5] = (u_char) (offset >> 16);
    off8[6] = (u_char) (offset >> 8);  off8[7] = (u_char) (offset);
    brix_ssi_rrinfo_decode(off8, &cmd, &id, &size);

    rq = brix_ssi_session_req(sess, id, 0);
    if (rq == NULL) {
        return brix_send_ok(ctx, c, NULL, 0);   /* unknown reqId → nothing */
    }

    /* Write-until-read protocol: a request never given an explicit size is
     * dispatched on its first read (the writes have all accumulated by now). */
    if (!rq->dispatched) {
        brix_ssi_dispatch(rq, sess->provider.process);
        BRIX_SRV_METRIC_INC(ctx, ssi_requests_total);
    }

    if (!rq->responded || rq->error) {
        return brix_send_ok(ctx, c, NULL, 0);   /* nothing to stream */
    }
    if (rq->read_cursor >= rq->resp.len) {
        return brix_send_ok(ctx, c, NULL, 0);   /* EOF */
    }
    avail = rq->resp.len - rq->read_cursor;
    n = (rlen < avail) ? rlen : avail;
    {
        u_char *p = rq->resp.data + rq->read_cursor;
        rq->read_cursor += n;
        return brix_send_ok(ctx, c, p, n);
    }
}
