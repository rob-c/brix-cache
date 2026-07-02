/*
 * cta_service.c — the "cta" SSI service. See cta_service.h.
 *
 * Two phases (the defer-or-respond pattern):
 *   submit     — decode the cta.xrd.Request, queue it, and defer (so a long
 *                archive/retrieve answers asynchronously with progress alerts).
 *                query/error answer inline.
 *   completion — run the executor on the stashed queue entry (alerts pushed live),
 *                then answer with a cta.xrd.Response.
 */

#include "cta_service.h"
#include "cta_pb.h"
#include "cta_queue.h"
#include "cta_exec.h"
#include <stdio.h>
#include <string.h>

/* Per-worker singletons (long-lived; created lazily) + config. */
static xrootd_cta_queue_t *g_cta_queue;
static char                g_cta_journal[1024];
static int                 g_cta_use_prod;

void
xrootd_ssi_cta_configure(const char *journal_path, int use_prod_executor)
{
    g_cta_use_prod = use_prod_executor;
    if (journal_path != NULL && journal_path[0] != '\0') {
        snprintf(g_cta_journal, sizeof(g_cta_journal), "%s", journal_path);
    } else {
        g_cta_journal[0] = '\0';
    }
}

static xrootd_cta_queue_t *
cta_queue(void)
{
    if (g_cta_queue == NULL) {
        g_cta_queue = cta_queue_create();
        if (g_cta_queue != NULL && g_cta_journal[0] != '\0') {
            cta_queue_open_journal(g_cta_queue, g_cta_journal);
        }
    }
    return g_cta_queue;
}

/* Executor selection — the simulated backend by default; config selects the
 * production (tier/frm) executor where a nearline backend exists. */
static const cta_exec_vtbl_t *
cta_exec_vtbl(void)
{
    return g_cta_use_prod ? cta_exec_prod_vtbl() : cta_exec_test_vtbl();
}

/* Bridge: forward an executor progress alert to the SSI responder. */
static void
cta_prog_alert(void *ctx, const char *msg)
{
    xrootd_ssi_responder_t *r = ctx;
    r->alert(r, (const unsigned char *) msg, strlen(msg));
}

/* Encode and deliver a cta.xrd.Response (set_response, terminal). */
static void
cta_respond(xrootd_ssi_responder_t *r, cta_rsp_type_t type, const char *msg,
            uint64_t archive_id)
{
    unsigned char buf[512];
    size_t        n = 0;

    if (cta_pb_encode_response(type, msg, archive_id, buf, sizeof(buf), &n) != 0) {
        r->error(r, 5 /* EIO */, "cta response encode failed");
        return;
    }
    r->set_response(r, buf, n, 1);
}

int
xrootd_ssi_cta_process(const unsigned char *req, size_t req_len,
                       xrootd_ssi_responder_t *r)
{
    void      **slot = r->svc_slot != NULL ? r->svc_slot(r) : NULL;
    cta_req_t  *e    = slot != NULL ? (cta_req_t *) *slot : NULL;

    if (e == NULL) {
        /* ---- submit phase ---- */
        cta_request_t creq;

        if (cta_pb_decode_request(req, req_len, &creq) != 0) {
            cta_respond(r, CTA_RSP_ERR_PROTOBUF, "malformed CTA request", 0);
            return 0;
        }
        if (creq.op == CTA_OP_QUERY) {
            char msg[64];
            snprintf(msg, sizeof(msg), "%d active request(s)",
                     cta_queue_active_count(cta_queue()));
            cta_respond(r, CTA_RSP_SUCCESS, msg, 0);
            return 0;
        }
        if (creq.op == CTA_OP_UNKNOWN) {
            cta_respond(r, CTA_RSP_ERR_USER, "unsupported workflow event", 0);
            return 0;
        }
        e = cta_queue_submit(cta_queue(), &creq, creq.owner_user);
        if (e == NULL) {
            cta_respond(r, CTA_RSP_ERR_CTA, "request queue full", 0);
            return 0;
        }
        if (slot != NULL) {
            *slot = e;
        }
        if (r->defer != NULL && r->defer(r) == 0) {
            return 0;   /* deferred — the executor runs at completion */
        }
        /* defer unavailable: fall through and run inline */
    }

    /* ---- completion phase ---- */
    {
        cta_progress_t prog = { cta_prog_alert, r };
        int rc = cta_exec_run(cta_exec_vtbl(), e, &prog);
        cta_respond(r, rc == 0 ? CTA_RSP_SUCCESS : CTA_RSP_ERR_CTA,
                    rc == 0 ? "request completed" : "request failed",
                    e->req.archive_id);
    }
    return 0;
}
