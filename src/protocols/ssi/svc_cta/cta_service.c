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
#include "cta_shm.h"
#include <stdio.h>
#include <string.h>

/* Per-worker executor selection (see cta_service.h and DEFECT CANDIDATE #63 in
 * tests/test_audit15aa_default_tokens.py — the executor still aliases across
 * server blocks; W8.6 moved the QUEUE, not the executor, off this global). */
static int  g_cta_use_prod;

void
brix_ssi_cta_configure(const char *journal_path, int use_prod_executor)
{
    /*
     * The journal is no longer opened here. It belongs to the shared queue,
     * which is one SHM zone opened in the master before fork (cta_shm.c), so
     * the path is taken from the config at postconfiguration time and this
     * argument is accepted and ignored. The parameter stays because the open
     * path still carries it and because dropping it would silently change the
     * ssi.c call site that DEFECT CANDIDATE #63 pins.
     */
    (void) journal_path;
    g_cta_use_prod = use_prod_executor;
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
    brix_ssi_responder_t *r = ctx;
    r->alert(r, (const unsigned char *) msg, strlen(msg));
}

/* Encode and deliver a cta.xrd.Response (set_response, terminal). */
static void
cta_respond(brix_ssi_responder_t *r, cta_rsp_type_t type, const char *msg,
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
brix_ssi_cta_process(const unsigned char *req, size_t req_len,
                       brix_ssi_responder_t *r)
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
                     brix_cta_shm_active_count());
            cta_respond(r, CTA_RSP_SUCCESS, msg, 0);
            return 0;
        }
        if (creq.op == CTA_OP_UNKNOWN) {
            cta_respond(r, CTA_RSP_ERR_USER, "unsupported workflow event", 0);
            return 0;
        }
        if (brix_cta_shm_queue() == NULL) {
            /* No zone: refuse. Falling back to a private per-worker queue is
             * exactly the defect W8.6 removes — it would hand out ids that
             * collide with another worker's. */
            cta_respond(r, CTA_RSP_ERR_CTA, "CTA queue unavailable", 0);
            return 0;
        }
        e = brix_cta_shm_submit(&creq, creq.owner_user);
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
        /* The executor transitions through brix_cta_shm_transition, which takes
         * the zone lock once per transition — never for the length of an
         * archive or retrieve. */
        cta_progress_t prog = { brix_cta_shm_queue(), brix_cta_shm_transition,
                                cta_prog_alert, r };
        int rc = cta_exec_run(cta_exec_vtbl(), e, &prog);
        cta_respond(r, rc == 0 ? CTA_RSP_SUCCESS : CTA_RSP_ERR_CTA,
                    rc == 0 ? "request completed" : "request failed",
                    e->req.archive_id);
    }
    return 0;
}
