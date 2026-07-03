#ifndef BRIX_SSI_CTA_SERVICE_H
#define BRIX_SSI_CTA_SERVICE_H

/*
 * cta_service.h — the flagship "cta" SSI service.
 *
 * WHAT: an brix_ssi_process_fn that speaks the CTA protobuf protocol: it decodes
 *       a cta.xrd.Request, queues it, runs the executor (pushing progress alerts),
 *       and answers with a cta.xrd.Response.
 * WHY:  proves the full SSI framework end-to-end against a real (byte-compatible)
 *       CTA wire contract.
 * HOW:  pure C — it uses only the responder ABI and the svc_cta codec/queue/exec.
 *       A per-worker request queue is created lazily.
 */

#include "protocols/ssi/ssi_service.h"

/* The "cta" service handler (registered via provider.c). */
int brix_ssi_cta_process(const unsigned char *req, size_t req_len,
                           brix_ssi_responder_t *r);

/*
 * Configure the CTA service (from the stream module config). journal_path NULL/""
 * disables the restart journal; use_prod_executor selects the production
 * (tier/frm) executor over the simulated one. Idempotent; applied when the
 * per-worker queue is first created.
 */
void brix_ssi_cta_configure(const char *journal_path, int use_prod_executor);

#endif /* BRIX_SSI_CTA_SERVICE_H */
