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
 * HOW:  it uses the responder ABI and the svc_cta codec/queue/exec. The request
 *       queue is ONE shared-memory zone for the whole worker set (cta_shm.c),
 *       registered at postconfiguration; when it is absent the service refuses
 *       rather than falling back to a private queue.
 */

#include "protocols/ssi/ssi_service.h"

/* The "cta" service handler (registered via provider.c). */
int brix_ssi_cta_process(const unsigned char *req, size_t req_len,
                           brix_ssi_responder_t *r);

/*
 * Configure the CTA service (from the stream module config). use_prod_executor
 * selects the production (tier/frm) executor over the simulated one.
 *
 * journal_path is accepted and IGNORED: the journal belongs to the shared
 * queue and is opened once at postconfiguration time (cta_shm.c), not on the
 * open path. See the note in cta_service.c.
 */
void brix_ssi_cta_configure(const char *journal_path, int use_prod_executor);

#endif /* BRIX_SSI_CTA_SERVICE_H */
