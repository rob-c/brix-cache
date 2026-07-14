#ifndef BRIX_SSI_INTERNAL_H
#define BRIX_SSI_INTERNAL_H

/*
 * ssi_internal.h — declarations shared between the two halves of the SSI engine
 * glue after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the one function that is called across the ssi.c /
 *       ssi_dispatch.c file boundary.
 * WHY:  ssi.c (match + open + query + read — the client-facing reply side) and
 *       ssi_dispatch.c (responder machinery + async deferral + the write/dispatch
 *       side) were one 725-line file; splitting keeps each focused and under the
 *       500-line cap. brix_ssi_read (in ssi.c) dispatches a write-until-read
 *       request through ssi_dispatch (now in ssi_dispatch.c), so exactly that one
 *       function becomes non-static.
 * HOW:  Both translation units include this header; the symbol is not exported
 *       beyond the SSI module.
 */

#include "ssi.h"           /* brix_ssi_req_t (via ssi_req.h) */
#include "ssi_service.h"   /* brix_ssi_process_fn */

/* Defined in ssi_dispatch.c; called by brix_ssi_read (ssi.c). Runs the resolved
 * service over the fully accumulated request (submit phase): the service answers
 * inline or calls r->defer to be completed later. */
void brix_ssi_dispatch(brix_ssi_req_t *rq, brix_ssi_process_fn process);

#endif /* BRIX_SSI_INTERNAL_H */
