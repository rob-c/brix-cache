/*
 * xfer_reconcile.h — the one shared journal-recovery scan.
 *
 * WHAT: xrootd_xfer_journal_foreach() — iterate the durable journal's records of
 *       a given status and transfer kind, invoking a callback per match.
 *
 * WHY:  Each kind's restart recovery (tape stage drain, write-through replay)
 *       walked the journal with the same `frm_request_list` cursor + a per-kind
 *       filter. This funnels that scan through one function so the per-kind
 *       re-drive logic is all that differs. Flow-control-heavy drains (a budgeted
 *       claim loop that must stop early) intentionally stay bespoke — the shared
 *       scan is for "visit every matching record".
 */

#ifndef XROOTD_FS_XFER_RECONCILE_H
#define XROOTD_FS_XFER_RECONCILE_H

#include <ngx_core.h>

#include "../../frm/frm.h"   /* the durable journal: frm_queue_t, record, kinds */

/* Invoked for each journal record matching (status, kind). */
typedef void (*xrootd_xfer_redrive_fn)(const frm_record_t *rec, void *data);

/* Visit every journal record with `status` and transfer `kind`, calling `fn`
 * (NULL = count only). Returns the number of matching records. */
ngx_uint_t xrootd_xfer_journal_foreach(frm_queue_t *q, int status,
    frm_xfer_kind_t kind, xrootd_xfer_redrive_fn fn, void *data, ngx_log_t *log);

#endif /* XROOTD_FS_XFER_RECONCILE_H */
