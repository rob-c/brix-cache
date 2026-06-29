/*
 * xfer_reconcile.c — the one shared journal-recovery scan (see xfer_reconcile.h).
 */

#include "xfer_reconcile.h"

ngx_uint_t
xrootd_xfer_journal_foreach(frm_queue_t *q, int status, frm_xfer_kind_t kind,
    xrootd_xfer_redrive_fn fn, void *data, ngx_log_t *log)
{
    frm_record_t rec;
    ngx_uint_t   cursor = 0;
    ngx_uint_t   n = 0;

    if (q == NULL) {
        return 0;
    }

    while (frm_request_list(q, &cursor, status, 0xff, NULL, &rec, log) == NGX_OK) {
        if (rec.xfer_kind != (uint8_t) kind) {
            continue;
        }
        n++;
        if (fn != NULL) {
            fn(&rec, data);
        }
    }
    return n;
}
