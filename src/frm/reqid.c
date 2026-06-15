/*
 * reqid.c — durable, globally-unique request-id generation.
 *
 * WHAT: frm_reqid_format() renders "<seq>.<pid>@<host>"; frm_reqid_generate()
 *   bumps the durable header sequence under the file lock and formats the result.
 *
 * WHY: The old prepare handler hard-coded reqid="0", so QPrep could not
 *   distinguish requests and nothing survived a reconnect. The sequence lives in
 *   the file header (frm_file_hdr_t.seq) so it is monotonic across restarts; the
 *   pid + host suffix keeps ids readable and unique even when several hosts share
 *   one queue file. The whole id fits FRM_REQID_LEN (the host is truncated if
 *   needed) — uniqueness rests on the durable seq, not the host string.
 *
 * Note: queue.c's frm_request_add() bumps the seq inline under the lock it
 *   already holds (avoiding a second fsync); this standalone entry point exists
 *   for callers that need an id without enqueuing.
 */

#include "frm_internal.h"

#include <stdio.h>
#include <string.h>


void
frm_reqid_format(const char *host, uint64_t seq, char *buf, size_t buf_sz)
{
    if (buf == NULL || buf_sz == 0) {
        return;
    }
    (void) snprintf(buf, buf_sz, "%llu.%ld@%s",
                    (unsigned long long) seq, (long) ngx_pid,
                    (host && host[0]) ? host : "localhost");
    buf[buf_sz - 1] = '\0';
}


ngx_int_t
frm_reqid_generate(frm_queue_t *q, char *buf, size_t buf_sz, ngx_log_t *log)
{
    frm_file_hdr_t hdr;
    uint64_t       seq;

    if (q == NULL || q->fd < 0 || buf == NULL || buf_sz < FRM_REQID_LEN) {
        return NGX_ERROR;
    }
    if (frm_file_lock(q, FRM_LK_EXCL) != NGX_OK) {
        return NGX_ERROR;
    }
    if (frm_hdr_read(q, &hdr, log) != NGX_OK) {
        frm_file_unlock(q);
        return NGX_ERROR;
    }
    seq = ++hdr.seq;
    if (frm_hdr_write(q, &hdr, log) != NGX_OK) {
        frm_file_unlock(q);
        return NGX_ERROR;
    }
    frm_file_unlock(q);

    frm_reqid_format(q->host, seq, buf, buf_sz);
    return NGX_OK;
}
