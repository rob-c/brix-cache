/*
 * streams.c — M8 parallel data streams (kXR_bind substreams).
 *
 * WHAT: Attach up to N-1 secondary TCP connections to a primary session via
 *       kXR_bind, and tear them down again.
 * WHY:  `xrdcp --streams N` opens extra bound channels — the parallel-transfer
 *       affordance of the protocol.
 * HOW:  Each secondary re-runs handshake + kXR_protocol [+ TLS] then sends
 *       kXR_bind{primary sessid} (brix_bind in conn.c). The Phase-94 pumps
 *       then fan self-addressed kXR_read/kXR_write REQUEST FRAMES across the
 *       bound secondaries — a BriX extension: stock servers treat a bound path
 *       as a pathid-directed DATA channel (ClientWriteRequest.pathid) and
 *       never answer a request frame arriving there, which would hang the
 *       transfer.  So after binding, the primary probes kXR_Qconfig
 *       "brix.substreams": without the "=rw" marker (BriX answers it, stock
 *       echoes the unknown key) the secondaries are torn down again and the
 *       whole transfer stays on the primary.  Best-effort throughout: a
 *       secondary that won't bind is skipped, never failing the copy.
 */
#include "brix.h"

#include <string.h>
#include <unistd.h>

int
brix_streams_open(brix_streamset *ss, brix_conn *primary, int streams,
                  brix_status *st)
{
    int want, i;

    memset(ss, 0, sizeof(*ss));
    if (streams <= 1) {
        return 0;
    }
    want = streams - 1;
    if (want > XRDC_MAX_STREAMS - 1) {
        want = XRDC_MAX_STREAMS - 1;
    }

    for (i = 0; i < want; i++) {
        brix_status bst;
        brix_status_clear(&bst);
        if (brix_bind(&ss->sec[ss->n], primary, &bst) != 0) {
            /* Best-effort: stop at the first failure, keep what bound. */
            break;
        }
        ss->n++;
    }

    if (ss->n > 0) {
        char        reply[64];
        brix_status qst;

        brix_status_clear(&qst);
        if (brix_query(primary, kXR_Qconfig, "brix.substreams",
                       reply, sizeof(reply), &qst) != 0
            || strstr(reply, "=rw") == NULL)
        {
            /* Peer does not serve request frames on bound paths (stock
             * semantics) — a fanned write would wait forever. Run primary-only. */
            brix_streams_close(ss);
        }
    }
    (void) st;
    return ss->n;
}

void
brix_streams_close(brix_streamset *ss)
{
    int i;
    for (i = 0; i < ss->n; i++) {
        /* A bound stream owns no session of its own — close it quietly, no
         * kXR_endsess (that belongs to the primary). */
        brix_tls_free(&ss->sec[i]);
        if (ss->sec[i].io.fd >= 0) {
            close(ss->sec[i].io.fd);
            ss->sec[i].io.fd = -1;
        }
    }
    ss->n = 0;
}
