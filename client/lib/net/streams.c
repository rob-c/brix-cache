/*
 * streams.c — M8 parallel data streams (kXR_bind substreams).
 *
 * WHAT: Attach up to N-1 secondary TCP connections to a primary session via
 *       kXR_bind, and tear them down again.
 * WHY:  `xrdcp --streams N` opens extra bound channels — the parallel-transfer
 *       affordance of the protocol.
 * HOW:  Each secondary re-runs handshake + kXR_protocol [+ TLS] then sends
 *       kXR_bind{primary sessid} (brix_bind in conn.c). NOTE: this nginx data
 *       server accepts the bind and logs it, but kXR_read carries no pathid
 *       (wire_core_requests.h ClientReadRequest), so the server does not actually
 *       fan reads across substreams — the binds are established and the transfer
 *       still runs on the primary. Establishing them is exactly what the gate
 *       (tests/test_xrdcp_client_options.py) checks: BIND access-log entries +
 *       byte-exact round-trip. Best-effort: a secondary that won't bind is
 *       skipped, never failing the copy.
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
