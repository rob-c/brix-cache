/* File: substreams.c — native TPC multi-stream: bind extra data channels
 * WHAT: tpc_substreams_open() dials up to (streams_requested - 1) additional
 *       sockets to the source, runs the transport bootstrap (handshake +
 *       kXR_protocol, TLS when the source demands it) on each, and joins them to
 *       the primary's session with kXR_bind; tpc_substreams_close() releases them.
 *
 * WHY (release-2.0 F7): the pre-F7 pull moved one 1 MiB window at a time over one
 *      socket, so a native TPC could not use the per-stream bandwidth a WAN path
 *      leaves on the table (stock xrootd's `ofs.tpc streams`). Sub-streams are
 *      best-effort: a source without kXR_bind (brix_data_substreams off, an old
 *      server) or one that refuses the join simply leaves the pull single-stream —
 *      a failed extra channel never fails the transfer, and the count is bounded
 *      by brix_tpc_streams on the destination regardless of the client's hint.
 *
 * HOW: XRootD wire — the secondary connection performs the ordinary handshake
 *      and kXR_protocol, then sends kXR_bind carrying the 16-byte session id the
 *      primary's kXR_login returned; the server answers kXR_ok with a 1-byte body,
 *      the pathid (1-253) that kXR_read read_args name to steer a reply out of
 *      that channel. Each sub-stream is registered in t->sub[] BEFORE its
 *      bootstrap so the fd-keyed TLS lookups in io.c/tls.c see it. */
#include "tpc/engine/tpc_internal.h"
#include "protocols/root/protocol/frame_hdr.h"   /* xrd_error_body_decode */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* kXR_bind rides its own tag so a stray reply can never be mistaken for the
 * primary's open (2) / read (3) traffic. */
static const u_char tpc_bind_streamid[2] = { 0, 4 };

/* WHAT: send kXR_bind on the sub-stream and take the pathid from the reply. */
static int
tpc_substream_bind(brix_tpc_pull_t *t, tpc_substream_t *sub)
{
    ClientBindRequest  br;
    uint16_t           status;
    uint32_t           dlen = 0;
    u_char            *body = NULL;

    ngx_memzero(&br, sizeof(br));
    ngx_memcpy(br.streamid, tpc_bind_streamid, sizeof(br.streamid));
    br.requestid = htons(kXR_bind);
    ngx_memcpy(br.sessid, t->sessid, BRIX_SESSION_ID_LEN);

    if (tpc_send_all(t, sub->fd, &br, sizeof(br)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_bind send failed");
        return -1;
    }
    if (tpc_recv_response(t, sub->fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_bind recv failed");
        return -1;
    }
    if (status != kXR_ok || body == NULL || dlen < 1 || body[0] == 0) {
        int          rerr    = 0;
        const char  *rmsg    = "";
        size_t       rmsglen = 0;

        if (status == kXR_error) {
            (void) xrd_error_body_decode(body, dlen, &rerr, &rmsg, &rmsglen);
        }
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC kXR_bind rejected (status=%u code=%d) %.*s",
                 (unsigned) status, rerr, (int) rmsglen, rmsg);
        free(body);
        return -1;
    }
    sub->pathid = body[0];
    free(body);
    return 0;
}

/* WHAT: tear one sub-stream down (TLS first, then the fd) and clear its slot. */
static void
tpc_substream_release(brix_tpc_pull_t *t, tpc_substream_t *sub)
{
    if (sub->fd >= 0) {
        tpc_tls_teardown_fd(t, sub->fd);
        close(sub->fd);
    }
    sub->fd     = -1;
    sub->pathid = 0;
}

/* WHAT: connect + transport-bootstrap + bind one more sub-stream into the next
 * free slot. Returns 0 with t->nsub advanced, -1 (slot released, t->err_msg
 * set) when the source would not give us another channel. */
static int
tpc_substream_open_one(brix_tpc_pull_t *t)
{
    tpc_substream_t *sub = &t->sub[t->nsub];
    int              fd  = tpc_connect(t);

    if (fd < 0) {
        return -1;
    }
    ngx_memzero(sub, sizeof(*sub));
    sub->fd = fd;
    t->nsub++;                 /* visible to the fd-keyed TLS lookups from here */

    if (tpc_bootstrap_transport(t, fd) != 0
        || tpc_substream_bind(t, sub) != 0)
    {
        tpc_substream_release(t, sub);   /* while the slot is still visible */
        t->nsub--;
        return -1;
    }
    return 0;
}

int
tpc_substreams_open(brix_tpc_pull_t *t, ngx_log_t *log)
{
    int  want      = t->streams_requested - 1;
    int  saved_err = t->xrd_error;
    char reason[sizeof(t->err_msg)];

    if (want <= 0) {
        return 0;
    }
    if (want > TPC_SUBSTREAMS_MAX) {
        want = TPC_SUBSTREAMS_MAX;
    }
    if (!t->sessid_known) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
                      "brix: TPC multi-stream: source %s returned no session "
                      "id; pulling single-stream", t->src_host);
        return 0;
    }

    reason[0] = '\0';
    while (t->nsub < want) {
        if (tpc_substream_open_one(t) != 0) {
            ngx_cpystrn((u_char *) reason, (u_char *) t->err_msg,
                        sizeof(reason));
            break;
        }
    }

    ngx_log_error(NGX_LOG_INFO, log, 0,
                  "brix: TPC multi-stream: %d of %d requested sub-streams "
                  "bound to %s%s%s", t->nsub, want, t->src_host,
                  reason[0] != '\0' ? " - " : "", reason);

    /* A refused extra channel is not a transfer failure: leave the pull's
     * error state exactly as the caller had it. */
    t->err_msg[0] = '\0';
    t->xrd_error  = saved_err;
    return 0;
}

void
tpc_substreams_close(brix_tpc_pull_t *t)
{
    int i;

    for (i = 0; i < t->nsub; i++) {
        tpc_substream_release(t, &t->sub[i]);
    }
    t->nsub = 0;
}
