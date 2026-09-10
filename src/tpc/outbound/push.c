#include "tpc/engine/tpc_internal.h"
#include "protocols/root/protocol/frame_hdr.h"  /* xrd_error_body_decode */
#include "source_internal.h"

#include <stdio.h>
#include <string.h>

/* File: push.c — F16 native root:// TPC PUSH, the source-side driver.
 *
 * WHAT: tpc_push_to_dest() runs the whole leg-2 worker sequence on an already
 * connected + bootstrapped socket to the REMOTE DESTINATION: open t->push_lfn
 * there for update carrying the rendezvous opaque, bind the sub-streams, stream
 * the local file out as kXR_write frames, sync the remote copy, then close the
 * remote handle and release the sub-streams on either outcome.
 *
 * WHY: stock xrootd has no push dialect — its native TPC is destination-side
 * pull only — so a source that can only reach the destination outbound (a
 * one-way firewall, an egress-only site) could not participate in a native
 * copy at all. F16 adds the mirrored leg. It is deliberately assembled from the
 * pull's own parts (tpc_open_remote, tpc_substreams_open/close,
 * tpc_close_source) rather than a parallel implementation: the async open
 * resolution, the redirect handling and the bind degradation are subtle and
 * must not exist twice.
 *
 * HOW: the opaque is "?tpc.key=K&tpc.org=<us>&tpc.stage=push". Presenting the
 * key is what CONSUMES it at the destination (single-use, replay-protected),
 * and tpc.stage=push is what tells the destination this write-open is leg 3 of
 * a push rather than an ordinary client write. The open options are
 * kXR_open_updt ONLY — see tpc_open_spec_t: leg 1 already created the file, so
 * an update-only open means a push can never write anywhere a client did not
 * explicitly ask for. A remote sync before close makes the destination's own
 * durability guarantee part of this transfer's success.
 */

/*
 * WHAT: render the leg-3 opaque suffix.
 * WHY: the destination authorizes this open on three facts — a key it minted
 * for a client (single-use), the identity of the server presenting it, and an
 * explicit statement that this is the push dialect. All three must be present:
 * a missing stage would be parsed as an ordinary keyed write, and a missing org
 * would leave the destination unable to attribute the bytes.
 * HOW: snprintf, overflow-checked. Returns 0 with *opqlen set, or -1 with
 * t->err_msg / t->xrd_error set.
 */
static int
tpc_push_build_opaque(brix_tpc_pull_t *t, char *opaque, size_t opaque_sz,
                      size_t *opqlen)
{
    size_t n;

    if (t->tpc_key[0] == '\0') {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC push has no rendezvous key");
        t->xrd_error = kXR_NotAuthorized;
        return -1;
    }

    n = (size_t) snprintf(opaque, opaque_sz,
                          "?tpc.key=%s&tpc.org=%s&tpc.stage=push",
                          t->tpc_key,
                          t->tpc_org[0] != '\0' ? t->tpc_org : "-");
    if (n >= opaque_sz) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC push opaque too long");
        t->xrd_error = kXR_ArgTooLong;
        return -1;
    }

    *opqlen = n;
    return 0;
}

/*
 * WHAT: kXR_sync the remote handle and require a clean answer.
 * WHY: unlike the pull — where this server owns the destination fd and fsyncs
 * it itself — a push hands every byte to a peer. Without an acknowledged remote
 * sync a "successful" push would only mean "the destination accepted the last
 * frame into its page cache", and the client would be told the copy is durable
 * when it may not be. This is the push's equivalent of tpc_stream_sync_dst, so
 * it is NOT best-effort: a refused or failed sync fails the transfer.
 * HOW: ClientSyncRequest on the open tag (streamid[1]=2), then one response
 * frame; anything but kXR_ok is an error carrying the remote's own code.
 */
static int
tpc_push_sync_dest(brix_tpc_pull_t *t, int fd, const u_char *fhandle)
{
    ClientSyncRequest  sreq;
    uint16_t           status = 0;
    uint32_t           dlen   = 0;
    u_char            *body   = NULL;

    ngx_memzero(&sreq, sizeof(sreq));
    sreq.streamid[1] = 2;
    sreq.requestid   = htons(kXR_sync);
    ngx_memcpy(sreq.fhandle, fhandle, XRD_FHANDLE_LEN);

    if (tpc_send_all(t, fd, &sreq, sizeof(sreq)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC push kXR_sync send failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC push kXR_sync reply failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    if (status != kXR_ok) {
        int          code   = kXR_ServerError;
        const char  *msg    = "";
        size_t       msglen = 0;

        if (status == kXR_error) {
            (void) xrd_error_body_decode(body, dlen, &code, &msg, &msglen);
        }
        /* `msg` is a bounded slice INTO body — format before the free. */
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC push destination sync failed: %.*s",
                 (int) msglen, msg);
        free(body);

        t->xrd_error = code;
        return -1;
    }

    free(body);
    return 0;
}

/*
 * tpc_push_to_dest — the whole push leg on one bootstrapped socket. Returns 0
 * on success (t->result = NGX_OK), -1 on failure with t->err_msg /
 * t->xrd_error set. The remote handle is closed and the sub-streams released
 * on both outcomes so nothing is leaked at the destination.
 */
int
tpc_push_to_dest(brix_tpc_pull_t *t, int fd)
{
    u_char           fhandle[XRD_FHANDLE_LEN];
    char             opaque[512];
    size_t           opqlen = 0;
    tpc_open_spec_t  spec;
    ngx_log_t       *log = (t->c != NULL) ? t->c->log : ngx_cycle->log;
    int              rc;

    if (tpc_push_build_opaque(t, opaque, sizeof(opaque), &opqlen) != 0) {
        return -1;
    }

    spec.path    = t->push_lfn;
    spec.opaque  = opaque;
    spec.opqlen  = opqlen;
    /* Update ONLY. Leg 1 (the client's own write-open at the destination)
     * created the file and registered the key; this open must never be able to
     * create one. */
    spec.options = kXR_open_updt;

    /* TPC_PUSH_REDIRECT propagates like the pull's: no handle here, re-run the
     * leg against t->redir_*. */
    rc = tpc_open_remote(t, fd, &spec, fhandle);
    if (rc != 0) {
        return rc;
    }

    /* Best-effort, exactly as the pull: a destination that cannot bind extra
     * channels simply receives the file over the primary socket. */
    (void) tpc_substreams_open(t, log);

    rc = tpc_push_stream(t, fd, fhandle);

    if (rc == 0) {
        rc = tpc_push_sync_dest(t, fd, fhandle);
        if (rc != 0) {
            t->result = NGX_ERROR;
        }
    }

    tpc_substreams_close(t);
    tpc_close_source(t, fd, fhandle);
    return rc;
}
