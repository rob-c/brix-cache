#include "tpc/engine/tpc_internal.h"
#include "protocols/root/protocol/frame_hdr.h"   /* xrd_error_body_decode (shared kXR_error codec) */


#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>

#if defined(__linux__)
#include <endian.h>
#endif

/* File: source.c — TPC remote source pull (open → read loop → close)
 * WHAT: Single public function `tpc_pull_from_source()` executes the complete native XRootD third-party-copy fetch from a remote origin into dst_fd. Phase 1 → builds ClientOpenRequest with src_path + opaque key/org params, sends kXR_open to remote, receives ServerOpenBody fhandle (handles both minimal 4-byte and full 12+ byte responses), extracts fhandle; Phase 2 → streaming read loop via repeated kXR_read requests at TPC_CHUNK_SIZE offsets, accumulates kXR_oksofar + kXR_ok frames per request, writes each frame's body bytes to dst_fd through the VFS core, tracks offset advancement and total bytes_written; Phase 3 → syncs dst_fd through the VFS core for durability, sets result=NGX_OK/xrd_error=0, best-effort remote close via kXR_close. Returns -1 on failure with error message + xrd_error code, 0 on success.
 *
 * WHY: TPC (Third-Party Copy) transfers require the destination server to connect to a remote root:// origin, open the source file, stream all bytes into dst_fd, and close the remote handle. This function encapsulates the entire pull lifecycle — open → read loop → fsync → close — so launch.c/thread.c can delegate it to a thread-pool worker without managing the protocol sequence themselves. Handles peer diversity (minimal vs full ServerOpenBody), oksofar accumulation for large reads, EINTR-safe writes, and best-effort remote cleanup on failure paths.
 *
 * HOW: Build open_buf with ClientOpenRequest header + src_path + opaque "?tpc.key=...&tpc.org=..." → send_all(fd) kXR_open → recv_response fd status/body → check kXR_ok + dlen>=XRD_FHANDLE_LEN → memcpy fhandle → free(body) → offset=0 loop: build ClientReadRequest with streamid[1]=3, kXR_read, fhandle, htobe64(offset), htonl(TPC_CHUNK_SIZE) → send_all → inner for-loop: recv_response accumulating kXR_oksofar/kXR_ok frames → write body bytes to dst_fd using a positional VFS WRITE job at offset+got_this_req → got_this_req+=dlen → offset+=got_this_req → outer loop exits when done=1(got_this_req==0/EOF) or failed=1 → VFS SYNC dst_fd → shared remote-close ladder: build ClientCloseRequest with kXR_close + fhandle → send_all + recv_response (best-effort, discard result). */


/* Set the socket receive idle-timeout (SO_RCVTIMEO) in whole seconds. Best
 * effort — a failure only means we fall back to the previously-set timeout. */
static void
tpc_set_rcvtimeo(int fd, int secs)
{
    struct timeval tv;

    tv.tv_sec  = secs;
    tv.tv_usec = 0;
    (void) setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/*
 * tpc_open_reply_t — WHAT: the outcome of one kXR_open resolution round: the
 * XRootD status word plus the (heap) response body and its length.
 * WHY: bundling the three former out-params of tpc_open_resolve() into one
 * struct keeps the resolver and its helpers under the param cap and lets a
 * sub-status frame (embedded asynresp) be produced by value.
 * HOW: pure data; the resolver fills it and the caller reads status/body/dlen.
 * `body` is owned by whoever last set it — freed by the caller on terminal
 * return, or by the resolver itself when it keeps looping.
 */
typedef struct {
    uint16_t  status;
    u_char   *body;
    uint32_t  dlen;
} tpc_open_reply_t;

/*
 * tpc_open_ctx_t — WHAT: the connected socket plus the immutable kXR_open request
 * bytes to RESEND on a kXR_wait. WHY: the async resolver and its helpers all
 * thread the same (fd, open-bytes) pair; bundling them into one context keeps
 * every layer under the param cap and avoids re-taking the buffer + length as
 * two separate params. HOW: fd + read-only pointer + length captured once by
 * tpc_open_source() and passed by const-pointer through the resolver.
 */
typedef struct {
    int            fd;
    const u_char  *buf;
    size_t         len;
} tpc_open_ctx_t;

/*
 * tpc_open_wait_resend — WHAT: sleep the clamped retry-after seconds then resend
 * the open. WHY: kXR_wait / deferred-wait share this exact sleep+resend step;
 * factoring it removes the duplicate and keeps the resolver flat.
 * HOW: parse the (bounded) wait seconds from `body`, sleep, resend `oc`; 0 on a
 * successful resend, -1 (with t->err_msg set) if the resend fails.
 */
static int
tpc_open_wait_resend(brix_tpc_pull_t *t, const tpc_open_ctx_t *oc,
                     const u_char *body, uint32_t dlen, const char *what)
{
    uint32_t secs = xrd_wait_secs_parse(body, dlen, 1, TPC_OPEN_WAIT_CAP_SEC);

    sleep((unsigned) secs);
    if (tpc_send_all(t, oc->fd, oc->buf, oc->len) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC kXR_open resend (after %s) failed", what);
        return -1;
    }
    return 0;
}

/*
 * tpc_open_resolve_attn — WHAT: unwrap a kXR_attn frame and either fold it back
 * into the resolution loop (deferred wait) or hand the caller a terminal
 * embedded reply. WHY: the asynresp unwrap is the densest branch of the resolver;
 * isolating it drops the resolver's complexity below the gate.
 * HOW: body layout is
 *   actnum[4 BE] reserved[4] embedded-ServerResponseHeader[8] body[dlen]
 * where the embedded header is { streamid[2], status[2 BE], dlen[4 BE] }. Only
 * kXR_asynresp carries a reply; anything else is not ours. Returns:
 *   0  → `out` holds a TERMINAL embedded reply (out->body owned by caller)
 *   1  → keep looping (nothing terminal yet; any embedded body already freed)
 *  -1  → hard failure (t->err_msg / t->xrd_error set)
 * `attn_body` is always consumed (freed) by this function.
 */
static int
tpc_open_resolve_attn(brix_tpc_pull_t *t, const tpc_open_ctx_t *oc,
                      u_char *attn_body, uint32_t attn_dlen,
                      tpc_open_reply_t *out)
{
    uint32_t  actnum, edlen;
    uint16_t  est;
    u_char   *ebody = NULL;

    if (attn_body == NULL || attn_dlen < 16) {
        free(attn_body);
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC kXR_attn frame too short (%u)", (unsigned) attn_dlen);
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    actnum = xrd_get_u32_be(attn_body);
    if (actnum != (uint32_t) kXR_asynresp) {
        free(attn_body);
        return 1;                               /* not ours — keep waiting */
    }
    est   = (uint16_t) (((uint16_t) attn_body[10] << 8)
                        | (uint16_t) attn_body[11]);
    edlen = xrd_get_u32_be(attn_body + 12);
    if ((size_t) edlen > (size_t) attn_dlen - 16) {
        edlen = attn_dlen - 16;                 /* never over-read */
    }
    if (edlen > 0) {
        ebody = malloc((size_t) edlen + 1);
        if (ebody == NULL) {
            free(attn_body);
            t->xrd_error = kXR_NoMemory;
            return -1;
        }
        memcpy(ebody, attn_body + 16, edlen);
        ebody[edlen] = '\0';
    }
    free(attn_body);

    /* A deferred reply that is itself a wait folds back into the loop. */
    if (est == kXR_wait) {
        int rc = tpc_open_wait_resend(t, oc, ebody, edlen, "asynresp wait");

        free(ebody);
        return (rc != 0) ? -1 : 1;
    }
    if (est == kXR_waitresp) {
        free(ebody);
        return 1;
    }

    out->status = est;
    out->body   = ebody;
    out->dlen   = edlen;
    return 0;                                   /* terminal embedded reply */
}

/*
 * tpc_open_resolve_round — WHAT: run exactly one resolution round: receive a
 * frame and classify it. WHY: keeps the driver loop (tpc_open_resolve) a flat
 * dispatch with the per-status handling extracted here.
 * HOW: recv one frame → kXR_wait (sleep+resend) / kXR_waitresp (wait) / kXR_attn
 * (delegate) / terminal (fill `out`). Returns 0 = terminal (out filled),
 * 1 = keep looping, -1 = failure.
 */
static int
tpc_open_resolve_round(brix_tpc_pull_t *t, const tpc_open_ctx_t *oc,
                       tpc_open_reply_t *out)
{
    u_char   *b  = NULL;
    uint32_t  dl = 0;
    uint16_t  st = 0;

    if (tpc_recv_response(t, oc->fd, &st, &b, &dl) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_open recv failed");
        return -1;
    }

    /* kXR_wait: sleep the (clamped) retry-after, then resend the open. */
    if (st == kXR_wait) {
        int rc = tpc_open_wait_resend(t, oc, b, dl, "kXR_wait");

        free(b);
        return (rc != 0) ? -1 : 1;
    }

    /* kXR_waitresp: the seconds are informational; the real reply arrives
     * unsolicited as a kXR_attn(asynresp). Do NOT resend — loop to receive
     * it (bounded by the tightened SO_RCVTIMEO + the wall-clock deadline). */
    if (st == kXR_waitresp) {
        free(b);
        return 1;
    }

    /* kXR_attn: unwrap the deferred response (may fold back into the loop). */
    if (st == kXR_attn) {
        return tpc_open_resolve_attn(t, oc, b, dl, out);
    }

    /* Any other status (kXR_ok / kXR_error / …) is the terminal reply. */
    out->status = st;
    out->body   = b;
    out->dlen   = dl;
    return 0;
}

/*
 * tpc_open_resolve — receive the kXR_open reply, transparently resolving the
 * asynchronous XRootD flow-control statuses a real source may return before the
 * open settles:
 *
 *   kXR_wait      — "retry in N s": sleep (clamped) and RESEND the open.
 *   kXR_waitresp  — "the answer arrives later, unsolicited": do NOT resend; wait
 *                   for the deferred kXR_attn(kXR_asynresp).
 *   kXR_attn      — unwrap the embedded ServerResponseHeader + body (asynresp)
 *                   and treat it as the real reply (which may itself be a wait →
 *                   fold back into the loop).
 *
 * On return 0 `out` carries a TERMINAL reply (kXR_ok / kXR_error / …) the caller
 * handles exactly as a synchronous open; the common case (a source that answers
 * kXR_ok immediately) returns on the very first frame with no change in
 * behaviour. Bounded on every axis — the caller tightens SO_RCVTIMEO around this
 * call, and a clamped single wait, a total iteration cap and a wall-clock
 * deadline guarantee a source that never resolves fails cleanly (-1) rather than
 * hanging the pull thread. Runs on a thread-pool worker, so the bounded sleeps
 * here block only this transfer's thread, never the nginx event loop.
 */
static int
tpc_open_resolve(brix_tpc_pull_t *t, const tpc_open_ctx_t *oc,
                 tpc_open_reply_t *out)
{
    time_t deadline = time(NULL) + TPC_OPEN_RESOLVE_MAX_SEC;
    int    iters;

    for (iters = 0; iters < TPC_OPEN_RESOLVE_MAX_ITERS; iters++) {
        int rc;

        if (time(NULL) >= deadline) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC kXR_open async deadline exceeded (%ds)",
                     TPC_OPEN_RESOLVE_MAX_SEC);
            t->xrd_error = kXR_ServerError;
            return -1;
        }

        rc = tpc_open_resolve_round(t, oc, out);
        if (rc == 0) {
            return 0;                           /* terminal reply in `out` */
        }
        if (rc < 0) {
            return -1;
        }
        /* rc == 1 → keep looping */
    }

    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC kXR_open did not resolve after %d async rounds",
             TPC_OPEN_RESOLVE_MAX_ITERS);
    t->xrd_error = kXR_ServerError;
    return -1;
}


/*
 * tpc_open_build_opaque — WHAT: render the "?tpc.key=…&tpc.org=…" opaque suffix
 * for the source open into `opaque` and report its length. WHY: the opaque
 * selection is a three-way policy branch (delegated / key+org / key-only) that
 * is cleanly separable from wire framing.
 * HOW: delegated proxy → empty opaque (authenticated read as the user); else
 * emit the key (+org) rendezvous params. Returns 0 with *opqlen set, or -1 with
 * t->err_msg / t->xrd_error set when the rendered opaque overflows the buffer.
 *
 * TPC-lite delegation: when we hold the user's delegated proxy we authenticate
 * to the source AS THE USER, so we open the file directly — no tpc.key opaque.
 * The tpc.key/tpc.org rendezvous is the *anonymous* TPC model where the pulling
 * server proves authorization with a key the client pre-registered on the
 * source; presenting it here makes the source defer with kXR_waitresp forever
 * (it waits for a client-side authorization that the delegate flow never
 * issues). A delegated open is a plain authenticated read by the file owner.
 */
static int
tpc_open_build_opaque(brix_tpc_pull_t *t, char *opaque, size_t opaque_sz,
                      size_t *opqlen)
{
    size_t n = 0;

    opaque[0] = '\0';

    if (t->deleg_cred_pem != NULL && t->deleg_cred_len > 0) {
        n = 0;
    } else if (t->tpc_key[0] != '\0' && t->tpc_org[0] != '\0') {
        n = (size_t) snprintf(opaque, opaque_sz, "?tpc.key=%s&tpc.org=%s",
                              t->tpc_key, t->tpc_org);
    } else if (t->tpc_key[0] != '\0') {
        n = (size_t) snprintf(opaque, opaque_sz, "?tpc.key=%s", t->tpc_key);
    }
    if (n >= opaque_sz) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC source opaque too long");
        t->xrd_error = kXR_ArgTooLong;
        return -1;
    }

    *opqlen = n;
    return 0;
}

/*
 * tpc_open_buf_t — WHAT: the destination buffer for the assembled kXR_open
 * request: its storage, capacity, and (on return) the number of bytes to send.
 * WHY: bundles the build target + result length so tpc_open_build_request stays
 * under the param cap. HOW: caller sets buf/cap; the builder fills len.
 */
typedef struct {
    u_char  *buf;
    size_t   cap;
    size_t   len;
} tpc_open_buf_t;

/*
 * tpc_open_build_request — WHAT: assemble the kXR_open request bytes for the
 * source into `dst->buf` and report the total length to send in `dst->len`.
 * WHY: the wire framing (header pack + payload append) is a distinct concern
 * from resolving the reply. HOW: see the wire-layout comment below. Returns 0
 * with dst->len set, or -1 (t->err_msg / t->xrd_error set) if path+opaque
 * overflow the buffer.
 */
static int
tpc_open_build_request(brix_tpc_pull_t *t, tpc_open_buf_t *dst,
                       const char *opaque, size_t opqlen)
{
    ClientOpenRequest *opreq;
    size_t             pathlen = strlen(t->src_path);
    size_t             len     = sizeof(ClientOpenRequest) + pathlen + opqlen;

    if (len > dst->cap) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC src path too long");
        t->xrd_error = kXR_ArgTooLong;
        return -1;
    }

    /*
     * Wire layout of the kXR_open request: fixed ClientOpenRequest header
     * immediately followed by the variable-length payload (path + opaque).
     * dlen counts only the payload bytes, NOT the header. All multi-byte
     * header fields are network byte order (htons/htonl). streamid[1]=2 is a
     * private tag we reuse across this socket so replies can be correlated.
     */
    ngx_memzero(dst->buf, len);
    opreq = (ClientOpenRequest *) dst->buf;
    opreq->streamid[1] = 2;
    opreq->requestid   = htons(kXR_open);
    {
        xrdw_open_req_t b = { .options = kXR_open_read };
        xrdw_open_req_pack(&b, ((ClientRequestHdr *) dst->buf)->body);
    }
    opreq->dlen        = htonl((kXR_int32)(pathlen + opqlen));

    /* Append payload right after the header: path first, then "?tpc..." opaque. */
    ngx_memcpy(dst->buf + sizeof(ClientOpenRequest), t->src_path, pathlen);
    if (opqlen > 0) {
        ngx_memcpy(dst->buf + sizeof(ClientOpenRequest) + pathlen,
                   opaque, opqlen);
    }

    dst->len = len;
    return 0;
}

/*
 * tpc_open_extract_fhandle — WHAT: validate a terminal kXR_open reply and copy
 * out the origin fhandle. WHY: separates reply classification (ok vs error, with
 * the shared kXR_error decode) from the framing/resolve steps. HOW: on kXR_ok
 * with a body >= XRD_FHANDLE_LEN, copy the leading fhandle bytes; otherwise
 * surface the remote's code/message. `reply->body` is always freed here.
 * Returns 0 (fhandle filled) or -1 (t->err_msg / t->xrd_error set).
 */
static int
tpc_open_extract_fhandle(brix_tpc_pull_t *t, tpc_open_reply_t *reply,
                         u_char fhandle[XRD_FHANDLE_LEN])
{
    if (reply->status != kXR_ok || reply->body == NULL
        || reply->dlen < XRD_FHANDLE_LEN)
    {
        /*
         * kXR_error body = [int32 BE errnum][message]. Surface the remote's
         * code/message verbatim so the destination's reply mirrors the true
         * origin failure; the shared decoder bounds the (non-NUL) message slice.
         */
        int          rerr;
        const char  *rmsg;
        size_t       rmsglen;

        if (reply->status == kXR_error
            && xrd_error_body_decode(reply->body, reply->dlen,
                                     &rerr, &rmsg, &rmsglen) == 0) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC source open failed: %.*s", (int) rmsglen, rmsg);
            t->xrd_error = rerr;
        } else {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC kXR_open rejected (status=%u dlen=%u)",
                     (unsigned) reply->status, (unsigned) reply->dlen);
        }
        free(reply->body);
        return -1;
    }

    /* fhandle is the first XRD_FHANDLE_LEN bytes regardless of body size
     * (minimal 4-byte reply vs full ServerOpenBody both lead with it). */
    ngx_memcpy(fhandle, reply->body, XRD_FHANDLE_LEN);
    free(reply->body);
    return 0;
}

/*
 * tpc_open_source — Phase 1: build and send the kXR_open for the remote source,
 * resolve the (possibly asynchronous) reply, and extract the origin fhandle.
 * Returns 0 with `fhandle` filled, or -1 with t->err_msg / t->xrd_error set. On
 * failure the caller has no origin handle to close.
 */
static int
tpc_open_source(brix_tpc_pull_t *t, int fd, u_char fhandle[XRD_FHANDLE_LEN])
{
    u_char            open_buf[sizeof(ClientOpenRequest) + PATH_MAX + 512];
    char              opaque[512];
    size_t            opqlen = 0;
    tpc_open_buf_t    ob = { .buf = open_buf, .cap = sizeof(open_buf), .len = 0 };
    tpc_open_ctx_t    oc;
    tpc_open_reply_t  reply = { 0 };

    if (tpc_open_build_opaque(t, opaque, sizeof(opaque), &opqlen) != 0) {
        return -1;
    }
    if (tpc_open_build_request(t, &ob, opaque, opqlen) != 0) {
        return -1;
    }

    if (tpc_send_all(t, fd, ob.buf, ob.len) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_open send failed");
        return -1;
    }

    /*
     * Resolve the open through the async XRootD flow (phase-57 §F8): a real
     * source (EOS/dCache, or any server still completing the TPC rendezvous) may
     * answer with kXR_wait / kXR_waitresp → kXR_attn(asynresp) before the open
     * settles. tpc_open_resolve() honours that and returns a TERMINAL reply. We
     * tighten SO_RCVTIMEO for the negotiation so a silent source fails fast (the
     * client's --tpc fallback still has time to run), then restore the full I/O
     * timeout for the streaming read loop below. A source that answers kXR_ok
     * immediately (e.g. our own nginx source) resolves on the first frame.
     *
     * Some peers return a minimal kXR_ok body with only the 4-byte fhandle;
     * others send the full ServerOpenBody (12+ bytes) — both lead with fhandle.
     */
    oc.fd  = fd;
    oc.buf = ob.buf;
    oc.len = ob.len;
    tpc_set_rcvtimeo(fd, TPC_OPEN_WAIT_CAP_SEC);
    if (tpc_open_resolve(t, &oc, &reply) != 0) {
        tpc_set_rcvtimeo(fd, TPC_IO_TIMEOUT_SEC);
        return -1;
    }
    tpc_set_rcvtimeo(fd, TPC_IO_TIMEOUT_SEC);

    return tpc_open_extract_fhandle(t, &reply, fhandle);
}


/*
 * tpc_stream_send_read — WHAT: build and send one kXR_read request for the
 * TPC_CHUNK_SIZE window at `offset`. WHY: isolates the read-request framing from
 * the drain/advance loop. HOW: kXR_read header with an 8-byte big-endian offset
 * (htobe64, NOT htonl) and a 4-byte requested length; streamid[1]=3 tags read
 * replies on this socket distinctly from the open/close tag (2). Returns 0 on a
 * successful send, -1 with t->err_msg set on failure.
 */
static int
tpc_stream_send_read(brix_tpc_pull_t *t, int fd, const u_char *fhandle,
                     uint64_t offset)
{
    ClientReadRequest rdreq;

    ngx_memzero(&rdreq, sizeof(rdreq));
    rdreq.streamid[1] = 3;
    rdreq.requestid   = htons(kXR_read);
    ngx_memcpy(rdreq.fhandle, fhandle, XRD_FHANDLE_LEN);
    rdreq.offset = (kXR_int64) htobe64(offset);
    rdreq.rlen   = htonl((kXR_int32) TPC_CHUNK_SIZE);

    if (tpc_send_all(t, fd, &rdreq, sizeof(rdreq)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC kXR_read send failed at offset %llu",
                 (unsigned long long) offset);
        return -1;
    }
    return 0;
}

/*
 * tpc_stream_classify_frame — WHAT: decide what a received read-reply frame
 * means. WHY: keeps the drain loop flat by lifting the kXR_error / invalid-status
 * classification out of it. HOW: kXR_error → decode the remote code/message;
 * anything other than kXR_ok / kXR_oksofar is a protocol violation. Returns 0 if
 * the frame is a valid data frame (caller writes its body), -1 on failure with
 * t->err_msg / t->xrd_error set. `body` is NOT freed here (the caller owns it).
 */
static int
tpc_stream_classify_frame(brix_tpc_pull_t *t, uint16_t status,
                          const u_char *body, uint32_t dlen, uint64_t offset)
{
    if (status == kXR_error) {
        if (body != NULL && dlen >= 4) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC source read error: %s", (const char *) body + 4);
            t->xrd_error = (int) ntohl(*(const uint32_t *) body);
        } else {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC kXR_read error at offset %llu",
                     (unsigned long long) offset);
            t->xrd_error = kXR_IOError;
        }
        return -1;
    }

    if (status != kXR_ok && status != kXR_oksofar) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC kXR_read returned invalid status %u at offset %llu",
                 (unsigned) status, (unsigned long long) offset);
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    return 0;
}

/*
 * tpc_stream_write_frame — WHAT: write one data frame's body to t->dst_fd at
 * (offset + *got_this_req) through the VFS core and advance the counters.
 * WHY: isolates the positional-write + progress side effect from frame receipt.
 * HOW: overflow-guard the destination offset, run a positional VFS WRITE job,
 * verify the full length was written, then bump *got_this_req / t->bytes_written
 * and emit a progress sample. Returns 0 on success, -1 with t->err_msg /
 * t->xrd_error set on overflow or a short/failed write.
 */
static int
tpc_stream_write_frame(brix_tpc_pull_t *t, uint64_t offset,
                       size_t *got_this_req, u_char *body, uint32_t dlen)
{
    brix_vfs_job_t job;
    off_t          dst_offset;

    if (offset > (uint64_t) LLONG_MAX - (uint64_t) *got_this_req) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC dst write offset too large");
        t->xrd_error = kXR_IOError;
        return -1;
    }

    dst_offset = (off_t) (offset + (uint64_t) *got_this_req);
    brix_vfs_job_write_init(&job, t->dst_fd, dst_offset, body, (size_t) dlen);
    brix_vfs_io_execute(&job);
    if (job.io_errno != 0 || job.nio < 0 || (uint32_t) job.nio != dlen) {
        int err = job.io_errno != 0 ? job.io_errno : EIO;

        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC dst write failed: %s", strerror(err));
        t->xrd_error = kXR_IOError;
        return -1;
    }

    *got_this_req    += (size_t) job.nio;
    t->bytes_written += (size_t) job.nio;
    (void) brix_tpc_progress_emit(
        t->transfer_id, (off_t) t->bytes_written, 0,
        BRIX_TPC_STATE_ACTIVE,
        t->c != NULL ? t->c->log : NULL);
    return 0;
}

/*
 * tpc_stream_drain_request — WHAT: receive and write every frame answering a
 * single kXR_read, reporting the byte count delivered in *got_this_req.
 * WHY: a single kXR_read may be answered by zero or more kXR_oksofar frames
 * (more data still coming for THIS request) terminated by exactly one kXR_ok
 * frame; draining that sequence is one nameable step.
 * HOW: loop recv → classify → write each valid data frame → stop on the terminal
 * kXR_ok. Returns 0 with *got_this_req set (0 means EOF for this window), or -1
 * with t->err_msg / t->xrd_error set.
 */
static int
tpc_stream_drain_request(brix_tpc_pull_t *t, int fd, uint64_t offset,
                         size_t *got_this_req)
{
    *got_this_req = 0;

    for (;;) {
        uint16_t  status;
        uint32_t  dlen;
        u_char   *body = NULL;
        int       rc;

        if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC kXR_read recv failed at offset %llu",
                     (unsigned long long) offset);
            return -1;
        }

        rc = tpc_stream_classify_frame(t, status, body, dlen, offset);
        if (rc != 0) {
            free(body);
            return -1;
        }

        if (dlen > 0 && body != NULL
            && tpc_stream_write_frame(t, offset, got_this_req, body, dlen) != 0)
        {
            free(body);
            return -1;
        }

        free(body);

        if (status == kXR_ok) {
            return 0;
        }
        /* kXR_oksofar: loop to receive next frame */
    }
}

/*
 * tpc_stream_sync_dst — WHAT: fsync t->dst_fd through the VFS core for
 * durability. WHY: the TPC durability guarantee — the client's kXR_open/sync
 * reply must not be sent until bytes are on stable storage. HOW: run a VFS SYNC
 * job; 0 on success, -1 with t->err_msg / t->xrd_error set on failure.
 */
static int
tpc_stream_sync_dst(brix_tpc_pull_t *t)
{
    brix_vfs_job_t job;

    brix_vfs_job_sync_init(&job, t->dst_fd);
    brix_vfs_io_execute(&job);
    if (job.io_errno != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC dst fsync failed: %s", strerror(job.io_errno));
        t->xrd_error = kXR_IOError;
        return -1;
    }
    return 0;
}

/*
 * tpc_stream_to_dst — Phase 2/3: stream the whole source into t->dst_fd one
 * kXR_read window at a time, then fsync for durability. Returns 0 (with
 * t->result=NGX_OK, t->xrd_error=0) once the file is fully written and synced,
 * or -1 with t->err_msg / t->xrd_error set. The caller still issues the
 * best-effort remote close on either outcome.
 *
 * Outer loop: one kXR_read request per TPC_CHUNK_SIZE window, advancing `offset`
 * by the bytes actually delivered. We never pipeline reads — each request is
 * fully drained before the next is issued, so `offset` math stays simple and a
 * short final read cleanly signals EOF. A request that delivers zero bytes means
 * we read past EOF and stop.
 *
 * Phase 39 (WS4): wall-clock cap on the whole pull, sampled once per 1 MiB chunk
 * (NOT per frame) so it adds no per-frame syscall cost. Bounds a slow-drip
 * remote that keeps resetting the per-recv SO_RCVTIMEO idle timer. 0 = no cap
 * (current behaviour). The per-recv idle timeout still applies.
 */
static int
tpc_stream_to_dst(brix_tpc_pull_t *t, int fd, const u_char *fhandle)
{
    uint64_t  offset     = 0;
    time_t    pull_start = time(NULL);
    time_t    pull_max   = (t->conf != NULL)
                           ? (time_t) t->conf->tpc_max_transfer_secs : 0;

    for (;;) {
        size_t got_this_req = 0;

        if (pull_max > 0 && (time(NULL) - pull_start) > pull_max) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC pull exceeded brix_tpc_max_transfer_secs (%lds) "
                     "at offset %llu", (long) pull_max,
                     (unsigned long long) offset);
            t->xrd_error = kXR_IOError;
            return -1;
        }

        if (tpc_stream_send_read(t, fd, fhandle, offset) != 0) {
            return -1;
        }
        if (tpc_stream_drain_request(t, fd, offset, &got_this_req) != 0) {
            /* Ensure an error code is always set (some paths set only the
             * message). */
            if (t->xrd_error == 0) {
                t->xrd_error = kXR_IOError;
            }
            return -1;
        }

        if (got_this_req == 0) {
            break;                              /* EOF */
        }
        offset += got_this_req;
    }

    if (tpc_stream_sync_dst(t) != 0) {
        return -1;
    }

    t->result    = NGX_OK;
    t->xrd_error = 0;
    return 0;
}


/*
 * tpc_close_source — best-effort kXR_close of the origin fhandle. Called on both
 * success and failure so the remote handle is never leaked; the result is
 * intentionally discarded, but we still drain the reply (and free its body) to
 * avoid leaving an unread frame on the socket and leaking the response buffer.
 * streamid[1]=2 reuses the open tag.
 */
static void
tpc_close_source(brix_tpc_pull_t *t, int fd, const u_char *fhandle)
{
    ClientCloseRequest clreq;
    uint16_t           s;
    uint32_t           d;
    u_char            *b = NULL;

    ngx_memzero(&clreq, sizeof(clreq));
    clreq.streamid[1] = 2;
    clreq.requestid   = htons(kXR_close);
    ngx_memcpy(clreq.fhandle, fhandle, XRD_FHANDLE_LEN);
    (void) tpc_send_all(t, fd, &clreq, sizeof(clreq));
    (void) tpc_recv_response(t, fd, &s, &b, &d);
    free(b);
}


/*
 * tpc_pull_from_source — execute the complete native XRootD third-party-copy
 * fetch from a remote origin into t->dst_fd: open the source (Phase 1), stream
 * every byte and fsync (Phase 2/3), then best-effort close the origin handle on
 * either outcome so it is never leaked. Returns 0 on success (t->result=NGX_OK),
 * -1 on failure (t->err_msg / t->xrd_error set). See the per-phase helpers above.
 */
int
tpc_pull_from_source(brix_tpc_pull_t *t, int fd)
{
    u_char fhandle[XRD_FHANDLE_LEN];
    int    rc;

    if (tpc_open_source(t, fd, fhandle) != 0) {
        return -1;
    }

    rc = tpc_stream_to_dst(t, fd, fhandle);

    tpc_close_source(t, fd, fhandle);
    return rc;
}
