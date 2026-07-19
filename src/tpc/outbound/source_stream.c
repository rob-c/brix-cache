#include "tpc/engine/tpc_internal.h"
#include "protocols/root/protocol/frame_hdr.h"   /* xrd_error_body_decode (shared kXR_error codec) */
#include "core/compat/checksum.h"                /* brix_checksum_hex_name_fd — dst-side verify */
#include "source_internal.h"


#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp — case-insensitive hex compare */
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>

#if defined(__linux__)
#include <endian.h>
#endif

/* File: source_stream.c — TPC remote source pull, Phase 2/3 (kXR_read stream
 * loop + fsync) and the best-effort remote close, split from source.c in the
 * phase-79 file-size burndown.
 * WHAT: tpc_stream_to_dst() streams the whole origin into t->dst_fd one
 * TPC_CHUNK_SIZE kXR_read window at a time (draining the kXR_oksofar/kXR_ok
 * frame sequence per request, writing each frame's body through the VFS core),
 * then fsyncs for durability; tpc_close_source() issues the best-effort
 * kXR_close so the origin handle is never leaked. WHY: keeps the byte-streaming
 * concern separate from the open/resolve (source_open.c) and the driver
 * (source.c). HOW: send read → drain → advance offset → repeat to EOF → sync.
 * Every framing helper is file-static; only tpc_stream_to_dst() and
 * tpc_close_source() cross the file boundary. */


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
int
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

    /*
     * Completion gate (hostile-network truncation fix): the loop's only in-band
     * EOF signal is a zero-byte read reply, which a truncating middlebox or a
     * source that dies mid-stream can produce (or forge) — so "the reads stopped"
     * is NOT proof the whole file arrived. Verify the delivered byte count against
     * the source's authoritative size (captured by tpc_stat_source before the
     * loop). A mismatch is unambiguous truncation and ALWAYS fails the pull; the
     * caller unlinks the partial destination so it is never committed as complete.
     * When the source would not declare a size, brix_tpc_require_source_size
     * decides whether an unverifiable pull is refused or proceeds (default).
     */
    if (t->src_size_known) {
        if ((uint64_t) t->bytes_written != t->src_size) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC pull truncated: wrote %llu of %llu source bytes",
                     (unsigned long long) t->bytes_written,
                     (unsigned long long) t->src_size);
            t->xrd_error = kXR_IOError;
            return -1;
        }
    } else if (t->conf != NULL && t->conf->tpc_require_source_size) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC pull: source declared no size and "
                 "brix_tpc_require_source_size is on");
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    if (tpc_stream_sync_dst(t) != 0) {
        return -1;
    }

    t->result    = NGX_OK;
    t->xrd_error = 0;
    return 0;
}


/*
 * tpc_stat_parse_size — WHAT: read the size (2nd whitespace token) out of an
 * XRootD kXR_stat reply body "id size flags mtime". WHY: the size is the pull's
 * authoritative completion target; the surrounding tokens are irrelevant here.
 * HOW: skip token 0 (id), then strtoull the leading digits of token 1. Returns 0
 * with *size set, or -1 if there is no numeric second token.
 */
static int
tpc_stat_parse_size(const char *body, uint64_t *size)
{
    const char         *p = body;
    char               *end;
    unsigned long long  v;

    while (*p == ' ') {
        p++;
    }
    while (*p != '\0' && *p != ' ') {           /* skip token 0 (id) */
        p++;
    }
    while (*p == ' ') {
        p++;
    }
    if (*p < '0' || *p > '9') {
        return -1;
    }
    errno = 0;
    v = strtoull(p, &end, 10);
    if (end == p || errno != 0) {
        return -1;
    }
    *size = (uint64_t) v;
    return 0;
}

/*
 * tpc_stat_source — kXR_stat the remote source by path to capture its
 * authoritative size (the pull's real completion signal). See source_internal.h.
 * A distinct streamid tag (4) separates the reply from open(2)/read(3)/close(2).
 * A source that errors the stat, or returns an unparseable body, leaves
 * src_size_known=0 — only a socket/framing failure aborts the pull here.
 */
int
tpc_stat_source(brix_tpc_pull_t *t, int fd)
{
    u_char             req[sizeof(ClientStatRequest) + PATH_MAX];
    ClientStatRequest  streq;
    size_t             pathlen = strlen(t->src_path);
    size_t             total   = sizeof(ClientStatRequest) + pathlen;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body = NULL;

    t->src_size       = 0;
    t->src_size_known = 0;

    if (total > sizeof(req)) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC src path too long for stat");
        t->xrd_error = kXR_ArgTooLong;
        return -1;
    }

    ngx_memzero(&streq, sizeof(streq));
    streq.streamid[1] = 4;                       /* distinct tag: stat replies */
    streq.requestid   = htons(kXR_stat);
    streq.dlen        = htonl((kXR_int32) pathlen);
    ngx_memcpy(req, &streq, sizeof(streq));
    ngx_memcpy(req + sizeof(streq), t->src_path, pathlen);

    if (tpc_send_all(t, fd, req, total) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_stat send failed");
        t->xrd_error = kXR_IOError;
        return -1;
    }
    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_stat recv failed");
        t->xrd_error = kXR_IOError;
        return -1;
    }

    if (status == kXR_ok && body != NULL
        && tpc_stat_parse_size((const char *) body, &t->src_size) == 0)
    {
        t->src_size_known = 1;
    }
    free(body);
    return 0;
}

/*
 * tpc_verify_source_checksum — opt-in post-copy integrity for the TPC pull.
 * kXR_query(kXR_Qcksum) the source (distinct streamid tag 5), parse the
 * "<alg> <hex>" reply, recompute the same algorithm over the written destination
 * with brix_checksum_hex_name_fd, and fail closed (kXR_ChkSumErr) on any of:
 * source cannot supply a checksum, malformed reply, an algorithm brix cannot
 * compute, a destination read failure, or a digest mismatch. See
 * source_internal.h.
 */
int
tpc_verify_source_checksum(brix_tpc_pull_t *t, int fd)
{
    u_char              req[sizeof(ClientQueryRequest) + PATH_MAX];
    ClientQueryRequest  qreq;
    size_t              pathlen = strlen(t->src_path);
    size_t              total   = sizeof(ClientQueryRequest) + pathlen;
    uint16_t            status;
    uint32_t            dlen;
    u_char             *body = NULL;
    const char         *sp;
    size_t              alglen, vlen;
    char                alg[32];
    char                src_hex[2 * EVP_MAX_MD_SIZE + 1];
    char                local_hex[2 * EVP_MAX_MD_SIZE + 1];
    char                normalized[32];
    ngx_log_t          *log = (t->c != NULL) ? t->c->log : ngx_cycle->log;

    if (total > sizeof(req)) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC src path too long for checksum query");
        t->xrd_error = kXR_ArgTooLong;
        return -1;
    }

    ngx_memzero(&qreq, sizeof(qreq));
    qreq.streamid[1] = 5;                        /* distinct tag: query replies */
    qreq.requestid   = htons(kXR_query);
    qreq.infotype    = htons(kXR_Qcksum);
    qreq.dlen        = htonl((kXR_int32) pathlen);
    ngx_memcpy(req, &qreq, sizeof(qreq));
    ngx_memcpy(req + sizeof(qreq), t->src_path, pathlen);

    if (tpc_send_all(t, fd, req, total) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum query send failed");
        t->xrd_error = kXR_IOError;
        return -1;
    }
    if (tpc_recv_response(t, fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum query recv failed");
        t->xrd_error = kXR_IOError;
        return -1;
    }

    /* Fail closed: the operator required verification and the source gave us no
     * checksum to verify against. Reply body is "<alg> <hex>". */
    if (status != kXR_ok || body == NULL) {
        free(body);
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum verify: source supplied no checksum");
        t->xrd_error = kXR_ChkSumErr;
        return -1;
    }

    sp = strchr((const char *) body, ' ');
    if (sp == NULL) {
        free(body);
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum verify: malformed source checksum reply");
        t->xrd_error = kXR_ChkSumErr;
        return -1;
    }
    alglen = (size_t) (sp - (const char *) body);
    if (alglen == 0 || alglen >= sizeof(alg)) {
        free(body);
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum verify: bad source checksum type");
        t->xrd_error = kXR_ChkSumErr;
        return -1;
    }
    ngx_memcpy(alg, body, alglen);
    alg[alglen] = '\0';

    /* value = token after the space, trimmed of trailing whitespace/CRLF. */
    sp++;
    while (*sp == ' ') {
        sp++;
    }
    vlen = 0;
    while (sp[vlen] != '\0' && sp[vlen] != ' '
           && sp[vlen] != '\n' && sp[vlen] != '\r')
    {
        vlen++;
    }
    if (vlen == 0 || vlen >= sizeof(src_hex)) {
        free(body);
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum verify: bad source checksum value");
        t->xrd_error = kXR_ChkSumErr;
        return -1;
    }
    ngx_memcpy(src_hex, sp, vlen);
    src_hex[vlen] = '\0';
    free(body);

    /* Recompute the SAME algorithm over the destination and compare. */
    if (brix_checksum_hex_name_fd(alg, t->dst_fd, t->dst_path, log,
                                  local_hex, sizeof(local_hex),
                                  normalized, sizeof(normalized)) != NGX_OK)
    {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum verify: cannot compute %s on destination", alg);
        t->xrd_error = kXR_ChkSumErr;
        return -1;
    }

    if (strcasecmp(local_hex, src_hex) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC checksum mismatch: source %s=%s destination=%s",
                 alg, src_hex, local_hex);
        t->xrd_error = kXR_ChkSumErr;
        return -1;
    }

    return 0;
}

/*
 * tpc_close_source — best-effort kXR_close of the origin fhandle. Called on both
 * success and failure so the remote handle is never leaked; the result is
 * intentionally discarded, but we still drain the reply (and free its body) to
 * avoid leaving an unread frame on the socket and leaking the response buffer.
 * streamid[1]=2 reuses the open tag.
 */
void
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
