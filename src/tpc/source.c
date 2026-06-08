#include "tpc_internal.h"


#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#if defined(__linux__)
#include <endian.h>
#endif

/* ---- File: source.c — TPC remote source pull (open → read loop → close) ----
 *
 * WHAT: Single public function `tpc_pull_from_source()` executes the complete native XRootD third-party-copy fetch from a remote origin into dst_fd. Phase 1 → builds ClientOpenRequest with src_path + opaque key/org params, sends kXR_open to remote, receives ServerOpenBody fhandle (handles both minimal 4-byte and full 12+ byte responses), extracts fhandle; Phase 2 → streaming read loop via repeated kXR_read requests at TPC_CHUNK_SIZE offsets, accumulates kXR_oksofar + kXR_ok frames per request, writes each frame's body bytes to dst_fd via write() (EINTR retry), tracks offset advancement and total bytes_written; Phase 3 → fsync(dst_fd) for durability, sets result=NGX_OK/xrd_error=0, best-effort remote close via kXR_close. Returns -1 on failure with error message + xrd_error code, 0 on success.
 *
 * WHY: TPC (Third-Party Copy) transfers require the destination server to connect to a remote root:// origin, open the source file, stream all bytes into dst_fd, and close the remote handle. This function encapsulates the entire pull lifecycle — open → read loop → fsync → close — so launch.c/thread.c can delegate it to a thread-pool worker without managing the protocol sequence themselves. Handles peer diversity (minimal vs full ServerOpenBody), oksofar accumulation for large reads, EINTR-safe writes, and best-effort remote cleanup on failure paths.
 *
 * HOW: Build open_buf with ClientOpenRequest header + src_path + opaque "?tpc.key=...&tpc.org=..." → send_all(fd) kXR_open → recv_response fd status/body → check kXR_ok + dlen>=XRD_FHANDLE_LEN → memcpy fhandle → free(body) → offset=0 loop: build ClientReadRequest with streamid[1]=3, kXR_read, fhandle, htobe64(offset), htonl(TPC_CHUNK_SIZE) → send_all → inner for-loop: recv_response accumulating kXR_oksofar/kXR_ok frames → write body bytes to dst_fd (EINTR continue, failure=break) → got_this_req+=dlen → offset+=got_this_req → outer loop exits when done=1(got_this_req==0/EOF) or failed=1 → fsync(dst_fd) → goto close_remote: build ClientCloseRequest with kXR_close + fhandle → send_all + recv_response (best-effort, discard result). */

/* ------------------------------------------------------------------ */
/* Remote file open, streaming read loop, and protocol-level close       */
/* ------------------------------------------------------------------ */

int
tpc_pull_from_source(xrootd_tpc_pull_t *t, int fd)
{
    u_char            open_buf[sizeof(ClientOpenRequest) + PATH_MAX + 512];
    ClientOpenRequest *opreq;
    size_t            pathlen, opqlen, send_len;
    char              opaque[512];

    ClientReadRequest  rdreq;
    ClientCloseRequest clreq;
    u_char             fhandle[XRD_FHANDLE_LEN];
    uint64_t           offset;
    int                done;
    int                failed;
    int                rc = -1;

    uint16_t  status;
    uint32_t  dlen;
    u_char   *body;

    /* ---------------------------------------------------------------- */
    /* Open source file                                                   */
    /* ---------------------------------------------------------------- */

    pathlen   = strlen(t->src_path);
    opqlen    = 0;
    opaque[0] = '\0';

    if (t->tpc_key[0] != '\0' && t->tpc_org[0] != '\0') {
        opqlen = (size_t) snprintf(opaque, sizeof(opaque),
                                   "?tpc.key=%s&tpc.org=%s",
                                   t->tpc_key, t->tpc_org);
    } else if (t->tpc_key[0] != '\0') {
        opqlen = (size_t) snprintf(opaque, sizeof(opaque),
                                   "?tpc.key=%s", t->tpc_key);
    }
    if (opqlen >= sizeof(opaque)) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC source opaque too long");
        t->xrd_error = kXR_ArgTooLong;
        return -1;
    }

    send_len = sizeof(ClientOpenRequest) + pathlen + opqlen;
    if (send_len > sizeof(open_buf)) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC src path too long");
        t->xrd_error = kXR_ArgTooLong;
        return -1;
    }

    ngx_memzero(open_buf, send_len);
    opreq = (ClientOpenRequest *) open_buf;
    opreq->streamid[1] = 2;
    opreq->requestid   = htons(kXR_open);
    opreq->options     = htons(kXR_open_read);
    opreq->dlen        = htonl((kXR_int32)(pathlen + opqlen));

    ngx_memcpy(open_buf + sizeof(ClientOpenRequest), t->src_path, pathlen);
    if (opqlen > 0) {
        ngx_memcpy(open_buf + sizeof(ClientOpenRequest) + pathlen,
                   opaque, opqlen);
    }

    if (tpc_send_all(fd, open_buf, send_len) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_open send failed");
        return -1;
    }

    body = NULL;
    if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_open recv failed");
        return -1;
    }
    /*
     * Some peers (including reference xrootd in common configs) return a
     * minimal kXR_ok body with only the 4-byte fhandle; others send the full
     * ServerOpenBody (12+ bytes).
     */
    if (status != kXR_ok || body == NULL || dlen < XRD_FHANDLE_LEN) {
        if (status == kXR_error && body != NULL && dlen >= 4) {
            const char *msg = (const char *) body + 4;
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC source open failed: %s", msg);
            t->xrd_error = (int) ntohl(*(uint32_t *) body);
        } else {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC kXR_open rejected (status=%u dlen=%u)",
                     (unsigned) status, (unsigned) dlen);
        }
        free(body);
        return -1;
    }

    ngx_memcpy(fhandle, body, XRD_FHANDLE_LEN);
    free(body);

    /* ---------------------------------------------------------------- */
    /* Stream source → dst_fd                                             */
    /* ---------------------------------------------------------------- */

    offset = 0;
    done   = 0;
    failed = 0;

    while (!done && !failed) {
        size_t got_this_req = 0;

        ngx_memzero(&rdreq, sizeof(rdreq));
        rdreq.streamid[1] = 3;
        rdreq.requestid   = htons(kXR_read);
        ngx_memcpy(rdreq.fhandle, fhandle, XRD_FHANDLE_LEN);
        rdreq.offset = (kXR_int64) htobe64(offset);
        rdreq.rlen   = htonl((kXR_int32) TPC_CHUNK_SIZE);

        if (tpc_send_all(fd, &rdreq, sizeof(rdreq)) != 0) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC kXR_read send failed at offset %llu",
                     (unsigned long long) offset);
            failed = 1;
            break;
        }

        /* Accumulate kXR_oksofar + kXR_ok frames for this read request. */
        for (;;) {
            body = NULL;
            if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
                snprintf(t->err_msg, sizeof(t->err_msg),
                         "TPC kXR_read recv failed at offset %llu",
                         (unsigned long long) offset);
                failed = 1;
                break;
            }

            if (status == kXR_error) {
                if (body != NULL && dlen >= 4) {
                    snprintf(t->err_msg, sizeof(t->err_msg),
                             "TPC source read error: %s",
                             (const char *) body + 4);
                    t->xrd_error = (int) ntohl(*(uint32_t *) body);
                } else {
                    snprintf(t->err_msg, sizeof(t->err_msg),
                             "TPC kXR_read error at offset %llu",
                             (unsigned long long) offset);
                    t->xrd_error = kXR_IOError;
                }
                free(body);
                failed = 1;
                break;
            }

            if (status != kXR_ok && status != kXR_oksofar) {
                snprintf(t->err_msg, sizeof(t->err_msg),
                         "TPC kXR_read returned invalid status %u at offset %llu",
                         (unsigned) status, (unsigned long long) offset);
                t->xrd_error = kXR_ServerError;
                free(body);
                failed = 1;
                break;
            }

            if (dlen > 0 && body != NULL) {
                const u_char *wp   = body;
                uint32_t      wrem = dlen;
                while (wrem > 0) {
                    ssize_t wn = write(t->dst_fd, wp, wrem);
                    if (wn < 0 && errno == EINTR) {
                        continue;
                    }
                    if (wn <= 0) {
                        snprintf(t->err_msg, sizeof(t->err_msg),
                                 "TPC dst write failed: %s", strerror(errno));
                        t->xrd_error = kXR_IOError;
                        free(body);
                        failed = 1;
                        break;
                    }
                    wp   += (size_t) wn;
                    wrem -= (size_t) wn;
                }
                if (failed) {
                    break;
                }
                got_this_req += dlen;
                t->bytes_written += dlen;
                (void) xrootd_tpc_progress_emit(
                    t->transfer_id, (off_t) t->bytes_written, 0,
                    XROOTD_TPC_STATE_ACTIVE,
                    t->c != NULL ? t->c->log : NULL);
            }

            free(body);

            if (status == kXR_ok) { break; }
            /* kXR_oksofar: loop to receive next frame */
        }

        if (failed) {
            break;
        }

        if (got_this_req == 0) {
            done = 1; /* EOF */
        } else {
            offset += got_this_req;
        }
    }

    if (failed) {
        if (t->xrd_error == 0) {
            t->xrd_error = kXR_IOError;
        }
        rc = -1;
        goto close_remote;
    }

    if (fsync(t->dst_fd) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC dst fsync failed: %s", strerror(errno));
        t->xrd_error = kXR_IOError;
        rc = -1;
        goto close_remote;
    }

    t->result    = NGX_OK;
    t->xrd_error = 0;
    rc = 0;

    /* Close the remote file handle (best-effort). */
close_remote:
    ngx_memzero(&clreq, sizeof(clreq));
    clreq.streamid[1] = 2;
    clreq.requestid   = htons(kXR_close);
    ngx_memcpy(clreq.fhandle, fhandle, XRD_FHANDLE_LEN);
    (void) tpc_send_all(fd, &clreq, sizeof(clreq));
    {
        uint16_t s; uint32_t d; u_char *b = NULL;
        (void) tpc_recv_response(fd, &s, &b, &d);
        free(b);
    }

    return rc;
}
