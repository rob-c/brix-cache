#include "cache_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared handshake/protocol/login packers */
#include "core/compat/fattr_codec.h"        /* xrdp_fattr_nvec_parse (kXR_fattr replies) */
#include "protocols/root/protocol/frame_hdr.h"        /* xrd_error_body_decode (kXR_error errnum) */
#include "auth/gsi/gsi_core.h"              /* shared XrdSecgsi handshake kernel (C-3 GSI) */
#include "protocols/root/protocol/gsi.h"              /* kXRS_x509 bucket id (origin-cert verify) */
#include "auth/sss/sss_keytab_kernel.h"     /* §14 SSS: shared keytab line grammar */
#include <stdio.h>                        /* fdopen/fgets for the keytab reader */


#if defined(__linux__)
#include <endian.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* NOTE: the XRootD connection bootstrap (ClientInitHandShake → kXR_protocol
 * negotiation/TLS-upgrade → anonymous kXR_login → credential dispatch) lives in
 * the sibling origin_protocol_bootstrap.c; brix_cache_origin_bootstrap is
 * declared in cache_internal.h. This file carries the post-session data-path
 * exchanges: kXR_open, kXR_query/kXR_Qcksum, and kXR_read. */

/* brix_cache_origin_open — kXR_open (read + kXR_retstat) of the source file:
 * parse ServerOpenBody for the fhandle and the appended stat string, so file_size
 * is known before a full download (the admission filter can reject oversized files
 * without fetching them). Returns 0 with fhandle set, -1 on error or redirect. */
int
brix_cache_origin_open(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, u_char fhandle[XRD_FHANDLE_LEN])
{
    size_t             pathlen, total;
    u_char            *buf;
    ClientOpenRequest *req;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body;

    pathlen = strlen(t->clean_path);
    total = sizeof(ClientOpenRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        brix_cache_set_error(t, kXR_NoMemory, 0,
                               "cache origin open allocation failed");
        return -1;
    }

    ngx_memzero(buf, total);
    req = (ClientOpenRequest *) buf;
    req->streamid[1] = 2;
    req->requestid = htons(kXR_open);
    /* kXR_retstat requests an ASCII stat string appended after the fhandle so we
     * can learn the file size before committing to a full download */
    {
        xrdw_open_req_t b = { .options = kXR_open_read | kXR_retstat };
        xrdw_open_req_pack(&b, ((ClientRequestHdr *) buf)->body);
    }
    req->dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(buf + sizeof(*req), t->clean_path, pathlen);

    if (brix_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin open write failed");
        return -1;
    }
    free(buf);

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen,
                                   BRIX_MAX_PATH + 256) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "cache origin open failed");
        free(body);
        return -1;
    }
    if (status == kXR_redirect) {
        free(body);
        brix_cache_set_error(t, kXR_Unsupported, 0,
                               "cache origin redirected open; direct data "
                               "server origin is required");
        return -1;
    }
    if (status != kXR_ok || dlen < sizeof(ServerOpenBody)) {
        free(body);
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin open returned invalid response");
        return -1;
    }

    ngx_memcpy(fhandle, ((ServerOpenBody *) body)->fhandle, XRD_FHANDLE_LEN);

    /*
     * If kXR_retstat was honored the stat string follows ServerOpenBody.
     * Format: "<id> <size> <flags> <modtime>" — we only need the size (field 2).
     * The body is always NUL-terminated by brix_cache_read_response, so
     * strtoull is safe.
     */
    if (dlen > sizeof(ServerOpenBody)) {
        const char     *stat_str = (const char *) body + sizeof(ServerOpenBody);
        const char     *p;

        p = strchr(stat_str, ' ');
        if (p != NULL) {
            char              *endp;
            unsigned long long  sv;

            errno = 0;
            sv = strtoull(p + 1, &endp, 10);
            if (errno == 0 && endp != p + 1) {
                t->file_size = (off_t) sv;
            }
        }
    }

    free(body);
    return 0;
}

/* origin_cksum_send_query — build and send the path-based kXR_query/kXR_Qcksum
 * request for t->clean_path. WHY separate: the request assembly (malloc + pack +
 * send + free) is the only allocation in the checksum exchange; isolating it
 * keeps the best-effort orchestrator a flat status sequence. Returns 0 on send,
 * -1 on OOM or write failure — NO task error is set (best-effort). */
static int
origin_cksum_send_query(brix_cache_fill_t *t, brix_cache_origin_conn_t *oc)
{
    size_t              pathlen, total;
    u_char             *buf;
    ClientQueryRequest *req;

    pathlen = strlen(t->clean_path);
    total = sizeof(ClientQueryRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        return -1;      /* best-effort: skip verification on OOM */
    }

    ngx_memzero(buf, total);
    req = (ClientQueryRequest *) buf;
    req->streamid[1] = 6;                       /* unused stream slot */
    req->requestid = htons(kXR_query);
    {
        xrdw_query_req_t b = { .infotype = kXR_Qcksum };  /* fhandle 0 ⇒ path-based */
        xrdw_query_req_pack(&b, ((ClientRequestHdr *) buf)->body);
    }
    req->dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(buf + sizeof(*req), t->clean_path, pathlen);

    if (brix_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        return -1;
    }
    free(buf);
    return 0;
}

/* origin_cksum_split — pure parse of the NUL-terminated "<algo> <hexvalue>"
 * reply body into the caller buffers, trimming trailing whitespace from the hex
 * field. Leaves both buffers untouched (still empty) when the body doesn't fit
 * the expected shape or exceeds the buffer sizes — the caller then treats it as
 * "no origin digest". No I/O, no task state. */
static void
origin_cksum_split(const u_char *body, char *alg_out, size_t alg_sz,
    char *hex_out, size_t hex_sz)
{
    const char *sp;

    sp = strchr((const char *) body, ' ');
    if (sp != NULL) {
        size_t       an = (size_t) (sp - (const char *) body);
        const char  *hv = sp + 1;
        const char  *end = hv + strlen(hv);
        size_t       hn;

        while (end > hv && (end[-1] == '\n' || end[-1] == '\r'
                            || end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        hn = (size_t) (end - hv);

        if (an > 0 && an < alg_sz && hn > 0 && hn < hex_sz) {
            ngx_memcpy(alg_out, body, an);
            alg_out[an] = '\0';
            ngx_memcpy(hex_out, hv, hn);
            hex_out[hn] = '\0';
        }
    }
}

/* brix_cache_origin_query_checksum — ask the origin for its stored digest of
 * t->clean_path (path-based kXR_query/kXR_Qcksum), returning "<algo> <hex>" split
 * into the caller buffers (out->alg / out->hex). Checksum-on-fill (verify.c)
 * validates downloaded bytes against this before publishing. BEST-EFFORT: an
 * origin with no checksum or a wire hiccup must NOT fail an otherwise-complete
 * fill (data is already on disk) — on ANY failure it restores t's error state
 * and returns 0 with out->alg emptied, so the caller treats it as "no origin
 * digest" and the verify policy decides.
 *
 * WAITRESP: a real origin usually does NOT have the digest cached at fill time —
 * it computes it on demand and PARKS the query with kXR_waitresp, then delivers
 * the answer as an unsolicited kXR_attn(kXR_asynresp) frame (exactly what a stock
 * XRootD client absorbs transparently). We follow that handshake for a bounded
 * number of hops so the common lazy-checksum origin still yields a digest for
 * verify=require, while a hostile origin that streams frames forever cannot wedge
 * the fill thread — each recv is bounded by the origin socket timeout and the hop
 * count caps the exchange. Unrelated async pushes (kXR_asyncms) are skipped. */
int
brix_cache_origin_query_checksum(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const brix_cache_cksum_out_t *out)
{
    uint16_t  status;
    uint32_t  dlen;
    u_char   *body;
    int       saved_result, saved_xrd;
    int       hops;

    if (out->alg_sz > 0) {
        out->alg[0] = '\0';
    }
    if (out->hex_sz > 0) {
        out->hex[0] = '\0';
    }

    /* The download already succeeded; never let a checksum-query failure leak an
     * error onto the task. Snapshot and restore the error triple. */
    saved_result = t->result;
    saved_xrd    = t->xrd_error;

    if (origin_cksum_send_query(t, oc) != 0) {
        return 0;
    }

    for (hops = 0; hops < 8; hops++) {
        body = NULL;
        if (brix_cache_read_response(t, oc, &status, &body, &dlen, 512) != 0) {
            t->result    = saved_result;
            t->xrd_error = saved_xrd;
            return 0;
        }

        if (status == kXR_waitresp) {
            free(body);      /* body = advised seconds; the answer frame follows */
            continue;
        }

        if (status == kXR_attn) {
            /* kXR_attn asynresp body layout (opcodes.h):
             *   actnum[4] reserved[4] ServerResponseHdr[8] response[inner_dlen] */
            uint32_t  actnum;
            uint16_t  inner_status;
            uint32_t  inner_dlen;

            if (body == NULL || dlen < 16) {
                free(body);
                return 0;
            }
            actnum = xrd_get_u32_be(body);
            if (actnum != (uint32_t) kXR_asynresp) {
                free(body);                 /* asyncms / other push — keep going */
                continue;
            }
            xrd_resp_hdr_unpack(body + 8, NULL, &inner_status, &inner_dlen);
            if (inner_status != kXR_ok || inner_dlen == 0
                || (size_t) 16 + inner_dlen > (size_t) dlen)
            {
                free(body);                 /* deferred result was not a digest */
                return 0;
            }
            /* NUL-terminate the inner payload before the split (read_response
             * over-allocated dlen+1, and 16+inner_dlen <= dlen, so this index is
             * in bounds). */
            body[16 + inner_dlen] = '\0';
            origin_cksum_split(body + 16, out->alg, out->alg_sz,
                               out->hex, out->hex_sz);
            free(body);
            return 0;
        }

        if (status == kXR_ok) {
            if (body == NULL || dlen == 0) {
                free(body);
                return 0;
            }
            /* body is NUL-terminated "<algo> <hexvalue>". */
            origin_cksum_split(body, out->alg, out->alg_sz,
                               out->hex, out->hex_sz);
            free(body);
            return 0;
        }

        /* kXR_error or any other status: origin has no usable checksum. */
        free(body);
        return 0;
    }

    return 0;   /* too many hops — treat as no origin digest (verify decides) */
}


/* brix_cache_origin_read_chunk — kXR_read at (rng->read_off, rng->want),
 * writing each reply payload to the sink via brix_cache_sink_pwrite and looping
 * over kXR_oksofar until the final kXR_ok. dlen is bounded (<= want, accumulated
 * rng->got within request bounds) to prevent overflow. Sets rng->got;
 * returns 0 / -1. */
int
brix_cache_origin_read_chunk(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    brix_cache_sink_t *sink, brix_cache_read_range_t *rng)
{
    ClientReadRequest req;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body;

    rng->got = 0;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 3;
    req.requestid = htons(kXR_read);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.offset = (kXR_int64) htobe64(rng->read_off);
    req.rlen = htonl((kXR_int32) rng->want);
    req.dlen = 0;

    if (brix_cache_io_send(oc, &req, sizeof(req)) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin read write failed");
        return -1;
    }

    for (;;) {
        body = NULL;
        if (brix_cache_read_response(t, oc, &status, &body, &dlen,
                                       BRIX_CACHE_FETCH_CHUNK) != 0) {
            return -1;
        }

        if (status == kXR_error) {
            brix_cache_set_origin_error(t, body, dlen,
                                          "cache origin read failed");
            free(body);
            return -1;
        }

        if (status != kXR_ok && status != kXR_oksofar) {
            free(body);
            brix_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin read returned invalid status");
            return -1;
        }

        if ((size_t) dlen > rng->want || rng->got > rng->want - (size_t) dlen) {
            free(body);
            brix_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin read returned too much data");
            return -1;
        }

        if (dlen > 0) {
            /* Write at dst_off + bytes already written this call (rng->got).
             * dst_off is the caller's WRITE base, decoupled from the origin READ
             * offset: the whole-file fetch passes dst_off==read_off (absolute), a
             * slice fill passes a 0-relative base. Using got alone restarts at 0
             * each 1 MiB chunk, so multi-chunk whole-file fetches overwrote at
             * offset 0 (corrupting any file > BRIX_CACHE_FETCH_CHUNK → adler32
             * mismatch). */
            if (brix_cache_sink_pwrite(sink, body, dlen,
                                         (off_t) (rng->dst_off + rng->got)) != 0)
            {
                free(body);
                brix_cache_set_syserror(t, kXR_IOError,
                                          "cache file write failed");
                return -1;
            }
            rng->got += (size_t) dlen;
        }

        free(body);

        if (status == kXR_ok) {
            return 0;
        }
    }
}

