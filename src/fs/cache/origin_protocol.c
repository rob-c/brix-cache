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

/* Extract the "gsi" protocol's parameter substring from a login advert that may
 * carry several "&P=<proto>,<parms>" entries (e.g. "&P=ztn,v:10000&P=gsi,v:10600,
 * c:ssl,ca:HASH"). Returns a pointer INTO `parms` just past "gsi," (the v:/c:/ca:
 * list brix_gsi_parse_parms wants), or NULL when gsi is not advertised. */
static const char *
cache_origin_gsi_parms(const char *parms, size_t plen)
{
    static const char needle[] = "gsi,";
    size_t            i;

    if (parms == NULL || plen < sizeof(needle) - 1) {
        return NULL;
    }
    for (i = 0; i + (sizeof(needle) - 1) <= plen; i++) {
        if (ngx_strncmp(parms + i, needle, sizeof(needle) - 1) == 0) {
            return parms + i + (sizeof(needle) - 1);
        }
    }
    return NULL;
}

/* brix_cache_origin_bootstrap — three-phase XRootD connection bootstrap on a
 * raw TCP/TLS socket: ClientInitHandShake → kXR_protocol negotiation (a
 * kXR_gotoTLS flag triggers a TLS upgrade when configured) → anonymous kXR_login
 * (user 'xrd', capver kXR_ver005, streamid[1]=1). When the origin demands auth
 * (kXR_authmore) and a bearer token is configured, a ztn kXR_auth completes the
 * session. Every cache fill needs a valid session before reading. Returns 0 on
 * success, -1 on any phase failure. */
int
brix_cache_origin_bootstrap(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc)
{
    ClientInitHandShake    hs;
    ClientProtocolRequest  pr;
    ClientLoginRequest     lr;
    uint16_t               status;
    uint32_t               dlen;
    u_char                *body;
    static const uint8_t   sid[2] = { 0, 1 };   /* cache-origin connector streamid */

    xrd_pack_handshake(&hs);

    if (brix_cache_io_send(oc, &hs, sizeof(hs)) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin handshake write failed");
        return -1;
    }

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen, 64) != 0) {
        return -1;
    }
    free(body);

    if (status != kXR_ok) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin handshake failed");
        return -1;
    }

    xrd_pack_protocol_request(&pr, sid, 0);

    if (brix_cache_io_send(oc, &pr, sizeof(pr)) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin protocol write failed");
        return -1;
    }

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen,
                                   sizeof(ServerProtocolBody)) != 0) {
        return -1;
    }

    if (status != kXR_ok) {
        free(body);
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin protocol negotiation failed");
        return -1;
    }

    if (dlen >= sizeof(ServerProtocolBody)) {
        ServerProtocolBody *pb;
        uint32_t            flags;

        pb = (ServerProtocolBody *) body;
        flags = (uint32_t) ntohl(pb->flags);

        if ((flags & kXR_gotoTLS) && !t->conf->cache_origin_tls) {
            free(body);
            brix_cache_set_error(t, kXR_TLSRequired, 0,
                "cache origin requires TLS; enable brix_cache_origin_tls");
            return -1;
        }
    }
    free(body);

    xrd_pack_login_request(&lr, sid, (int32_t) ngx_pid, "xrd", kXR_ver005);

    if (brix_cache_io_send(oc, &lr, sizeof(lr)) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin login write failed");
        return -1;
    }

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }

    /* A kXR_ok login on an AUTHENTICATED origin still carries an auth advert:
     * body = sessid(16) + "&P=<proto>,..." (anonymous origins send only the 16-byte
     * sessid). So a kXR_ok with a "&P=" parameter block means the session is NOT yet
     * authenticated — present the configured bearer via ztn (§14/C-3). kXR_authmore
     * is the mid-protocol variant; handle it the same way. */
    if ((status == kXR_ok || status == kXR_authmore)
        && dlen > BRIX_SESSION_ID_LEN)
    {
        const u_char *parms = body + BRIX_SESSION_ID_LEN;
        size_t        plen  = dlen - BRIX_SESSION_ID_LEN;
        int           needs_auth = (ngx_strlchr((u_char *) parms,
                                        (u_char *) parms + plen, '=') != NULL);
        int           has_ztn = (ngx_strnstr((u_char *) parms, "ztn", plen) != NULL);
        int           has_sss = (ngx_strnstr((u_char *) parms, "sss", plen) != NULL);
        const char   *gp = cache_origin_gsi_parms((const char *) parms, plen);
        char          gsi_parms[256];
        int           has_gsi = 0;

        /* Copy the gsi v:/c:/ca: list out of the (about-to-be-freed) body, stopping
         * at the next "&P=" entry so a co-advertised ztn block isn't mis-parsed. */
        if (gp != NULL) {
            const char *amp = gp;
            size_t      end = (size_t) ((const char *) parms + plen - gp);
            size_t      i;

            for (i = 0; i < end && amp[i] != '&'; i++) { /* find terminator */ }
            if (i >= sizeof(gsi_parms)) { i = sizeof(gsi_parms) - 1; }
            ngx_memcpy(gsi_parms, gp, i);
            gsi_parms[i] = '\0';
            has_gsi = 1;
        }

        free(body);
        if (needs_auth) {
            if (has_ztn && t->conf->cache_origin_bearer.len > 0) {
                return brix_cache_origin_auth_ztn(t, oc,
                                                    &t->conf->cache_origin_bearer);
            }
            if (has_gsi && t->conf->cache_origin_x509_proxy.len > 0) {
                return brix_cache_origin_auth_gsi(t, oc, gsi_parms,
                    (const char *) t->conf->cache_origin_x509_proxy.data);
            }
            if (has_sss && t->conf->cache_origin_sss_keytab.len > 0) {
                return brix_cache_origin_auth_sss(t, oc,
                    (const char *) t->conf->cache_origin_sss_keytab.data);
            }
            brix_cache_set_error(t, kXR_AuthFailed, 0,
                (t->conf->cache_origin_bearer.len > 0
                 || t->conf->cache_origin_x509_proxy.len > 0
                 || t->conf->cache_origin_sss_keytab.len > 0)
                    ? "cache origin auth protocol not supported (need ztn/gsi/sss)"
                    : "cache origin requires authentication (no credential set)");
            return -1;
        }
        return 0;
    }
    free(body);

    if (status == kXR_authmore) {
        if (t->conf->cache_origin_bearer.len > 0) {
            return brix_cache_origin_auth_ztn(t, oc, &t->conf->cache_origin_bearer);
        }
        brix_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin requires authentication");
        return -1;
    }
    if (status != kXR_ok) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin anonymous login failed");
        return -1;
    }

    return 0;
}

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

/* brix_cache_origin_query_checksum — ask the origin for its stored digest of
 * t->clean_path (path-based kXR_query/kXR_Qcksum), returning "<algo> <hex>" split
 * into the caller buffers. Checksum-on-fill (verify.c) validates downloaded bytes
 * against this before publishing. BEST-EFFORT: an origin with no checksum or a
 * wire hiccup must NOT fail an otherwise-complete fill (data is already on disk) —
 * on ANY failure it restores t's error state and returns 0 with alg_out emptied,
 * so the caller treats it as "no origin digest" and the verify policy decides. */
int
brix_cache_origin_query_checksum(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, char *alg_out, size_t alg_sz,
    char *hex_out, size_t hex_sz)
{
    size_t              pathlen, total;
    u_char             *buf;
    ClientQueryRequest *req;
    uint16_t            status;
    uint32_t            dlen;
    u_char             *body;
    char               *sp;
    int                 saved_result, saved_xrd;

    if (alg_sz > 0) {
        alg_out[0] = '\0';
    }
    if (hex_sz > 0) {
        hex_out[0] = '\0';
    }

    /* The download already succeeded; never let a checksum-query failure leak an
     * error onto the task. Snapshot and restore the error triple. */
    saved_result = t->result;
    saved_xrd    = t->xrd_error;

    pathlen = strlen(t->clean_path);
    total = sizeof(ClientQueryRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        return 0;       /* best-effort: skip verification on OOM */
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
        return 0;
    }
    free(buf);

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen, 512) != 0) {
        t->result    = saved_result;
        t->xrd_error = saved_xrd;
        return 0;
    }

    if (status != kXR_ok || body == NULL || dlen == 0) {
        free(body);                             /* origin has no checksum */
        return 0;
    }

    /* body is NUL-terminated "<algo> <hexvalue>". */
    sp = strchr((char *) body, ' ');
    if (sp != NULL) {
        size_t  an = (size_t) (sp - (char *) body);
        char   *hv = sp + 1;
        char   *end = hv + strlen(hv);
        size_t  hn;

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

    free(body);
    return 0;
}


/* brix_cache_origin_read_chunk — kXR_read at (offset, rlen), writing each reply
 * payload to the sink via brix_cache_sink_pwrite and looping over kXR_oksofar
 * until the final kXR_ok. dlen is bounded (<= want, accumulated *got within
 * request bounds) to prevent overflow. Sets *got; returns 0 / -1. */
int
brix_cache_origin_read_chunk(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    brix_cache_sink_t *sink, uint64_t read_off, uint64_t dst_off,
    size_t want, size_t *got)
{
    ClientReadRequest req;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body;

    *got = 0;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 3;
    req.requestid = htons(kXR_read);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.offset = (kXR_int64) htobe64(read_off);
    req.rlen = htonl((kXR_int32) want);
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

        if ((size_t) dlen > want || *got > want - (size_t) dlen) {
            free(body);
            brix_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin read returned too much data");
            return -1;
        }

        if (dlen > 0) {
            /* Write at dst_off + bytes already written this call (*got). dst_off
             * is the caller's WRITE base, decoupled from the origin READ offset:
             * the whole-file fetch passes dst_off==read_off (absolute), a slice
             * fill passes a 0-relative base. Using *got alone restarts at 0 each
             * 1 MiB chunk, so multi-chunk whole-file fetches overwrote at offset 0
             * (corrupting any file > BRIX_CACHE_FETCH_CHUNK → adler32 mismatch). */
            if (brix_cache_sink_pwrite(sink, body, dlen,
                                         (off_t) (dst_off + *got)) != 0) {
                free(body);
                brix_cache_set_syserror(t, kXR_IOError,
                                          "cache file write failed");
                return -1;
            }
            *got += (size_t) dlen;
        }

        free(body);

        if (status == kXR_ok) {
            return 0;
        }
    }
}

