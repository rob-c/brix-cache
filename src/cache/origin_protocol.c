#include "cache_internal.h"

#if (NGX_THREADS)

#if defined(__linux__)
#include <endian.h>
#endif
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

int
xrootd_cache_origin_bootstrap(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc)
{
    ClientInitHandShake    hs;
    ClientProtocolRequest  pr;
    ClientLoginRequest     lr;
    uint16_t               status;
    uint32_t               dlen;
    u_char                *body;

    ngx_memzero(&hs, sizeof(hs));
    hs.fourth = htonl(4);
    hs.fifth = htonl(ROOTD_PQ);

    if (xrootd_cache_io_send(oc, &hs, sizeof(hs)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin handshake write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 64) != 0) {
        return -1;
    }
    free(body);

    if (status != kXR_ok) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin handshake failed");
        return -1;
    }

    ngx_memzero(&pr, sizeof(pr));
    pr.streamid[1] = 1;
    pr.requestid = htons(kXR_protocol);
    pr.clientpv = htonl(kXR_PROTOCOLVERSION);
    pr.expect = 0x03;
    pr.dlen = 0;

    if (xrootd_cache_io_send(oc, &pr, sizeof(pr)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin protocol write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   sizeof(ServerProtocolBody)) != 0) {
        return -1;
    }

    if (status != kXR_ok) {
        free(body);
        xrootd_cache_set_error(t, kXR_ServerError, 0,
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
            xrootd_cache_set_error(t, kXR_TLSRequired, 0,
                "cache origin requires TLS; enable xrootd_cache_origin_tls");
            return -1;
        }
    }
    free(body);

    ngx_memzero(&lr, sizeof(lr));
    lr.streamid[1] = 1;
    lr.requestid = htons(kXR_login);
    lr.pid = htonl((kXR_int32) ngx_pid);
    lr.username[0] = 'x';
    lr.username[1] = 'r';
    lr.username[2] = 'd';
    lr.capver = kXR_ver005;
    lr.dlen = 0;

    if (xrootd_cache_io_send(oc, &lr, sizeof(lr)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin login write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }
    free(body);

    if (status == kXR_authmore) {
        xrootd_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin requires authentication");
        return -1;
    }
    if (status != kXR_ok) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin anonymous login failed");
        return -1;
    }

    return 0;
}

int
xrootd_cache_origin_open(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, u_char fhandle[XRD_FHANDLE_LEN])
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
        xrootd_cache_set_error(t, kXR_NoMemory, 0,
                               "cache origin open allocation failed");
        return -1;
    }

    ngx_memzero(buf, total);
    req = (ClientOpenRequest *) buf;
    req->streamid[1] = 2;
    req->requestid = htons(kXR_open);
    /* kXR_retstat requests an ASCII stat string appended after the fhandle so we
     * can learn the file size before committing to a full download */
    req->options = htons(kXR_open_read | kXR_retstat);
    req->dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(buf + sizeof(*req), t->clean_path, pathlen);

    if (xrootd_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin open write failed");
        return -1;
    }
    free(buf);

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   XROOTD_MAX_PATH + 256) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "cache origin open failed");
        free(body);
        return -1;
    }
    if (status == kXR_redirect) {
        free(body);
        xrootd_cache_set_error(t, kXR_Unsupported, 0,
                               "cache origin redirected open; direct data "
                               "server origin is required");
        return -1;
    }
    if (status != kXR_ok || dlen < sizeof(ServerOpenBody)) {
        free(body);
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin open returned invalid response");
        return -1;
    }

    ngx_memcpy(fhandle, ((ServerOpenBody *) body)->fhandle, XRD_FHANDLE_LEN);

    /*
     * If kXR_retstat was honored the stat string follows ServerOpenBody.
     * Format: "<id> <size> <flags> <modtime>" — we only need the size (field 2).
     * The body is always NUL-terminated by xrootd_cache_read_response, so
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

void
xrootd_cache_origin_close_file(xrootd_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN])
{
    ClientCloseRequest req;
    uint16_t           rsp_status;
    uint32_t           dlen;
    u_char            *body;
    xrootd_cache_fill_t dummy;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 2;
    req.requestid = htons(kXR_close);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.dlen = 0;

    (void) xrootd_cache_io_send(oc, &req, sizeof(req));

    ngx_memzero(&dummy, sizeof(dummy));
    dummy.result = NGX_OK;
    body = NULL;
    if (xrootd_cache_read_response(&dummy, oc, &rsp_status, &body, &dlen,
                                   4096) == 0) {
        free(body);
    }
}

int
xrootd_cache_origin_read_chunk(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    int outfd, uint64_t offset, size_t want, size_t *got)
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
    req.offset = (kXR_int64) htobe64(offset);
    req.rlen = htonl((kXR_int32) want);
    req.dlen = 0;

    if (xrootd_cache_io_send(oc, &req, sizeof(req)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin read write failed");
        return -1;
    }

    for (;;) {
        body = NULL;
        if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                       XROOTD_CACHE_FETCH_CHUNK) != 0) {
            return -1;
        }

        if (status == kXR_error) {
            xrootd_cache_set_origin_error(t, body, dlen,
                                          "cache origin read failed");
            free(body);
            return -1;
        }

        if (status != kXR_ok && status != kXR_oksofar) {
            free(body);
            xrootd_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin read returned invalid status");
            return -1;
        }

        if ((size_t) dlen > want || *got > want - (size_t) dlen) {
            free(body);
            xrootd_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin read returned too much data");
            return -1;
        }

        if (dlen > 0) {
            if (xrootd_cache_fd_write_all(outfd, body, dlen) != 0) {
                free(body);
                xrootd_cache_set_syserror(t, kXR_IOError,
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

#endif /* NGX_THREADS */
