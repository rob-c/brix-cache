#include "cache_internal.h"

#if (NGX_THREADS)

#include <errno.h>
#include <stdlib.h>

int
xrootd_cache_read_response(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, uint16_t *status, u_char **body,
    uint32_t *dlen, uint32_t max_body)
{
    ServerResponseHdr hdr;

    *body = NULL;
    *dlen = 0;

    if (xrootd_cache_io_recv_exact(oc, &hdr, sizeof(hdr)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin response read failed");
        return -1;
    }

    *status = ntohs(hdr.status);
    *dlen = (uint32_t) ntohl(hdr.dlen);

    if (*dlen > max_body) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin response body too large");
        return -1;
    }

    if (*dlen == 0) {
        return 0;
    }

    *body = malloc((size_t) *dlen + 1);
    if (*body == NULL) {
        xrootd_cache_set_error(t, kXR_NoMemory, 0,
                               "cache origin response allocation failed");
        return -1;
    }

    if (xrootd_cache_io_recv_exact(oc, *body, *dlen) != 0) {
        free(*body);
        *body = NULL;
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin response body read failed");
        return -1;
    }

    (*body)[*dlen] = '\0';
    return 0;
}

void
xrootd_cache_set_origin_error(xrootd_cache_fill_t *t, u_char *body,
    uint32_t dlen, const char *fallback)
{
    int  errcode;
    char msg[256];

    errcode = kXR_ServerError;

    if (body != NULL && dlen >= 4) {
        uint32_t ebe;
        size_t   mlen;

        ngx_memcpy(&ebe, body, sizeof(ebe));
        errcode = (int) ntohl(ebe);

        mlen = dlen - 4;
        if (mlen > sizeof(msg) - 1) {
            mlen = sizeof(msg) - 1;
        }
        if (mlen > 0) {
            ngx_memcpy(msg, body + 4, mlen);
            msg[mlen] = '\0';
            xrootd_cache_set_error(t, errcode, 0, msg);
            return;
        }
    }

    xrootd_cache_set_error(t, errcode, 0, fallback);
}

#endif /* NGX_THREADS */
