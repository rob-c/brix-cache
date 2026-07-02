#include "cache_internal.h"
#include "protocols/root/protocol/frame_hdr.h"   /* xrd_error_body_decode (shared kXR_error codec) */


#include <errno.h>
#include <stdlib.h>

/* xrootd_cache_read_response — read XRootD server response header + body
 * WHAT: Reads ServerResponseHdr (fixed-size wire header) via recv_exact, extracts status
 *       and dlen fields via ntohs/ntohl, validates dlen against max_body guard, allocates
 *       body buffer (dlen+1 for null termination), reads body payload, null-terminates.
 *       Returns 0 on success with status/dlen/body populated, -1 on any error.
 *
 * WHY: Every XRootD request/response cycle requires parsing the fixed-size response header
 *      before reading the variable-length data body. max_body prevents oversized responses
 *      from exhausting thread-pool memory (malloc on each call). The +1 byte for null
 *      termination enables string operations on error messages and stat strings.
 *      All wire fields are big-endian — ntohs/ntohl convert to host byte order. */

/* xrootd_cache_set_origin_error — extract origin error code + message, fallback
 * WHAT: Parses the first 4 bytes of body as big-endian kXR error code, extracts remaining
 *       bytes as error message string (capped at 256 chars), calls set_error with extracted
 *       values. If body is NULL or too short (< 4 bytes): falls back to generic fallback msg.
 *
 * WHY: XRootD error responses embed a kXR error code in the first 4 bytes followed by a
 *      human-readable message string. This function preserves the origin's exact error code
 *      (e.g., kXR_NotFound, kXR_NotAuthorized) rather than collapsing everything to
 *      ServerError — clients need precise codes for retry/redirect decisions. The fallback
 *      handles malformed responses where body is missing or truncated. */
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
    int          errcode = kXR_ServerError;
    const char  *wmsg;
    size_t       wlen;
    char         msg[256];

    /* [int32 BE errnum][message] — decode bounds the (non-NUL) message slice. */
    if (xrd_error_body_decode(body, dlen, &errcode, &wmsg, &wlen) == 0
        && wlen > 0) {
        if (wlen > sizeof(msg) - 1) {
            wlen = sizeof(msg) - 1;
        }
        ngx_memcpy(msg, wmsg, wlen);
        msg[wlen] = '\0';
        xrootd_cache_set_error(t, errcode, 0, msg);
        return;
    }

    xrootd_cache_set_error(t, errcode, 0, fallback);
}

