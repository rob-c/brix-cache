/* ---- File: tpc io — low-level socket helpers for native TPC data transfer ----
 *
 * WHAT: Three blocking I/O primitives used exclusively by the TPC thread-pool worker
 *       to read/write bytes between a remote XRootD origin and nginx's local file.
 *       All functions run inside NGX_THREADS detached workers — allocations use
 *       malloc/free (not ngx_palloc). No SSL wrapping; plain TCP sockets only.
 *
 * WHY: TPC transfers require the destination server to connect directly to the
 *      source XRootD endpoint and pull data over raw TCP. Unlike event-loop I/O
 *      which accumulates incrementally via callbacks, these helpers guarantee
 *      exact byte counts — partial sends/recv loop until complete. The recv_response
 *      function additionally parses XRootD ServerResponseHdr framing (status +
 *      payload length) and allocates the body for caller use.
 *
 * HOW: tpc_send_all iterates remaining bytes with send() loop, continues on EINTR,
 *      returns -1 on any other failure. tpc_recv_exact mirrors this pattern with
 *      recv(). tpc_recv_response reads fixed-size ServerResponseHdr first, then
 *      mallocs the payload body and calls tpc_recv_exact for the remainder.
 *      Caller must free the returned body pointer.
 *
 *      phase-57 §F5: when the pull upgraded to TLS (t->tls != NULL, set by
 *      tpc_start_tls after a kXR_gotoTLS), send/recv route through SSL_write/
 *      SSL_read instead of the raw fd. The SSL sits on a blocking fd in the
 *      thread-pool worker, so a single SSL_write/SSL_read completes or errors;
 *      <=0 is treated as a hard failure exactly like the plain recv()/send() path. */
#include "tpc_internal.h"


#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <openssl/ssl.h>

/* ------------------------------------------------------------------ */
/* WHAT: Send all bytes from buf over fd using send() loop — continues on EINTR, returns -1 on any other failure. Returns 0 on full write success. Caller: thread.c, bootstrap.c, source.c (wire I/O pipeline). */
/* Low-level socket helpers                                              */
/* ------------------------------------------------------------------ */

int
tpc_send_all(xrootd_tpc_pull_t *t, int fd, const void *buf, size_t len)
{
    const u_char *cursor = buf;
    SSL          *ssl = (t != NULL) ? (SSL *) t->tls : NULL;

    while (len > 0) {
        ssize_t bytes_sent;

        if (ssl != NULL) {
            int n = SSL_write(ssl, cursor, (int) (len > INT_MAX ? INT_MAX : len));
            if (n <= 0) {
                return -1;
            }
            bytes_sent = n;
        } else {
            bytes_sent = send(fd, cursor, len, 0);
            if (bytes_sent < 0 && errno == EINTR) {
                continue;
            }
            if (bytes_sent <= 0) {
                return -1;
            }
        }

        cursor += (size_t) bytes_sent;
        len -= (size_t) bytes_sent;
    }

    return 0;
}
/* WHAT: Receive exactly len bytes into buf over fd using recv() loop — continues on EINTR, returns -1 on any other failure. Returns 0 on full read success. Caller: tpc_recv_response (header + payload), thread.c (wire I/O pipeline). */

static int
tpc_recv_exact(xrootd_tpc_pull_t *t, int fd, void *buf, size_t len)
{
    u_char *cursor = buf;
    SSL    *ssl = (t != NULL) ? (SSL *) t->tls : NULL;

    while (len > 0) {
        ssize_t bytes_read;

        if (ssl != NULL) {
            int n = SSL_read(ssl, cursor, (int) (len > INT_MAX ? INT_MAX : len));
            if (n <= 0) {
                return -1;
            }
            bytes_read = n;
        } else {
            bytes_read = recv(fd, cursor, len, 0);
            if (bytes_read < 0 && errno == EINTR) {
                continue;
            }
            if (bytes_read <= 0) {
                return -1;
            }
        }

        cursor += (size_t) bytes_read;
        len -= (size_t) bytes_read;
    }

    return 0;
}

/* ---- Function: tpc_recv_response — read one complete XRootD response frame ----
 *
 * WHAT: Reads a full XRootD ServerResponseHdr (status code + payload length), then
 *       allocates and reads the payload body. Returns parsed status, malloc'd body,
 *       and payload length via output pointers. NULL body when dlen==0.
 *
 * WHY: TPC transfers require parsing wire protocol response frames before processing
 *      data — the header encodes whether the operation succeeded (kXR_ok) or failed
 *      with a specific kXR error code, plus how many bytes of payload follow. The
 *      malloc'd body lets callers handle variable-length responses without fixed buffers.
 *
 * HOW: Three-phase read → 1) tpc_recv_exact fetches sizeof(ServerResponseHdr) bytes,
 *      then ntohs/ntohl decode status and dlen from network byte order. 2) If dlen==0
 *      returns immediately with NULL body. 3) Validates dlen <= TPC_RESP_MAX_BODY,
 *      mallocs (dlen + 1) bytes for safety, calls tpc_recv_exact to read payload,
 *      null-terminates the buffer, sets output pointers, and returns 0 on success.
 *      Caller must free(*body) after use. Returns -1 on any I/O or allocation error. */
int
tpc_recv_response(xrootd_tpc_pull_t *t, int fd, uint16_t *status,
                  u_char **body, uint32_t *dlen)
{
    ServerResponseHdr hdr;
    u_char           *response_body;

    if (tpc_recv_exact(t, fd, &hdr, sizeof(hdr)) != 0) {
        return -1;
    }

    *status = ntohs(hdr.status);
    *dlen   = (uint32_t) ntohl(hdr.dlen);
    *body   = NULL;

    if (*dlen == 0) {
        return 0;
    }

    if (*dlen > TPC_RESP_MAX_BODY) {
        return -1;
    }

    response_body = malloc((size_t) (*dlen) + 1);
    if (response_body == NULL) {
        return -1;
    }

    if (tpc_recv_exact(t, fd, response_body, *dlen) != 0) {
        free(response_body);
        return -1;
    }

    response_body[*dlen] = '\0';
    *body = response_body;
    return 0;
}

