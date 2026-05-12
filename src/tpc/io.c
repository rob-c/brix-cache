#include "tpc_internal.h"

#if (NGX_THREADS)

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Low-level socket helpers                                              */
/* ------------------------------------------------------------------ */

int
tpc_send_all(int fd, const void *buf, size_t len)
{
    const u_char *cursor = buf;

    while (len > 0) {
        ssize_t bytes_sent;

        bytes_sent = send(fd, cursor, len, 0);
        if (bytes_sent < 0 && errno == EINTR) {
            continue;
        }
        if (bytes_sent <= 0) {
            return -1;
        }

        cursor += (size_t) bytes_sent;
        len -= (size_t) bytes_sent;
    }

    return 0;
}

static int
tpc_recv_exact(int fd, void *buf, size_t len)
{
    u_char *cursor = buf;

    while (len > 0) {
        ssize_t bytes_read;

        bytes_read = recv(fd, cursor, len, 0);
        if (bytes_read < 0 && errno == EINTR) {
            continue;
        }
        if (bytes_read <= 0) {
            return -1;
        }

        cursor += (size_t) bytes_read;
        len -= (size_t) bytes_read;
    }

    return 0;
}

/*
 * Read one complete XRootD response frame.
 * *body is malloc'd (caller must free); NULL when dlen==0.
 * Returns 0 on success, -1 on I/O or allocation error.
 */
int
tpc_recv_response(int fd, uint16_t *status, u_char **body, uint32_t *dlen)
{
    ServerResponseHdr hdr;
    u_char           *response_body;

    if (tpc_recv_exact(fd, &hdr, sizeof(hdr)) != 0) {
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

    if (tpc_recv_exact(fd, response_body, *dlen) != 0) {
        free(response_body);
        return -1;
    }

    response_body[*dlen] = '\0';
    *body = response_body;
    return 0;
}

#endif /* NGX_THREADS */
