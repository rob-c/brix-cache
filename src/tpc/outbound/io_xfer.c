/* File: tpc io_xfer — the blocking full-transfer byte loop, free of nginx
 * WHAT: brix_tpc_xfer_all() — loop until exactly `len` bytes have moved in one
 *       direction, over a raw blocking fd or an OpenSSL session.
 *
 * WHY:  see io_xfer.h.  The single copy of the EINTR / <=0 / INT_MAX rules is
 *       the point: TPC's wire framing reads a fixed-size ServerResponseHdr and
 *       then a length-prefixed body, so a loop that returns early on a partial
 *       transfer desynchronises the stream rather than failing it.
 *
 * HOW:  cursor + remaining, decremented by whatever the syscall reports moved.
 *       EINTR retries; every other short-circuit (<=0) is a hard failure, which
 *       covers peer close, RST and SSL errors alike — the caller has no useful
 *       recovery from a half-moved frame, so the distinction is not surfaced.
 *       The SSL branch clamps to INT_MAX because SSL_read/SSL_write take int. */
#include "io_xfer.h"

#include <errno.h>
#include <limits.h>
#include <sys/socket.h>

int
brix_tpc_xfer_all(SSL *ssl, int fd, void *buf, size_t len, int sending)
{
    unsigned char *cursor = buf;

    while (len > 0) {
        ssize_t moved;

        if (ssl != NULL) {
            int chunk = (int) (len > INT_MAX ? INT_MAX : len);
            int n = sending ? SSL_write(ssl, cursor, chunk)
                            : SSL_read(ssl, cursor, chunk);
            if (n <= 0) {
                return -1;
            }
            moved = n;
        } else {
            moved = sending ? send(fd, cursor, len, 0)
                            : recv(fd, cursor, len, 0);
            if (moved < 0 && errno == EINTR) {
                continue;
            }
            if (moved <= 0) {
                return -1;
            }
        }

        cursor += (size_t) moved;
        len -= (size_t) moved;
    }

    return 0;
}
