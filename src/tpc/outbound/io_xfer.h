/* File: tpc io_xfer — the blocking full-transfer byte loop, free of nginx
 * WHAT: One primitive, brix_tpc_xfer_all(), that moves exactly `len` bytes in
 *       one direction over either a raw blocking fd or an OpenSSL session.
 *
 * WHY:  tpc_send_all() and tpc_recv_exact() in io.c were byte-for-byte the same
 *       loop with send/recv and SSL_write/SSL_read swapped — 25 duplicated
 *       lines carrying the EINTR rule, the <=0 rule and the INT_MAX clamp in
 *       two places, so a fix to one silently left the other wrong.  Extracting
 *       it also lifts it out of nginx's include graph: this header needs only
 *       OpenSSL and libc, so the loop can be compiled and driven over a
 *       socketpair by a standalone unit test (io_xfer_unittest.c) instead of
 *       being reachable only through a live TPC pull.
 *
 * HOW:  the caller passes the already-resolved SSL* (NULL for cleartext), so
 *       this TU never sees brix_tpc_pull_t.  Direction is a flag rather than a
 *       function pointer: send() takes a const buffer and recv() does not, and
 *       one branch inside the loop is cheaper to read than two shims. */
#ifndef BRIX_TPC_IO_XFER_H_INCLUDED
#define BRIX_TPC_IO_XFER_H_INCLUDED

#include <stddef.h>
#include <openssl/ssl.h>

#define BRIX_TPC_XFER_RECV  0
#define BRIX_TPC_XFER_SEND  1

/* Move exactly len bytes in the given direction. Returns 0 when every byte
 * moved, -1 on peer close, short-circuit error, or any errno other than EINTR.
 * A zero-length transfer is a no-op success and touches neither fd nor ssl. */
int brix_tpc_xfer_all(SSL *ssl, int fd, void *buf, size_t len, int sending);

#endif /* BRIX_TPC_IO_XFER_H_INCLUDED */
