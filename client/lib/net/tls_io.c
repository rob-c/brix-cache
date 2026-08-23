/*
 * tls_io.c — TLS byte transfer for the native client.
 *
 * WHAT: The read/write half of the client's TLS support — brix_tls_read (fills
 *       exactly n, for root:// framing), brix_tls_read_some (one record, for the
 *       HTTP client) and brix_tls_write, plus the retry/deadline helpers they
 *       share.
 * WHY:  Split from tls.c when that file crossed the 600-line cap
 *       (coding-standards §1).  Session setup and byte transfer are separate
 *       concerns, and the slow-drip deadline logic is the part worth reading
 *       without the SSL_CTX plumbing around it.
 * HOW:  The fd is non-blocking, so every operation drives OpenSSL's
 *       WANT_READ/WANT_WRITE through brix_tls_wait_io() under one whole-operation
 *       deadline; a stalled peer trips the deadline rather than the idle timeout.
 *       Setup, teardown and introspection stay in tls.c; see tls_internal.h.
 */
#include "brix.h"
#include "tls_internal.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <poll.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Clamp the idle timeout to a whole-operation deadline; see read_wait_ms in
 * sock.c for the rationale (slow-drip guard). -1 = deadline passed. */
static int
tls_read_wait_ms(int timeout_ms, uint64_t deadline_ns)
{
    if (deadline_ns == 0) {
        return timeout_ms;
    }
    {
        uint64_t now = brix_mono_ns();
        int64_t  rem_ms;

        if (now >= deadline_ns) {
            return -1;
        }
        rem_ms = (int64_t) ((deadline_ns - now) / 1000000ULL);
        if (rem_ms <= 0) {
            return -1;
        }
        if (timeout_ms > 0 && (int64_t) timeout_ms < rem_ms) {
            return timeout_ms;
        }
        return (int) rem_ms;
    }
}

/*
 * WHAT: Wait for the socket readiness requested by a retryable TLS read.
 * WHY:  WANT_READ/WANT_WRITE must share one slow-drip deadline and diagnostics.
 * HOW:  Clamp poll time to the operation deadline and translate timeout/error.
 */
static int
tls_read_retry_wait(brix_io *io, int ssl_error, uint64_t deadline_ns,
    size_t got, size_t wanted, brix_status *status)
{
    short events = ssl_error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
    int   wait_ms = tls_read_wait_ms(io->timeout_ms, deadline_ns);
    int   ready;

    if (wait_ms < 0) {
        brix_status_set(status, XRDC_ESOCK, ETIMEDOUT,
                        "TLS read exceeded slow-drip deadline "
                        "(%d ms, got %zu/%zu bytes)",
                        io->stall_deadline_ms, got, wanted);
        return -1;
    }
    ready = brix_tls_wait_io(io->fd, events, wait_ms);
    if (ready == 0 && deadline_ns != 0 && brix_mono_ns() >= deadline_ns) {
        brix_status_set(status, XRDC_ESOCK, ETIMEDOUT,
                        "TLS read exceeded slow-drip deadline "
                        "(%d ms, got %zu/%zu bytes)",
                        io->stall_deadline_ms, got, wanted);
        return -1;
    }
    if (ready == 0) {
        brix_status_set(status, XRDC_ESOCK, ETIMEDOUT, "TLS read timed out");
        return -1;
    }
    if (ready < 0) {
        brix_status_set(status, XRDC_ESOCK, errno, "poll(tls read): %s",
                        strerror(errno));
        return -1;
    }
    return 0;
}

/*
 * WHAT: Translate a terminal SSL_read_ex failure into the client status model.
 * WHY:  Peer close, syscall failure, and TLS protocol errors need distinct reports.
 * HOW:  Map SSL error classes, preserving retryable errno only for the caller.
 */
static int
tls_read_failure(int ssl_error, size_t got, size_t wanted, brix_status *status)
{
    if (ssl_error == SSL_ERROR_ZERO_RETURN) {
        brix_status_set(status, XRDC_ESOCK, 0,
                        "TLS connection closed by peer (read %zu/%zu)",
                        got, wanted);
        return -1;
    }
    if (ssl_error == SSL_ERROR_SYSCALL) {
        if (errno == EINTR || errno == EAGAIN)
            return 1;
        brix_status_set(status, XRDC_ESOCK, errno, "TLS read: %s",
                        errno ? strerror(errno) : "unexpected EOF");
        return -1;
    }
    brix_tls_err(status, XRDC_ESOCK, "TLS read");
    return -1;
}

int
brix_tls_read(brix_io *io, void *buf, size_t n, brix_status *st)
{
    SSL     *ssl = (SSL *) io->ssl;
    uint8_t *p   = (uint8_t *) buf;
    size_t   got = 0;
    /* Shared absolute cutoff for the whole logical operation (armed once by
     * brix_io_stall_arm), so a multi-record TLS read shares one budget rather
     * than re-arming per record. 0 = disabled. */
    uint64_t deadline_ns = io->stall_deadline_ns;

    while (got < n) {
        size_t nread = 0;
        int    ok, err;

        if (brix_copy_quit_requested()) {   /* Phase 40 (a): prompt cancel */
            brix_status_set(st, XRDC_ESOCK, EINTR, "transfer cancelled (signal)");
            return -1;
        }
        ERR_clear_error();   /* so SSL_get_error reflects THIS op, not a stale queue */
        ok = SSL_read_ex(ssl, p + got, n - got, &nread);

        if (ok == 1) {
            got += nread;
            continue;
        }
        err = SSL_get_error(ssl, 0);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            if (tls_read_retry_wait(io, err, deadline_ns, got, n, st) != 0)
                return -1;
            continue;
        }
        if (tls_read_failure(err, got, n, st) < 0)
            return -1;
    }
    return 0;
}

int
brix_tls_write(brix_io *io, const void *buf, size_t n, brix_status *st)
{
    SSL           *ssl  = (SSL *) io->ssl;
    const uint8_t *p    = (const uint8_t *) buf;
    size_t         sent = 0;

    while (sent < n) {
        size_t nw = 0;
        int    ok, err;

        if (brix_copy_quit_requested()) {   /* Phase 40 (a): prompt cancel */
            brix_status_set(st, XRDC_ESOCK, EINTR, "transfer cancelled (signal)");
            return -1;
        }
        ERR_clear_error();
        ok = SSL_write_ex(ssl, p + sent, n - sent, &nw);

        if (ok == 1) {
            sent += nw;
            continue;
        }
        err = SSL_get_error(ssl, 0);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            short ev = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            int   pr = brix_tls_wait_io(io->fd, ev, io->timeout_ms);
            if (pr == 0) {
                brix_status_set(st, XRDC_ESOCK, ETIMEDOUT, "TLS write timed out");
                return -1;
            }
            if (pr < 0) {
                brix_status_set(st, XRDC_ESOCK, errno, "poll(tls write): %s",
                                strerror(errno));
                return -1;
            }
            continue;
        }
        if (err == SSL_ERROR_SYSCALL) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            brix_status_set(st, XRDC_ESOCK, errno, "TLS write: %s",
                            errno ? strerror(errno) : "unexpected EOF");
            return -1;
        }
        brix_tls_err(st, XRDC_ESOCK, "TLS write");
        return -1;
    }
    return 0;
}

/*
 * Read UP TO n bytes (one record) over TLS — unlike brix_tls_read (which fills
 * exactly n for root:// framing), this is a stream read for the HTTP client: sets
 * *got to the bytes read (0 = clean EOF / peer close) and returns 0, or -1 on error.
 */
int
brix_tls_read_some(brix_io *io, void *buf, size_t n, size_t *got, brix_status *st)
{
    SSL   *ssl = (SSL *) io->ssl;
    size_t nread = 0;

    *got = 0;
    for (;;) {
        int ok, err;
        ERR_clear_error();
        ok = SSL_read_ex(ssl, buf, n, &nread);
        if (ok == 1) {
            *got = nread;
            return 0;
        }
        err = SSL_get_error(ssl, 0);
        if (err == SSL_ERROR_ZERO_RETURN) {
            return 0;                    /* clean close → *got stays 0 (EOF) */
        }
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            short ev = (err == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            int   pr = brix_tls_wait_io(io->fd, ev, io->timeout_ms);
            if (pr <= 0) {
                brix_status_set(st, XRDC_ESOCK, pr == 0 ? ETIMEDOUT : errno,
                                "TLS read %s", pr == 0 ? "timed out" : "poll failed");
                return -1;
            }
            continue;
        }
        if (err == SSL_ERROR_SYSCALL && errno == 0) {
            return 0;                    /* unclean EOF — treat as end of body */
        }
        if (err == SSL_ERROR_SYSCALL && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        brix_tls_err(st, XRDC_ESOCK, "TLS read");
        return -1;
    }
}
