/* Exercise real async framing and queues with finite socket/TLS failure boundaries. */
#include "core/aio/aio_internal.h"
#include <assert.h>
#include <sys/socket.h>

typedef struct {
    brix_loop loop;
    brix_aconn ac;
    const char *fault;
    unsigned calls, errors, callbacks, arms;
    int peer, ssl_error, result;
    brix_status error;
    uint8_t received[256], landing[258];
    uint32_t length;
    uint64_t now;
} fixture;

/* WHAT: Retrieve per-process state. WHY: Faults must not require production hooks.
 * HOW: Decode the pointer installed by this driver's main. */
static fixture *state(void)
{
    void *p = NULL; const char *value = getenv("BRIX_AIO_TRANSPORT_FIXTURE");
    if (value != NULL) { assert(sscanf(value, "%p", &p) == 1); }
    return p;
}

/* WHAT: Select a finite fault. WHY: Unrelated runtime calls remain real.
 * HOW: Compare the active operation label. */
static int fault(const char *name)
{
    fixture *f = state(); return f && f->fault && !strcmp(f->fault, name);
}

ssize_t __real_send(int, const void *, size_t, int);
ssize_t __real_read(int, void *, size_t);
void *__real_realloc(void *, size_t);

/* WHAT: Interrupt, block or refuse a queued write. WHY: Queue offsets own unsent bytes.
 * HOW: Inject one bounded boundary before falling through to the real socket. */
ssize_t __wrap_send(int fd, const void *data, size_t length, int flags)
{
    fixture *f = state();
    if (f == NULL || fd != f->ac.fd) { return __real_send(fd, data, length, flags); }
    unsigned call = f->calls++;
    if (fault("interrupt") && call == 0) { errno = EINTR; return -1; }
    if (fault("blocked") && call == 1) { errno = EAGAIN; return -1; }
    if (fault("fatal")) { errno = EPIPE; return -1; }
    if (fault("blocked") && length > 3) { length = 3; }
    return __real_send(fd, data, length, flags);
}

/* WHAT: Inject read interruption or refusal. WHY: Partial frames must remain owned.
 * HOW: Fault only the fixture fd, preserving actual socket bytes otherwise. */
ssize_t __wrap_read(int fd, void *data, size_t length)
{
    fixture *f = state();
    if (f == NULL || fd != f->ac.fd) { return __real_read(fd, data, length); }
    unsigned call = f->calls++;
    if (fault("interrupt") && call == 0) { errno = EINTR; return -1; }
    if (fault("fatal")) { errno = ECONNRESET; return -1; }
    return __real_read(fd, data, length);
}

/* WHAT: Refuse buffer growth. WHY: Allocation failure must stop byte consumption.
 * HOW: Arm the allocator only after all request bookkeeping is initialized. */
void *__wrap_realloc(void *pointer, size_t length)
{
    if (fault("allocation")) { return NULL; }
    return __real_realloc(pointer, length);
}

/* WHAT: Model an OpenSSL write boundary. WHY: WANT_READ differs from WANT_WRITE.
 * HOW: Keep byte movement real and use an explicit finite SSL error otherwise. */
int __wrap_SSL_write(SSL *ssl, const void *data, int length)
{
    fixture *f = state(); assert(ssl == (SSL *) f);
    if (f->ssl_error) { return -1; }
    return (int) __wrap_send(f->ac.fd, data, (size_t) length, MSG_NOSIGNAL);
}

/* WHAT: Model an OpenSSL read boundary. WHY: Buffered replies precede terminal EOF.
 * HOW: Read real socket bytes or return the configured OpenSSL status. */
int __wrap_SSL_read(SSL *ssl, void *data, int length)
{
    fixture *f = state(); assert(ssl == (SSL *) f);
    if (f->ssl_error) { return -1; }
    int rc = (int) __wrap_read(f->ac.fd, data, (size_t) length);
    if (rc < 0) { f->ssl_error = SSL_ERROR_WANT_READ; }
    return rc;
}

/* WHAT: Decode the selected TLS result. WHY: The production branch owns the policy.
 * HOW: Return the finite boundary error without interpreting it in the fixture. */
int __wrap_SSL_get_error(const SSL *ssl, int result)
{
    assert(ssl == (SSL *) state() && result < 0); return state()->ssl_error;
}

/* WHAT: Observe a terminal transport refusal. WHY: Assert the first precise error.
 * HOW: Mark the connection dead while retaining requests for explicit test cleanup. */
void __wrap_aconn_on_transport_error(brix_aconn *ac, const brix_status *status)
{
    fixture *f = state(); assert(ac == &f->ac && ++f->errors == 1);
    f->error = *status; ac->dead = 1; ac->state = ACONN_DEAD;
}

/* WHAT: Observe poll rearming. WHY: A successful I/O dispatch must retain readiness.
 * HOW: Validate both owners and count the registration request. */
int __wrap_io_engine_arm(brix_loop *loop, brix_aconn *ac, int events)
{
    fixture *f = state(); assert(loop == &f->loop && ac == &f->ac);
    assert(events & EPOLLIN); f->arms++; return 0;
}

/* WHAT: Supply a stable clock. WHY: RTT bounds must be independently predictable.
 * HOW: Return the fixture's explicit nanosecond value. */
uint64_t __wrap_brix_mono_ns(void) { return state()->now; }

/* WHAT: Inspect a completed response. WHY: Callback count, bytes and ownership matter.
 * HOW: Copy the bounded result and free only an allocated response body. */
static void completed(void *context, int rc, uint16_t status, uint8_t *body,
                      uint32_t length, const brix_status *error)
{
    fixture *f = context; assert(++f->callbacks == 1 && length <= sizeof(f->received));
    f->result = rc; f->length = length;
    if (rc == 0) {
        assert(status == kXR_ok && error == NULL);
        memcpy(f->received, body, length);
        if (body != f->landing + 1) { free(body); }
    } else { assert(error != NULL && body == NULL); f->error = *error; }
}

/* WHAT: Install a real request map entry. WHY: Parser dispatch must use stream identity.
 * HOW: Allocate the production request and optionally give it a guarded landing buffer. */
static void request_start(fixture *f, int direct)
{
    brix_areq *r = calloc(1, sizeof(*r)); assert(r);
    r->sid = 7; r->cb = completed; r->ctx = f; r->submit_ns = f->now - 1000000;
    if (direct) { r->dst = f->landing + 1; r->dst_cap = 256; }
    assert(reqmap_put(&f->ac.inflight, r) == 0);
}

/* WHAT: Encode a response for the real parser. WHY: Tests exercise actual wire bytes.
 * HOW: Use the repository's authoritative response-header codec. */
static size_t response(uint8_t *wire, uint16_t status, uint32_t length)
{
    xrd_put_u16_be(wire, 7); xrd_put_u16_be(wire + 2, status);
    xrd_put_u32_be(wire + 4, length);
    for (uint32_t i = 0; i < length; i++) { wire[8 + i] = (uint8_t) (i ^ 0xa5); }
    return 8 + length;
}

/* WHAT: Check queued writes. WHY: Retry boundaries must neither drop nor repeat bytes.
 * HOW: Inspect retained offsets, resume, and compare the peer's exact payload. */
static void check_write(fixture *f, const char *mode, int tls)
{
    static const uint8_t payload[] = "finite write ownership";
    assert(xbuf_append(&f->ac.wbuf, payload, sizeof(payload)) == 0);
    f->fault = mode;
    if (tls) { f->ac.ssl = (SSL *) f; }
    if (!strcmp(mode, "want-read")) { f->ssl_error = SSL_ERROR_WANT_READ; }
    if (!strcmp(mode, "want-write")) { f->ssl_error = SSL_ERROR_WANT_WRITE; }
    if (tls && !strcmp(mode, "fatal")) { f->ssl_error = SSL_ERROR_SSL; }
    aconn_do_write(&f->ac);
    if (!strcmp(mode, "fatal")) {
        assert(f->errors == 1 && f->error.kxr == XRDC_ESOCK);
        assert(f->ac.wbuf.start == 0 && f->ac.wbuf.len == sizeof(payload)); return;
    }
    if (f->ssl_error) {
        assert(f->ac.wbuf.start == 0 && f->ac.wbuf.len == sizeof(payload));
        assert(f->ac.tls_want_read_on_write == (f->ssl_error == SSL_ERROR_WANT_READ));
    }
    if (!strcmp(mode, "blocked")) { assert(f->ac.wbuf.start == 3); }
    f->ssl_error = 0; f->fault = NULL; aconn_do_write(&f->ac);
    assert(f->errors == 0 && f->ac.wbuf.start == 0 && f->ac.wbuf.len == 0);
    uint8_t received[sizeof(payload)];
    assert(recv(f->peer, received, sizeof(received), MSG_WAITALL) == sizeof(received));
    assert(!memcmp(received, payload, sizeof(payload)));
}

/* WHAT: Exercise fragmented replies. WHY: Stream boundaries do not equal frame boundaries.
 * HOW: Split the header/body, then require one callback and untouched canaries. */
static void check_fragment(fixture *f, unsigned split, int direct)
{
    uint8_t wire[264]; size_t length = response(wire, kXR_ok, 256);
    request_start(f, direct);
    assert(send(f->peer, wire, split, 0) == (ssize_t) split);
    aconn_handle_io(&f->ac, EPOLLIN);
    assert(f->callbacks == 0 && !f->ac.dead && f->arms == 1);
    assert(send(f->peer, wire + split, length - split, 0) == (ssize_t) (length - split));
    aconn_handle_io(&f->ac, EPOLLIN);
    assert(f->callbacks == 1 && f->result == 0 && f->length == 256);
    assert(!memcmp(f->received, wire + 8, 256) && f->ac.inflight.count == 0);
    assert(f->landing[0] == 0xcc && f->landing[257] == 0xcc);
}

/* WHAT: Exercise read failures and TLS retry direction. WHY: Refusal must preserve bounds.
 * HOW: Feed a finite reply or invalid length and inspect transport/callback outcomes. */
static void prepare_read(fixture *f, const char *mode, int tls, uint8_t wire[24])
{
    size_t length = response(wire, kXR_ok, 16);
    request_start(f, 0); f->fault = mode;
    if (tls) { f->ac.ssl = (SSL *) f; }
    if (!strcmp(mode, "want-read")) { f->ssl_error = SSL_ERROR_WANT_READ; }
    if (!strcmp(mode, "want-write")) { f->ssl_error = SSL_ERROR_WANT_WRITE; }
    if (!strcmp(mode, "tls-eof")) { f->ssl_error = SSL_ERROR_ZERO_RETURN; }
    if (tls && !strcmp(mode, "fatal")) { f->ssl_error = SSL_ERROR_SSL; }
    if (!strcmp(mode, "oversize")) { xrd_put_u32_be(wire + 4, XRDC_DLEN_MAX + 1); }
    if (!strcmp(mode, "tls-eof")) {
        assert(xbuf_append(&f->ac.rbuf, wire, length) == 0);
    } else { assert(send(f->peer, wire, length, 0) == (ssize_t) length); }
    if (!strcmp(mode, "eof")) { assert(shutdown(f->peer, SHUT_WR) == 0); }
}

/* WHAT: Inspect read outcomes. WHY: Retry, refusal and EOF have distinct ownership.
 * HOW: Resume TLS retries and compare exact callback bytes or retained requests. */
static void check_read(fixture *f, const char *mode, int tls)
{
    uint8_t wire[24]; prepare_read(f, mode, tls, wire);
    aconn_do_read(&f->ac);
    if (!strcmp(mode, "want-read") || !strcmp(mode, "want-write")) {
        assert(f->errors == 0 && f->callbacks == 0);
        assert(f->ac.tls_want_write_on_read == (f->ssl_error == SSL_ERROR_WANT_WRITE));
        f->ssl_error = 0; f->fault = NULL; aconn_do_read(&f->ac);
    }
    if (!strcmp(mode, "allocation") || !strcmp(mode, "fatal") || !strcmp(mode, "oversize")) {
        assert(f->errors == 1 && f->callbacks == 0 && f->ac.inflight.count == 1); return;
    }
    assert(f->callbacks == 1 && f->length == 16 && !memcmp(f->received, wire + 8, 16));
    assert(f->errors == (unsigned) (!strcmp(mode, "eof") || !strcmp(mode, "tls-eof")));
}

/* WHAT: Refuse a direct reply that exceeds caller capacity. WHY: Untrusted lengths fail closed.
 * HOW: Keep the entire guarded destination unchanged and retain the owned request. */
static void check_overflow(fixture *f)
{
    uint8_t header[8]; xrd_put_u16_be(header, 7); xrd_put_u16_be(header + 2, kXR_ok);
    xrd_put_u32_be(header + 4, 257); request_start(f, 1);
    assert(xbuf_append(&f->ac.rbuf, header, sizeof(header)) == 0);
    aconn_parse(&f->ac);
    assert(f->errors == 1 && f->error.kxr == XRDC_EPROTO && f->callbacks == 0);
    for (unsigned i = 0; i < sizeof(f->landing); i++) { assert(f->landing[i] == 0xcc); }
}

/* WHAT: Check RTT adaptation limits. WHY: Timer arithmetic must preserve bounded delays.
 * HOW: Supply known sample times and compare exact estimator results. */
static void check_rtt(fixture *f)
{
    brix_areq request = {0}; assert(aconn_rto_ns(&f->ac) == 1000000000ULL);
    aconn_note_rtt(&f->ac, &request); assert(!f->ac.have_rtt);
    request.submit_ns = f->now; aconn_note_rtt(&f->ac, &request); assert(!f->ac.have_rtt);
    request.submit_ns = f->now - 1000000; aconn_note_rtt(&f->ac, &request);
    assert(f->ac.srtt_ns == 1000000 && f->ac.rttvar_ns == 500000);
    assert(aconn_rto_ns(&f->ac) == 200000000);
    request.submit_ns = f->now - 3000000; aconn_note_rtt(&f->ac, &request);
    assert(f->ac.srtt_ns == 1250000 && f->ac.rttvar_ns == 875000);
    f->ac.srtt_ns = 40000000000ULL; assert(aconn_rto_ns(&f->ac) == 30000000000ULL);
}

/* WHAT: Reject incomplete accumulation. WHY: Memory pressure must never truncate a success.
 * HOW: Fail the first or a later append, then check exactly one failure and ignore late data. */
static void check_accumulation(fixture *f, const char *mode)
{
    uint8_t body[16]; memset(body, 0x5a, sizeof(body));
    int direct = !strcmp(mode, "landing-overflow"); request_start(f, direct);
    if (!strcmp(mode, "growth")) {
        aconn_dispatch_frame(&f->ac, 7, kXR_oksofar, body, 4);
        assert(f->callbacks == 0 && f->ac.inflight.count == 1);
    }
    uint16_t status = !strcmp(mode, "continuation") ? kXR_oksofar : kXR_ok;
    if (direct) {
        reqmap_get(&f->ac.inflight, 7)->dst_cap = 8; status = kXR_redirect;
    } else { f->fault = "allocation"; }
    aconn_dispatch_frame(&f->ac, 7, status, body, sizeof(body));
    assert(f->callbacks == 1 && f->result == -1 && f->error.kxr == XRDC_EPROTO);
    assert(f->length == 0 && f->ac.inflight.count == 0 && !f->ac.dead);
    f->fault = NULL; aconn_dispatch_frame(&f->ac, 7, kXR_ok, body, sizeof(body));
    assert(f->callbacks == 1);
    for (unsigned i = 0; i < sizeof(f->landing); i++) { assert(f->landing[i] == 0xcc); }
}

/* WHAT: Run one async transport contract. WHY: Each fault requires isolated ownership.
 * HOW: Use a nonblocking socket pair, execute the selected path and release all buffers. */
int main(int argc, char **argv)
{
    assert(argc == 4); fixture f = {0}; char pointer[64]; int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
    f.ac.fd = pair[0]; f.peer = pair[1]; f.ac.loop = &f.loop; f.ac.state = ACONN_ALIVE;
    f.ac.uring_slot = -1; f.now = 100000000000ULL; memset(f.landing, 0xcc, sizeof(f.landing));
    snprintf(pointer, sizeof(pointer), "%p", (void *) &f);
    assert(setenv("BRIX_AIO_TRANSPORT_FIXTURE", pointer, 1) == 0);
    if (!strcmp(argv[1], "write")) { check_write(&f, argv[2], atoi(argv[3])); }
    else if (!strcmp(argv[1], "read")) { check_read(&f, argv[2], atoi(argv[3])); }
    else if (!strcmp(argv[1], "fragment")) { check_fragment(&f, (unsigned) atoi(argv[2]), atoi(argv[3])); }
    else if (!strcmp(argv[1], "overflow")) { check_overflow(&f); }
    else if (!strcmp(argv[1], "accumulation")) { check_accumulation(&f, argv[2]); }
    else { assert(!strcmp(argv[1], "rtt")); check_rtt(&f); }
    f.fault = NULL; brix_areq *request = reqmap_get(&f.ac.inflight, 7);
    areq_free(request); free(f.ac.inflight.slots); xbuf_free(&f.ac.rbuf); xbuf_free(&f.ac.wbuf);
    assert(close(pair[0]) == 0 && close(pair[1]) == 0);
    assert(unsetenv("BRIX_AIO_TRANSPORT_FIXTURE") == 0);
    puts("async transport verified"); return 0;
}
