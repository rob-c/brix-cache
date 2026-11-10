/* GridFTP GSI state transitions with real credential/delegation cryptography.
 * TLS record exchange is observed at the SSL API boundary. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/gsiftp/gftp_gsi_internal.h"
#include "auth/gsi/proxy_req.h"
#include "native_alloc_fail.h"
#include <openssl/err.h>
#include <openssl/pem.h>

typedef struct {
    gftp_gsi_t *gsi;
    const char *mode;
    const unsigned char *application;
    size_t length, consumed;
    int writes, connects, issued;
} fixture;

/* WHAT: Recover test state. WHY: No production globals. HOW: Cycle context. */
static fixture *state(void) { return (fixture *) ngx_cycle->conf_ctx; }

/* WHAT: Select a failure. WHY: Keep cases independent. HOW: Fixture mode. */
static int mode(const char *name) { return !strcmp(state()->mode, name); }

/* WHAT: Supply TLS handshake outcomes. WHY: Exercise each GSI transition.
 * HOW: Real output BIO, selected SSL return status, no network dependency. */
int __wrap_SSL_connect(SSL *ssl)
{
    fixture *f = state(); assert(ssl == f->gsi->ssl); f->connects++;
    if (mode("want-read") || mode("want-write")) {
        assert(BIO_write(f->gsi->wbio, "token", 5) == 5); return -1;
    }
    return mode("handshake-error") ? -1 : 1;
}

/* WHAT: Supply the handshake disposition. WHY: WANT is not a terminal failure.
 * HOW: Match the explicitly selected SSL outcome. */
int __wrap_SSL_get_error(const SSL *ssl, int rc)
{
    assert(ssl == state()->gsi->ssl && rc == -1);
    if (mode("want-read")) { return SSL_ERROR_WANT_READ; }
    return mode("want-write") ? SSL_ERROR_WANT_WRITE : SSL_ERROR_SSL;
}

/* WHAT: Validate an issued proxy. WHY: State success must carry a real signature.
 * HOW: Decode DER and verify its issuer/signature against the loaded credential. */
static void issued_proxy(const void *data, int length)
{
    const unsigned char *cursor = data; X509 *cert = d2i_X509(NULL, &cursor, length);
    assert(cert && cursor == (const unsigned char *) data + length);
    assert(X509_verify(cert, state()->gsi->key) == 1);
    assert(X509_get_ext_by_NID(cert, NID_proxyCertInfo, -1) >= 0);
    X509_free(cert); state()->issued++;
}

/* WHAT: Observe protected commands/delegation. WHY: Do not accept a missing token.
 * HOW: Check marker or real certificate and leave a finite TLS record in wbio. */
int __wrap_SSL_write(SSL *ssl, const void *data, int length)
{
    fixture *f = state(); assert(ssl == f->gsi->ssl); f->writes++;
    if (mode("write-error") || (mode("issue-write-error") && length > 1)) { return -1; }
    if (length == 1) { assert(!memcmp(data, "D", 1)); }
    else if (length == 7) { assert(!memcmp(data, "command", 7)); }
    else { issued_proxy(data, length); }
    assert(BIO_write(f->gsi->wbio, "record", 6) == 6); return length;
}

/* WHAT: Supply protected application bytes. WHY: Exercise growth and empty input.
 * HOW: Copy caller-owned data in exactly the capacity requested by production. */
int __wrap_SSL_read(SSL *ssl, void *data, int capacity)
{
    fixture *f = state(); size_t take = f->length - f->consumed;
    assert(ssl == f->gsi->ssl && capacity > 0);
    if (take > (size_t) capacity) { take = (size_t) capacity; }
    if (!take) { return -1; }
    memcpy(data, f->application + f->consumed, take); f->consumed += take;
    return (int) take;
}

int __real_BIO_write(BIO *, const void *, int);
/* WHAT: Refuse input buffering. WHY: An unbuffered peer token cannot advance state.
 * HOW: Fail only the selected input BIO; credential BIO operations stay real. */
int __wrap_BIO_write(BIO *bio, const void *data, int length)
{
    if (mode("input-error") && state()->gsi && bio == state()->gsi->rbio) { return -1; }
    return __real_BIO_write(bio, data, length);
}

/* WHAT: Verify error diagnostics. WHY: Empty OpenSSL stacks still need a reason.
 * HOW: Run both the empty and populated error queue through the real formatter. */
static void diagnostic(gftp_session_t *session)
{
    ERR_clear_error();
    if (mode("openssl-detail")) { ERR_raise(ERR_LIB_SSL, SSL_R_BAD_DATA); }
    assert(gftp_ssl_error(session, "fixture action") == -1 && errno == EACCES);
    assert(strstr(session->error, "fixture action") && ERR_peek_error() == 0);
    if (!mode("openssl-detail")) { assert(strstr(session->error, "no OpenSSL detail")); }
}

/* WHAT: Drive one handshake. WHY: Fatal states cannot be reused.
 * HOW: Assert token ownership, failure stickiness and exact SSL call count. */
static void handshake(gftp_session_t *session, int expected)
{
    fixture *f = state(); uint8_t *out = NULL; size_t size = 0; int rc;
    if (mode("drain-allocation")) { native_alloc_arm("malloc", 0); }
    rc = gftp_gsi_step(f->gsi, (const uint8_t *) "peer", 4, &out, &size, session);
    native_alloc_disarm(); assert(rc == expected);
    if (rc > 0) { assert(out && size > 0); }
    else { assert(out == NULL && size == 0); }
    free(out);
    if (mode("handshake-error") || mode("write-error") || mode("input-error")) {
        assert(gftp_gsi_step(f->gsi, NULL, 0, &out, &size, session) == -1);
        assert(strstr(session->error, "context has failed"));
    }
}

/* WHAT: Exercise protected application I/O. WHY: Empty or failed payloads must fail.
 * HOW: Verify bytes after real allocation/growth and observe output record release. */
static void application(gftp_session_t *session, int expected, size_t length)
{
    fixture *f = state(); uint8_t *out = NULL; size_t size = 0; int rc;
    unsigned char *data = malloc(length ? length : 1); assert(data != NULL);
    memset(data, 'p', length); f->application = data; f->length = length;
    if (mode("payload-allocation")) { native_alloc_arm("malloc", 0); }
    if (mode("payload-growth")) { native_alloc_arm("realloc", 0); }
    if (mode("wrap") || mode("write-error") || mode("drain-allocation")) {
        if (mode("drain-allocation")) { native_alloc_arm("malloc", 0); }
        rc = gftp_gsi_wrap(f->gsi, "command", 7, &out, &size, session);
        if (!rc) { assert(size == 6 && !memcmp(out, "record", 6)); }
    } else {
        rc = gftp_gsi_unwrap(f->gsi, (const uint8_t *) "peer", 4, &out, &size, session);
        if (!rc) { assert(size == length && !memcmp(out, data, size)); }
    }
    native_alloc_disarm(); assert(rc == expected); free(out); free(data);
}

/* WHAT: Delegate a real proxy. WHY: A successful state needs valid cryptography.
 * HOW: Build the canonical request, pass it through the real signer and inspect DER. */
static void delegate(gftp_session_t *session, int expected)
{
    fixture *f = state(); EVP_PKEY *key = NULL; brix_gsi_buf_t request = {0};
    brix_gsi_blob_t parent = {f->gsi->pem, f->gsi->pem_len};
    uint8_t *out = NULL; size_t size = 0;
    assert(gftp_gsi_step(f->gsi, NULL, 0, &out, &size, session) == 1); free(out);
    assert(brix_gsi_build_pxyreq(&parent, &key, &request, NULL) == 0);
    f->application = request.data; f->length = request.len;
    if (mode("empty")) { f->length = 0; }
    if (mode("bad-request")) { request.data[0] ^= 0xff; }
    if (mode("payload-allocation")) { native_alloc_arm("malloc", 0); }
    assert(gftp_gsi_step(f->gsi, NULL, 0, &out, &size, session) == expected);
    native_alloc_disarm(); free(out);
    if (expected > 0) {
        assert(f->issued == 1);
        assert(gftp_gsi_step(f->gsi, NULL, 0, &out, &size, session) == 0);
        assert(out == NULL && size == 0);
        assert(gftp_gsi_step(f->gsi, NULL, 0, &out, &size, session) == 0);
    }
    EVP_PKEY_free(key); free(request.data);
}

/* WHAT: Run one bounded GSI contract. WHY: Isolate credentials and injected faults.
 * HOW: Real SSL context/key parsing with observed record-layer calls only. */
int main(int argc, char **argv)
{
    fixture f = {0}; ngx_cycle_t cycle = {0}; gftp_session_t session = {0};
    assert(argc == 7); f.mode = argv[2]; cycle.conf_ctx = (void ****) &f; ngx_cycle = &cycle;
    if (!strcmp(argv[1], "diagnostic")) { diagnostic(&session); return 0; }
    gftp_gsi_free(NULL);
    if (mode("context-allocation")) { native_alloc_arm("calloc", 0); }
    if (mode("chain-allocation")) { native_alloc_arm("malloc", 0); }
    f.gsi = gftp_gsi_create(argv[3], mode("default-ca") ? NULL : argv[4], &session);
    native_alloc_disarm();
    if (!strcmp(argv[1], "create")) {
        assert((f.gsi != NULL) == atoi(argv[5]));
        if (!f.gsi) { assert(session.error[0]); }
    } else {
        assert(f.gsi != NULL);
        if (!strcmp(argv[1], "handshake")) { handshake(&session, atoi(argv[5])); }
        else if (!strcmp(argv[1], "delegate")) { delegate(&session, atoi(argv[5])); }
        else { application(&session, atoi(argv[5]), (size_t) atoi(argv[6])); }
    }
    gftp_gsi_free(f.gsi);
    printf("connects=%d writes=%d issued=%d %s\n", f.connects, f.writes, f.issued, session.error);
    return 0;
}
