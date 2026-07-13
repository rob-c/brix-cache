/* test_sd_remote_wrongkind.c — unit test for the Phase-3 review defense-in-
 * depth fix: sd_remote_open_cred (src/fs/backend/remote/sd_remote.c) must
 * REFUSE (EACCES) a wrong-kind credential under fallback_deny instead of
 * silently signing the request with the export's static service credential.
 *
 * sd_remote (S3) can present ONLY an S3 access-key/secret-key pair at the
 * origin. A brix_sd_cred_t whose selected kind is x509 or bearer (the VFS
 * gate resolved a `<key>.pem` or `<key>.token` file, but this export is
 * S3-backed) carries cred->s3_ak == NULL / cred->s3_sk == NULL. Before the
 * fix, sd_remote_open_cred treated that exactly like a NULL cred and fell
 * through to sd_remote_open_impl(..., NULL, NULL, NULL, ...) — i.e. it
 * signed the request with the instance's static access_key/secret_key,
 * even when the operator set fallback_deny=1 to forbid exactly that.
 *
 * This test builds a real brix_sd_instance_t via brix_sd_remote_create (no
 * network I/O — pure config copy) with an injected transport whose
 * request() callback calls abort() if ever invoked, proving the refusal
 * path never reaches the wire. It then calls driver->open_cred directly
 * with (a) a wrong-kind cred + fallback_deny=1 (must refuse, EACCES,
 * transport untouched) and (b) the same wrong-kind cred with
 * fallback_deny=0 (must fall back to the service credential and proceed
 * to the transport — proving the deny flag, not the wrong kind alone,
 * drives the refusal). Run via tests/c/run_sd_remote_wrongkind_tests.sh.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/remote/sd_remote.h"
#include "core/compat/crypto.h"   /* brix_crypto_init: HMAC/SHA256 EVP fetch,
                                    * normally done by nginx worker init; the
                                    * SigV4 sign path (sd_s3_sign) needs it
                                    * even on the allow-mode control path
                                    * below, which reaches a real HEAD sign
                                    * before the stub transport is called. */

static int g_transport_called = 0;

/* Fires only on the fallback_deny=0 path (proceeds to sd_remote_open_impl),
 * where it is expected to run and return a transport-level failure — the
 * test only cares that it WAS reached, not that the object opens cleanly. */
static int
stub_request(void *tctx, const char *host, int port, int tls,
    const char *method, const char *path_and_query, const char *headers,
    const void *body, size_t body_len, int timeout_ms,
    brix_s3_resp_t *resp, char *errbuf, size_t errcap)
{
    (void) tctx; (void) host; (void) port; (void) tls; (void) method;
    (void) path_and_query; (void) headers; (void) body; (void) body_len;
    (void) timeout_ms; (void) resp;

    g_transport_called++;
    snprintf(errbuf, errcap, "stub: refused (test double, no real network)");
    return -1;
}

static int
stub_resp_header(const brix_s3_resp_t *resp, const char *name, char *out,
    size_t outcap)
{
    (void) resp; (void) name; (void) out; (void) outcap;
    return -1;
}

static const void *
stub_resp_body(const brix_s3_resp_t *resp, size_t *len)
{
    (void) resp;
    if (len) { *len = 0; }
    return NULL;
}

static void
stub_resp_free(brix_s3_resp_t *resp)
{
    (void) resp;
}

static const brix_s3_transport_t g_stub_transport = {
    .request     = stub_request,
    .resp_header = stub_resp_header,
    .resp_body   = stub_resp_body,
    .resp_free   = stub_resp_free,
};

static brix_sd_instance_t *
build_instance(void)
{
    brix_sd_remote_cfg_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.scheme = BRIX_SD_REMOTE_S3;
    snprintf(cfg.host, sizeof(cfg.host), "127.0.0.1");
    cfg.port = 9999;
    cfg.tls  = 0;
    snprintf(cfg.bucket, sizeof(cfg.bucket), "test-bucket");
    snprintf(cfg.access_key, sizeof(cfg.access_key), "SERVICE-AK-STATIC");
    snprintf(cfg.secret_key, sizeof(cfg.secret_key), "SERVICE-SK-STATIC");
    snprintf(cfg.region, sizeof(cfg.region), "us-east-1");
    cfg.timeout_ms = 2000;
    cfg.transport  = &g_stub_transport;
    cfg.tctx       = NULL;

    return brix_sd_remote_create(&cfg, NULL);
}

/* Test 1: wrong-kind cred (x509-shaped: no s3_ak/s3_sk) + fallback_deny=1
 * must be refused with EACCES, WITHOUT ever calling the transport (no
 * silent open on the service credential). */
static void
test_wrongkind_deny_refused(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_cred_t        cred;
    brix_sd_obj_t       *obj;
    int                    err = 0;

    assert(inst != NULL);
    assert(inst->driver->open_cred != NULL);

    memset(&cred, 0, sizeof(cred));
    cred.x509_proxy    = "/some/path/user.pem";  /* the VFS gate normally sets
                                                    * this from a resolved
                                                    * ucred, but the KIND that
                                                    * matters to sd_remote is
                                                    * s3_ak/s3_sk, which stay
                                                    * NULL below — sd_remote
                                                    * cannot use an x509 proxy
                                                    * at all. */
    cred.s3_ak          = NULL;
    cred.s3_sk          = NULL;
    cred.principal      = "Test User C";
    cred.fallback_deny  = 1;

    g_transport_called = 0;
    errno = 0;
    obj = inst->driver->open_cred(inst, "/probe.bin", BRIX_SD_O_READ, 0,
                                    &cred, &err);

    assert(obj == NULL);
    assert(err == EACCES);
    assert(g_transport_called == 0);   /* proves: refused before any wire I/O,
                                         * i.e. never signed with the static
                                         * service access_key/secret_key. */

    printf("  ok   1: wrong-kind cred (no s3_ak/s3_sk) + fallback_deny=1 -> "
           "refused EACCES, transport never invoked (no silent service-cred "
           "open)\n");

    brix_sd_remote_destroy(inst);
}

/* Test 2: control — the SAME wrong-kind cred with fallback_deny=0 must fall
 * back to the service credential and DOES reach the transport (proves the
 * deny flag, not the missing kind by itself, is what drives the refusal —
 * i.e. allow-mode behaviour is unchanged by this fix). */
static void
test_wrongkind_allow_falls_back(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_cred_t        cred;
    brix_sd_obj_t       *obj;
    int                    err = 0;

    assert(inst != NULL);

    memset(&cred, 0, sizeof(cred));
    cred.x509_proxy    = "/some/path/user.pem";
    cred.s3_ak          = NULL;
    cred.s3_sk          = NULL;
    cred.principal      = "Test User C";
    cred.fallback_deny  = 0;               /* allow mode */

    g_transport_called = 0;
    errno = 0;
    obj = inst->driver->open_cred(inst, "/probe.bin", BRIX_SD_O_READ, 0,
                                    &cred, &err);

    /* The stub transport always fails the request, so open still returns
     * NULL/EIO-ish — but the transport MUST have been reached (it wasn't
     * refused pre-flight), proving allow-mode still falls back as before. */
    (void) obj;
    assert(g_transport_called > 0);
    assert(err != EACCES);

    printf("  ok   2: wrong-kind cred + fallback_deny=0 (allow) -> falls "
           "back to service credential, transport invoked (unchanged "
           "allow-mode behaviour)\n");

    brix_sd_remote_destroy(inst);
}

/* Test 3: a NULL cred is untouched by this fix (existing plain-open path). */
static void
test_null_cred_unaffected(void)
{
    brix_sd_instance_t *inst = build_instance();
    brix_sd_obj_t       *obj;
    int                    err = 0;

    assert(inst != NULL);

    g_transport_called = 0;
    errno = 0;
    obj = inst->driver->open_cred(inst, "/probe.bin", BRIX_SD_O_READ, 0,
                                    NULL, &err);
    (void) obj;
    assert(g_transport_called > 0);
    assert(err != EACCES);

    printf("  ok   3: NULL cred -> unchanged (service credential, transport "
           "invoked)\n");

    brix_sd_remote_destroy(inst);
}

int
main(void)
{
    assert(brix_crypto_init());   /* HMAC/SHA256 EVP fetch — required before any
                                    * sd_s3_sign call (allow-mode control path). */
    test_wrongkind_deny_refused();
    test_wrongkind_allow_falls_back();
    test_null_cred_unaffected();
    printf("test_sd_remote_wrongkind: ALL PASS\n");
    return 0;
}
