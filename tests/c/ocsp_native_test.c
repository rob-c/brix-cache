/* Exercise public OCSP policy and staple ownership against signed HTTP replies. */
#include "auth/crypto/ocsp.h"
#include <openssl/pem.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

void *__real_ngx_alloc(size_t size, ngx_log_t *log);

/* WHAT: Fail only the staple allocation requested by this fixture's log.
 * WHY: Failed refresh must retain the previously owned response.
 * HOW: Other nginx allocations retain their real implementation. */
void *__wrap_ngx_alloc(size_t size, ngx_log_t *log)
{
    if (log != NULL && log->data != NULL) { return NULL; }
    return __real_ngx_alloc(size, log);
}

/* WHAT: Load an explicitly supplied fixture certificate, or omit it.
 * WHY: Missing identity and issuer have separate public policy paths.
 * HOW: Parse PEM through OpenSSL and keep ownership with the caller. */
static X509 *load_certificate(const char *path)
{
    if (strcmp(path, "-") == 0) { return NULL; }
    FILE *file = fopen(path, "r");
    assert(file != NULL);
    X509 *cert = PEM_read_X509(file, NULL, NULL, NULL);
    assert(fclose(file) == 0 && cert != NULL);
    return cert;
}

/* WHAT: Fetch and optionally replace a real DER staple.
 * WHY: Every response must be verified before publication or replacement.
 * HOW: Build the actual server configuration, repeat, emit and free its bytes. */
static void staple(ngx_log_t *log, X509 *leaf, X509 *issuer, char **argv)
{
    ngx_stream_brix_srv_conf_t conf = {0};
    conf.gsi_cert = leaf;
    if (strcmp(argv[7], "no-store") != 0) {
        conf.gsi_store = X509_STORE_new();
        assert(conf.gsi_store != NULL);
        if (issuer != NULL) {
            assert(X509_STORE_add_cert(conf.gsi_store, issuer) == 1);
        }
    }
    if (strcmp(argv[7], "allocation") == 0) {
        conf.ocsp.staple_data = malloc(3);
        assert(conf.ocsp.staple_data != NULL);
        memcpy(conf.ocsp.staple_data, "OLD", 3);
        conf.ocsp.staple_len = 3;
        log->data = &conf;
    }
    ngx_int_t status = NGX_ERROR;
    int repeats = atoi(argv[6]);
    assert(repeats > 0 && repeats <= 2);
    for (int i = 0; i < repeats; ++i) {
        status = brix_ocsp_staple_fetch(log, &conf);
    }
    printf("%ld\n", (long)status);
    if (conf.ocsp.staple_len != 0) {
        assert(fwrite(conf.ocsp.staple_data, 1, conf.ocsp.staple_len, stdout)
               == conf.ocsp.staple_len);
    }
    ngx_free(conf.ocsp.staple_data);
    X509_STORE_free(conf.gsi_store);
}

/* WHAT: Run one public OCSP operation with explicit certificates and policy.
 * WHY: The crypto, DNS, HTTP and resource ownership paths remain production.
 * HOW: Initialize nginx time, dispatch, and release both certificate references. */
int main(int argc, char **argv)
{
    assert(argc == 8);
    ngx_log_t log = {0};
    ngx_cycle_t cycle = {.log = &log};
    ngx_cycle = &cycle;
    ngx_time_init();
    X509 *leaf = load_certificate(argv[2]);
    X509 *issuer = load_certificate(argv[3]);
    if (strcmp(argv[1], "check") == 0) {
        printf("%d\n", brix_ocsp_check_cert(&log, NULL, leaf, issuer,
                                           atoi(argv[4]), atoi(argv[5])));
    } else {
        assert(strcmp(argv[1], "staple") == 0);
        staple(&log, leaf, issuer, argv);
    }
    X509_free(leaf);
    X509_free(issuer);
    return 0;
}
