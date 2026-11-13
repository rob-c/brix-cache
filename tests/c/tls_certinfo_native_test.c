/* Real X509 metadata parsing behind the TLS peer-certificate ownership seam. */
#include "brix.h"
#include <assert.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>

typedef struct { brix_conn connection; X509 *cert; } fixture;

X509 *__wrap_SSL_get1_peer_certificate(const SSL *ssl)
{
    X509 *cert = ((const fixture *) ssl)->cert;
    if (cert) { assert(X509_up_ref(cert) == 1); }
    return cert;
}

int main(int argc, char **argv)
{
    assert(argc == 4);
    fixture f = {0}; brix_cert_info info;
    X509 *cert = NULL;
    if (strcmp(argv[1], "-") != 0) {
        FILE *input = fopen(argv[1], "r"); assert(input);
        cert = PEM_read_X509(input, NULL, NULL, NULL);
        assert(cert && fclose(input) == 0);
    }
    f.connection.io.ssl = strcmp(argv[3], "cleartext") ? (void *) &f : NULL;
    f.cert = cert;
    snprintf(f.connection.host, sizeof(f.connection.host), "%s", argv[2]);
    memset(&info, 0xa5, sizeof(info));
    int rc = brix_tls_peer_cert_info(&f.connection, &info);
    if (!cert || !f.connection.io.ssl) {
        brix_cert_info empty = {0};
        assert(rc == -1 && memcmp(&info, &empty, sizeof(info)) == 0);
        puts("absent");
    } else {
        assert(rc == 0 && info.have == 1);
        printf("%d %d %d %d %ld %ld %ld\n%s\n%s\n%s\n",
               info.self_signed, info.host_match, info.expired, info.not_yet_valid,
               info.not_before, info.not_after, info.days_left,
               info.subject, info.issuer, info.sans);
        /* The API must release only its borrowed reference. */
        assert(X509_get_subject_name(cert));
    }
    X509_free(cert);
    return 0;
}
