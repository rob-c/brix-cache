/* TLS-library compatibility with unchanged certificate and protocol policy.
 * Requires: OpenSSL >= 1.1.1 and POSIX address parsing. No DNS is performed.
 */
#pragma once
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* WHAT: Pin exactly one DNS or IP certificate identity on verify parameters.
 * WHY: Legacy SSL_set1_host treats IP literals as DNS names; iPAddress SANs
 * must use the IP verifier, never a numeric dNSName or CommonName fallback.
 * HOW: Parse addresses without DNS, clear the other identity type, and return
 * failure for absent names or any native parameter-setting error. */
static inline int
brix_crypto_verify_peer_name(X509_VERIFY_PARAM *parameters, const char *host)
{
    unsigned char address[16];
    size_t length = 0;

    if (parameters == NULL || host == NULL || host[0] == '\0') {
        return 0;
    }
    if (inet_pton(AF_INET, host, address) == 1) {
        length = 4;
    } else if (inet_pton(AF_INET6, host, address) == 1) {
        length = 16;
    }
    if (length != 0) {
        return X509_VERIFY_PARAM_set1_host(parameters, NULL, 0) == 1
            && X509_VERIFY_PARAM_set1_ip(parameters, address, length) == 1;
    }
    return X509_VERIFY_PARAM_set1_ip(parameters, NULL, 0) == 1
        && X509_VERIFY_PARAM_set1_host(parameters, host, 0) == 1;
}

/* WHAT: Bind an SSL connection to its expected certificate identity.
 * WHY: Native clients and outbound server connections need the same contract.
 * HOW: Apply the shared parameter helper, refusing a missing SSL handle. */
static inline int
brix_crypto_tls_peer_name(SSL *ssl, const char *host)
{
    return ssl != NULL && brix_crypto_verify_peer_name(SSL_get0_param(ssl), host);
}

/* ---- Preserve GridFTP data-channel close semantics on OpenSSL 3 ----
 * WHAT: Enable the native unexpected-EOF option where the TLS library has it.
 * WHY: OpenSSL 3 treats missing close_notify as an error by default; 1.1.1
 *      reports the pre-existing syscall/empty-error EOF instead. Callers retain
 *      their data-frame/transfer-completion checks and control-channel policy.
 * HOW: 1. Set the option on 3+. 2. Leave the existing 1.1.1 behavior unchanged.
 */
static inline void
brix_crypto_gridftp_data_eof(SSL *ssl)
{
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
    SSL_set_options(ssl, SSL_OP_IGNORE_UNEXPECTED_EOF);
#else
    (void) ssl;
#endif
}
