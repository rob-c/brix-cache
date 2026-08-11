/*
 * tls_certinfo.c — peer-certificate introspection for the native TLS client.
 *
 * WHAT: Extract the negotiated peer certificate's subject/issuer, validity
 *       window, self-signed / hostname-match flags, and DNS subjectAltNames
 *       into a caller-owned brix_cert_info.
 * WHY:  The verbose/interop paths (roots:// diagnostics, `xrdfs ... query`)
 *       want a structured view of what the server presented, independent of
 *       whether verification was enforced.
 * HOW:  Split verbatim out of tls.c to keep that translation unit under the
 *       file-size cap; see brix_tls_peer_cert_info() there historically.
 */
#include "brix.h"

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <string.h>
#include <time.h>

/* Join the cert's DNS subjectAltNames into out[] as a comma-separated list. */
static void
peer_collect_sans(X509 *cert, char *out, size_t outsz)
{
    GENERAL_NAMES *gens;
    int            i, n;
    size_t         off = 0;

    out[0] = '\0';
    gens = (GENERAL_NAMES *) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (gens == NULL) {
        return;
    }
    n = sk_GENERAL_NAME_num(gens);
    for (i = 0; i < n; i++) {
        GENERAL_NAME *g = sk_GENERAL_NAME_value(gens, i);
        const char   *dns;
        int           len;
        if (g->type != GEN_DNS) {
            continue;
        }
        dns = (const char *) ASN1_STRING_get0_data(g->d.dNSName);
        len = ASN1_STRING_length(g->d.dNSName);
        if (len <= 0 || off + (size_t) len + 2 >= outsz) {
            continue;
        }
        if (off > 0) { out[off++] = ','; }
        memcpy(out + off, dns, (size_t) len);
        off += (size_t) len;
        out[off] = '\0';
    }
    GENERAL_NAMES_free(gens);
}

int
brix_tls_peer_cert_info(const brix_conn *c, brix_cert_info *out)
{
    SSL             *ssl = (SSL *) c->io.ssl;
    X509            *cert;
    const ASN1_TIME *nb, *na;
    struct tm        tmv;
    time_t           now = time(NULL);
    int              dd = 0, ds = 0;

    memset(out, 0, sizeof(*out));
    if (ssl == NULL) {
        return -1;   /* cleartext: no peer cert */
    }
    cert = SSL_get_peer_certificate(ssl);   /* bumps refcount; free below */
    if (cert == NULL) {
        return -1;
    }
    out->have = 1;
    X509_NAME_oneline(X509_get_subject_name(cert), out->subject, sizeof(out->subject));
    X509_NAME_oneline(X509_get_issuer_name(cert),  out->issuer,  sizeof(out->issuer));
    out->self_signed = (X509_check_issued(cert, cert) == X509_V_OK);
    out->host_match  = (c->host[0] != '\0'
                        && X509_check_host(cert, c->host, 0, 0, NULL) == 1);

    nb = X509_get0_notBefore(cert);
    na = X509_get0_notAfter(cert);
    if (ASN1_TIME_to_tm(nb, &tmv)) { out->not_before = (long) timegm(&tmv); }
    if (ASN1_TIME_to_tm(na, &tmv)) { out->not_after  = (long) timegm(&tmv); }
    out->expired       = (out->not_after  != 0 && out->not_after  < (long) now);
    out->not_yet_valid = (out->not_before != 0 && out->not_before > (long) now);
    if (ASN1_TIME_diff(&dd, &ds, NULL, na)) {
        out->days_left = dd;   /* whole days; negative once expired */
    }
    peer_collect_sans(cert, out->sans, sizeof(out->sans));

    X509_free(cert);
    return 0;
}
