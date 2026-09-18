/*
 * shared/voms/voms_lsc.h — vomsdir trust for a VOMS server certificate
 *
 * WHAT: brix_voms_lsc_match — does vomsdir/<vo>/ name the server chain?
 * WHY:  Chain validity says the server certificate is genuine; the LSC file
 *       says this VO is served by that server. Both are required.
 * HOW:  Every vomsdir/<vo>/<host>.lsc holds DN pairs (subject then issuer, one per
 *       line, '#' comments) describing the server chain from the signer up;
 *       each pair must equal the corresponding chain certificate. Failing
 *       that, a PEM certificate in vomsdir/<vo>/ or vomsdir/ equal to the
 *       signer (the legacy layout) also matches.
 */

#ifndef BRIX_SHARED_VOMS_LSC_H
#define BRIX_SHARED_VOMS_LSC_H

#include <openssl/x509.h>

/* 1 when a match was found, 0 otherwise (including an unreadable vomsdir). */
int brix_voms_lsc_match(const char *vomsdir, const char *vo,
    STACK_OF(X509) *signer_chain);

/* Compare a DN line from an LSC file against `name`: the OpenSSL one-line
 * form (/DC=ch/DC=cern/...) and the RFC 2253 form are both accepted. */
int brix_voms_dn_line_matches(const char *line, const X509_NAME *name);

#endif /* BRIX_SHARED_VOMS_LSC_H */
