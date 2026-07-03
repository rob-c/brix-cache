/*
 * sigv4.h — AWS Signature Version 4 signing-key derivation (shared).
 *
 * WHAT: the four-round HMAC-SHA256 chain that turns a secret access key into the
 *       date/region/service-scoped SigV4 signing key.
 * WHY:  the S3 server (verify path) and the native client (sign path) must derive
 *       byte-identical keys or every signature mismatches; one shared kernel makes
 *       that true by construction.
 * HOW:  k1=HMAC("AWS4"+secret,date) k2=HMAC(k1,region) k3=HMAC(k2,service)
 *       out=HMAC(k3,"aws4_request"), using the shared brix_hmac_sha256 kernel.
 *       Pure ptr+len; no ngx, no allocation. (libxrdproto)
 */
#ifndef BRIX_COMPAT_SIGV4_H
#define BRIX_COMPAT_SIGV4_H

#include <stddef.h>
#include <stdint.h>

/*
 * Derive the SigV4 signing key into out[32].
 *   secret/secret_len — the raw secret access key (no "AWS4" prefix)
 *   date              — "YYYYMMDD" datestamp
 *   region            — e.g. "us-east-1"
 *   service           — e.g. "s3"
 * Returns 1 on success, 0 on a bad arg, an over-long secret, or an HMAC failure.
 */
int brix_sigv4_signing_key(const uint8_t *secret, size_t secret_len,
                             const char *date, const char *region,
                             const char *service, uint8_t out[32]);

#endif /* BRIX_COMPAT_SIGV4_H */
