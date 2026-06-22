/*
 * sss_bf.h — Blowfish-CFB64 crypt for the SSS credential (shared).
 *
 * WHAT: encrypt/decrypt with EVP_bf_cfb64, padding off, variable key length, an
 *       all-zero 8-byte IV — the exact transform the XRootD SSS blob uses.
 * WHY:  the module (SSS verify/challenge) and the native client (SSS mint) each
 *       carried their own copy plus an OpenSSL-3 "legacy" provider loader; one
 *       shared kernel keeps the crypto (and the legacy-provider dance) in step.
 * HOW:  caller buffers (ptr+len); loads the legacy provider once internally
 *       (Blowfish moved there in OpenSSL 3.x), warming SHA2-256 first. ngx-free;
 *       OpenSSL only. (libxrdproto)
 */
#ifndef XROOTD_COMPAT_SSS_BF_H
#define XROOTD_COMPAT_SSS_BF_H

#include <stddef.h>
#include <stdint.h>

/*
 * Blowfish-CFB64 transform. encrypt != 0 → encrypt, 0 → decrypt. CFB64 is a
 * stream mode so out length == src_len (dst_max must be >= src_len). Writes the
 * byte count to *out_len. Returns 0 on success, -1 on a bad arg or EVP failure.
 */
int xrootd_sss_bf_crypt(int encrypt, const uint8_t *key, size_t key_len,
                        const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_max, size_t *out_len);

#endif /* XROOTD_COMPAT_SSS_BF_H */
