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

/*
 * xrootd_sss_build_credential — assemble a complete SSS kXR_auth credential blob
 * (the SSS *client* side: what a native client, or the module acting as an SSS
 * client to an upstream, sends after a server requests SSS via kXR_authmore).
 *
 * THE single source of truth for the SSS credential wire format. Output:
 *   [16B outer header: "sss\0" ver(1) spare(0) kn(0) enc(BF32) key_id(8B BE)]
 *   [BF32( 40B data header [nonce32 | gen_time BE | USEDATA] + NAME TLV + CRC32 )]
 * using the shared IEEE-CRC32 and Blowfish-CFB64 kernels.
 *
 * Pure and ngx-free by construction: the caller supplies the 32-byte random nonce
 * and gen_time (seconds since XROOTD_SSS_BASE_TIME) so the RNG and clock stay at
 * the edges. username NULL/empty defaults to "xrd" (NAME TLV capped at 64 bytes).
 *
 * out_max must be >= XROOTD_SSS_HDR_LEN + XROOTD_SSS_DATA_HDR_LEN + 3 + 64 + 1 + 4
 * (256 bytes is always sufficient). Returns 0 on success with *out_len set to the
 * total blob length, or -1 on a bad argument, too-small buffer, or cipher failure.
 */
int xrootd_sss_build_credential(const uint8_t *key, size_t key_len,
                                uint64_t key_id, const char *username,
                                const uint8_t nonce32[32], uint32_t gen_time,
                                uint8_t *out, size_t out_max, size_t *out_len);

#endif /* XROOTD_COMPAT_SSS_BF_H */
