#include "sss_internal.h"
#include "core/compat/sss_bf.h"   /* brix_sss_build_credential — shared with the client */

#include <openssl/rand.h>
#include <string.h>

/*
 * WHAT: Builds an SSS kXR_auth payload that a proxy server sends to an upstream XRootD server when the upstream requests SSS authentication via kXR_authmore. Constructs header (magic 'sss\0', version, enc type BF32, 8-byte BE key-id) + Blowfish-CFB encrypted cleartext block containing RAND_bytes nonce + gen_time encode + TLV NAME field for username.
 *
 * WHY: In proxy mode the nginx-xrootd server acts as an SSS client to its upstream — it must encrypt a credential with its own shared secret key, append CRC32 integrity check, and send it in kXR_auth format. The upstream decrypts and verifies to authenticate the proxy.
 *
 * HOW: brix_sss_build_proxy_credential() → validate inputs (key + buf + username) → build cleartext: RAND_bytes(32) + gen_time BE encode + BRIX_SSS_OPT_USEDATA flag → TLV NAME block with bounded username → CRC32 append to plain buffer → Blowfish-CFB encrypt via brix_sss_bf32_crypt() → write outer header (magic, version, enc type, key-id as 8-byte BE) → return total length. */
/*
 * brix_sss_build_proxy_credential — build an SSS kXR_auth payload.
 *
 * Constructs the credential that a proxy sends to an upstream XRootD server
 * when the upstream requests SSS authentication via kXR_authmore.
 *
 * Output layout:
 *   [BRIX_SSS_HDR_LEN bytes: magic + version + enc + key-id]
 *   [cipher_len bytes: BF32-encrypted cleartext + CRC32]
 *
 * buf must be at least BRIX_SSS_HDR_LEN + BRIX_SSS_DATA_HDR_LEN + 64 + 4
 * bytes (at least 256 bytes is always sufficient).
 *
 * Returns NGX_OK on success, NGX_ERROR if the key is missing or crypto fails.
 */
ngx_int_t
brix_sss_build_proxy_credential(const brix_sss_key_t *key,
    const char *username, u_char *buf, size_t buf_max, size_t *out_len)
{
    u_char   nonce[32];
    uint32_t gen_time;

    if (key == NULL) {
        return NGX_ERROR;
    }

    /* RNG + clock at the edge; the byte assembly lives in the shared kernel
     * (brix_sss_build_credential) so client and server mint the identical
     * SSS credential wire format from one audited implementation. */
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        return NGX_ERROR;
    }
    gen_time = (uint32_t) (ngx_time() - BRIX_SSS_BASE_TIME);

    if (brix_sss_build_credential(key->key, key->key_len, (uint64_t) key->id,
                                    username, nonce, gen_time,
                                    buf, buf_max, out_len) != 0)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}

