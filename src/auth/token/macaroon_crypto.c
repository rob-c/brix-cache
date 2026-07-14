/* Macaroon third-party-caveat vid decryption — AES-256-CBC recovery of a discharge macaroon's 32-byte root key.
 *
 * WHAT: Recovers the 32-byte root key of a discharge macaroon from a third-party caveat's vid blob. The vid is
 * [16-byte IV || AES-256-CBC ciphertext]; the AES key is the HMAC signature captured immediately before the cid
 * update (sig_before_cid). macaroon_decrypt_vid() owns the OpenSSL cipher context and plaintext scratch and calls the
 * flat, early-return inner routine that drives the EVP decrypt.
 *
 * WHY: Split out of macaroon.c (phase-79 file-size split). At macaroon creation time the discharge key was encrypted
 * as vid = [IV] || AES-256-CBC(sig_before_cid, discharge_key); reversing that here is the one crypto operation that
 * lets bundle validation (macaroon.c) reconstruct and verify each discharge macaroon with its recovered key. Isolating
 * the AES machinery keeps the key material handling (cleanse-on-every-exit) in one auditable place.
 *
 * HOW: macaroon_decrypt_vid_inner() disables PKCS7 padding (the plaintext is always two AES blocks), runs
 * EVP_DecryptInit/Update/Final over vid[16..] with vid[0..15] as IV, verifies ≥32 plaintext bytes, and copies the
 * 32-byte key out. macaroon_decrypt_vid() allocates the context, bundles the operands into a macaroon_vid_t, invokes
 * the inner routine, then OPENSSL_cleanse()es the plaintext scratch and frees the context on every path. */

#include "token_internal.h"
#include "macaroon.h"
#include "macaroon_internal.h"
#include "b64url.h"
#include "scopes.h"
#include "core/compat/hex.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>   /* OPENSSL_cleanse — wipe recovered key material */
#include <string.h>
#include <time.h>

/*
 * WHAT: One AES-256-CBC vid-decrypt request — the inputs and the output buffer
 *       for recovering a discharge macaroon's 32-byte root key from a
 *       third-party caveat's vid blob.
 * WHY:  macaroon_decrypt_vid_inner previously took vid/vid_len/aes_key/
 *       discharge_key as four separate parameters (6 total with ctx+plain).
 *       Bundling the crypto operands into one file-local descriptor keeps the
 *       helper's parameter count ≤5 without changing any value threaded into
 *       the OpenSSL calls — every field carries the identical bytes.
 * HOW:  vid = [16-byte IV || ciphertext]; aes_key = 32-byte HMAC sig used as the
 *       AES-256 key; discharge_key receives the recovered 32-byte key on success.
 */
typedef struct {
    const u_char  *vid;
    size_t         vid_len;
    const u_char  *aes_key;
    u_char        *discharge_key;
} macaroon_vid_t;

/*
 * Inner AES-256-CBC decrypt over an already-created ctx, writing the plaintext
 * into the caller's `plain` scratch and, on success, copying the recovered
 * 32-byte discharge key out. Returns 0 on success, -1 on any OpenSSL failure or
 * a plaintext shorter than 32 bytes. The caller owns ctx and the cleanse/free of
 * plain — keeping that cleanup at the edge lets this use flat early returns.
 */
static int
macaroon_decrypt_vid_inner(EVP_CIPHER_CTX *ctx, u_char *plain,
    const macaroon_vid_t *v)
{
    int olen = 0, flen = 0;

    /*
     * Disable PKCS7 padding: the discharge key is always 32 bytes (two AES
     * blocks), so the ciphertext is always a multiple of the block size.
     * This avoids ambiguity regardless of whether the issuer used padding.
     */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    /* vid[0..15] = IV; vid[16..] = ciphertext; aes_key = 32-byte HMAC sig */
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, v->aes_key, v->vid)
        != 1) {
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plain, &olen,
                          v->vid + 16, (int)(v->vid_len - 16)) != 1) {
        return -1;
    }

    if (EVP_DecryptFinal_ex(ctx, plain + olen, &flen) != 1) {
        return -1;
    }

    if (olen + flen < 32) {
        return -1;
    }

    ngx_memcpy(v->discharge_key, plain, 32);
    return 0;
}

/* WHAT: Decrypt a third-party caveat vid blob to recover the discharge macaroon's 32-byte root key via AES-256-CBC.
 * WHY: At macaroon creation time, the discharge key was encrypted as vid = [16-byte IV] || AES-256-CBC(sig_before_cid, discharge_key).
 * sig_before_cid (the HMAC signature before cid update) serves as the AES decryption key. This function reverses that encryption so we can validate the discharge macaroon with its recovered root key.
 * HOW: Validate vid_len≥32 (16-byte IV + minimum 16-byte ciphertext); EVP_CIPHER_CTX_new(); bundle operands into macaroon_vid_t; call macaroon_decrypt_vid_inner (set_padding=0, DecryptInit/Update/Final, verify ≥32 plaintext, copy key out); OPENSSL_cleanse plain; EVP_CIPHER_CTX_free(ctx); return 0 success or -1 failure. */
int
macaroon_decrypt_vid(const u_char *vid, size_t vid_len,
    const u_char *aes_key, u_char *discharge_key)
{
    EVP_CIPHER_CTX *ctx;
    u_char          plain[64];
    int             rc;
    macaroon_vid_t  v;

    /* Need at least 16-byte IV + 16-byte ciphertext (one AES block) */
    if (vid_len < 32) {
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    ngx_memzero(&v, sizeof(v));
    v.vid           = vid;
    v.vid_len       = vid_len;
    v.aes_key       = aes_key;
    v.discharge_key = discharge_key;

    rc = macaroon_decrypt_vid_inner(ctx, plain, &v);

    OPENSSL_cleanse(plain, sizeof(plain));
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}
