/*
 * gsi_core.h — ngx-free GSI/sigver crypto + wire kernels (shared by the nginx
 * module and the native client; see gsi_core.c). Pure OpenSSL + libc.
 */
#ifndef BRIX_GSI_CORE_H
#define BRIX_GSI_CORE_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

/* ---- XrdSutBuffer (name\0 + step[4] + {type[4] len[4] data}* + kXRS_none) ---- */

/* Find the first bucket of `type`; 0 with out/outlen set, -1 if absent. */
int brix_gsi_find_bucket(const uint8_t *buf, size_t len, uint32_t type,
                           const uint8_t **out, size_t *outlen);

/* Growable builder; allocation failure is sticky (->err, checked once). */
typedef struct {
    uint8_t *p;
    size_t   len;
    size_t   cap;
    int      err;
} brix_gbuf;

void brix_gbuf_init(brix_gbuf *g);
void brix_gbuf_free(brix_gbuf *g);
void brix_gbuf_raw(brix_gbuf *g, const void *data, size_t n);
void brix_gbuf_u32(brix_gbuf *g, uint32_t v);                 /* big-endian */
void brix_gbuf_start(brix_gbuf *g, uint32_t step);           /* "gsi\0" + step */
void brix_gbuf_bucket(brix_gbuf *g, uint32_t type, const void *d, size_t n);
void brix_gbuf_end(brix_gbuf *g);                           /* kXRS_none */

/* ---- Diffie-Hellman (ffdhe2048) ---- */

EVP_PKEY *brix_gsi_dh_keygen(void);                            /* caller frees */
/* "---BPUB---<hex>---EPUB--" blob → BIGNUM (caller BN_free), NULL on failure. */
BIGNUM   *brix_gsi_dh_pub_decode(const uint8_t *blob, size_t len);
/* pub → malloc'd "---BPUB---<UPPERCASE hex>---EPUB--" string, NULL on failure. */
char     *brix_gsi_dh_pub_encode(EVP_PKEY *dh);
/* peer key from `mine`'s params (ffdhe2048) + peer_pub; caller frees. */
EVP_PKEY *brix_gsi_dh_build_peer(EVP_PKEY *mine, BIGNUM *peer_pub);
/* shared secret (unpadded, dh_pad=0); malloc'd, *slen set; NULL on failure. */
uint8_t  *brix_gsi_dh_derive(EVP_PKEY *mine, EVP_PKEY *peer, size_t *slen);

/* ---- XrdCryptosslCipher-compatible session cipher (phase-48 W4) ----
 * Byte-exact with stock XrdSecgsi: one fixed 3072-bit DH group, the Public()
 * wire form (PEM params + "---BPUB---"<UPPER hex>"---EPUB---"), AES-128 key =
 * first 16 bytes of the padded (dh_pad=1) DH secret, Encrypt = random 16-byte
 * IV prepended to AES-128-CBC/PKCS7.  Shared by client (encode/encrypt) and
 * server (decode/decrypt). */

/* DH keypair from the fixed 3072-bit params; caller EVP_PKEY_free. */
EVP_PKEY *brix_gsi_cipher_keygen(void);
/* DH keypair using the PEER's params (its group may differ, e.g. ffdhe2048);
 * required for the derive to succeed.  caller EVP_PKEY_free. */
EVP_PKEY *brix_gsi_cipher_keygen_from(EVP_PKEY *peer);
/* Serialize dh's public part to the kXRS_cipher wire blob; malloc'd, *outlen
 * set (NOT NUL-terminated). NULL on failure. */
char     *brix_gsi_cipher_public(EVP_PKEY *dh, size_t *outlen);
/* Parse a peer kXRS_cipher blob → peer public EVP_PKEY; caller frees. */
EVP_PKEY *brix_gsi_cipher_parse_peer(const uint8_t *buf, size_t len);
/* Phase 52 (WS-A): a negotiated GSI session cipher.  evp/key_len/iv_len come from
 * EVP_get_cipherbyname for one of the allowed names (aes-128-cbc, aes-256-cbc,
 * bf-cbc, des-ede3-cbc). */
#define BRIX_GSI_MAX_KEY  32   /* largest session key (aes-256) */
#define BRIX_GSI_MAX_IV   16   /* largest IV (AES); bf/3des use 8 */

typedef struct {
    const EVP_CIPHER *evp;
    int               key_len;
    int               iv_len;
} brix_gsi_cipher_t;

/* The default server-advertised cipher preference list (aes-128-cbc first, so the
 * proven default + stock interop stays byte-for-byte unchanged). */
const char *brix_gsi_cipher_default_list(void);
/* Resolve `name` (must be in the allowlist AND its provider loaded) into *out.
 * Returns 1 on success, 0 if not allowed / unavailable. */
int  brix_gsi_cipher_lookup(const char *name, brix_gsi_cipher_t *out);
/* Pick the first cipher in the colon-separated `offered` list that we support;
 * fills *out and (if non-NULL) chosen[] with its name. Returns 1/0. */
int  brix_gsi_cipher_pick(const char *offered, brix_gsi_cipher_t *out,
                            char chosen[24]);

/* Session key = first key_len bytes of the DH secret; `padded` must match the
 * peer's XrdSecgsi HasPad (0 for pre-DHsigned <10400 peers, 1 for newer). 1/0. */
int       brix_gsi_cipher_session_key(EVP_PKEY *mine, EVP_PKEY *peer,
                                        int padded, uint8_t *key, int key_len);
/* Encrypt with the negotiated cipher `c`.  use_iv: 1 = a fresh random IV
 * (c->iv_len bytes) is prepended (XrdSecgsi >=DHsigned peers); 0 = zero IV,
 * nothing prepended (pre-DHsigned).  malloc'd, *outlen. */
uint8_t  *brix_gsi_cipher_encrypt(const brix_gsi_cipher_t *c,
                                    const uint8_t *key, const uint8_t *in,
                                    size_t inlen, int use_iv, size_t *outlen);
uint8_t  *brix_gsi_cipher_decrypt(const brix_gsi_cipher_t *c,
                                    const uint8_t *key, const uint8_t *in,
                                    size_t inlen, int use_iv, size_t *outlen);

/* ---- XrdSecgsi handshake helpers (shared client/server, phase-48) ---- */

/* Cryptographically-strong random bytes into out[0..n). Returns 1/0. */
int brix_gsi_rand(uint8_t *out, size_t n);

/* RSA private-key sign (XrdCryptosslRSA::EncryptPrivate): proof-of-possession
 * (sign the server rtag with the proxy key).  out >= EVP_PKEY_size(key)+inlen;
 * returns sig length or 0. */
size_t brix_gsi_rsa_sign_raw(EVP_PKEY *key, const uint8_t *in, size_t inlen,
                               uint8_t *out);

/* Chunked RSA EncryptPrivate / DecryptPublic (XrdCryptosslRSA), PKCS#1 v1.5 —
 * for the v>=DHsigned signed-DH path (sign/verify the cipher Public() blob).
 * encrypt_private chunks input by key_size-11; decrypt_public by key_size.
 * Return the produced length, or 0. */
size_t brix_gsi_rsa_encrypt_private(EVP_PKEY *key, const uint8_t *in,
                                      size_t inlen, uint8_t *out, size_t outmax);
size_t brix_gsi_rsa_decrypt_public(EVP_PKEY *key, const uint8_t *in,
                                     size_t inlen, uint8_t *out, size_t outmax);

/* Parse a gsi protocol parms string "v:10600,c:ssl,ca:HASH|HASH"; any out may
 * be NULL.  crypto/ca are NUL-terminated, truncated to size. */
void brix_gsi_parse_parms(const char *parms, uint32_t *version,
                            char *crypto, size_t cryptosz,
                            char *ca, size_t casz);

/* Build the standard round-1 certreq buffer (outer + nested main with rtag),
 * mirroring a stock XrdSecgsi client.  malloc'd (*outlen set), NULL on failure. */
uint8_t *brix_gsi_build_certreq(const char *cryptomod, uint32_t version,
                                  const char *issuer_hash, uint32_t clnt_opts,
                                  const uint8_t *rtag, size_t rtaglen,
                                  size_t *outlen);

/* Build the round-2 kXGC_cert response to a server's kXGS_cert, the single shared
 * XrdSecgsi client/dest round-2 (both DH variants: signed-DH via kXRS_cipher when
 * the server sends one, else unsigned kXRS_puk). Agrees the AES session key, signs
 * the server's random tag with proxy_key (proof-of-possession), and emits an
 * encrypted main carrying proxy_pem (the proxy cert chain PEM) + the signed tag +
 * a fresh tag, plus our DH public (RSA-signed in the signed-DH case).
 *
 * proxy_pem (proxy_pem_len) and proxy_key are BORROWED — the caller still owns and
 * frees them. On success payload+plen receive a malloc'd kXGC_cert buffer the
 * caller must free(); returns 0. On failure returns -1 and, if err!=NULL, writes a
 * short reason into err[errcap]. Both the native client (client/lib/sec/sec_gsi.c)
 * and the TPC destination (src/tpc/gsi/gsi_outbound_exchange.c) call this. */
int brix_gsi_build_cert_response(const uint8_t *sbody, uint32_t slen,
                                   const uint8_t *proxy_pem, size_t proxy_pem_len,
                                   EVP_PKEY *proxy_key,
                                   uint8_t **payload, uint32_t *plen,
                                   char *err, size_t errcap);

/* As brix_gsi_build_cert_response, but also hands the agreed session cipher
 * out to the caller: out_key[out_keylen] the raw AES key, out_cipher the cipher
 * name, out_use_iv the IV-prepend flag.  Client-side X.509 delegation needs this
 * to encrypt the follow-up kXGC_sigpxy.  Any out pointer may be NULL. */
int brix_gsi_build_cert_response_ex(const uint8_t *sbody, uint32_t slen,
                                      const uint8_t *proxy_pem,
                                      size_t proxy_pem_len, EVP_PKEY *proxy_key,
                                      uint8_t **payload, uint32_t *plen,
                                      uint8_t *out_key, size_t *out_keylen,
                                      char *out_cipher, size_t out_cipher_cap,
                                      int *out_use_iv,
                                      char *err, size_t errcap);

/* ---- kXR_sigver opcode policy ---- */
int brix_gsi_sigver_required(uint16_t opcode, int level);

/* ---- kXR_sigver HMAC (request signing / verification) ---- */
/* Serialise a 64-bit sigver seqno to big-endian 8 bytes. */
void brix_gsi_sigver_seqno_be(uint64_t seq, uint8_t out[8]);
/* HMAC-SHA256(key, seqno_be(8) || hdr24(24) || [payload unless nodata]) into
 * mac_out[32]. Both the client (sign) and the server (verify) call this so the
 * covered-byte layout is single-source. Returns 1 on success, 0 on failure. */
int  brix_gsi_sigver_hmac(const uint8_t key[32], uint64_t seqno,
                            const uint8_t hdr24[24], const uint8_t *payload,
                            size_t plen, int nodata, uint8_t mac_out[32]);

#endif /* BRIX_GSI_CORE_H */
