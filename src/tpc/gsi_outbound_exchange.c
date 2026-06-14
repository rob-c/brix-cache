#include "tpc_internal.h"
#include "../session/session.h"
#include "../protocol/gsi.h"

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#if defined(__linux__)
#include <endian.h>
#endif

/* ---- File: gsi_outbound_exchange.c — GSI DH key exchange handshake for TPC pull ----
 *
 * WHAT: Single function tpc_outbound_gsi_exchange implements the complete two-round Diffie-Hellman authentication handshake on the outbound TPC socket. Round 1 (kXGC_cert): parse server kXRS_puk blob → extract PEM params via memmem + PEM_read_bio_Parameters_ex → generate client DH keypair via EVP_PKEY_keygen → parse server public hex via tpc_parse_hex_pub → merge local params with peer pubkey into srv_peer via tpc_dh_peer_from → derive shared secret via EVP_PKEY_derive → select cipher from kXRS_cipher_alg bucket via tpc_gsi_select_cipher → build inner buffer (gsi + cert + x509 chain PEM) → encrypt inner buffer with derived secret via EVP_EncryptInit/Update/Final_ex. Round 2 (kXGC_cert): build client puk blob (PEM params + ---BPUB--- hex ---EPUB--) → construct outer wire message (gsi + kXRS_puk + client_puk_len + client_puk + kXRS_main + enc_len + encrypted inner) via tpc_put_u32 + ngx_memcpy → send outer via tpc_send_kxr_auth(fd, seq=4) → recv_response checking status == kXR_ok. Optional: verify server leaf cert using conf->gsi_store CA store with X509_STORE_CTX (X509_V_FLAG_ALLOW_PROXY_CERTS). Returns 0 or -1 with error code set on t->xrd_error. Caller: thread.c (auth path dispatch after bootstrap).
 *
 * WHY: GSI authentication requires Diffie-Hellman key exchange to derive a shared symmetric secret between client and server for encrypting the cert chain payload. The outbound TPC socket carries this handshake in two kXR_auth messages with ctype=kXGC_cert — first round sends encrypted cert chain + cipher algorithm negotiation, second round sends client's DH public key blob + encrypted inner buffer. This function bridges the wire protocol ↔ OpenSSL pipeline: parsing server pubkey PEM/hex → generating client DH keypair → deriving shared secret → encrypting payload → constructing outer wire message → sending via send_all. Without this exchange the cert chain cannot be confidentially transmitted to the server during TPC pull authentication.
 *
 * HOW: Round 1 — gsi_find_bucket(body, kXRS_puk) for puk_blob → memmem "---BPUB---" marker → BIO_new_mem_buf(puk_blob up-to-marker) + PEM_read_bio_Parameters_ex(dh_params) → EVP_PKEY_CTX_new(dh_params) + keygen_init + keygen(client_kp) → tpc_parse_hex_pub(puk_blob, puk_blob_len) for srv_pub_bn → BN_free(srv_pub_bn) → tpc_dh_peer_from(client_kp, srv_pub_bn) for srv_peer → EVP_PKEY_CTX_new(client_kp) + derive_init + set_dh_pad(0) + derive_set_peer(srv_peer) → derive(NULL, &secret_len) malloc(secret) → derive(secret, &secret_len) → tpc_gsi_select_cipher(body, dlen, cipher_name, 64) → EVP_get_cipherbyname(cipher_name) → BIO_new(BIO_s_mem()) for mbio_chain + loop PEM_write_bio_X509(chain certs) → BIO_get_mem_ptr(bptr) pem_chain_len → malloc(256+chain+64) inner_plain → ngx_memcpy("gsi\x00") tpc_put_u32(kXGC_cert) tpc_put_u32(kXRS_x509) tpc_put_u32(pem_chain_len) ngx_memcpy(bptr->data, pem_chain_len) tpc_put_u32(kXRS_none) tpc_put_u32(0) → EVP_CIPHER_CTX_new(ectx) → EVP_CipherInit_ex(tctx) key_length adjustment if secret_len != cipher default → EVP_EncryptInit_ex(ectx, evp_cipher, NULL, NULL, NULL) + set_key_length(use_len) → EncryptInit_ex(NULL, NULL, NULL, secret, iv[zeroed]) → malloc(ilen+block_size) enc_out → EncryptUpdate(enc_out, &enc_len, inner_plain, ilen) → EncryptFinal_ex(enc_out+enc_len, &enc_flen) → EVP_CIPHER_CTX_free(ectx) + free(inner_plain). Round 2 — BIO_new(BIO_s_mem()) pbio + PEM_write_bio_Parameters(pbio, client_kp) + BIO_get_mem_ptr(bptr) → EVP_PKEY_get_bn_param(client_kp, OSSL_PKEY_PARAM_PUB_KEY, pub_bn) → BN_bn2hex(pub_bn) BN_free(pub_bn) → snprintf("%.*s---BPUB---%s---EPUB--", bptr->length, bptr->data, pub_hex) for puk_client → outer_len = 4+4 + 8+puk_client_len + 8+enc_len + 8 → malloc(outer_len+64) outer → ngx_memcpy("gsi\x00") tpc_put_u32(kXGC_cert) tpc_put_u32(kXRS_puk) tpc_put_u32(puk_client_len) ngx_memcpy(puk_client, puk_client_len) free(puk_client) tpc_put_u32(kXRS_main) tpc_put_u32(enc_len) ngx_memcpy(enc_out, enc_len) free(enc_out) tpc_put_u32(kXRS_none) tpc_put_u32(0) → outer_len = wp - outer → free(body) body=NULL → tpc_send_kxr_auth(t, fd, 4, outer, outer_len) free(outer) → recv_response(fd, &status, &body, &dlen) status==kXR_ok → rc=0. Error paths: return tpc_gsi_exchange_round_fail (EVP_PKEY_free(client_kp), free(body), then BIO_free(pbio)); success and the pre-keygen cert-verify failure return tpc_gsi_exchange_done (BIO_free(pbio) only). Optional cert verification at start: gsi_find_bucket(kXRS_x509) srv_pem → BIO_new_mem_buf + PEM_read_bio_X509(srv) → X509_STORE_CTX_init(conf->gsi_store, srv) + set_flags(ALLOW_PROXY_CERTS) + verify_cert != 1 → error.
 * ------------------------------------------------------------------ */

/*
 * Two-tier cleanup for tpc_outbound_gsi_exchange, replacing the former
 * round_fail/done labels.
 *
 * tpc_gsi_exchange_done frees only the shared pbio and returns rc — the exit
 * used once the keypair and server body have already been released (the success
 * path and the early pre-keygen cert-verification failure both use it).
 *
 * tpc_gsi_exchange_round_fail additionally releases the resources that may still
 * be live on a mid-handshake error — the client keypair and the server body —
 * before delegating the shared pbio free to _done. Both guards are NULL-safe.
 */
static int
tpc_gsi_exchange_done(int rc, BIO *pbio)
{
    if (pbio) BIO_free(pbio);
    return rc;
}

static int
tpc_gsi_exchange_round_fail(int rc, EVP_PKEY *client_kp, u_char *body, BIO *pbio)
{
    if (client_kp) EVP_PKEY_free(client_kp);
    if (body) free(body);
    return tpc_gsi_exchange_done(rc, pbio);
}

/* WHAT: Complete two-round GSI DH auth handshake on outbound TPC socket — round 1 (kXGC_cert): parse server puk + derive secret + encrypt cert chain; round 2 (kXGC_cert): send client puk blob + encrypted inner → recv_response status==kXR_ok. Returns 0 or -1 with t->xrd_error set. Caller: thread.c auth path dispatch after bootstrap. */
int
tpc_outbound_gsi_exchange(xrootd_tpc_pull_t *t, int fd,
    u_char *body, uint32_t dlen,
    X509 *x, STACK_OF(X509) *chain, EVP_PKEY *pkey,
    u_char *certreq, BIO *cbio, BIO *kbio)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    int rc = -1;
    uint16_t status;
    EVP_PKEY              *client_kp = NULL;
    BIO                   *pbio = NULL;

    /*
     * Optional: verify server leaf cert using our CA store when configured.
     * This runs before the DH exchange so we reject an untrusted origin before
     * deriving a shared secret with it. X509_V_FLAG_ALLOW_PROXY_CERTS is set
     * because GSI delegated proxies are legitimate in this ecosystem. Note the
     * verification is skipped entirely when no store is configured or the
     * server omitted its kXRS_x509 bucket — failure to find the cert is NOT
     * fatal here, only a present-but-invalid cert aborts the handshake.
     */
    if (conf->gsi_store != NULL) {
        const u_char *srv_pem;
        size_t        srv_pem_len;

        if (gsi_find_bucket(body, dlen, (uint32_t) kXRS_x509,
                            &srv_pem, &srv_pem_len)
            == 0 && srv_pem_len > 0)
        {
            BIO              *mbio;
            X509             *srv;
            X509_STORE_CTX   *sctx;

            mbio = BIO_new_mem_buf(srv_pem, (int) srv_pem_len);
            srv = PEM_read_bio_X509(mbio, NULL, NULL, NULL);
            BIO_free(mbio);

            if (srv != NULL) {
                sctx = X509_STORE_CTX_new();
                if (sctx
                    && X509_STORE_CTX_init(sctx, conf->gsi_store, srv, NULL)
                       == 1)
                {
                    X509_STORE_CTX_set_flags(sctx, X509_V_FLAG_ALLOW_PROXY_CERTS);
                    if (X509_verify_cert(sctx) != 1) {
                        snprintf(t->err_msg, sizeof(t->err_msg),
                                 "TPC GSI server certificate verification failed");
                        t->xrd_error = kXR_NotAuthorized;
                        X509_STORE_CTX_free(sctx);
                        X509_free(srv);
                        /* Pre-keygen failure: client_kp/body not ours to free
                         * here — only the shared pbio (still NULL). */
                        return tpc_gsi_exchange_done(rc, pbio);
                    }
                }
                if (sctx) {
                    X509_STORE_CTX_free(sctx);
                }
                X509_free(srv);
            }
        }
    }

    /* ---- Parse server kXRS_puk, generate client DH, derive secret ---- */
    {
        EVP_PKEY              *dh_params = NULL;
        const u_char *puk_blob;
        size_t        puk_blob_len;
        const u_char *bp_marker;
        BIO           *pbio_mem;
        BUF_MEM       *bptr;
        EVP_PKEY_CTX  *kgctx = NULL;
        BIGNUM                *srv_pub_bn = NULL;
        EVP_PKEY              *srv_peer = NULL;
        unsigned char         *secret = NULL;
        size_t                 secret_len = 0;
        EVP_PKEY_CTX          *dkctx = NULL;
        char                   cipher_name[64];
        const EVP_CIPHER      *evp_cipher;
        EVP_CIPHER_CTX        *ectx = NULL;
        u_char                *inner_plain = NULL;
        int                    ilen = 0;
        u_char                *inner_cursor;
        BIO                   *mbio_chain;
        u_char                *enc_out = NULL;
        int                    enc_len = 0, enc_flen = 0;
        size_t                 pem_chain_len = 0;
        u_char                *puk_client = NULL;
        size_t                 puk_client_len;
        u_char                *outer = NULL;
        size_t                 outer_len;
        u_char                *wp;
        int                    ci;

        if (gsi_find_bucket(body, dlen, (uint32_t) kXRS_puk,
                            &puk_blob, &puk_blob_len)
            != 0)
        {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI server kXRS_puk missing");
            t->xrd_error = kXR_NotAuthorized;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        /*
         * The server kXRS_puk blob is a concatenation:
         *   <PEM DH parameters> ---BPUB--- <server pubkey hex> ---EPUB--
         * Everything before the "---BPUB---" marker is the PEM-encoded DH group
         * parameters; the hex public key sits between the BPUB/EPUB markers.
         * We split here: PEM portion -> dh_params, hex portion -> srv_pub_bn.
         */
        bp_marker = memmem(puk_blob, puk_blob_len, "---BPUB---",
                           sizeof("---BPUB---") - 1);
        if (bp_marker == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI malformed server DH puk");
            t->xrd_error = kXR_NotAuthorized;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        /* Parse only the [start .. ---BPUB---) slice as PEM DH parameters. */
        pbio_mem = BIO_new_mem_buf(puk_blob, (int) (bp_marker - puk_blob));
        if (pbio_mem == NULL) {
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        dh_params = PEM_read_bio_Parameters_ex(pbio_mem, NULL, NULL, NULL);
        BIO_free(pbio_mem);

        if (dh_params == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI cannot parse server DH PEM parameters");
            t->xrd_error = kXR_NotAuthorized;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        /* Generate OUR DH keypair in the server-supplied group (dh_params). The
         * private half stays in client_kp; its public half is sent back to the
         * server in round 2. dh_params is freed once keygen succeeds — the group
         * is now embedded in client_kp. */
        kgctx = EVP_PKEY_CTX_new(dh_params, NULL);
        if (kgctx == NULL
            || EVP_PKEY_keygen_init(kgctx) <= 0
            || EVP_PKEY_keygen(kgctx, &client_kp) <= 0
            || client_kp == NULL)
        {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI client DH keygen failed");
            t->xrd_error = kXR_ServerError;
            EVP_PKEY_CTX_free(kgctx);
            kgctx = NULL;
            EVP_PKEY_free(dh_params);
            dh_params = NULL;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }
        EVP_PKEY_CTX_free(kgctx);
        kgctx = NULL;
        EVP_PKEY_free(dh_params);
        dh_params = NULL;

        /* Build the peer (server) DH key: parse the hex public value between the
         * BPUB/EPUB markers, then graft it onto our group params to form a full
         * peer key suitable for EVP_PKEY_derive_set_peer. */
        srv_pub_bn = tpc_parse_hex_pub(puk_blob, puk_blob_len);
        if (srv_pub_bn == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI cannot parse server DH public hex");
            t->xrd_error = kXR_NotAuthorized;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        srv_peer = tpc_dh_peer_from(client_kp, srv_pub_bn);
        BN_free(srv_pub_bn);
        srv_pub_bn = NULL;

        if (srv_peer == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI cannot build server DH peer key");
            t->xrd_error = kXR_ServerError;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        /*
         * Derive the shared DH secret = (server_pub ^ our_priv) mod p.
         * set_dh_pad(0) selects the legacy unpadded representation that the
         * xrootd GSI peer expects (a padded secret would not match the server's
         * key derivation). The derive is done in two calls: first with NULL out
         * to size the buffer, then again to fill it.
         */
        dkctx = EVP_PKEY_CTX_new(client_kp, NULL);
        if (dkctx == NULL
            || EVP_PKEY_derive_init(dkctx) != 1
            || EVP_PKEY_CTX_set_dh_pad(dkctx, 0) != 1
            || EVP_PKEY_derive_set_peer(dkctx, srv_peer) != 1)
        {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI DH derive init failed");
            t->xrd_error = kXR_ServerError;
            EVP_PKEY_free(srv_peer);
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        if (EVP_PKEY_derive(dkctx, NULL, &secret_len) != 1) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI DH derive size failed");
            t->xrd_error = kXR_ServerError;
            EVP_PKEY_CTX_free(dkctx);
            dkctx = NULL;
            EVP_PKEY_free(srv_peer);
            srv_peer = NULL;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        secret = OPENSSL_malloc(secret_len);
        if (secret == NULL
            || EVP_PKEY_derive(dkctx, secret, &secret_len) != 1)
        {
            snprintf(t->err_msg, sizeof(t->err_msg), "TPC GSI DH derive failed");
            t->xrd_error = kXR_ServerError;
            OPENSSL_free(secret);
            secret = NULL;
            EVP_PKEY_CTX_free(dkctx);
            EVP_PKEY_free(srv_peer);
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }
        EVP_PKEY_CTX_free(dkctx);
        dkctx = NULL;
        EVP_PKEY_free(srv_peer);
        srv_peer = NULL;

        tpc_gsi_select_cipher(body, dlen, cipher_name, sizeof(cipher_name));

        evp_cipher = EVP_get_cipherbyname(cipher_name);
        if (evp_cipher == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI unknown cipher from server: %s", cipher_name);
            t->xrd_error = kXR_NotAuthorized;
            OPENSSL_free(secret);
            secret = NULL;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        /* Inner buffer: gsi + step + kXRS_x509(certs PEM) + none */
        mbio_chain = BIO_new(BIO_s_mem());
        if (mbio_chain == NULL) {
            OPENSSL_free(secret);
            secret = NULL;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        /* Concatenate the full client cert chain as PEM into one memory BIO;
         * bptr->data/length then point at the contiguous PEM blob we embed. */
        for (ci = 0; ci < sk_X509_num(chain); ci++) {
            PEM_write_bio_X509(mbio_chain, sk_X509_value(chain, ci));
        }
        BIO_get_mem_ptr(mbio_chain, &bptr);
        pem_chain_len = bptr->length;

        /* Overflow guard: the 256+...+64 alloc below must not wrap size_t. */
        if (pem_chain_len > (size_t)-1 - 320) {
            BIO_free(mbio_chain);
            OPENSSL_free(secret);
            secret = NULL;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }
        inner_plain = malloc(256 + pem_chain_len + 64);
        if (inner_plain == NULL) {
            BIO_free(mbio_chain);
            OPENSSL_free(secret);
            secret = NULL;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        /*
         * Build the plaintext that will be symmetrically encrypted under the DH
         * secret (the kXRS_main bucket of round 2). Layout, written field by
         * field via a moving cursor (tpc_put_u32 emits one 4-byte length/tag):
         *
         *   [4]  "gsi\0"                protocol name, NUL-padded to 4
         *   [4]  kXGC_cert             GSI handshake step
         *   [4]  kXRS_x509             bucket type: the cert chain
         *   [4]  pem_chain_len         bucket length
         *   [N]  <PEM cert chain>      bucket payload
         *   [4]  kXRS_none             terminator bucket type
         *   [4]  0                     terminator length
         *
         * ilen is the exact plaintext size handed to the cipher below.
         */
        inner_cursor = inner_plain;
        ngx_memcpy(inner_cursor, "gsi\x00", 4);
        inner_cursor += 4;
        tpc_put_u32(inner_cursor, (uint32_t) kXGC_cert);
        inner_cursor += 4;
        tpc_put_u32(inner_cursor, (uint32_t) kXRS_x509);
        inner_cursor += 4;
        tpc_put_u32(inner_cursor, (uint32_t) pem_chain_len);
        inner_cursor += 4;
        ngx_memcpy(inner_cursor, bptr->data, pem_chain_len);
        inner_cursor += pem_chain_len;
        tpc_put_u32(inner_cursor, (uint32_t) kXRS_none);
        inner_cursor += 4;
        tpc_put_u32(inner_cursor, 0);
        inner_cursor += 4;

        ilen = (int) (inner_cursor - inner_plain);
        BIO_free(mbio_chain);

        ectx = EVP_CIPHER_CTX_new();
        if (ectx == NULL) {
            free(inner_plain);
            OPENSSL_free(secret);
            secret = NULL;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        /*
         * Key-length reconciliation. The DH secret length (secret_len) rarely
         * equals the cipher's default key length (ldef). We must use as much of
         * the secret as the cipher will accept as a key, matching what the
         * xrootd peer does, otherwise both sides derive different keys.
         *
         *   ltmp    = secret bytes available, clamped to EVP_MAX_KEY_LENGTH
         *   ldef    = cipher's natural key length
         *   use_len = key length we will actually set
         *
         * If ltmp != ldef we probe with a THROWAWAY ctx (tctx): try to set the
         * key length to ltmp and check it took. Only if the cipher accepts ltmp
         * do we adopt it; otherwise we fall back to ldef. The real ctx (ectx)
         * is then initialised in two steps — cipher first, key length override,
         * then key+IV — because the key length must be fixed before the key is
         * installed. The IV is all-zero (this GSI mode keys per handshake).
         */
        {
            size_t ltmp = (secret_len > (size_t) EVP_MAX_KEY_LENGTH)
                          ? (size_t) EVP_MAX_KEY_LENGTH : secret_len;
            int    ldef = EVP_CIPHER_key_length(evp_cipher);
            size_t use_len = (size_t) ldef;
            unsigned char iv[EVP_MAX_IV_LENGTH];

            if ((int) ltmp != ldef) {
                EVP_CIPHER_CTX *tctx = EVP_CIPHER_CTX_new();

                /* Probe: does this cipher accept a key of length ltmp? */
                EVP_CipherInit_ex(tctx, evp_cipher, NULL, NULL, NULL, 1);
                EVP_CIPHER_CTX_set_key_length(tctx, (int) ltmp);
                if (EVP_CIPHER_CTX_key_length(tctx) == (int) ltmp) {
                    use_len = ltmp;
                }
                EVP_CIPHER_CTX_free(tctx);
            }

            ngx_memset(iv, 0, sizeof(iv));

            /* Two-phase init: set cipher, then (if non-default) key length,
             * then bind the key+IV. Order matters — key length is locked once
             * the key is supplied. */
            EVP_EncryptInit_ex(ectx, evp_cipher, NULL, NULL, NULL);
            if (use_len != (size_t) ldef) {
                EVP_CIPHER_CTX_set_key_length(ectx, (int) use_len);
            }
            EVP_EncryptInit_ex(ectx, NULL, NULL, secret, iv);
            OPENSSL_free(secret);  /* key now copied into ectx */
            secret = NULL;
        }

        /* Ciphertext can grow by up to one block (PKCS padding from Final),
         * so size enc_out as plaintext + one cipher block. */
        enc_out = malloc((size_t) ilen + (size_t) EVP_CIPHER_block_size(evp_cipher));
        if (enc_out == NULL) {
            free(inner_plain);
            EVP_CIPHER_CTX_free(ectx);
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        if (EVP_EncryptUpdate(ectx, enc_out, &enc_len,
                              inner_plain, ilen)
            != 1)
        {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI encrypt update failed");
            free(inner_plain);
            free(enc_out);
            EVP_CIPHER_CTX_free(ectx);
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        if (EVP_EncryptFinal_ex(ectx, enc_out + enc_len, &enc_flen) != 1) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI encrypt final failed");
            free(inner_plain);
            free(enc_out);
            EVP_CIPHER_CTX_free(ectx);
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        EVP_CIPHER_CTX_free(ectx);
        free(inner_plain);

        /* Total ciphertext = Update output + Final (padding) output. */
        enc_len += enc_flen;

        /*
         * Now build OUR kXRS_puk blob to send the server, mirroring the format
         * it sent us: PEM DH params, then "---BPUB---" <our pubkey hex>
         * "---EPUB--". pbio holds the PEM params; pub_hex holds the hex pubkey.
         */
        /* Client kXRS_puk public blob (PEM params + BPUB hex) */
        pbio = BIO_new(BIO_s_mem());
        if (pbio == NULL) {
            free(enc_out);
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        PEM_write_bio_Parameters(pbio, client_kp);
        BIO_get_mem_ptr(pbio, &bptr);

        {
            BIGNUM *pub_bn = NULL;
            char   *pub_hex = NULL;
            int     wlen;

            if (!EVP_PKEY_get_bn_param(client_kp, OSSL_PKEY_PARAM_PUB_KEY,
                                       &pub_bn))
            {
                snprintf(t->err_msg, sizeof(t->err_msg),
                         "TPC GSI cannot export client DH public key");
                free(enc_out);
                BIO_free(pbio);
                pbio = NULL;
                return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
            }

            pub_hex = BN_bn2hex(pub_bn);
            BN_free(pub_bn);
            if (pub_hex == NULL) {
                free(enc_out);
                BIO_free(pbio);
                pbio = NULL;
                return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
            }

            puk_client_len = (size_t) bptr->length + strlen(pub_hex) + 64;
            puk_client = malloc(puk_client_len);
            if (puk_client == NULL) {
                OPENSSL_free(pub_hex);
                free(enc_out);
                BIO_free(pbio);
                pbio = NULL;
                return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
            }

            wlen = snprintf((char *) puk_client, puk_client_len,
                            "%.*s---BPUB---%s---EPUB--",
                            (int) bptr->length, bptr->data, pub_hex);
            OPENSSL_free(pub_hex);
            BIO_free(pbio);
            pbio = NULL;

            if (wlen <= 0 || (size_t) wlen >= puk_client_len) {
                free(enc_out);
                free(puk_client);
                return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
            }

            puk_client_len = (size_t) wlen;
        }

        /*
         * Size the round-2 outer message. Each bucket contributes an 8-byte
         * header (4-byte type tag + 4-byte length) plus its payload:
         *   4 + 4                   "gsi\0" + kXGC_cert step
         *   8 + puk_client_len      kXRS_puk bucket (our DH public blob)
         *   8 + enc_len             kXRS_main bucket (encrypted cert chain)
         *   8                       kXRS_none terminator (zero-length payload)
         */
        outer_len = 4 + 4;
        outer_len += 8 + puk_client_len;
        outer_len += 8 + (size_t) enc_len;
        outer_len += 8;

        /* Overflow guard before the +64 slack allocation below. */
        if (outer_len > (size_t)-1 - 64) {
            free(enc_out);
            free(puk_client);
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }
        outer = malloc(outer_len + 64);
        if (outer == NULL) {
            free(enc_out);
            free(puk_client);
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        /*
         * Serialise the outer message with a moving write pointer (wp), in the
         * exact order accounted for above. Each bucket: 4-byte type, 4-byte
         * length, then payload. Payload buffers are freed immediately after
         * being copied so nothing leaks on the success path.
         */
        wp = outer;
        ngx_memcpy(wp, "gsi\x00", 4);          /* protocol name */
        wp += 4;
        tpc_put_u32(wp, (uint32_t) kXGC_cert); /* handshake step */
        wp += 4;

        tpc_put_u32(wp, (uint32_t) kXRS_puk);          /* bucket: our DH pub */
        wp += 4;
        tpc_put_u32(wp, (uint32_t) puk_client_len);
        wp += 4;
        ngx_memcpy(wp, puk_client, puk_client_len);
        wp += puk_client_len;
        free(puk_client);

        tpc_put_u32(wp, (uint32_t) kXRS_main);         /* bucket: ciphertext */
        wp += 4;
        tpc_put_u32(wp, (uint32_t) enc_len);
        wp += 4;
        ngx_memcpy(wp, enc_out, (size_t) enc_len);
        wp += (size_t) enc_len;
        free(enc_out);

        tpc_put_u32(wp, (uint32_t) kXRS_none);         /* terminator bucket */
        wp += 4;
        tpc_put_u32(wp, 0);
        wp += 4;

        /* Recompute the exact length actually written (== outer_len above). */
        outer_len = (size_t) (wp - outer);

        /* The round-1 server body is no longer needed; free it before we block
         * on the round-2 round trip. NULL it so the error ladder won't double
         * free (round_fail also frees body). */
        free(body);
        body = NULL;

        /* ---- round 2: send encrypted cert chain + client puk ---- */
        /* seq=4 is this handshake's second client auth message (kXR_auth). */
        if (tpc_send_kxr_auth(t, fd, 4, outer, (uint32_t) outer_len) != 0) {
            free(outer);
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        free(outer);

        /* Await the server's verdict. kXR_ok == authenticated; any other status
         * means GSI auth was rejected. */
        body = NULL;
        if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI final auth recv failed");
            t->xrd_error = kXR_ServerError;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        if (status != kXR_ok) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI authentication failed (status=%u)",
                     (unsigned) status);
            t->xrd_error = kXR_AuthFailed;
            /* round_fail frees body — don't free it here too. */
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        /* Success: drop the verdict body and our keypair, set rc=0. We exit via
         * tpc_gsi_exchange_done (NOT _round_fail) so client_kp/body are not freed
         * twice — they are already released here. */
        free(body);
        body = NULL;
        EVP_PKEY_free(client_kp);
        client_kp = NULL;
        rc = 0;
    }

    /* Success exit: only the shared pbio remains; client_kp and body were
     * released inline above. Every error path returns earlier through
     * tpc_gsi_exchange_round_fail (keypair + body) or, before keygen,
     * tpc_gsi_exchange_done (pbio only). */
    return tpc_gsi_exchange_done(rc, pbio);
}

