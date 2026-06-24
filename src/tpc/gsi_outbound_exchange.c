#include "tpc_internal.h"
#include "../session/session.h"
#include "../protocol/gsi.h"
#include "../gsi/gsi_core.h"   /* shared XrdSecgsi DH/cipher kernel (EOS-proven) */

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

/* The session cipher this outbound (plain-DH) path keys and echoes back to the
 * server in kXRS_cipher_alg.  Kept in lock-step with the xrootd_gsi_cipher_lookup
 * call below; aes-128-cbc is the universally-supported XrdSecgsi default. */
#define XRDC_TPC_CIPHER_ALG  "aes-128-cbc"

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
        EVP_PKEY              *peer = NULL;
        const u_char *puk_blob;
        size_t        puk_blob_len;
        BUF_MEM       *bptr;
        uint8_t                aeskey[XROOTD_GSI_MAX_KEY];
        xrootd_gsi_cipher_t    cipher;
        u_char                *inner_plain = NULL;
        int                    ilen = 0;
        u_char                *inner_cursor;
        BIO                   *mbio_chain;
        u_char                *enc_out = NULL;
        int                    enc_len = 0;
        size_t                 enc_out_len = 0;
        size_t                 pem_chain_len = 0;
        u_char                *puk_client = NULL;
        size_t                 puk_client_len;
        u_char                *outer = NULL;
        size_t                 outer_len;
        u_char                *wp;
        int                    ci;
        char                   md_alg[32];        /* digest echoed to the server  */
        size_t                 md_alg_len;
        size_t                 cipher_alg_len;    /* len of XRDC_TPC_CIPHER_ALG    */

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
         * Agree the AES-128 session key via the shared gsi_core kernel — the exact
         * DH-parse + keygen + secret-derive + key-derivation the native client uses
         * (proven wire-compatible vs real EOS + stock XrdSecgsi). parse_peer reads
         * the server's "<PEM params>---BPUB---<hex>---EPUB--" kXRS_puk blob;
         * keygen_from mints OUR key in the same DH group (kept in client_kp for the
         * round-2 puk + freed at the end); session_key derives the 16-byte key.
         * This is the plain-DH (kXRS_puk, unsigned) path → padded = 0. Replaces
         * ~135 lines of raw-OpenSSL DH params/keygen/peer/derive + cipher select.
         */
        /* Phase 52: TPC outbound keys aes-128-cbc (the universal default every
         * conformant TPC-source server advertises); resolve its descriptor. */
        peer = xrootd_gsi_cipher_parse_peer(puk_blob, puk_blob_len);
        client_kp = (peer != NULL) ? xrootd_gsi_cipher_keygen_from(peer) : NULL;
        if (peer == NULL || client_kp == NULL
            || !xrootd_gsi_cipher_lookup("aes-128-cbc", &cipher)
            || !xrootd_gsi_cipher_session_key(client_kp, peer, 0, aeskey,
                                              cipher.key_len))
        {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI DH session-key agreement failed");
            t->xrd_error = kXR_NotAuthorized;
            EVP_PKEY_free(peer);
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }
        EVP_PKEY_free(peer);
        peer = NULL;

        /* Inner buffer: gsi + step + kXRS_x509(certs PEM) + none */
        mbio_chain = BIO_new(BIO_s_mem());
        if (mbio_chain == NULL) {
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
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }
        inner_plain = malloc(256 + pem_chain_len + 64);
        if (inner_plain == NULL) {
            BIO_free(mbio_chain);
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

        /*
         * Encrypt the inner (kXRS_main) under the AES-128 session key via the
         * shared kernel — use_iv = 0 (zero IV, nothing prepended) for the plain-DH
         * path, exactly as the native client does. Replaces ~90 lines of raw EVP
         * cipher-context setup + DH-secret key-length reconciliation.
         */
        enc_out = xrootd_gsi_cipher_encrypt(&cipher, aeskey, inner_plain,
                                            (size_t) ilen, 0, &enc_out_len);
        free(inner_plain);
        inner_plain = NULL;
        if (enc_out == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI main encrypt failed");
            t->xrd_error = kXR_ServerError;
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }
        enc_len = (int) enc_out_len;

        /*
         * OUR kXRS_puk blob (PEM DH params + "---BPUB---"<hex>"---EPUB---") built
         * by the shared gsi_core encoder — the exact one the native client uses,
         * proven wire-compatible against real EOS + stock XrdSecgsi. Replaces ~55
         * lines of duplicated raw-OpenSSL PEM-params + BN_bn2hex + snprintf. (The
         * encoder emits a 3-dash "---EPUB---" terminator vs the legacy 2-dash
         * "---EPUB--"; XrdSecgsi delimits the hex on the marker prefix, so both
         * are accepted — verified by tests/test_tpc_gsi_outbound.py.)
         */
        puk_client = (u_char *) xrootd_gsi_cipher_public(client_kp,
                                                         &puk_client_len);
        if (puk_client == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI cannot encode client DH public key");
            t->xrd_error = kXR_ServerError;
            free(enc_out);
            return tpc_gsi_exchange_round_fail(rc, client_kp, body, pbio);
        }

        /*
         * Size the round-2 outer message. Each bucket contributes an 8-byte
         * header (4-byte type tag + 4-byte length) plus its payload:
         *   4 + 4                   "gsi\0" + kXGC_cert step
         *   8 + puk_client_len      kXRS_puk bucket (our DH public blob)
         *   8 + enc_len             kXRS_main bucket (encrypted cert chain)
         *   8                       kXRS_none terminator (zero-length payload)
         */
        /*
         * Echo the cipher we keyed (bare name — use_iv=0 on this plain-DH path,
         * so no "#ivlen" suffix) and a digest chosen from the server's
         * kXRS_md_alg offer (prefer sha256, else its first token, default
         * sha256).  dCache's GSI plugin reads kXRS_cipher_alg and kXRS_md_alg as
         * MANDATORY StringBuckets and throws a server-side NPE when either is
         * absent ("digestBucket is null"); stock XRootD/EOS accept them as the
         * normal client echo.  This is the outbound (TPC) twin of the native
         * client's md_alg fix — see
         * docs/10-reference/comparison/xrootd-implementations.md §5 and
         * tests/test_gsi_interop_guards.py. */
        {
            const u_char *mlist = NULL;
            size_t        mlen = 0, i;

            md_alg_len = 0;
            if (gsi_find_bucket(body, dlen, (uint32_t) kXRS_md_alg,
                                &mlist, &mlen) == 0 && mlen > 0) {
                for (i = 0; i + 6 <= mlen; i++) {
                    if (ngx_memcmp(mlist + i, "sha256", 6) == 0) {
                        ngx_memcpy(md_alg, "sha256", 6);
                        md_alg_len = 6;
                        break;
                    }
                }
                if (md_alg_len == 0) {              /* echo the server's first token */
                    while (md_alg_len < mlen && md_alg_len + 1 < sizeof(md_alg)
                           && mlist[md_alg_len] != ':') {
                        md_alg[md_alg_len] = (char) mlist[md_alg_len];
                        md_alg_len++;
                    }
                }
            }
            if (md_alg_len == 0) {                  /* server offered none → default */
                ngx_memcpy(md_alg, "sha256", 6);
                md_alg_len = 6;
            }
            md_alg[md_alg_len] = '\0';
        }
        cipher_alg_len = ngx_strlen(XRDC_TPC_CIPHER_ALG);

        outer_len = 4 + 4;
        outer_len += 8 + puk_client_len;
        outer_len += 8 + cipher_alg_len;            /* kXRS_cipher_alg */
        outer_len += 8 + md_alg_len;                /* kXRS_md_alg */
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

        tpc_put_u32(wp, (uint32_t) kXRS_cipher_alg);   /* bucket: chosen cipher */
        wp += 4;
        tpc_put_u32(wp, (uint32_t) cipher_alg_len);
        wp += 4;
        ngx_memcpy(wp, XRDC_TPC_CIPHER_ALG, cipher_alg_len);
        wp += cipher_alg_len;

        tpc_put_u32(wp, (uint32_t) kXRS_md_alg);       /* bucket: chosen digest */
        wp += 4;
        tpc_put_u32(wp, (uint32_t) md_alg_len);
        wp += 4;
        ngx_memcpy(wp, md_alg, md_alg_len);
        wp += md_alg_len;

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

