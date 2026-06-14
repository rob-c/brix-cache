#include "gsi_internal.h"
#include "keypool.h"

/*---- GSI round 1 response function — generate ephemeral DH key + assemble kXGS_cert ----
 *
 * WHAT: Responds to kXGC_certreq (GSI authentication round 1) by generating an ephemeral Diffie-Hellman (DH) key pair using fffdhe2048,
 *       encoding the public key as hex blob, signing a client rtag with RSA PKCS1, and assembling the kXGS_cert wire response. */

/*---- GSI round 1 protocol flow ----
 *
 * HOW: 1) Generate ephemeral DH key pair via EVP_PKEY_CTX_new_from_name("DH") + EVP_PKEY_keygen (ffdhe2048); 
 *      2) Extract public BIGNUM → hex string; encode as "---BPUB---...---EPUB--" blob;
 *      3) PEM-write DH parameters to memory BIO for inclusion in response;
 *      4) Sign client rtag with server RSA private key (conf->gsi_key) via EVP_PKEY_sign(RSA_PKCS1_PADDING);
 *      5) Assemble kXGS_cert wire payload: gsi\0 + kXGS_cert + signed_rtag bucket + puk_blob bucket + cipher/md alg buckets. */

/*---- Ephemeral DH key generation mechanism (ffdhe2048) ----
 *
 * WHAT: Uses OpenSSL 3 EVP_PKEY_CTX_new_from_name() to generate a standard fffdhe2048 DH key pair — this is the FFDHE group from RFC 7919.
 *      The ephemeral nature means each authentication session gets a fresh key pair, preventing key reuse attacks across sessions. */

/*---- FFDHE2048 parameter configuration ----
 *
 * WHY: fffdhe2048 is the standard 2048-bit DH group from RFC 7919 — ensures interoperability with all GSI clients using standardized parameters.
 *      OSSL_PARAM_utf8_string("group", "ffdhe2048") configures OpenSSL to use this exact group for key generation. */

/*---- DH public key encoding mechanism ----
 *
 * HOW: EVP_PKEY_get_bn_param(dhkey, "pub") extracts the public BIGNUM → BN_bn2hex() converts to hex string → 
 *      snprintf formats as "---BPUB---<hex>---EPUB--" blob for inclusion in kXGS_cert wire response. */

/*---- DH key PEM encoding invariant ----
 *
 * WHY: PEM_write_bio_Parameters(bio, dhkey) writes the full DH key (private + parameters) to memory BIO — 
 *      this is stored as ctx->gsi_dh_key for use in round 2 (DH shared secret derivation via EVP_PKEY_derive()). */

/*---- Client rtag signing mechanism ----
 *
 * WHAT: If client provides an rtag (round-tag identifier), signs it with server RSA private key using EVP_PKEY_sign(RSA_PKCS1_PADDING).
 *      This provides cryptographic proof that the response came from this specific server instance. */

/*---- RSA signature generation flow ----
 *
 * HOW: 1) EVP_PKEY_CTX_new(conf->gsi_key, NULL) creates context from server private key; 
 *      2) EVP_PKEY_sign_init() + EVP_PKEY_CTX_set_rsa_padding(RSA_PKCS1_PADDING);
 *      3) EVP_PKEY_sign(sctx, signed_rtag, &slen, clnt_rtag, clnt_rtlen) produces RSA PKCS1 signature. */

/*---- kXGS_cert wire payload assembly ----
 *
 * HOW: The top-level kXGS_cert response carries five buckets, in order:
 *      kXRS_puk (puk_blob = DH public key + PEM parameters), kXRS_cipher_alg
 *      ("aes-256-cbc:aes-128-cbc:bf-cbc"), kXRS_md_alg ("sha256:sha1"),
 *      kXRS_x509 (server cert PEM), and kXRS_main.
 *      The optional signed_rtag is NOT a top-level bucket: it lives INSIDE the
 *      kXRS_main container bucket. kXRS_main is itself a nested bucket list
 *      ("gsi\0" + kXGS_cert opcode + optional kXRS_signed_rtag bucket +
 *      kXRS_none terminator) that is then wrapped as the kXRS_main top-level
 *      bucket — see the kXRS_main assembly at L186-216 and its packing at L277. */

/*---- Cipher algorithm negotiation list ----
 *
 * WHY: Client specifies supported ciphers in kXRS_cipher_alg; server lists supported ciphers in response as colon-separated OpenSSL names.
 *      "aes-256-cbc:aes-128-cbc:bf-cbc" represents the GSI wire protocol standard cipher preference order. */

/*---- MD algorithm negotiation list ----
 *
 * WHY: Server lists supported message digest algorithms for future operations as colon-separated OpenSSL names.
 *      "sha256:sha1" represents the GSI wire protocol standard digest preference order (SHA-256 preferred). */

/*---- kXGS_cert wire response entry point ----
 *
 * WHAT: Called from src/gsi/auth.c as part of kXGC_certreq handling after credential type verification. Returns ngx_int_t result. */

/*
 * Respond to kXGC_certreq with kXGS_cert.
 */

ngx_int_t
xrootd_gsi_send_cert(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    EVP_PKEY     *dhkey = NULL;
    BIGNUM       *pub_bn = NULL;
    char         *pub_hex = NULL;
    BIO          *bio;
    BUF_MEM      *bptr;
    u_char       *buf, *p;
    u_char       *cert_pem, *puk_blob;
    size_t        cert_len, puk_len, body_len, total;
    char          puk_buf[4096];
    int           puk_written;
    const u_char *main_data = NULL;
    size_t        main_dlen = 0;
    const u_char *clnt_rtag = NULL;
    size_t        clnt_rtlen = 0;
    u_char       *signed_rtag = NULL;
    size_t        signed_rtag_len = 0;
    size_t        main_len;
    u_char       *main_buf;
    const char   *cipher_alg = "aes-256-cbc:aes-128-cbc:bf-cbc";
    const char   *md_alg = "sha256:sha1";
    size_t        calg_len = strlen(cipher_alg);
    size_t        malg_len = strlen(md_alg);

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_xrootd_module);

    if (conf->gsi_cert_pem == NULL || conf->gsi_cert_pem_len == 0) {
        return NGX_ERROR;
    }
    cert_pem = conf->gsi_cert_pem;
    cert_len = conf->gsi_cert_pem_len;

    /*
     * Phase 33: take a pre-generated ephemeral ffdhe2048 DH key from the
     * per-worker pool so keygen never runs on the nginx event thread under a
     * concurrent certreq burst (the head-of-line-blocking wedge).  If the pool is
     * momentarily empty, fall back to an inline keygen — correct, just not
     * offloaded.  Ownership transfers to this connection (freed after round 2).
     */
    if (!xrootd_gsi_keypool_pop(conf->common.thread_pool, c->log, &dhkey)) {
        dhkey = xrootd_gsi_dh_keygen();
        if (dhkey == NULL) {
            return NGX_ERROR;
        }
    }

    if (!EVP_PKEY_get_bn_param(dhkey, "pub", &pub_bn)) {
        EVP_PKEY_free(dhkey);
        return NGX_ERROR;
    }
    pub_hex = BN_bn2hex(pub_bn);
    BN_free(pub_bn);
    if (pub_hex == NULL) {
        EVP_PKEY_free(dhkey);
        return NGX_ERROR;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        OPENSSL_free(pub_hex);
        EVP_PKEY_free(dhkey);
        return NGX_ERROR;
    }
    PEM_write_bio_Parameters(bio, dhkey);
    ctx->gsi_dh_key = dhkey;
    BIO_get_mem_ptr(bio, &bptr);

    puk_written = snprintf(puk_buf, sizeof(puk_buf),
                           "%.*s---BPUB---%s---EPUB--",
                           (int) bptr->length, bptr->data, pub_hex);
    BIO_free(bio);
    OPENSSL_free(pub_hex);

    if (puk_written <= 0 || (size_t) puk_written >= sizeof(puk_buf)) {
        return NGX_ERROR;
    }
    puk_len = (size_t) puk_written;

    puk_blob = ngx_palloc(c->pool, puk_len);
    if (puk_blob == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(puk_blob, puk_buf, puk_len);

    if (gsi_find_bucket(ctx->payload, ctx->cur_dlen,
                        (uint32_t) kXRS_main, &main_data, &main_dlen) == 0) {
        gsi_find_bucket(main_data, main_dlen,
                        (uint32_t) kXRS_rtag, &clnt_rtag, &clnt_rtlen);
    }

    if (clnt_rtag && clnt_rtlen > 0) {
        EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new(conf->gsi_key, NULL);

        if (sctx) {
            size_t slen = (size_t) EVP_PKEY_size(conf->gsi_key);

            signed_rtag = ngx_palloc(c->pool, slen);
            if (signed_rtag
                && EVP_PKEY_sign_init(sctx) > 0
                && EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PADDING) > 0
                && EVP_PKEY_sign(sctx, signed_rtag, &slen,
                                 clnt_rtag, clnt_rtlen) > 0)
            {
                signed_rtag_len = slen;
            } else {
                signed_rtag = NULL;
            }
            EVP_PKEY_CTX_free(sctx);
        }
    }

    /*
     * Build the kXRS_main container — a nested bucket list that the kXGS_cert
     * response carries as a single top-level kXRS_main bucket (packed at L277).
     * It is NOT a flat field: it re-encapsulates its own protocol header plus
     * an inner bucket list.  Inner wire layout (network byte order throughout):
     *   "gsi\0"                      protocol name (4 bytes, NUL-padded)
     *   kXGS_cert                    opcode (uint32, 4 bytes)
     *   [ kXRS_signed_rtag bucket ]  optional: type(4) + len(4) + signature
     *   kXRS_none                    terminator (uint32, 4 bytes)
     * main_len reserves the fixed 12 bytes (name + opcode + terminator) and,
     * when the rtag was signed, the 8-byte bucket header plus the signature.
     * The mp pointer walks main_buf byte-by-byte to emit this layout below.
     */
    main_len = 4 + 4 + 4;
    if (signed_rtag_len > 0) {
        main_len += 4 + 4 + signed_rtag_len;
    }

    main_buf = ngx_palloc(c->pool, main_len);
    if (main_buf == NULL) {
        return NGX_ERROR;
    }

    {
        u_char *mp = main_buf;

        mp[0] = 'g';
        mp[1] = 's';
        mp[2] = 'i';
        mp[3] = '\0';
        mp += 4;
        *(uint32_t *) mp = htonl(kXGS_cert);
        mp += 4;
        if (signed_rtag_len > 0) {
            *(uint32_t *) mp = htonl(kXRS_signed_rtag);
            mp += 4;
            *(uint32_t *) mp = htonl((uint32_t) signed_rtag_len);
            mp += 4;
            ngx_memcpy(mp, signed_rtag, signed_rtag_len);
            mp += signed_rtag_len;
        }
        *(uint32_t *) mp = htonl(kXRS_none);
        mp += 4;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXGS_cert signed rtag=%uz bytes main_len=%uz",
                   signed_rtag_len, main_len);

    body_len = 4 + 4
             + 4 + 4 + puk_len
             + 4 + 4 + calg_len
             + 4 + 4 + malg_len
             + 4 + 4 + cert_len
             + 4 + 4 + main_len
             + 4;

    total = XRD_RESPONSE_HDR_LEN + body_len;
    buf = ngx_palloc(c->pool, total);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    xrootd_build_resp_hdr(ctx->cur_streamid, kXR_authmore,
                          (uint32_t) body_len, (ServerResponseHdr *) buf);

    p = buf + XRD_RESPONSE_HDR_LEN;

    p[0] = 'g';
    p[1] = 's';
    p[2] = 'i';
    p[3] = '\0';
    p += 4;
    *(uint32_t *) p = htonl(kXGS_cert);
    p += 4;

    *(uint32_t *) p = htonl(kXRS_puk);
    p += 4;
    *(uint32_t *) p = htonl((uint32_t) puk_len);
    p += 4;
    ngx_memcpy(p, puk_blob, puk_len);
    p += puk_len;

    *(uint32_t *) p = htonl(kXRS_cipher_alg);
    p += 4;
    *(uint32_t *) p = htonl((uint32_t) calg_len);
    p += 4;
    ngx_memcpy(p, cipher_alg, calg_len);
    p += calg_len;

    *(uint32_t *) p = htonl(kXRS_md_alg);
    p += 4;
    *(uint32_t *) p = htonl((uint32_t) malg_len);
    p += 4;
    ngx_memcpy(p, md_alg, malg_len);
    p += malg_len;

    *(uint32_t *) p = htonl(kXRS_x509);
    p += 4;
    *(uint32_t *) p = htonl((uint32_t) cert_len);
    p += 4;
    ngx_memcpy(p, cert_pem, cert_len);
    p += cert_len;

    *(uint32_t *) p = htonl(kXRS_main);
    p += 4;
    *(uint32_t *) p = htonl((uint32_t) main_len);
    p += 4;
    ngx_memcpy(p, main_buf, main_len);
    p += main_len;

    *(uint32_t *) p = htonl(kXRS_none);
    p += 4;

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "xrootd: kXGS_cert sent cert_len=%uz puk_len=%uz main_len=%uz",
                   cert_len, puk_len, main_len);

    return xrootd_queue_response(ctx, c, buf, total);
}
