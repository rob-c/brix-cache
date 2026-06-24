#include "gsi_internal.h"
#include "gsi_core.h"
#include "keypool.h"
#include "../compat/alloc_guard.h"

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
 * gsi_certreq_version — best-effort read of the client's advertised XrdSecgsi
 * version from the certreq's kXRS_version bucket (a 4-byte int).  Encoders
 * differ on byte order (our client emits big-endian; stock XrdSut writes the
 * host-order int), so accept whichever interpretation lands in the plausible
 * XrdSecgsi range; 0 when absent/implausible (caller then treats as legacy).
 */
static uint32_t
gsi_certreq_version(const u_char *payload, size_t plen)
{
    const u_char *vb = NULL;
    size_t        vlen = 0;
    uint32_t      raw, be;

    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_version, &vb, &vlen) != 0
        || vlen < 4)
    {
        return 0;
    }
    ngx_memcpy(&raw, vb, 4);            /* host-order as written by stock XrdSut */
    be = ntohl(raw);                   /* big-endian as written by our client   */
    if (be >= 10000 && be <= 99999) {
        return be;
    }
    if (raw >= 10000 && raw <= 99999) {
        return raw;
    }
    return 0;
}

/*
 * gsi_use_signed_dh — resolve the signed-DH decision for this handshake from
 * the operator policy (conf->gsi_signed_dh) and the client's advertised
 * version.  REQUIRE always signs; AUTO signs only modern (>=10400) clients;
 * OFF never signs.  An unknown client version (0) is treated as legacy.
 */
static int
gsi_use_signed_dh(ngx_uint_t policy, uint32_t client_version)
{
    if (policy == XROOTD_GSI_SDH_REQUIRE) {
        return 1;
    }
    if (policy == XROOTD_GSI_SDH_AUTO) {
        return client_version >= XROOTD_GSI_VERS_DHSIGNED;
    }
    return 0;
}

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
    char          cipher_alg[96];
    const char   *md_alg = "sha256:sha1";
    size_t        calg_len;
    size_t        malg_len = strlen(md_alg);
    int           signed_dh;
    uint32_t      pub_type;          /* kXRS_puk (unsigned) or kXRS_cipher */
    u_char       *pub_data;          /* the DH-public bucket payload to emit */
    size_t        pub_len;

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_xrootd_module);

    if (conf->gsi_cert_pem == NULL || conf->gsi_cert_pem_len == 0) {
        return NGX_ERROR;
    }
    cert_pem = conf->gsi_cert_pem;
    cert_len = conf->gsi_cert_pem_len;

    /*
     * Phase 52 (WS-A): build the advertised kXRS_cipher_alg list from the
     * configured preference (or the built-in default, aes-128-cbc first), keeping
     * ONLY ciphers this build can actually key — so a client never selects one we
     * cannot decrypt (e.g. bf-cbc without the OpenSSL legacy provider).
     */
    {
        const char *src = (conf->gsi_ciphers.len > 0)
                          ? (const char *) conf->gsi_ciphers.data
                          : xrootd_gsi_cipher_default_list();
        const char *p = src;
        size_t      out = 0;

        cipher_alg[0] = '\0';
        while (*p && out + 1 < sizeof(cipher_alg)) {
            const char *start = p;
            char        name[24];
            size_t      n;
            xrootd_gsi_cipher_t tmp;

            while (*p && *p != ':') { p++; }
            n = (size_t) (p - start);
            if (n > 0 && n < sizeof(name)) {
                ngx_memcpy(name, start, n);
                name[n] = '\0';
                if (xrootd_gsi_cipher_lookup(name, &tmp)
                    && out + n + 1 < sizeof(cipher_alg)) {
                    if (out > 0) { cipher_alg[out++] = ':'; }
                    ngx_memcpy(cipher_alg + out, name, n);
                    out += n;
                    cipher_alg[out] = '\0';
                }
            }
            if (*p == ':') { p++; }
        }
        if (out == 0) {
            ngx_cpystrn((u_char *) cipher_alg, (u_char *) "aes-128-cbc",
                        sizeof(cipher_alg));
        }
    }
    calg_len = ngx_strlen(cipher_alg);

    /*
     * Resolve the signed-DH variant for this handshake from the operator policy
     * and the client's advertised version, and record it on the connection so
     * round 2 (parse_x509.c) agrees on the padding/IV.  A REQUIRE policy with no
     * server key cannot sign — degrade to unsigned rather than fail the auth.
     */
    signed_dh = gsi_use_signed_dh(conf->gsi_signed_dh,
                                  gsi_certreq_version(ctx->payload,
                                                      ctx->cur_dlen));
    if (signed_dh && conf->gsi_key == NULL) {
        signed_dh = 0;
    }
    ctx->gsi_signed_dh = signed_dh;

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

    XROOTD_PALLOC_OR_RETURN(puk_blob, c->pool, puk_len, NGX_ERROR);
    ngx_memcpy(puk_blob, puk_buf, puk_len);

    /*
     * Choose the DH-public bucket.  Unsigned (default): the bare Public() blob
     * as kXRS_puk.  Signed-DH (>=10400): the SAME Public() blob RSA-signed with
     * the server key (XrdCryptosslRSA::EncryptPrivate) as kXRS_cipher — the
     * client recovers it with DecryptPublic against the kXRS_x509 server cert we
     * also send, authenticating the DH parameters in transit.
     */
    if (signed_dh) {
        size_t  cap = puk_len + 2 * (size_t) EVP_PKEY_size(conf->gsi_key) + 64;
        u_char *sig = ngx_palloc(c->pool, cap);

        pub_len = sig ? xrootd_gsi_rsa_encrypt_private(conf->gsi_key, puk_blob,
                                                       puk_len, sig, cap) : 0;
        if (pub_len == 0) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "xrootd: GSI signed-DH: failed to sign DH public");
            return NGX_ERROR;
        }
        pub_data = sig;
        pub_type = (uint32_t) kXRS_cipher;
    } else {
        pub_data = puk_blob;
        pub_len  = puk_len;
        pub_type = (uint32_t) kXRS_puk;
    }

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

    XROOTD_PALLOC_OR_RETURN(main_buf, c->pool, main_len, NGX_ERROR);

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
             + 4 + 4 + pub_len
             + 4 + 4 + calg_len
             + 4 + 4 + malg_len
             + 4 + 4 + cert_len
             + 4 + 4 + main_len
             + 4;

    total = XRD_RESPONSE_HDR_LEN + body_len;
    XROOTD_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

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

    *(uint32_t *) p = htonl(pub_type);
    p += 4;
    *(uint32_t *) p = htonl((uint32_t) pub_len);
    p += 4;
    ngx_memcpy(p, pub_data, pub_len);
    p += pub_len;

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
