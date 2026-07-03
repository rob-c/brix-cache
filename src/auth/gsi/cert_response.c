#include "gsi_internal.h"
#include "gsi_core.h"
#include "keypool.h"
#include "core/compat/alloc_guard.h"

/*
 * cert_response.c — GSI round 1: reply to kXGC_certreq with kXGS_cert.
 *
 * Generates an ephemeral ffdhe2048 DH key (from the per-worker keypool, so
 * keygen never runs on the event thread), advertises the keyable cipher/md
 * lists, optionally signs the DH public (signed-DH) and the client rtag with the
 * server RSA key, and emits the kXGS_cert bucket list (kXRS_puk/cipher,
 * cipher_alg, md_alg, x509, main).  Each function is documented at its
 * definition below; the wire layout is described inline at the assembly sites.
 */

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
 * gsi_certreq_clnt_opts — read the client's kXRS_clnt_opts (int32 kOpts* flags)
 * from the certreq payload. XrdSut marshals it host-order; our client emits it
 * big-endian (gsi_core.c). The flags are a small bitmask (< 256), so pick the
 * interpretation whose value is a plausible flag word. Returns 0 if absent.
 */
static uint32_t
gsi_certreq_clnt_opts(const u_char *payload, size_t plen)
{
    const u_char *ob = NULL;
    size_t        olen = 0;
    uint32_t      raw, be;

    if (gsi_find_bucket(payload, plen, (uint32_t) kXRS_clnt_opts, &ob, &olen) != 0
        || olen < 4)
    {
        return 0;
    }
    ngx_memcpy(&raw, ob, 4);
    be = ntohl(raw);
    if (be != 0 && be < 4096) {
        return be;
    }
    if (raw != 0 && raw < 4096) {
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
    if (policy == BRIX_GSI_SDH_REQUIRE) {
        return 1;
    }
    if (policy == BRIX_GSI_SDH_AUTO) {
        return client_version >= BRIX_GSI_VERS_DHSIGNED;
    }
    return 0;
}

/*
 * Phase 52 (WS-A): build the advertised kXRS_cipher_alg list into out[] (NUL-
 * terminated) from the configured preference (or the built-in default, aes-128-
 * cbc first), keeping ONLY ciphers this build can actually key — so a client
 * never selects one we cannot decrypt (e.g. bf-cbc without the OpenSSL legacy
 * provider).  Falls back to "aes-128-cbc" if nothing usable remains.
 */
static void
gsi_build_cipher_alg_list(const ngx_stream_brix_srv_conf_t *conf,
    char *out, size_t outsz)
{
    const char *src = (conf->gsi_ciphers.len > 0)
                      ? (const char *) conf->gsi_ciphers.data
                      : brix_gsi_cipher_default_list();
    const char *p = src;
    size_t      out_n = 0;

    out[0] = '\0';
    while (*p && out_n + 1 < outsz) {
        const char *start = p;
        char        name[24];
        size_t      n;
        brix_gsi_cipher_t tmp;

        while (*p && *p != ':') { p++; }
        n = (size_t) (p - start);
        if (n > 0 && n < sizeof(name)) {
            ngx_memcpy(name, start, n);
            name[n] = '\0';
            if (brix_gsi_cipher_lookup(name, &tmp)
                && out_n + n + 1 < outsz) {
                if (out_n > 0) { out[out_n++] = ':'; }
                ngx_memcpy(out + out_n, name, n);
                out_n += n;
                out[out_n] = '\0';
            }
        }
        if (*p == ':') { p++; }
    }
    if (out_n == 0) {
        ngx_cpystrn((u_char *) out, (u_char *) "aes-128-cbc", outsz);
    }
}

/*
 * Respond to kXGC_certreq with kXGS_cert.
 */

ngx_int_t
brix_gsi_send_cert(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_brix_srv_conf_t *conf;
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
                                          ngx_stream_brix_module);

    if (conf->gsi_cert_pem == NULL || conf->gsi_cert_pem_len == 0) {
        return NGX_ERROR;
    }
    cert_pem = conf->gsi_cert_pem;
    cert_len = conf->gsi_cert_pem_len;

    /* Advertise the kXRS_cipher_alg list (config preference or default, keyable
     * ciphers only).  See gsi_build_cipher_alg_list(). */
    gsi_build_cipher_alg_list(conf, cipher_alg, sizeof(cipher_alg));
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

    /* §F6: capture the client's advertised delegation mode (kXRS_clnt_opts) so a
     * later delegation round picks the flow the client actually supports —
     * kOptsFwdPxy (forward) vs kOptsDlgPxy/kOptsSigReq (sign-request). */
    ctx->gsi_clnt_opts = gsi_certreq_clnt_opts(ctx->payload, ctx->cur_dlen);
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: GSI client delegation opts=0x%02xd (fwd=%d sign=%d dlg=%d)",
                  (unsigned) ctx->gsi_clnt_opts,
                  (ctx->gsi_clnt_opts & 0x2) ? 1 : 0,
                  (ctx->gsi_clnt_opts & 0x4) ? 1 : 0,
                  (ctx->gsi_clnt_opts & 0x1) ? 1 : 0);

    /*
     * Phase 33: take a pre-generated ephemeral ffdhe2048 DH key from the
     * per-worker pool so keygen never runs on the nginx event thread under a
     * concurrent certreq burst (the head-of-line-blocking wedge).  If the pool is
     * momentarily empty, fall back to an inline keygen — correct, just not
     * offloaded.  Ownership transfers to this connection (freed after round 2).
     */
    if (!brix_gsi_keypool_pop(conf->common.thread_pool, c->log, &dhkey)) {
        dhkey = brix_gsi_dh_keygen();
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

    BRIX_PALLOC_OR_RETURN(puk_blob, c->pool, puk_len, NGX_ERROR);
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

        pub_len = sig ? brix_gsi_rsa_encrypt_private(conf->gsi_key, puk_blob,
                                                       puk_len, sig, cap) : 0;
        if (pub_len == 0) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "brix: GSI signed-DH: failed to sign DH public");
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

    BRIX_PALLOC_OR_RETURN(main_buf, c->pool, main_len, NGX_ERROR);

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
                   "brix: kXGS_cert signed rtag=%uz bytes main_len=%uz",
                   signed_rtag_len, main_len);

    body_len = 4 + 4
             + 4 + 4 + pub_len
             + 4 + 4 + calg_len
             + 4 + 4 + malg_len
             + 4 + 4 + cert_len
             + 4 + 4 + main_len
             + 4;

    total = XRD_RESPONSE_HDR_LEN + body_len;
    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_resp_hdr(ctx->cur_streamid, kXR_authmore,
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
                   "brix: kXGS_cert sent cert_len=%uz puk_len=%uz main_len=%uz",
                   cert_len, puk_len, main_len);

    return brix_queue_response(ctx, c, buf, total);
}
