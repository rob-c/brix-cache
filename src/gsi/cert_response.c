#include "gsi_internal.h"

/*
 * Respond to kXGC_certreq with kXGS_cert.
 */

ngx_int_t
xrootd_gsi_send_cert(xrootd_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    EVP_PKEY_CTX *pctx;
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

    {
        OSSL_PARAM dh_params[] = {
            OSSL_PARAM_utf8_string("group", "ffdhe2048", 0),
            OSSL_PARAM_END
        };

        pctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL);
        if (pctx == NULL) {
            return NGX_ERROR;
        }
        EVP_PKEY_keygen_init(pctx);
        EVP_PKEY_CTX_set_params(pctx, dh_params);
        if (EVP_PKEY_keygen(pctx, &dhkey) <= 0) {
            EVP_PKEY_CTX_free(pctx);
            return NGX_ERROR;
        }
        EVP_PKEY_CTX_free(pctx);
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
