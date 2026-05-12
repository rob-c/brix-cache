/*
 * gsi_outbound.c — credentialed XRootD login for native TPC pulls.
 *
 * After kXR_login returns kXR_authmore, completes kXR_auth using either:
 *   - WLCG JWT (ztn) from xrootd_tpc_outbound_bearer_file when the server
 *     advertises &P=ztn in the login parameter block, or
 *   - GSI (gsi) using xrootd_certificate / xrootd_certificate_key when the
 *     server advertises &P=gsi (full kXGC_certreq → kXGS_cert → kXGC_cert).
 */

#include "tpc_internal.h"

#if (NGX_THREADS)

#include "../session/session.h"
#include "../protocol/gsi.h"

#include <stdio.h>
#include <ctype.h>
#include <errno.h>

#if defined(__linux__)
#include <endian.h>
#endif

#define TPC_BEARER_MAX     65536
#define TPC_GSI_MAX_BODY   (256 * 1024)

static void
tpc_put_u32(u_char *p, uint32_t v)
{
    uint32_t be;

    be = htonl(v);
    ngx_memcpy(p, &be, sizeof(be));
}

static int
tpc_send_kxr_auth(xrootd_tpc_pull_t *t, int fd, u_char stream_seq,
    const u_char *cred_payload, uint32_t cred_len)
{
    ClientRequestHdr  hdr;
    u_char            ctype[4];

    ngx_memzero(&hdr, sizeof(hdr));
    hdr.streamid[1]    = stream_seq;
    hdr.requestid      = htons(kXR_auth);
    ngx_memcpy(ctype, cred_payload, sizeof(ctype));
    ngx_memcpy(hdr.body + 12, ctype, 4);
    hdr.dlen           = htonl((kXR_int32) cred_len);

    if (tpc_send_all(fd, &hdr, sizeof(hdr)) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_auth send hdr failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    if (tpc_send_all(fd, cred_payload, cred_len) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC kXR_auth send body failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }

    return 0;
}

static int
tpc_read_bearer_token(xrootd_tpc_pull_t *t, u_char *buf, size_t buf_sz,
    size_t *out_len)
{
    FILE          *fp;
    char           pathz[PATH_MAX];
    ngx_str_t     *path;
    size_t         n, tail;

    path = &t->conf->tpc_outbound_bearer_file;
    if (path->len == 0 || path->len >= sizeof(pathz)) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC outbound bearer file path invalid or missing");
        t->xrd_error = kXR_ArgInvalid;
        return -1;
    }

    ngx_memcpy(pathz, path->data, path->len);
    pathz[path->len] = '\0';

    fp = fopen(pathz, "rb");
    if (fp == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC cannot open xrootd_tpc_outbound_bearer_file: %s",
                 strerror(errno));
        t->xrd_error = kXR_IOError;
        return -1;
    }

    n = fread(buf, 1, buf_sz - 1, fp);
    fclose(fp);
    buf[n] = '\0';

    while (n > 0 && isspace((unsigned char) buf[n - 1])) {
        buf[--n] = '\0';
    }

    tail = n;
    while (tail > 0 && isspace((unsigned char) buf[tail - 1])) {
        tail--;
    }
    n = tail;

    if (n == 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC outbound bearer file is empty");
        t->xrd_error = kXR_ArgInvalid;
        return -1;
    }

    *out_len = n;
    return 0;
}

static int
tpc_outbound_ztn(xrootd_tpc_pull_t *t, int fd)
{
    u_char         *cred;
    uint32_t        cred_len;
    uint16_t        status;
    uint32_t        dlen;
    u_char         *body;
    size_t          token_len;

    /*
     * Use the delegated token from OAuth2/OIDC token exchange when available;
     * otherwise fall back to reading from the bearer file.
     */
    if (t->delegated_token[0] != '\0') {
        token_len = strlen(t->delegated_token);
    } else {
        u_char token_buf[TPC_BEARER_MAX];
        if (tpc_read_bearer_token(t, token_buf, sizeof(token_buf), &token_len)
            != 0)
        {
            return -1;
        }
        ngx_memcpy(t->delegated_token, token_buf, token_len + 1);
        token_len = strlen(t->delegated_token);
    }

    cred_len = (uint32_t) (4 + token_len);
    cred = malloc((size_t) cred_len);
    if (cred == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC ztn cred OOM");
        t->xrd_error = kXR_NoMemory;
        return -1;
    }

    ngx_memcpy(cred, "ztn\x00", 4);
    ngx_memcpy(cred + 4, t->delegated_token, token_len);

    if (tpc_send_kxr_auth(t, fd, 3, cred, cred_len) != 0) {
        free(cred);
        return -1;
    }
    free(cred);

    body = NULL;
    if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg), "TPC ztn auth recv failed");
        t->xrd_error = kXR_ServerError;
        return -1;
    }
    free(body);

    if (status != kXR_ok) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC ztn auth rejected (status=%u)", (unsigned) status);
        t->xrd_error = kXR_AuthFailed;
        return -1;
    }

    return 0;
}

static void
tpc_gsi_select_cipher(const u_char *payload, size_t payload_len,
    char *cipher_name, size_t cipher_name_size)
{
    const u_char *cipher_bucket;
    size_t        cipher_bucket_len;
    size_t        name_len;

    ngx_cpystrn((u_char *) cipher_name, (u_char *) "aes-256-cbc",
                cipher_name_size);

    if (gsi_find_bucket(payload, payload_len, (uint32_t) kXRS_cipher_alg,
                        &cipher_bucket, &cipher_bucket_len)
        != 0 || cipher_bucket_len == 0)
    {
        return;
    }

    for (name_len = 0;
         name_len < cipher_bucket_len && name_len < cipher_name_size - 1;
         name_len++)
    {
        if (cipher_bucket[name_len] == ':') {
            break;
        }
        cipher_name[name_len] = (char) cipher_bucket[name_len];
    }

    cipher_name[name_len] = '\0';
}

static BIGNUM *
tpc_parse_hex_pub(const u_char *puk_data, size_t puk_len)
{
    static const char begin_marker[] = "---BPUB---";
    static const char end_marker[]   = "---EPUB--";
    const u_char     *hex_start;
    const u_char     *hex_end;
    char             *hex_copy;
    size_t            hex_len;
    BIGNUM           *bn;

    hex_start = memmem(puk_data, puk_len, begin_marker, sizeof(begin_marker) - 1);
    hex_end = memmem(puk_data, puk_len, end_marker, sizeof(end_marker) - 1);

    if (hex_start == NULL || hex_end == NULL
        || hex_end <= hex_start + (int) sizeof(begin_marker) - 1)
    {
        return NULL;
    }

    hex_start += sizeof(begin_marker) - 1;
    hex_len = (size_t) (hex_end - hex_start);

    hex_copy = malloc(hex_len + 1);
    if (hex_copy == NULL) {
        return NULL;
    }

    ngx_memcpy(hex_copy, hex_start, hex_len);
    hex_copy[hex_len] = '\0';

    bn = NULL;
    if (BN_hex2bn(&bn, hex_copy) == 0) {
        bn = NULL;
    }

    free(hex_copy);
    return bn;
}

static EVP_PKEY *
tpc_dh_peer_from(EVP_PKEY *local_key, BIGNUM *peer_pub_bn)
{
    EVP_PKEY_CTX   *pkey_ctx;
    EVP_PKEY       *peer_key;
    OSSL_PARAM_BLD *param_builder;
    OSSL_PARAM     *server_params;
    OSSL_PARAM     *client_params;
    OSSL_PARAM     *merged_params;

    pkey_ctx = NULL;
    peer_key = NULL;
    param_builder = NULL;
    server_params = NULL;
    client_params = NULL;
    merged_params = NULL;

    if (EVP_PKEY_todata(local_key, EVP_PKEY_KEY_PARAMETERS, &server_params)
        != 1 || server_params == NULL)
    {
        goto done;
    }

    param_builder = OSSL_PARAM_BLD_new();
    if (param_builder == NULL
        || OSSL_PARAM_BLD_push_BN(param_builder, OSSL_PKEY_PARAM_PUB_KEY,
                                  peer_pub_bn)
           != 1)
    {
        goto done;
    }

    client_params = OSSL_PARAM_BLD_to_param(param_builder);
    if (client_params == NULL) {
        goto done;
    }

    merged_params = OSSL_PARAM_merge(server_params, client_params);
    if (merged_params == NULL) {
        goto done;
    }

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (pkey_ctx == NULL
        || EVP_PKEY_fromdata_init(pkey_ctx) != 1
        || EVP_PKEY_fromdata(pkey_ctx, &peer_key, EVP_PKEY_PUBLIC_KEY,
                             merged_params)
           != 1)
    {
        if (peer_key) {
            EVP_PKEY_free(peer_key);
            peer_key = NULL;
        }
        goto done;
    }

done:
    EVP_PKEY_CTX_free(pkey_ctx);
    OSSL_PARAM_BLD_free(param_builder);
    OSSL_PARAM_free(server_params);
    OSSL_PARAM_free(client_params);
    OSSL_PARAM_free(merged_params);

    return peer_key;
}

static int
tpc_outbound_gsi(xrootd_tpc_pull_t *t, int fd)
{
    ngx_stream_xrootd_srv_conf_t *conf = t->conf;
    u_char           cert_path[PATH_MAX];
    u_char           key_path[PATH_MAX];
    BIO             *cbio = NULL, *kbio = NULL, *pbio = NULL;
    X509            *x = NULL;
    STACK_OF(X509)  *chain = NULL;
    EVP_PKEY        *pkey = NULL;
    u_char          *certreq = NULL;
    u_char          *body = NULL;
    uint16_t         status;
    uint32_t         dlen;
    int              rc = -1;

    if (conf->certificate.len == 0 || conf->certificate_key.len == 0
        || conf->certificate.len >= sizeof(cert_path)
        || conf->certificate_key.len >= sizeof(key_path))
    {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI outbound needs xrootd_certificate and "
                 "xrootd_certificate_key");
        t->xrd_error = kXR_ArgInvalid;
        return -1;
    }

    ngx_memcpy(cert_path, conf->certificate.data, conf->certificate.len);
    cert_path[conf->certificate.len] = '\0';
    ngx_memcpy(key_path, conf->certificate_key.data, conf->certificate_key.len);
    key_path[conf->certificate_key.len] = '\0';

    cbio = BIO_new_file((char *) cert_path, "r");
    kbio = BIO_new_file((char *) key_path, "r");
    if (cbio == NULL || kbio == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI cannot read certificate or key PEM");
        t->xrd_error = kXR_IOError;
        goto done;
    }

    chain = sk_X509_new_null();
    if (chain == NULL) {
        goto done;
    }

    while ((x = PEM_read_bio_X509(cbio, NULL, NULL, NULL)) != NULL) {
        sk_X509_push(chain, x);
        x = NULL;
    }

    if (sk_X509_num(chain) == 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI certificate file has no X.509 certs");
        t->xrd_error = kXR_ArgInvalid;
        goto done;
    }

    pkey = PEM_read_bio_PrivateKey(kbio, NULL, NULL, NULL);
    if (pkey == NULL) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI cannot read private key PEM");
        t->xrd_error = kXR_ArgInvalid;
        goto done;
    }

    /* ---- round 1: kXGC_certreq ---- */
    {
        size_t crlen = 4 + 4 + 8;
        u_char *cr;

        certreq = malloc(crlen);
        if (certreq == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg), "TPC GSI certreq OOM");
            t->xrd_error = kXR_NoMemory;
            goto done;
        }

        cr = certreq;
        ngx_memcpy(cr, "gsi\x00", 4);
        cr += 4;
        tpc_put_u32(cr, (uint32_t) kXGC_certreq);
        cr += 4;
        tpc_put_u32(cr, (uint32_t) kXRS_none);
        cr += 4;
        tpc_put_u32(cr, 0);

        if (tpc_send_kxr_auth(t, fd, 3, certreq, (uint32_t) crlen) != 0) {
            goto done;
        }
    }

    body = NULL;
    if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI kXGS_cert recv failed");
        t->xrd_error = kXR_ServerError;
        goto done;
    }

    if (status != kXR_authmore || body == NULL || dlen < 16) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC GSI expected kXR_authmore after certreq (status=%u)",
                 (unsigned) status);
        t->xrd_error = kXR_AuthFailed;
        goto done;
    }

    /*
     * Optional: verify server leaf cert using our CA store when configured.
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
                        goto done;
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
        EVP_PKEY              *client_kp = NULL;
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
            goto round_fail;
        }

        bp_marker = memmem(puk_blob, puk_blob_len, "---BPUB---",
                           sizeof("---BPUB---") - 1);
        if (bp_marker == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI malformed server DH puk");
            t->xrd_error = kXR_NotAuthorized;
            goto round_fail;
        }

        pbio_mem = BIO_new_mem_buf(puk_blob, (int) (bp_marker - puk_blob));
        if (pbio_mem == NULL) {
            goto round_fail;
        }

        dh_params = PEM_read_bio_Parameters_ex(pbio_mem, NULL, NULL, NULL);
        BIO_free(pbio_mem);

        if (dh_params == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI cannot parse server DH PEM parameters");
            t->xrd_error = kXR_NotAuthorized;
            goto round_fail;
        }

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
            goto round_fail;
        }
        EVP_PKEY_CTX_free(kgctx);
        kgctx = NULL;
        EVP_PKEY_free(dh_params);
        dh_params = NULL;

        srv_pub_bn = tpc_parse_hex_pub(puk_blob, puk_blob_len);
        if (srv_pub_bn == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI cannot parse server DH public hex");
            t->xrd_error = kXR_NotAuthorized;
            goto round_fail;
        }

        srv_peer = tpc_dh_peer_from(client_kp, srv_pub_bn);
        BN_free(srv_pub_bn);
        srv_pub_bn = NULL;

        if (srv_peer == NULL) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI cannot build server DH peer key");
            t->xrd_error = kXR_ServerError;
            goto round_fail;
        }

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
            goto round_fail;
        }

        if (EVP_PKEY_derive(dkctx, NULL, &secret_len) != 1) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI DH derive size failed");
            t->xrd_error = kXR_ServerError;
            EVP_PKEY_CTX_free(dkctx);
            dkctx = NULL;
            EVP_PKEY_free(srv_peer);
            srv_peer = NULL;
            goto round_fail;
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
            goto round_fail;
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
            goto round_fail;
        }

        /* Inner buffer: gsi + step + kXRS_x509(certs PEM) + none */
        mbio_chain = BIO_new(BIO_s_mem());
        if (mbio_chain == NULL) {
            OPENSSL_free(secret);
            secret = NULL;
            goto round_fail;
        }

        for (ci = 0; ci < sk_X509_num(chain); ci++) {
            PEM_write_bio_X509(mbio_chain, sk_X509_value(chain, ci));
        }
        BIO_get_mem_ptr(mbio_chain, &bptr);
        pem_chain_len = bptr->length;

        inner_plain = malloc(256 + pem_chain_len + 64);
        if (inner_plain == NULL) {
            BIO_free(mbio_chain);
            OPENSSL_free(secret);
            secret = NULL;
            goto round_fail;
        }

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
            goto round_fail;
        }

        {
            size_t ltmp = (secret_len > (size_t) EVP_MAX_KEY_LENGTH)
                          ? (size_t) EVP_MAX_KEY_LENGTH : secret_len;
            int    ldef = EVP_CIPHER_key_length(evp_cipher);
            size_t use_len = (size_t) ldef;
            unsigned char iv[EVP_MAX_IV_LENGTH];

            if ((int) ltmp != ldef) {
                EVP_CIPHER_CTX *tctx = EVP_CIPHER_CTX_new();

                EVP_CipherInit_ex(tctx, evp_cipher, NULL, NULL, NULL, 1);
                EVP_CIPHER_CTX_set_key_length(tctx, (int) ltmp);
                if (EVP_CIPHER_CTX_key_length(tctx) == (int) ltmp) {
                    use_len = ltmp;
                }
                EVP_CIPHER_CTX_free(tctx);
            }

            ngx_memset(iv, 0, sizeof(iv));

            EVP_EncryptInit_ex(ectx, evp_cipher, NULL, NULL, NULL);
            if (use_len != (size_t) ldef) {
                EVP_CIPHER_CTX_set_key_length(ectx, (int) use_len);
            }
            EVP_EncryptInit_ex(ectx, NULL, NULL, secret, iv);
            OPENSSL_free(secret);
            secret = NULL;
        }

        enc_out = malloc((size_t) ilen + (size_t) EVP_CIPHER_block_size(evp_cipher));
        if (enc_out == NULL) {
            free(inner_plain);
            EVP_CIPHER_CTX_free(ectx);
            goto round_fail;
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
            goto round_fail;
        }

        if (EVP_EncryptFinal_ex(ectx, enc_out + enc_len, &enc_flen) != 1) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI encrypt final failed");
            free(inner_plain);
            free(enc_out);
            EVP_CIPHER_CTX_free(ectx);
            goto round_fail;
        }

        EVP_CIPHER_CTX_free(ectx);
        free(inner_plain);

        enc_len += enc_flen;

        /* Client kXRS_puk public blob (PEM params + BPUB hex) */
        pbio = BIO_new(BIO_s_mem());
        if (pbio == NULL) {
            free(enc_out);
            goto round_fail;
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
                goto round_fail;
            }

            pub_hex = BN_bn2hex(pub_bn);
            BN_free(pub_bn);
            if (pub_hex == NULL) {
                free(enc_out);
                BIO_free(pbio);
                pbio = NULL;
                goto round_fail;
            }

            puk_client_len = (size_t) bptr->length + strlen(pub_hex) + 64;
            puk_client = malloc(puk_client_len);
            if (puk_client == NULL) {
                OPENSSL_free(pub_hex);
                free(enc_out);
                BIO_free(pbio);
                pbio = NULL;
                goto round_fail;
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
                goto round_fail;
            }

            puk_client_len = (size_t) wlen;
        }

        outer_len = 4 + 4;
        outer_len += 8 + puk_client_len;
        outer_len += 8 + (size_t) enc_len;
        outer_len += 8;

        outer = malloc(outer_len + 64);
        if (outer == NULL) {
            free(enc_out);
            free(puk_client);
            goto round_fail;
        }

        wp = outer;
        ngx_memcpy(wp, "gsi\x00", 4);
        wp += 4;
        tpc_put_u32(wp, (uint32_t) kXGC_cert);
        wp += 4;

        tpc_put_u32(wp, (uint32_t) kXRS_puk);
        wp += 4;
        tpc_put_u32(wp, (uint32_t) puk_client_len);
        wp += 4;
        ngx_memcpy(wp, puk_client, puk_client_len);
        wp += puk_client_len;
        free(puk_client);

        tpc_put_u32(wp, (uint32_t) kXRS_main);
        wp += 4;
        tpc_put_u32(wp, (uint32_t) enc_len);
        wp += 4;
        ngx_memcpy(wp, enc_out, (size_t) enc_len);
        wp += (size_t) enc_len;
        free(enc_out);

        tpc_put_u32(wp, (uint32_t) kXRS_none);
        wp += 4;
        tpc_put_u32(wp, 0);
        wp += 4;

        outer_len = (size_t) (wp - outer);

        free(body);
        body = NULL;

        if (tpc_send_kxr_auth(t, fd, 4, outer, (uint32_t) outer_len) != 0) {
            free(outer);
            goto round_fail;
        }

        free(outer);

        body = NULL;
        if (tpc_recv_response(fd, &status, &body, &dlen) != 0) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI final auth recv failed");
            t->xrd_error = kXR_ServerError;
            goto round_fail;
        }

        if (status != kXR_ok) {
            snprintf(t->err_msg, sizeof(t->err_msg),
                     "TPC GSI authentication failed (status=%u)",
                     (unsigned) status);
            t->xrd_error = kXR_AuthFailed;
            free(body);
            goto round_fail;
        }

        free(body);
        body = NULL;
        EVP_PKEY_free(client_kp);
        client_kp = NULL;
        rc = 0;

round_fail:
        if (client_kp) {
            EVP_PKEY_free(client_kp);
            client_kp = NULL;
        }
        if (body) {
            free(body);
            body = NULL;
        }
        if (rc == 0) {
            goto done;
        }
    }

done:
    if (certreq) {
        free(certreq);
    }
    if (chain) {
        sk_X509_pop_free(chain, X509_free);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    if (cbio) {
        BIO_free(cbio);
    }
    if (kbio) {
        BIO_free(kbio);
    }

    return rc;
}

int
tpc_outbound_finish_login(xrootd_tpc_pull_t *t, int fd,
    u_char *login_body, uint32_t login_dlen)
{
    char              *parms;
    int                want_ztn;
    int                want_gsi;
    ngx_flag_t         have_bearer;
    ngx_flag_t         have_cert;

    if (login_dlen <= XROOTD_SESSION_ID_LEN + 1) {
        snprintf(t->err_msg, sizeof(t->err_msg),
                 "TPC login authmore body too short");
        t->xrd_error = kXR_ArgInvalid;
        return -1;
    }

    parms = (char *) login_body + XROOTD_SESSION_ID_LEN;

    want_ztn = (strstr(parms, "ztn") != NULL);
    want_gsi = (strstr(parms, "gsi") != NULL);

    have_bearer = (t->conf->tpc_outbound_bearer_file.len > 0) ? 1 : 0;
    have_cert = (t->conf->certificate.len > 0
                 && t->conf->certificate_key.len > 0) ? 1 : 0;

    /*
     * Prefer WLCG JWT when the server lists ztn first (typical for auth=both)
     * and we have a bearer file.
     */
    if (want_ztn && have_bearer) {
        if (tpc_outbound_ztn(t, fd) == 0) {
            return 0;
        }
        /*
         * If the server also allows GSI, fall through so sites can recover from
         * an expired token file without silent failure.
         */
        if (!want_gsi || !have_cert) {
            return -1;
        }
    }

    if (want_gsi && have_cert) {
        return tpc_outbound_gsi(t, fd);
    }

    snprintf(t->err_msg, sizeof(t->err_msg),
             "TPC source %s requires authentication. Configure "
             "xrootd_tpc_outbound_bearer_file (token) and/or "
             "xrootd_certificate + xrootd_certificate_key + xrootd_trusted_ca "
             "(GSI) on this destination.",
             t->src_host);
    t->xrd_error = kXR_AuthFailed;
    return -1;
}

#endif /* NGX_THREADS */
