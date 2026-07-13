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
 * gsi_cert_chunks_t — the computed byte chunks the kXGS_cert framer emits, one
 * field per top-level bucket payload.  Populated by the build/sign helpers and
 * consumed by gsi_frame_cert_response() so the wire assembly takes one struct
 * instead of a long parameter list; every field is a plain pointer+length view
 * into c->pool memory (no ownership transfer).  Zero-initialised at the call
 * site so an unset chunk frames as an empty (len 0) payload deterministically.
 */
typedef struct {
    uint32_t      pub_type;          /* kXRS_puk (unsigned) or kXRS_cipher */
    const u_char *pub_data;          /* DH-public bucket payload */
    size_t        pub_len;
    const char   *cipher_alg;        /* kXRS_cipher_alg list, NUL-terminated */
    size_t        calg_len;
    const char   *md_alg;            /* kXRS_md_alg list */
    size_t        malg_len;
    const u_char *cert_pem;          /* kXRS_x509 server cert (PEM) */
    size_t        cert_len;
    const u_char *main_buf;          /* kXRS_main nested container */
    size_t        main_len;
    size_t        puk_len;           /* unsigned DH-public length (log only) */
} gsi_cert_chunks_t;

/*
 * gsi_record_handshake_opts — WHAT: resolve and record the two per-handshake
 * policy decisions on the connection (signed-DH variant, client delegation
 * opts) from the certreq payload + operator config.  WHY: round 2
 * (parse_x509.c) must agree on the signed-DH padding/IV, and a later delegation
 * round must pick the flow the client advertised, so both are latched onto
 * ctx->gsi here.  HOW: apply the operator policy against the client's advertised
 * version; a REQUIRE policy with no server key degrades to unsigned rather than
 * failing the auth.  Returns the resolved signed-DH flag; logs the delegation
 * opts at INFO (byte-identical to the pre-split line).
 */
static int
gsi_record_handshake_opts(brix_ctx_t *ctx, ngx_connection_t *c,
    const ngx_stream_brix_srv_conf_t *conf)
{
    int signed_dh = gsi_use_signed_dh(conf->gsi_signed_dh,
                                      gsi_certreq_version(ctx->recv.payload,
                                                          ctx->recv.cur_dlen));

    if (signed_dh && conf->gsi_key == NULL) {
        signed_dh = 0;
    }
    ctx->gsi.signed_dh = signed_dh;

    /* §F6: capture the client's advertised delegation mode (kXRS_clnt_opts) so a
     * later delegation round picks the flow the client actually supports —
     * kOptsFwdPxy (forward) vs kOptsDlgPxy / kOptsSigReq (sign-request). */
    ctx->gsi.clnt_opts = gsi_certreq_clnt_opts(ctx->recv.payload,
                                               ctx->recv.cur_dlen);
    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "brix: GSI client delegation opts=0x%02xd (fwd=%d sign=%d dlg=%d)",
                  (unsigned) ctx->gsi.clnt_opts,
                  (ctx->gsi.clnt_opts & 0x2) ? 1 : 0,
                  (ctx->gsi.clnt_opts & 0x4) ? 1 : 0,
                  (ctx->gsi.clnt_opts & 0x1) ? 1 : 0);

    return signed_dh;
}

/*
 * gsi_build_dh_public — WHAT: take/generate an ephemeral ffdhe2048 DH key and
 * build the kXRS_puk blob ("<PEM params>---BPUB---<pub hex>---EPUB--") into a
 * c->pool buffer.  WHY: this is the DH-public body the kXGS_cert advertises; the
 * key is latched on ctx->gsi.dh_key for round-2 shared-secret derivation.  HOW:
 * pop a pre-generated key from the per-worker pool (keygen never runs on the
 * event thread under a certreq burst) or inline-keygen on an empty pool; own the
 * key on this connection.  On any failure the DH key is freed and NGX_ERROR is
 * returned.  Returns NGX_OK with *puk_out / *puk_len_out set on success.
 */
static ngx_int_t
gsi_build_dh_public(brix_ctx_t *ctx, ngx_connection_t *c,
    const ngx_stream_brix_srv_conf_t *conf,
    u_char **puk_out, size_t *puk_len_out)
{
    EVP_PKEY *dhkey = NULL;
    BIGNUM   *pub_bn = NULL;
    char     *pub_hex = NULL;
    BIO      *bio;
    BUF_MEM  *bptr;
    char      puk_buf[4096];
    int       puk_written;
    u_char   *puk_blob;
    size_t    puk_len;

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
    ctx->gsi.dh_key = dhkey;            /* ownership transfers to the connection */
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

    *puk_out = puk_blob;
    *puk_len_out = puk_len;
    return NGX_OK;
}

/*
 * gsi_select_dh_public_bucket — WHAT: choose the DH-public bucket payload+type
 * for the kXGS_cert.  WHY: unsigned (default) advertises the bare Public() blob
 * as kXRS_puk; signed-DH (>=10400) advertises the SAME blob RSA-signed with the
 * server key (XrdCryptosslRSA::EncryptPrivate) as kXRS_cipher, which the client
 * recovers via DecryptPublic against the kXRS_x509 cert we also send —
 * authenticating the DH parameters in transit.  HOW: on the signed path,
 * RSA-encrypt-private into a c->pool buffer sized for the signature; on failure
 * WARN and return NGX_ERROR.  On entry *ch already carries the unsigned default
 * (pub_data/pub_len = the bare puk blob); the signed path overwrites it and sets
 * pub_type to kXRS_cipher, the unsigned path only stamps kXRS_puk.  Returns
 * NGX_OK on success.
 */
static ngx_int_t
gsi_select_dh_public_bucket(ngx_connection_t *c,
    const ngx_stream_brix_srv_conf_t *conf, int signed_dh,
    gsi_cert_chunks_t *ch)
{
    if (signed_dh) {
        size_t  cap = ch->pub_len
                      + 2 * (size_t) EVP_PKEY_size(conf->gsi_key) + 64;
        u_char *sig = ngx_palloc(c->pool, cap);
        size_t  pub_len = sig ? brix_gsi_rsa_encrypt_private(conf->gsi_key,
                                    ch->pub_data, ch->pub_len, sig, cap) : 0;

        if (pub_len == 0) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                          "brix: GSI signed-DH: failed to sign DH public");
            return NGX_ERROR;
        }
        ch->pub_data = sig;
        ch->pub_len = pub_len;
        ch->pub_type = (uint32_t) kXRS_cipher;
        return NGX_OK;
    }

    ch->pub_type = (uint32_t) kXRS_puk;
    return NGX_OK;
}

/*
 * gsi_sign_client_rtag — WHAT: RSA-PKCS1 sign the client's random tag (kXRS_rtag
 * inside the certreq's kXRS_main container) with the server key.  WHY: the signed
 * rtag proves possession of the server private key to the client and rides in the
 * response's nested kXRS_main container.  HOW: locate the client rtag; if present
 * and the whole sign sequence succeeds, emit the signature into a c->pool buffer;
 * any step failing leaves *rtag_out NULL / *rtag_len_out 0 (unsigned response,
 * not an error — matches the pre-split fall-through).  No return code: the
 * out-params carry the result.
 */
static void
gsi_sign_client_rtag(brix_ctx_t *ctx, ngx_connection_t *c,
    const ngx_stream_brix_srv_conf_t *conf,
    u_char **rtag_out, size_t *rtag_len_out)
{
    const u_char *main_data = NULL;
    size_t        main_dlen = 0;
    const u_char *clnt_rtag = NULL;
    size_t        clnt_rtlen = 0;

    *rtag_out = NULL;
    *rtag_len_out = 0;

    if (gsi_find_bucket(ctx->recv.payload, ctx->recv.cur_dlen,
                        (uint32_t) kXRS_main, &main_data, &main_dlen) == 0) {
        gsi_find_bucket(main_data, main_dlen,
                        (uint32_t) kXRS_rtag, &clnt_rtag, &clnt_rtlen);
    }

    if (clnt_rtag && clnt_rtlen > 0) {
        EVP_PKEY_CTX *sctx = EVP_PKEY_CTX_new(conf->gsi_key, NULL);

        if (sctx) {
            size_t  slen = (size_t) EVP_PKEY_size(conf->gsi_key);
            u_char *signed_rtag = ngx_palloc(c->pool, slen);

            if (signed_rtag
                && EVP_PKEY_sign_init(sctx) > 0
                && EVP_PKEY_CTX_set_rsa_padding(sctx, RSA_PKCS1_PADDING) > 0
                && EVP_PKEY_sign(sctx, signed_rtag, &slen,
                                 clnt_rtag, clnt_rtlen) > 0)
            {
                *rtag_out = signed_rtag;
                *rtag_len_out = slen;
            }
            EVP_PKEY_CTX_free(sctx);
        }
    }
}

/*
 * gsi_build_main_container — WHAT: build the nested kXRS_main container the
 * kXGS_cert carries as a single top-level kXRS_main bucket.  WHY: it is NOT a
 * flat field — it re-encapsulates its own protocol header plus an inner bucket
 * list.  Inner wire layout (network byte order throughout):
 *   "gsi\0"                      protocol name (4 bytes, NUL-padded)
 *   kXGS_cert                    opcode (uint32, 4 bytes)
 *   [ kXRS_signed_rtag bucket ]  optional: type(4) + len(4) + signature
 *   kXRS_none                    terminator (uint32, 4 bytes)
 * HOW: reserve the fixed 12 bytes (name + opcode + terminator) plus, when the
 * rtag was signed, the 8-byte bucket header and signature; then walk mp
 * byte-by-byte to emit the layout.  Returns NGX_OK with *buf_out / *len_out set.
 */
static ngx_int_t
gsi_build_main_container(ngx_connection_t *c,
    const u_char *signed_rtag, size_t signed_rtag_len,
    u_char **buf_out, size_t *len_out)
{
    size_t  main_len = 4 + 4 + 4;
    u_char *main_buf;
    u_char *mp;

    if (signed_rtag_len > 0) {
        main_len += 4 + 4 + signed_rtag_len;
    }

    BRIX_PALLOC_OR_RETURN(main_buf, c->pool, main_len, NGX_ERROR);

    mp = main_buf;
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

    ngx_log_debug2(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXGS_cert signed rtag=%uz bytes main_len=%uz",
                   signed_rtag_len, main_len);

    *buf_out = main_buf;
    *len_out = main_len;
    return NGX_OK;
}

/*
 * gsi_frame_cert_response — WHAT: assemble and queue the kXGS_cert response frame
 * from the computed chunks.  WHY: this is the single wire-emission site — the
 * top-level bucket list (kXRS_puk/cipher, kXRS_cipher_alg, kXRS_md_alg, kXRS_x509,
 * kXRS_main, kXRS_none) wrapped in the kXR_authmore server header.  HOW: sum the
 * body length, allocate the c->pool frame, write the response header, then walk p
 * byte-by-byte emitting each bucket (type, len, payload) in network byte order;
 * byte layout is frozen and identical to the pre-split assembly.  Returns the
 * brix_queue_response() result (NGX_OK on queued).
 */
static ngx_int_t
gsi_frame_cert_response(brix_ctx_t *ctx, ngx_connection_t *c,
    const gsi_cert_chunks_t *ch)
{
    size_t  body_len = 4 + 4
                     + 4 + 4 + ch->pub_len
                     + 4 + 4 + ch->calg_len
                     + 4 + 4 + ch->malg_len
                     + 4 + 4 + ch->cert_len
                     + 4 + 4 + ch->main_len
                     + 4;
    size_t  total = XRD_RESPONSE_HDR_LEN + body_len;
    u_char *buf;
    u_char *p;

    BRIX_PALLOC_OR_RETURN(buf, c->pool, total, NGX_ERROR);

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_authmore,
                          (uint32_t) body_len, (ServerResponseHdr *) buf);

    p = buf + XRD_RESPONSE_HDR_LEN;

    p[0] = 'g';
    p[1] = 's';
    p[2] = 'i';
    p[3] = '\0';
    p += 4;
    *(uint32_t *) p = htonl(kXGS_cert);
    p += 4;

    *(uint32_t *) p = htonl(ch->pub_type);
    p += 4;
    *(uint32_t *) p = htonl((uint32_t) ch->pub_len);
    p += 4;
    ngx_memcpy(p, ch->pub_data, ch->pub_len);
    p += ch->pub_len;

    *(uint32_t *) p = htonl(kXRS_cipher_alg);
    p += 4;
    *(uint32_t *) p = htonl((uint32_t) ch->calg_len);
    p += 4;
    ngx_memcpy(p, ch->cipher_alg, ch->calg_len);
    p += ch->calg_len;

    *(uint32_t *) p = htonl(kXRS_md_alg);
    p += 4;
    *(uint32_t *) p = htonl((uint32_t) ch->malg_len);
    p += 4;
    ngx_memcpy(p, ch->md_alg, ch->malg_len);
    p += ch->malg_len;

    *(uint32_t *) p = htonl(kXRS_x509);
    p += 4;
    *(uint32_t *) p = htonl((uint32_t) ch->cert_len);
    p += 4;
    ngx_memcpy(p, ch->cert_pem, ch->cert_len);
    p += ch->cert_len;

    *(uint32_t *) p = htonl(kXRS_main);
    p += 4;
    *(uint32_t *) p = htonl((uint32_t) ch->main_len);
    p += 4;
    ngx_memcpy(p, ch->main_buf, ch->main_len);
    p += ch->main_len;

    *(uint32_t *) p = htonl(kXRS_none);

    ngx_log_debug3(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXGS_cert sent cert_len=%uz puk_len=%uz main_len=%uz",
                   ch->cert_len, ch->puk_len, ch->main_len);

    return brix_queue_response(ctx, c, buf, total);
}

/*
 * Respond to kXGC_certreq with kXGS_cert.  Orchestrates the four
 * equal-behavior phases: latch handshake opts, build the DH-public body, sign
 * the client rtag into the nested kXRS_main container, and frame+queue the
 * response.  Wire bytes are frozen — see the per-helper doc blocks.
 */

ngx_int_t
brix_gsi_send_cert(brix_ctx_t *ctx, ngx_connection_t *c)
{
    ngx_stream_brix_srv_conf_t *conf;
    gsi_cert_chunks_t ch = {0};
    char              cipher_alg[96];
    u_char           *puk_blob = NULL;
    size_t            puk_len = 0;
    u_char           *signed_rtag = NULL;
    size_t            signed_rtag_len = 0;
    int               signed_dh;

    conf = ngx_stream_get_module_srv_conf(ctx->session,
                                          ngx_stream_brix_module);

    if (conf->gsi_cert_pem == NULL || conf->gsi_cert_pem_len == 0) {
        return NGX_ERROR;
    }
    ch.cert_pem = conf->gsi_cert_pem;
    ch.cert_len = conf->gsi_cert_pem_len;

    /* Advertise the kXRS_cipher_alg list (config preference or default, keyable
     * ciphers only).  See gsi_build_cipher_alg_list(). */
    gsi_build_cipher_alg_list(conf, cipher_alg, sizeof(cipher_alg));
    ch.cipher_alg = cipher_alg;
    ch.calg_len = ngx_strlen(cipher_alg);

    ch.md_alg = "sha256:sha1";
    ch.malg_len = strlen(ch.md_alg);

    signed_dh = gsi_record_handshake_opts(ctx, c, conf);

    if (gsi_build_dh_public(ctx, c, conf, &puk_blob, &puk_len) != NGX_OK) {
        return NGX_ERROR;
    }
    ch.puk_len = puk_len;
    ch.pub_data = puk_blob;            /* unsigned default; signed path overwrites */
    ch.pub_len = puk_len;

    if (gsi_select_dh_public_bucket(c, conf, signed_dh, &ch) != NGX_OK) {
        return NGX_ERROR;
    }

    gsi_sign_client_rtag(ctx, c, conf, &signed_rtag, &signed_rtag_len);

    if (gsi_build_main_container(c, signed_rtag, signed_rtag_len,
                                 (u_char **) &ch.main_buf, &ch.main_len)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    return gsi_frame_cert_response(ctx, c, &ch);
}
