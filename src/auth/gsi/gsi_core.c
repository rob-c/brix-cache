/*
 * gsi_core.c - (kept) routing + shared helpers
 * Phase-38 split of gsi_core.c; behavior-identical.
 */
#include "gsi_core_internal.h"

const char brix_gsi_dh_params_pem[] =
"-----BEGIN DH PARAMETERS-----\n"
"MIIBiAKCAYEAzcEAf3ZCkm0FxJLgKd1YoT16Hietl7QV8VgJNc5CYKmRu/gKylxT\n"
"MVZJqtUmoh2IvFHCfbTGEmZM5LdVaZfMLQf7yXjecg0nSGklYZeQQ3P0qshFLbI9\n"
"u3z1XhEeCbEZPq84WWwXacSAAxwwRRrN5nshgAavqvyDiGNi+GqYpqGPb9JE38R3\n"
"GJ51FTPutZlvQvEycjCbjyajhpItBB+XvIjWj2GQyvi+cqB0WrPQAsxCOPrBTCZL\n"
"OjM0NfJ7PQfllw3RDQev2u1Q+Rt8QyScJQCFUj/SWoxpw2ydpWdgAkrqTmdVYrev\n"
"x5AoXE52cVIC8wfOxaaJ4cBpnJui3Y0jZcOQj0FtC0wf4WcBpHnLLBzKSOQwbxts\n"
"WE8LkskPnwwrup/HqWimFFg40bC9F5Lm3CTDCb45mtlBxi3DydIbRLFhGAjlKzV3\n"
"s9G3opHwwfgXpFf3+zg7NPV3g1//HLgWCvooOvMqaO+X7+lXczJJLMafEaarcAya\n"
"Kyo8PGKIAORrAgEF\n"
"-----END DH PARAMETERS-----\n";

const char *const gsi_cipher_allow[] = {
    "aes-128-cbc", "aes-256-cbc", "bf-cbc", "des-ede3-cbc", NULL
};



/* Parse a gsi protocol parms string "v:10600,c:ssl,ca:HASH|HASH" into fields.
 * Any out pointer may be NULL.  `crypto`/`ca` are NUL-terminated, truncated. */
void
brix_gsi_parse_parms(const char *parms, uint32_t *version,
                       char *crypto, size_t cryptosz,
                       char *ca, size_t casz)
{
    const char *p;

    if (version != NULL) { *version = 0; }
    if (crypto != NULL && cryptosz > 0) { crypto[0] = '\0'; }
    if (ca != NULL && casz > 0) { ca[0] = '\0'; }
    if (parms == NULL) {
        return;
    }

    for (p = parms; *p != '\0'; ) {
        const char *comma = strchr(p, ',');
        size_t      flen  = comma ? (size_t) (comma - p) : strlen(p);

        if (flen > 2 && p[1] == ':') {
            const char *val = p + 2;
            size_t      vlen = flen - 2;
            if (p[0] == 'v' && version != NULL) {
                *version = (uint32_t) strtoul(val, NULL, 10);
            } else if (p[0] == 'c' && crypto != NULL && cryptosz > 0) {
                size_t n = vlen < cryptosz - 1 ? vlen : cryptosz - 1;
                memcpy(crypto, val, n);
                crypto[n] = '\0';
            }
        } else if (flen > 3 && p[0] == 'c' && p[1] == 'a' && p[2] == ':'
                   && ca != NULL && casz > 0) {
            const char *val = p + 3;
            size_t      vlen = flen - 3;
            size_t      n = vlen < casz - 1 ? vlen : casz - 1;
            memcpy(ca, val, n);
            ca[n] = '\0';
        }
        p += flen;
        if (*p == ',') { p++; }
    }
}


/*
 * Build the standard XrdSecgsi round-1 certreq buffer.  Outer (Step
 * kXGC_certreq) carries kXRS_cryptomod, kXRS_version, kXRS_issuer_hash,
 * kXRS_clnt_opts and a kXRS_main bucket whose data is a *nested* buffer
 * (Step kXGC_certreq + kXRS_rtag + kXRS_none).  Mirrors a stock client's first
 * message; the server's XrdSutBuffer parser reads the certreq opcode from the
 * main bucket (a bare top-level opcode is rejected with "main buffer missing").
 * Returns a malloc'd buffer (*outlen set), or NULL.
 */
uint8_t *
brix_gsi_build_certreq(const char *cryptomod, uint32_t version,
                         const char *issuer_hash, uint32_t clnt_opts,
                         const uint8_t *rtag, size_t rtaglen, size_t *outlen)
{
    brix_gbuf inner, outer;
    uint32_t    ver_be  = htonl(version);
    uint32_t    opts_be = htonl(clnt_opts);
    uint8_t    *result  = NULL;

    /* Nested main: "gsi\0" + kXGC_certreq + rtag bucket + terminator. */
    brix_gbuf_init(&inner);
    brix_gbuf_start(&inner, (uint32_t) kXGC_certreq);
    brix_gbuf_bucket(&inner, (uint32_t) kXRS_rtag, rtag, rtaglen);
    brix_gbuf_end(&inner);
    if (inner.err) {
        brix_gbuf_free(&inner);
        return NULL;
    }

    brix_gbuf_init(&outer);
    brix_gbuf_start(&outer, (uint32_t) kXGC_certreq);
    brix_gbuf_bucket(&outer, (uint32_t) kXRS_cryptomod,
                       cryptomod, strlen(cryptomod));
    brix_gbuf_bucket(&outer, (uint32_t) kXRS_version, &ver_be, 4);
    brix_gbuf_bucket(&outer, (uint32_t) kXRS_issuer_hash,
                       issuer_hash, strlen(issuer_hash));
    brix_gbuf_bucket(&outer, (uint32_t) kXRS_clnt_opts, &opts_be, 4);
    brix_gbuf_bucket(&outer, (uint32_t) kXRS_main, inner.p, inner.len);
    brix_gbuf_end(&outer);

    if (!outer.err) {
        result  = outer.p;
        *outlen = outer.len;
        outer.p = NULL;          /* ownership → caller */
    }
    brix_gbuf_free(&inner);
    brix_gbuf_free(&outer);
    return result;
}



/* Public key of the first X.509 cert in a PEM bucket (the peer's EEC). */
EVP_PKEY *
gsi_cresp_cert_pubkey(const uint8_t *pem, size_t len)
{
    BIO      *bio = BIO_new_mem_buf(pem, (int) len);
    X509     *cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    EVP_PKEY *pk = cert ? X509_get_pubkey(cert) : NULL;

    X509_free(cert);
    BIO_free(bio);
    return pk;
}


/* Export an EVP_PKEY public part as PEM SubjectPublicKeyInfo
 * (XrdCryptosslRSA::ExportPublic = PEM_write_bio_PUBKEY).  malloc'd,
 * NUL-terminated, *outlen = strlen.  The signed-DH path sends this as kXRS_puk so
 * the server can verify our signed DH before it has decrypted our cert chain. */
char *
gsi_cresp_export_pubkey_pem(EVP_PKEY *key, size_t *outlen)
{
    BIO  *bio = BIO_new(BIO_s_mem());
    char *pem = NULL, *out = NULL;
    long  len;

    if (bio != NULL && PEM_write_bio_PUBKEY(bio, key) == 1) {
        len = BIO_get_mem_data(bio, &pem);
        out = malloc((size_t) len + 1);
        if (out != NULL) {
            memcpy(out, pem, (size_t) len);
            out[len] = '\0';
            *outlen = (size_t) len;
        }
    }
    BIO_free(bio);
    return out;
}


/* Choose the kXRS_md_alg digest to echo back: prefer "sha256" when the server
 * offers it (it matches our SHA256(secret) key derivation), else the server's
 * first ':'-separated token, else "sha256".  dCache rejects the handshake if the
 * reply names a digest it did not advertise. */
size_t
gsi_cresp_pick_md_alg(const uint8_t *sbody, uint32_t slen, char *out, size_t outcap)
{
    const uint8_t *list = NULL;
    size_t         listlen = 0, n = 0;

    if (brix_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_md_alg,
                               &list, &listlen) == 0 && listlen > 0) {
        if (listlen >= 6) {
            for (size_t i = 0; i + 6 <= listlen; i++) {
                if (memcmp(list + i, "sha256", 6) == 0) {
                    memcpy(out, "sha256", 6);
                    out[6] = '\0';
                    return 6;
                }
            }
        }
        while (n < listlen && n + 1 < outcap && list[n] != ':') {
            out[n] = (char) list[n];
            n++;
        }
    }
    if (n == 0) {
        memcpy(out, "sha256", 6);
        n = 6;
    }
    out[n] = '\0';
    return n;
}


/*
 * gsi_cresp_ctx — owned resources for the round-2 response, freed once by
 * gsi_cresp_cleanup (single NULL-safe destructor, no goto).  proxy_pem and the
 * proxy private key are NOT held here — they are borrowed from the caller.
 */

int
gsi_cresp_fail(gsi_cresp_ctx *x, char *err, size_t errcap, const char *msg)
{
    if (err != NULL && errcap > 0 && msg != NULL) {
        snprintf(err, errcap, "%s", msg);
    }
    free(x->peerblob);
    free(x->signed_rtag);
    free(x->signed_cpub);
    free(x->pubpem);
    free(x->enc);
    free(x->cpub);
    EVP_PKEY_free(x->mine);
    EVP_PKEY_free(x->peer);
    EVP_PKEY_free(x->servpub);
    brix_gbuf_free(&x->inner);
    brix_gbuf_free(&x->outer);
    return -1;
}


int
brix_gsi_build_cert_response_ex(const uint8_t *sbody, uint32_t slen,
                              const uint8_t *proxy_pem, size_t proxy_pem_len,
                              EVP_PKEY *proxy_key,
                              uint8_t **payload, uint32_t *plen,
                              uint8_t *out_key, size_t *out_keylen,
                              char *out_cipher, size_t out_cipher_cap,
                              int *out_use_iv,
                              char *err, size_t errcap)
{
    const uint8_t *cipher = NULL, *puk = NULL, *sx509 = NULL, *xmain = NULL;
    size_t         cipherlen = 0, puklen = 0, sx509len = 0;
    size_t         xmainlen = 0, enclen = 0, cpublen = 0;
    const uint8_t *peerpub = NULL;
    size_t         peerpublen = 0;
    int            signed_dh;
    uint8_t        aeskey[BRIX_GSI_MAX_KEY];
    brix_gsi_cipher_t sesscipher;
    char           chosen_cipher[24];
    char           cipher_field[40];
    int            use_iv;
    uint8_t        newrtag[8];
    char           md_alg[32];
    size_t         md_alg_len;
    gsi_cresp_ctx  x;

    memset(&x, 0, sizeof(x));
    brix_gbuf_init(&x.inner);
    brix_gbuf_init(&x.outer);

    if (proxy_pem == NULL || proxy_key == NULL) {
        return gsi_cresp_fail(&x, err, errcap, "gsi: missing proxy credential");
    }

    /* 1. Determine the DH variant + recover the server's DH public blob. */
    signed_dh = brix_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_cipher,
                                       &cipher, &cipherlen) == 0;
    if (signed_dh) {
        if (brix_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_x509,
                                   &sx509, &sx509len) != 0
            || (x.servpub = gsi_cresp_cert_pubkey(sx509, sx509len)) == NULL) {
            return gsi_cresp_fail(&x, err, errcap,
                                  "gsi: server certificate missing");
        }
        x.peerblob = malloc(cipherlen + 64);
        if (x.peerblob == NULL) {
            return gsi_cresp_fail(&x, err, errcap, "gsi: out of memory");
        }
        peerpublen = brix_gsi_rsa_decrypt_public(x.servpub, cipher, cipherlen,
                                                   x.peerblob, cipherlen + 64);
        if (peerpublen == 0) {
            return gsi_cresp_fail(&x, err, errcap,
                                  "gsi: verifying signed server DH parameters");
        }
        peerpub = x.peerblob;
    } else if (brix_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_puk,
                                      &puk, &puklen) == 0) {
        peerpub = puk;
        peerpublen = puklen;
    } else {
        return gsi_cresp_fail(&x, err, errcap, "gsi: server DH public missing");
    }

    /* Choose the session cipher from the server's kXRS_cipher_alg list, preferring
     * aes-128-cbc (the universal XrdSecgsi default) whenever offered. */
    {
        const uint8_t *ca = NULL; size_t cal = 0;
        char           offered[128];

        snprintf(chosen_cipher, sizeof(chosen_cipher), "aes-128-cbc");
        if (brix_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_cipher_alg,
                                   &ca, &cal) == 0 && cal > 0
            && cal < sizeof(offered)) {
            memcpy(offered, ca, cal);
            offered[cal] = '\0';
            if (memmem(offered, cal, "aes-128-cbc", 11) == NULL) {
                (void) brix_gsi_cipher_pick(offered, &sesscipher, chosen_cipher);
            }
        }
        if (!brix_gsi_cipher_lookup(chosen_cipher, &sesscipher)) {
            (void) brix_gsi_cipher_lookup("aes-128-cbc", &sesscipher);
            snprintf(chosen_cipher, sizeof(chosen_cipher), "aes-128-cbc");
        }
    }

    /* 2. Agree the session key (HasPad follows the variant). */
    {
        const uint8_t *cm = NULL; size_t cml = 0;
        int peer_nopad = (brix_gsi_find_bucket(sbody, slen,
                              (uint32_t) kXRS_cryptomod, &cm, &cml) == 0
                          && cml >= 5
                          && memmem(cm, cml, "nopad", 5) != NULL);
        int dh_pad = signed_dh && !peer_nopad;

        x.peer = brix_gsi_cipher_parse_peer(peerpub, peerpublen);
        x.mine = x.peer ? brix_gsi_cipher_keygen_from(x.peer) : NULL;
        if (x.peer == NULL || x.mine == NULL
            || !brix_gsi_cipher_session_key(x.mine, x.peer, dh_pad, aeskey,
                                              sesscipher.key_len)) {
            return gsi_cresp_fail(&x, err, errcap,
                                  "gsi: session-key agreement failed");
        }
    }

    /* 3. Sign the server's random tag with the proxy key (proof of possession). */
    if (brix_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_main,
                               &xmain, &xmainlen) == 0) {
        const uint8_t *srtag = NULL;
        size_t         srtaglen = 0;

        if (brix_gsi_find_bucket(xmain, xmainlen, (uint32_t) kXRS_rtag,
                                   &srtag, &srtaglen) == 0) {
            uint8_t sig[1024];
            size_t  siglen = brix_gsi_rsa_sign_raw(proxy_key, srtag, srtaglen,
                                                     sig);
            if (siglen == 0 || siglen > sizeof(sig)
                || (x.signed_rtag = malloc(siglen)) == NULL) {
                OPENSSL_cleanse(aeskey, sizeof(aeskey));
                return gsi_cresp_fail(&x, err, errcap,
                                  "gsi: signing the server tag with the proxy key");
            }
            memcpy(x.signed_rtag, sig, siglen);
            x.signed_rtag_len = siglen;
        }
    }

    /* 4. Build + encrypt the response main: proxy chain + signed tag + new tag. */
    if (!brix_gsi_rand(newrtag, sizeof(newrtag))) {
        OPENSSL_cleanse(aeskey, sizeof(aeskey));
        return gsi_cresp_fail(&x, err, errcap, "gsi: RNG failed");
    }
    brix_gbuf_start(&x.inner, (uint32_t) kXGC_cert);
    brix_gbuf_bucket(&x.inner, (uint32_t) kXRS_x509, proxy_pem, proxy_pem_len);
    if (x.signed_rtag != NULL) {
        brix_gbuf_bucket(&x.inner, (uint32_t) kXRS_signed_rtag,
                           x.signed_rtag, x.signed_rtag_len);
    }
    brix_gbuf_bucket(&x.inner, (uint32_t) kXRS_rtag, newrtag, sizeof(newrtag));
    brix_gbuf_end(&x.inner);
    /* IV is prepended exactly for v>=10400 peers (signed_dh tracks the same
     * condition); XRDC_GSI_USEIV overrides for interop debugging. */
    use_iv = signed_dh;
    {
        const char *ivov = getenv("XRDC_GSI_USEIV");
        if (ivov != NULL) { use_iv = atoi(ivov); }
    }
    if (!x.inner.err) {
        x.enc = brix_gsi_cipher_encrypt(&sesscipher, aeskey, x.inner.p,
                                          x.inner.len, use_iv, &enclen);
    }
    /* Hand the agreed session cipher to the caller before we wipe it — the
     * client's X.509 delegation round (kXGC_sigpxy) reuses the same key/cipher. */
    if (out_key != NULL && out_keylen != NULL) {
        memcpy(out_key, aeskey, sesscipher.key_len);
        *out_keylen = sesscipher.key_len;
    }
    if (out_cipher != NULL && out_cipher_cap > 0) {
        snprintf(out_cipher, out_cipher_cap, "%s", chosen_cipher);
    }
    if (out_use_iv != NULL) {
        *out_use_iv = use_iv;
    }
    OPENSSL_cleanse(aeskey, sizeof(aeskey));
    if (x.inner.err || x.enc == NULL) {
        return gsi_cresp_fail(&x, err, errcap, "gsi: main encrypt failed");
    }

    /* 5. Outer kXGC_cert: our DH public — kXRS_cipher (RSA-signed) for signed-DH,
     *    else a plain kXRS_puk. */
    x.cpub = brix_gsi_cipher_public(x.mine, &cpublen);
    if (x.cpub == NULL) {
        return gsi_cresp_fail(&x, err, errcap, "gsi: cannot encode session public");
    }
    brix_gbuf_start(&x.outer, (uint32_t) kXGC_cert);
    brix_gbuf_bucket(&x.outer, (uint32_t) kXRS_cryptomod, "ssl", 3);
    if (signed_dh) {
        size_t cap = cpublen + (size_t) EVP_PKEY_size(proxy_key) + 64;
        x.signed_cpub = malloc(cap);
        if (x.signed_cpub != NULL) {
            x.signed_cpub_len = brix_gsi_rsa_encrypt_private(
                proxy_key, (const uint8_t *) x.cpub, cpublen, x.signed_cpub, cap);
        }
        if (x.signed_cpub == NULL || x.signed_cpub_len == 0) {
            return gsi_cresp_fail(&x, err, errcap, "gsi: signing session public");
        }
        brix_gbuf_bucket(&x.outer, (uint32_t) kXRS_cipher,
                           x.signed_cpub, x.signed_cpub_len);
        {
            size_t ppl = 0;
            x.pubpem = gsi_cresp_export_pubkey_pem(proxy_key, &ppl);
            if (x.pubpem == NULL) {
                return gsi_cresp_fail(&x, err, errcap, "gsi: export proxy pubkey");
            }
            brix_gbuf_bucket(&x.outer, (uint32_t) kXRS_puk, x.pubpem, ppl);
        }
    } else {
        brix_gbuf_bucket(&x.outer, (uint32_t) kXRS_puk, x.cpub, cpublen);
    }
    if (use_iv) {
        snprintf(cipher_field, sizeof(cipher_field), "%s#%d",
                 chosen_cipher, sesscipher.iv_len);
    } else {
        snprintf(cipher_field, sizeof(cipher_field), "%s", chosen_cipher);
    }
    brix_gbuf_bucket(&x.outer, (uint32_t) kXRS_cipher_alg, cipher_field,
                       strlen(cipher_field));
    md_alg_len = gsi_cresp_pick_md_alg(sbody, slen, md_alg, sizeof(md_alg));
    brix_gbuf_bucket(&x.outer, (uint32_t) kXRS_md_alg, md_alg, md_alg_len);
    brix_gbuf_bucket(&x.outer, (uint32_t) kXRS_main, x.enc, enclen);
    brix_gbuf_end(&x.outer);
    if (x.outer.err) {
        return gsi_cresp_fail(&x, err, errcap, "gsi: out of memory");
    }

    *payload = x.outer.p;
    *plen = (uint32_t) x.outer.len;
    x.outer.p = NULL;          /* ownership → caller */
    (void) gsi_cresp_fail(&x, NULL, 0, NULL);   /* free everything else, no err */
    return 0;
}


/* Back-compat wrapper: the round-2 builder without the session-key export. */
int
brix_gsi_build_cert_response(const uint8_t *sbody, uint32_t slen,
                              const uint8_t *proxy_pem, size_t proxy_pem_len,
                              EVP_PKEY *proxy_key,
                              uint8_t **payload, uint32_t *plen,
                              char *err, size_t errcap)
{
    return brix_gsi_build_cert_response_ex(sbody, slen, proxy_pem,
                                             proxy_pem_len, proxy_key,
                                             payload, plen,
                                             NULL, NULL, NULL, 0, NULL,
                                             err, errcap);
}


int
brix_gsi_sigver_required(uint16_t op, int level)
{
    if (level <= 1) {
        return 0;
    }
    if (op == kXR_login || op == kXR_protocol || op == kXR_auth
        || op == kXR_endsess || op == kXR_ping || op == kXR_sigver
        || op == kXR_bind) {
        return 0;
    }
    if (level == 2) {
        return (op == kXR_open || op == kXR_write || op == kXR_pgwrite
                || op == kXR_writev || op == kXR_truncate || op == kXR_mkdir
                || op == kXR_rm || op == kXR_rmdir || op == kXR_mv
                || op == kXR_chmod || op == kXR_fattr || op == kXR_chkpoint
                || op == kXR_clone);
    }
    return 1;   /* level >= 3 */
}


/* kXR_sigver HMAC — request signing (client) / verification (server). */

void
brix_gsi_sigver_seqno_be(uint64_t seq, uint8_t out[8])
{
    out[0] = (uint8_t) (seq >> 56);
    out[1] = (uint8_t) (seq >> 48);
    out[2] = (uint8_t) (seq >> 40);
    out[3] = (uint8_t) (seq >> 32);
    out[4] = (uint8_t) (seq >> 24);
    out[5] = (uint8_t) (seq >> 16);
    out[6] = (uint8_t) (seq >> 8);
    out[7] = (uint8_t) seq;
}


int
brix_gsi_sigver_hmac(const uint8_t key[32], uint64_t seqno,
                       const uint8_t hdr24[24], const uint8_t *payload,
                       size_t plen, int nodata, uint8_t mac_out[32])
{
    uint8_t  seqbe[8];
    uint8_t *msg;
    size_t   mlen;
    int      cover_payload, ok;

    if (key == NULL || hdr24 == NULL || mac_out == NULL) {
        return 0;
    }
    cover_payload = (!nodata && payload != NULL && plen > 0);
    mlen = 8 + 24 + (cover_payload ? plen : 0);
    msg  = (uint8_t *) malloc(mlen);
    if (msg == NULL) {
        return 0;
    }
    brix_gsi_sigver_seqno_be(seqno, seqbe);
    memcpy(msg, seqbe, 8);
    memcpy(msg + 8, hdr24, 24);
    if (cover_payload) {
        memcpy(msg + 32, payload, plen);
    }
    ok = brix_hmac_sha256(key, 32, msg, mlen, mac_out);
    free(msg);
    return ok;
}
