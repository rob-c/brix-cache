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


static void
brix_gsi_copy_parm(char *dst, size_t dst_cap, const char *value,
                   size_t value_len)
{
    size_t copy_len;

    if (dst == NULL || dst_cap == 0) {
        return;
    }

    copy_len = value_len < dst_cap - 1 ? value_len : dst_cap - 1;
    memcpy(dst, value, copy_len);
    dst[copy_len] = '\0';
}

static void
brix_gsi_parse_short_parm(const char *field, size_t field_len,
                          uint32_t *version, char *crypto, size_t cryptosz)
{
    const char *value;
    size_t value_len;

    if (field_len <= 2 || field[1] != ':') {
        return;
    }

    value = field + 2;
    value_len = field_len - 2;
    if (field[0] == 'v' && version != NULL) {
        *version = (uint32_t) strtoul(value, NULL, 10);
        return;
    }
    if (field[0] == 'c') {
        brix_gsi_copy_parm(crypto, cryptosz, value, value_len);
    }
}

static void
brix_gsi_parse_ca_parm(const char *field, size_t field_len,
                       char *ca, size_t casz)
{
    if (field_len <= 3 || field[0] != 'c' || field[1] != 'a'
        || field[2] != ':') {
        return;
    }

    brix_gsi_copy_parm(ca, casz, field + 3, field_len - 3);
}


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

        brix_gsi_parse_short_parm(p, flen, version, crypto, cryptosz);
        brix_gsi_parse_ca_parm(p, flen, ca, casz);
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

/*
 * WHAT: gsi_cresp_state_t — file-local aggregate threading the whole round-2
 *       cert-response state (owned resources, server body, borrowed proxy
 *       credential, the negotiated DH/session-key/cipher state, and the
 *       optional session-cipher export) through the static builder helpers.
 * WHY:  the round-2 builders (extract-peer-pub → agree-session-key →
 *       sign-server-tag → build-inner → build-outer) each need most of the same
 *       state; passed loose it produced 8–16-param signatures.  Promoting one
 *       file-local struct is pure signature consolidation — it moves no logic,
 *       changes no OpenSSL call order and no emitted bytes.
 * HOW:  brix_gsi_build_cert_response_ex (frozen extern) zero-inits one on the
 *       stack, initialises the two brix_gbuf members via brix_gbuf_init, seeds
 *       the borrowed inputs, and passes &st to each helper.  `res` embeds the
 *       header's gsi_cresp_ctx so the extern gsi_cresp_fail destructor is used
 *       unchanged via &st->res.  Buffers (aeskey/chosen_cipher) live inline so
 *       their addresses stay stable across the helper chain.
 */
typedef struct {
    gsi_cresp_ctx       res;            /* owned resources (freed by gsi_cresp_fail) */

    /* server round-1 body (borrowed) */
    const uint8_t      *sbody;
    uint32_t            slen;

    /* borrowed proxy credential */
    const uint8_t      *proxy_pem;
    size_t              proxy_pem_len;
    EVP_PKEY           *proxy_key;

    /* negotiated during the exchange */
    int                 signed_dh;
    const uint8_t      *peerpub;        /* server DH public (into peerblob or sbody) */
    size_t              peerpublen;
    brix_gsi_cipher_t   sesscipher;
    uint8_t             aeskey[BRIX_GSI_MAX_KEY];
    char                chosen_cipher[24];
    int                 use_iv;
    size_t              enclen;

    /* optional session-cipher export (any may be NULL) */
    uint8_t            *out_key;
    size_t             *out_keylen;
    char               *out_cipher;
    size_t              out_cipher_cap;
    int                *out_use_iv;

    /* error sink (borrowed) */
    char               *err;
    size_t              errcap;
} gsi_cresp_state_t;

/*
 * WHAT: gsi_cresp_state_fail — thin adapter forwarding a failure through the
 *       state struct to the extern gsi_cresp_fail destructor.
 * WHY:  the builder helpers now carry err/errcap inside gsi_cresp_state_t;
 *       this keeps the single "free everything + set reason + return -1"
 *       contract without re-threading err/errcap at every callsite.
 * HOW:  passes &st->res and the borrowed err/errcap to gsi_cresp_fail; returns
 *       its -1 verbatim.  Behaviour is identical to the pre-refactor direct call.
 */
static int
gsi_cresp_state_fail(gsi_cresp_state_t *st, const char *msg)
{
    return gsi_cresp_fail(&st->res, st->err, st->errcap, msg);
}

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

/*
 * WHAT: gsi_cresp_extract_peer_pub — resolve the server's DH public key,
 *       detecting the signed-DH variant (kXRS_cipher present) vs. the plain
 *       kXRS_puk variant, and record st->signed_dh / st->peerpub / st->peerpublen.
 * WHY:  the signed-DH branch must verify the server's DH blob by RSA-decrypting
 *       kXRS_cipher with the server cert public key before trusting it; the
 *       plain branch borrows kXRS_puk directly.  Byte-for-byte identical to the
 *       pre-struct version — only the state now flows through st.
 * HOW:  writes st->signed_dh/peerpub/peerpublen; on the signed path takes
 *       ownership of st->res.servpub and st->res.peerblob for later cleanup.
 */
static int
gsi_cresp_extract_peer_pub(gsi_cresp_state_t *st)
{
    const uint8_t *cipher = NULL;
    const uint8_t *puk = NULL;
    const uint8_t *sx509 = NULL;
    size_t cipherlen = 0;
    size_t puklen = 0;
    size_t sx509len = 0;

    st->signed_dh = brix_gsi_find_bucket(st->sbody, st->slen,
                                         (uint32_t) kXRS_cipher,
                                         &cipher, &cipherlen) == 0;
    if (st->signed_dh) {
        if (brix_gsi_find_bucket(st->sbody, st->slen, (uint32_t) kXRS_x509,
                                 &sx509, &sx509len) != 0) {
            return gsi_cresp_state_fail(st,
                                        "gsi: server certificate missing");
        }
        st->res.servpub = gsi_cresp_cert_pubkey(sx509, sx509len);
        if (st->res.servpub == NULL) {
            return gsi_cresp_state_fail(st,
                                        "gsi: server certificate missing");
        }
        st->res.peerblob = malloc(cipherlen + 64);
        if (st->res.peerblob == NULL) {
            return gsi_cresp_state_fail(st, "gsi: out of memory");
        }
        st->peerpublen = brix_gsi_rsa_decrypt_public(st->res.servpub, cipher,
                                                     cipherlen,
                                                     st->res.peerblob,
                                                     cipherlen + 64);
        if (st->peerpublen == 0) {
            return gsi_cresp_state_fail(st,
                              "gsi: verifying signed server DH parameters");
        }
        st->peerpub = st->res.peerblob;
        return 0;
    }

    if (brix_gsi_find_bucket(st->sbody, st->slen, (uint32_t) kXRS_puk, &puk,
                             &puklen) != 0) {
        return gsi_cresp_state_fail(st, "gsi: server DH public missing");
    }

    st->peerpub = puk;
    st->peerpublen = puklen;
    return 0;
}

/*
 * WHAT: gsi_cresp_choose_cipher — pick the session cipher, preferring
 *       aes-128-cbc and falling back to the server's kXRS_cipher_alg offer,
 *       writing st->sesscipher and st->chosen_cipher.
 * WHY:  the response must name a cipher the peer accepts; aes-128-cbc is the
 *       default and any non-matching offer is negotiated via brix_gsi_cipher_pick.
 *       Logic and defaults are unchanged — only the state now lives in st.
 * HOW:  fills st->chosen_cipher[sizeof(st->chosen_cipher)] and st->sesscipher;
 *       always leaves a valid looked-up cipher (aes-128-cbc on any failure).
 */
static void
gsi_cresp_choose_cipher(gsi_cresp_state_t *st)
{
    const uint8_t *ca = NULL;
    size_t cal = 0;
    char offered[128];

    snprintf(st->chosen_cipher, sizeof(st->chosen_cipher), "aes-128-cbc");
    if (brix_gsi_find_bucket(st->sbody, st->slen, (uint32_t) kXRS_cipher_alg,
                             &ca, &cal) == 0 && cal > 0
        && cal < sizeof(offered)) {
        memcpy(offered, ca, cal);
        offered[cal] = '\0';
        if (memmem(offered, cal, "aes-128-cbc", 11) == NULL) {
            (void) brix_gsi_cipher_pick(offered, &st->sesscipher,
                                        st->chosen_cipher);
        }
    }
    if (!brix_gsi_cipher_lookup(st->chosen_cipher, &st->sesscipher)) {
        (void) brix_gsi_cipher_lookup("aes-128-cbc", &st->sesscipher);
        snprintf(st->chosen_cipher, sizeof(st->chosen_cipher), "aes-128-cbc");
    }
}

/*
 * WHAT: gsi_cresp_agree_session_key — parse the peer DH public, generate our
 *       matching keypair, and derive the AES session key into st->aeskey.
 * WHY:  the derived key both encrypts the response main and (in the export
 *       path) is handed to the caller.  The DH padding rule (pad only in the
 *       signed-DH case unless the server advertised "nopad") is byte-frozen.
 * HOW:  reads st->peerpub/peerpublen/signed_dh/sesscipher; writes st->res.peer,
 *       st->res.mine and st->aeskey; fails through gsi_cresp_state_fail.
 */
static int
gsi_cresp_agree_session_key(gsi_cresp_state_t *st)
{
    const uint8_t *cm = NULL;
    size_t cml = 0;
    int peer_nopad;
    int dh_pad;

    peer_nopad = (brix_gsi_find_bucket(st->sbody, st->slen,
                                       (uint32_t) kXRS_cryptomod,
                                       &cm, &cml) == 0
                  && cml >= 5
                  && memmem(cm, cml, "nopad", 5) != NULL);
    dh_pad = st->signed_dh && !peer_nopad;

    st->res.peer = brix_gsi_cipher_parse_peer(st->peerpub, st->peerpublen);
    st->res.mine = st->res.peer
                   ? brix_gsi_cipher_keygen_from(st->res.peer) : NULL;
    if (st->res.peer == NULL || st->res.mine == NULL
        || !brix_gsi_cipher_session_key(st->res.mine, st->res.peer, dh_pad,
                                        st->aeskey, st->sesscipher.key_len)) {
        return gsi_cresp_state_fail(st, "gsi: session-key agreement failed");
    }
    return 0;
}

/*
 * WHAT: gsi_cresp_sign_server_tag — if the server's main bucket carries a
 *       kXRS_rtag, RSA-sign it with the proxy key (proof-of-possession) and
 *       stash the signature in st->res.signed_rtag.
 * WHY:  the signature proves we hold the proxy private key; absent a server
 *       rtag it is a no-op (returns 0).  On a signing failure st->aeskey is
 *       cleansed before failing, exactly as before.
 * HOW:  writes st->res.signed_rtag / st->res.signed_rtag_len; borrows
 *       st->proxy_key and st->sbody/slen; fails via gsi_cresp_state_fail.
 */
static int
gsi_cresp_sign_server_tag(gsi_cresp_state_t *st)
{
    const uint8_t *xmain = NULL;
    const uint8_t *srtag = NULL;
    size_t xmainlen = 0;
    size_t srtaglen = 0;
    uint8_t sig[1024];
    size_t siglen;

    if (brix_gsi_find_bucket(st->sbody, st->slen, (uint32_t) kXRS_main,
                             &xmain, &xmainlen) != 0) {
        return 0;
    }
    if (brix_gsi_find_bucket(xmain, xmainlen, (uint32_t) kXRS_rtag,
                             &srtag, &srtaglen) != 0) {
        return 0;
    }

    siglen = brix_gsi_rsa_sign_raw(st->proxy_key, srtag, srtaglen, sig);
    if (siglen == 0 || siglen > sizeof(sig)) {
        OPENSSL_cleanse(st->aeskey, BRIX_GSI_MAX_KEY);
        return gsi_cresp_state_fail(st,
                              "gsi: signing the server tag with the proxy key");
    }

    st->res.signed_rtag = malloc(siglen);
    if (st->res.signed_rtag == NULL) {
        OPENSSL_cleanse(st->aeskey, BRIX_GSI_MAX_KEY);
        return gsi_cresp_state_fail(st,
                              "gsi: signing the server tag with the proxy key");
    }
    memcpy(st->res.signed_rtag, sig, siglen);
    st->res.signed_rtag_len = siglen;
    return 0;
}

/*
 * gsi_add_fullproxy_bucket — OPT-IN client full-proxy passthrough (phase-70
 * §5.1). When XRD_DELEGATEFULLPROXY is set, load the FULL proxy (cert chain +
 * private key PEM) from $X509_USER_PROXY and append it as a kXRS_x509_fullproxy
 * bucket in the encrypted inner buffer, so a delegation-enabled node can present
 * the user's own proxy upstream. STRICTLY off by default: no env ⇒ no-op, so
 * the shared kernel's server/TPC callers (which never set the var) are inert.
 * Best-effort — a load failure silently omits the bucket (login still succeeds
 * with the normal chain-only kXRS_x509). The bytes carry a private key: the
 * caller encrypts the whole inner buffer, so they never cross the wire in clear,
 * and the server accepts them only under TLS.
 */
static void
gsi_add_fullproxy_bucket(brix_gbuf *inner)
{
    const char *proxy;
    FILE       *fp;
    uint8_t     buf[16384];
    size_t      total;

    if (getenv("XRD_DELEGATEFULLPROXY") == NULL) {
        return;
    }
    proxy = getenv("X509_USER_PROXY");
    if (proxy == NULL || proxy[0] == '\0') {
        return;
    }

    fp = fopen(proxy, "r");
    if (fp == NULL) {
        return;
    }
    /* A grid proxy file stores the proxy cert chain followed by its private key
     * in PEM — forward it verbatim as the full proxy (chain + key). Capped at
     * buf[]; a proxy larger than that omits the bucket rather than truncating. */
    total = fread(buf, 1, sizeof(buf), fp);
    if (total > 0 && total < sizeof(buf)) {
        brix_gbuf_bucket(inner, (uint32_t) kXRS_x509_fullproxy, buf, total);
    }
    OPENSSL_cleanse(buf, sizeof(buf));
    (void) fclose(fp); /* phase74-fp: read-only stream, close failure cannot lose data */
}

/*
 * WHAT: gsi_cresp_build_inner — assemble and encrypt the response's inner
 *       (main) buffer: kXGC_cert + proxy PEM + optional full-proxy passthrough
 *       + optional signed server tag + a fresh client rtag, encrypted with the
 *       agreed AES session cipher; then satisfy the optional cipher export.
 * WHY:  the encrypted main is what proves possession and carries the credential
 *       to the peer.  The XRDC_GSI_USEIV override, the export copy-out, and the
 *       unconditional aeskey cleanse are all preserved verbatim.
 * HOW:  reads st->proxy_pem/proxy_pem_len/signed_dh/sesscipher/aeskey/
 *       chosen_cipher; writes st->use_iv, st->enclen, st->res.enc, and (when
 *       non-NULL) st->out_key/out_keylen/out_cipher/out_use_iv.
 */
static int
gsi_cresp_build_inner(gsi_cresp_state_t *st)
{
    uint8_t newrtag[8];

    if (!brix_gsi_rand(newrtag, sizeof(newrtag))) {
        OPENSSL_cleanse(st->aeskey, BRIX_GSI_MAX_KEY);
        return gsi_cresp_state_fail(st, "gsi: RNG failed");
    }

    brix_gbuf_start(&st->res.inner, (uint32_t) kXGC_cert);
    brix_gbuf_bucket(&st->res.inner, (uint32_t) kXRS_x509, st->proxy_pem,
                     st->proxy_pem_len);
    gsi_add_fullproxy_bucket(&st->res.inner); /* phase-70 §5.1 opt-in passthrough */
    if (st->res.signed_rtag != NULL) {
        brix_gbuf_bucket(&st->res.inner, (uint32_t) kXRS_signed_rtag,
                         st->res.signed_rtag, st->res.signed_rtag_len);
    }
    brix_gbuf_bucket(&st->res.inner, (uint32_t) kXRS_rtag, newrtag,
                     sizeof(newrtag));
    brix_gbuf_end(&st->res.inner);

    st->use_iv = st->signed_dh;
    {
        const char *ivov = getenv("XRDC_GSI_USEIV");
        if (ivov != NULL) {
            st->use_iv = atoi(ivov);
        }
    }
    if (!st->res.inner.err) {
        st->res.enc = brix_gsi_cipher_encrypt(&st->sesscipher, st->aeskey,
                                              st->res.inner.p,
                                              st->res.inner.len, st->use_iv,
                                              &st->enclen);
    }

    if (st->out_key != NULL && st->out_keylen != NULL) {
        memcpy(st->out_key, st->aeskey, st->sesscipher.key_len);
        *st->out_keylen = st->sesscipher.key_len;
    }
    if (st->out_cipher != NULL && st->out_cipher_cap > 0) {
        snprintf(st->out_cipher, st->out_cipher_cap, "%s", st->chosen_cipher);
    }
    if (st->out_use_iv != NULL) {
        *st->out_use_iv = st->use_iv;
    }

    OPENSSL_cleanse(st->aeskey, BRIX_GSI_MAX_KEY);
    if (st->res.inner.err || st->res.enc == NULL) {
        return gsi_cresp_state_fail(st, "gsi: main encrypt failed");
    }
    return 0;
}

/*
 * WHAT: gsi_cresp_add_signed_public — signed-DH branch of the outer buffer:
 *       RSA-sign our DH public with the proxy key (kXRS_cipher) and append the
 *       proxy public key PEM (kXRS_puk) so the server can verify it.
 * WHY:  in the signed-DH variant the peer must be able to verify our DH public
 *       came from the proxy key holder before decrypting our cert chain.  The
 *       two-bucket layout (signed cpub, then proxy pubkey PEM) is byte-frozen.
 * HOW:  reads st->proxy_key and st->res.cpub (length cpublen); writes
 *       st->res.signed_cpub / st->res.pubpem and appends both outer buckets.
 */
static int
gsi_cresp_add_signed_public(gsi_cresp_state_t *st, size_t cpublen)
{
    size_t cap = cpublen + (size_t) EVP_PKEY_size(st->proxy_key) + 64;
    size_t public_pem_len = 0;

    st->res.signed_cpub = malloc(cap);
    if (st->res.signed_cpub != NULL) {
        st->res.signed_cpub_len = brix_gsi_rsa_encrypt_private(
            st->proxy_key, (const uint8_t *) st->res.cpub, cpublen,
            st->res.signed_cpub, cap);
    }
    if (st->res.signed_cpub == NULL || st->res.signed_cpub_len == 0) {
        return gsi_cresp_state_fail(st, "gsi: signing session public");
    }
    brix_gbuf_bucket(&st->res.outer, (uint32_t) kXRS_cipher,
                     st->res.signed_cpub, st->res.signed_cpub_len);

    st->res.pubpem = gsi_cresp_export_pubkey_pem(st->proxy_key,
                                                 &public_pem_len);
    if (st->res.pubpem == NULL) {
        return gsi_cresp_state_fail(st, "gsi: export proxy pubkey");
    }
    brix_gbuf_bucket(&st->res.outer, (uint32_t) kXRS_puk, st->res.pubpem,
                     public_pem_len);
    return 0;
}

/*
 * WHAT: gsi_cresp_build_outer — assemble the cleartext outer kXGC_cert buffer:
 *       cryptomod, our DH public (signed or plain), the negotiated cipher_alg
 *       (with #iv_len suffix when IV is used), the echoed md_alg, and the
 *       encrypted main produced by gsi_cresp_build_inner.
 * WHY:  this is the wire payload the caller ships back to the server; its
 *       bucket set, order and cipher_field/md_alg formatting are byte-frozen.
 * HOW:  reads st->res.mine/enc, st->signed_dh/use_iv/sesscipher/chosen_cipher/
 *       enclen and st->sbody/slen; writes st->res.cpub and st->res.outer.
 */
static int
gsi_cresp_build_outer(gsi_cresp_state_t *st)
{
    size_t cpublen = 0;
    char cipher_field[40];
    char md_alg[32];
    size_t md_alg_len;

    st->res.cpub = brix_gsi_cipher_public(st->res.mine, &cpublen);
    if (st->res.cpub == NULL) {
        return gsi_cresp_state_fail(st, "gsi: cannot encode session public");
    }

    brix_gbuf_start(&st->res.outer, (uint32_t) kXGC_cert);
    brix_gbuf_bucket(&st->res.outer, (uint32_t) kXRS_cryptomod, "ssl", 3);
    if (st->signed_dh) {
        if (gsi_cresp_add_signed_public(st, cpublen) != 0) {
            return -1;
        }
    } else {
        brix_gbuf_bucket(&st->res.outer, (uint32_t) kXRS_puk, st->res.cpub,
                         cpublen);
    }

    if (st->use_iv) {
        snprintf(cipher_field, sizeof(cipher_field), "%s#%d",
                 st->chosen_cipher, st->sesscipher.iv_len);
    } else {
        snprintf(cipher_field, sizeof(cipher_field), "%s", st->chosen_cipher);
    }
    brix_gbuf_bucket(&st->res.outer, (uint32_t) kXRS_cipher_alg, cipher_field,
                     strlen(cipher_field));
    md_alg_len = gsi_cresp_pick_md_alg(st->sbody, st->slen, md_alg,
                                       sizeof(md_alg));
    brix_gbuf_bucket(&st->res.outer, (uint32_t) kXRS_md_alg, md_alg,
                     md_alg_len);
    brix_gbuf_bucket(&st->res.outer, (uint32_t) kXRS_main, st->res.enc,
                     st->enclen);
    brix_gbuf_end(&st->res.outer);
    if (st->res.outer.err) {
        return gsi_cresp_state_fail(st, "gsi: out of memory");
    }
    return 0;
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
    gsi_cresp_state_t st;

    memset(&st, 0, sizeof(st));
    brix_gbuf_init(&st.res.inner);
    brix_gbuf_init(&st.res.outer);
    st.sbody = sbody;
    st.slen = slen;
    st.proxy_pem = proxy_pem;
    st.proxy_pem_len = proxy_pem_len;
    st.proxy_key = proxy_key;
    st.out_key = out_key;
    st.out_keylen = out_keylen;
    st.out_cipher = out_cipher;
    st.out_cipher_cap = out_cipher_cap;
    st.out_use_iv = out_use_iv;
    st.err = err;
    st.errcap = errcap;

    if (proxy_pem == NULL || proxy_key == NULL) {
        return gsi_cresp_state_fail(&st, "gsi: missing proxy credential");
    }

    if (gsi_cresp_extract_peer_pub(&st) != 0) {
        return -1;
    }

    gsi_cresp_choose_cipher(&st);
    if (gsi_cresp_agree_session_key(&st) != 0) {
        return -1;
    }

    if (gsi_cresp_sign_server_tag(&st) != 0) {
        return -1;
    }

    if (gsi_cresp_build_inner(&st) != 0) {
        return -1;
    }

    if (gsi_cresp_build_outer(&st) != 0) {
        return -1;
    }

    *payload = st.res.outer.p;
    *plen = (uint32_t) st.res.outer.len;
    st.res.outer.p = NULL;      /* ownership → caller */
    (void) gsi_cresp_fail(&st.res, NULL, 0, NULL); /* free everything else, no err */
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
    static const uint16_t exempt_ops[] = {
        kXR_login, kXR_protocol, kXR_auth, kXR_endsess,
        kXR_ping, kXR_sigver, kXR_bind
    };
    static const uint16_t level2_ops[] = {
        kXR_open, kXR_write, kXR_pgwrite, kXR_writev, kXR_truncate,
        kXR_mkdir, kXR_rm, kXR_rmdir, kXR_mv, kXR_chmod, kXR_fattr,
        kXR_chkpoint, kXR_clone
    };
    size_t op_index;

    if (level <= 1) {
        return 0;
    }

    for (op_index = 0; op_index < sizeof(exempt_ops) / sizeof(exempt_ops[0]);
         op_index++) {
        if (op == exempt_ops[op_index]) {
            return 0;
        }
    }

    if (level == 2) {
        for (op_index = 0; op_index < sizeof(level2_ops) / sizeof(level2_ops[0]);
             op_index++) {
            if (op == level2_ops[op_index]) {
                return 1;
            }
        }
        return 0;
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
