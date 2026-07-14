/*
 * gsi_core_cresp.c — round-2 XrdSecgsi cert-response state machine.
 *
 * WHAT: The client/dest round-2 exchange — resolve the server DH public
 *       (signed-DH via kXRS_cipher, else plain kXRS_puk), negotiate the session
 *       cipher, agree the AES session key, sign the server tag with the proxy
 *       key, and assemble+encrypt the inner main + cleartext outer kXGC_cert.
 *       brix_gsi_build_cert_response_ex is the frozen extern entry point (with
 *       optional cipher export); brix_gsi_build_cert_response wraps it.
 *
 * WHY:  gsi_core.c exceeded the ~500-line file-size guard, so this state machine
 *       was carved out from the leaf helpers (gsi_core_cresp_util.c) under
 *       phase-79. SECURITY-CRITICAL: the split moves no logic and changes no
 *       OpenSSL call order and no emitted bytes — the DH exchange, cert/response
 *       build, signature crypto, and key handling are byte-for-byte identical.
 *
 * HOW:  brix_gsi_build_cert_response_ex zero-inits one gsi_cresp_state_t and
 *       drives the helper chain (extract-peer-pub → choose-cipher →
 *       agree-session-key → sign-server-tag → build-inner → build-outer); each
 *       helper fails through gsi_cresp_state_fail → the extern gsi_cresp_fail
 *       destructor. Leaf helpers are declared in shared gsi_core_internal.h.
 */
#include "gsi_core_internal.h"


/*
 * WHAT: gsi_cresp_state_t — file-local aggregate threading the whole round-2
 *       cert-response state (owned resources, server body, borrowed proxy
 *       credential, the negotiated DH/session-key/cipher state, and the
 *       optional session-cipher export) through the static builder helpers.
 * WHY:  the round-2 builders each need most of the same state; passed loose it
 *       produced 8–16-param signatures.  One file-local struct is pure signature
 *       consolidation — it moves no logic and changes no emitted bytes.
 * HOW:  brix_gsi_build_cert_response_ex zero-inits one on the stack, seeds the
 *       borrowed inputs, and passes &st to each helper.  `res` embeds the
 *       header's gsi_cresp_ctx so the extern gsi_cresp_fail destructor is used
 *       unchanged via &st->res.  Buffers live inline so their addresses stay
 *       stable across the helper chain.
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
        /* phase79-fp: unix.Malloc "potential leak" — peerblob (and the
         * signed_rtag/signed_cpub mallocs below) transfer ownership to the
         * st->res struct; all three are released by the res cleanup in
         * gsi_core_cresp_util.c (free(x->peerblob/signed_rtag/signed_cpub)). The
         * analyzer does not track the struct-stored pointer to that free. */
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
