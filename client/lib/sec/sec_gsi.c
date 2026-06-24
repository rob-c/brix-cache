/*
 * sec_gsi.c — GSI (X.509 proxy) auth module, client side.
 *
 * WHAT: Drives the XRootD GSI two-round exchange against the nginx dialect:
 *   round 1  client → kXGC_certreq;  server → kXGS_cert (kXR_authmore) with its DH
 *            public key + cert + cipher list.
 *   round 2  client → kXGC_cert: our DH pubkey + selected cipher + AES-256-CBC
 *            (kXRS_main) wrapping inner "gsi\0"+kXGC_cert+kXRS_x509(proxy PEM);
 *            server → kXR_ok.
 * WHY:  X.509 proxies are the dominant WLCG auth.
 * HOW:  All the DH/bucket/secret math lives in the shared gsi_core (compiled into
 *       both this client and the nginx module); this file is only the orchestration
 *       plus the two client-specific bits: loading the proxy PEM and AES-encrypting
 *       the inner buffer. signing_key = SHA256(secret) via libxrdproto's xrootd_sha256.
 *
 * Clean-room: every wire fact is the inverse of our own server code under src/gsi.
 */
#include "sec.h"
#include "gsi/gsi_core.h"     /* shared GSI crypto + bucket kernels (-I src) */
#include "compat/crypto.h"    /* xrootd_sha256 (libxrdproto) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

/* Resolve the proxy path: $X509_USER_PROXY, else /tmp/x509up_u<uid>. */
static void
proxy_path(char *out, size_t outsz)
{
    const char *env = getenv("X509_USER_PROXY");
    if (env != NULL && env[0] != '\0') {
        snprintf(out, outsz, "%s", env);
    } else {
        snprintf(out, outsz, "/tmp/x509up_u%u", (unsigned) geteuid());
    }
}

static int
gsi_have(void)
{
    char path[512];
    proxy_path(path, sizeof(path));
    return access(path, R_OK) == 0;
}


/* Load the proxy cert chain from disk as concatenated PEM (certs only). */
static uint8_t *
load_proxy_pem(size_t *outlen)
{
    char     path[512];
    BIO     *in, *out;
    X509    *cert;
    BUF_MEM *bm;
    uint8_t *buf = NULL;
    int      n = 0;

    proxy_path(path, sizeof(path));
    in = BIO_new_file(path, "r");
    if (in == NULL) {
        return NULL;
    }
    out = BIO_new(BIO_s_mem());
    if (out == NULL) {
        BIO_free(in);
        return NULL;
    }
    while ((cert = PEM_read_bio_X509(in, NULL, NULL, NULL)) != NULL) {
        PEM_write_bio_X509(out, cert);
        X509_free(cert);
        n++;
    }
    ERR_clear_error();   /* the loop's terminating NULL leaves a benign PEM EOF error */
    BIO_free(in);

    if (n > 0) {
        BIO_get_mem_ptr(out, &bm);
        buf = (uint8_t *) malloc(bm->length);
        if (buf != NULL) {
            memcpy(buf, bm->data, bm->length);
            *outlen = bm->length;
        }
    }
    BIO_free(out);
    return buf;
}

/* ---- module callbacks ---- */

/*
 * Per-connection GSI handshake state retained between gsi_first and gsi_more.
 * The CLI client runs one connection at a time, so a file-static is sufficient
 * (and avoids touching the xrdc_conn ABI); a multiplexing client would move this
 * into the connection object.
 */
static uint8_t g_client_rtag[8];   /* our round-1 random tag (server signs it) */
static int     g_have_rtag;

static int
gsi_first(xrdc_conn *c, const char *parms, uint8_t **payload, uint32_t *plen,
          xrdc_status *st)
{
    uint32_t version = 0;
    char     crypto[16] = { 0 };
    char     ca[256]    = { 0 };
    uint8_t *buf;
    size_t   buflen = 0;

    (void) c;

    /* The server advertised v:/c:/ca: in the gsi protocol parms; echo crypto+ca
     * so it picks the right module + CA chain (a stock client does the same). */
    xrootd_gsi_parse_parms(parms, &version, crypto, sizeof(crypto),
                           ca, sizeof(ca));
    if (crypto[0] == '\0') { memcpy(crypto, "ssl", 4); }

    /* phase-48: advertise a pre-DHsigned version (< XrdSecgsiVersDHsigned=10400)
     * so the (modern) server uses the simpler UNSIGNED DH path: it sends its DH
     * public as a plain kXRS_puk Public() blob (no RSA-signed DH params), which
     * we parse with the shared cipher primitives.  Proof-of-possession is still
     * enforced — we sign the server's rtag with the proxy key in round 2.
     *
     * phase-48: advertise the modern version (>= XrdSecgsiVersDHsigned=10400) by
     * default so the server uses the SIGNED-DH path (the DH params are bound to
     * the certificates — stronger, and what a stock client does).  gsi_more
     * branches on the server's actual response (kXRS_cipher = signed,
     * kXRS_puk = unsigned), so this stays compatible with old servers too.
     * XRDC_GSI_VERSION overrides (e.g. 10300 to force the unsigned path). */
    {
        const char *vov = getenv("XRDC_GSI_VERSION");
        version = vov != NULL ? (uint32_t) strtoul(vov, NULL, 10) : 10600;
    }

    if (!xrootd_gsi_rand(g_client_rtag, sizeof(g_client_rtag))) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: RNG failed");
        return -1;
    }
    g_have_rtag = 1;

    /* clnt_opts 0x80 matches a stock client's default (delegated-proxy off). */
    buf = xrootd_gsi_build_certreq(crypto, version, ca, 0x80u,
                                   g_client_rtag, sizeof(g_client_rtag), &buflen);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: cannot build certreq");
        return -1;
    }
    *payload = buf;          /* ownership → caller */
    *plen = (uint32_t) buflen;
    return 0;
}

/* Load the proxy RSA private key (the proxy PEM holds the key + the chain). */
static EVP_PKEY *
load_proxy_key(void)
{
    char      path[512];
    BIO      *in;
    EVP_PKEY *k = NULL;

    proxy_path(path, sizeof(path));
    in = BIO_new_file(path, "r");
    if (in != NULL) {
        k = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
        BIO_free(in);
    }
    return k;
}

/* Public key of the first X.509 cert in a PEM bucket (the peer's EEC). */
static EVP_PKEY *
cert_pubkey(const uint8_t *pem, size_t len)
{
    BIO      *bio = BIO_new_mem_buf(pem, (int) len);
    X509     *cert = bio ? PEM_read_bio_X509(bio, NULL, NULL, NULL) : NULL;
    EVP_PKEY *pk = cert ? X509_get_pubkey(cert) : NULL;

    X509_free(cert);
    BIO_free(bio);
    return pk;
}

/* Export an EVP_PKEY public part as PEM SubjectPublicKeyInfo
 * (XrdCryptosslRSA::ExportPublic = PEM_write_bio_PUBKEY).  NUL-terminated;
 * malloc'd, *outlen = strlen.  The signed-DH path sends this as kXRS_puk so the
 * server can verify our signed DH before it has decrypted our cert chain. */
static char *
export_pubkey_pem(EVP_PKEY *key, size_t *outlen)
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

/*
 * gsi_more_ctx — owned resources for the round-2 (kXGC_cert) exchange, freed
 * once by gsi_more_ctx_cleanup (coding-standards §4 recipe 2: bundle + single
 * NULL-safe destructor, no goto).  Every member is zeroed at init.
 */
typedef struct {
    EVP_PKEY    *mine;          /* our session DH keypair                  */
    EVP_PKEY    *peer;          /* server session DH public                */
    EVP_PKEY    *pkey;          /* proxy private key (rtag + cipher sign)   */
    EVP_PKEY    *servpub;       /* server cert public key (verify signed DH)*/
    uint8_t     *peerblob;      /* recovered server Public() blob (signed)  */
    uint8_t     *proxy;         /* proxy cert chain (PEM)                  */
    uint8_t     *signed_rtag;   /* server rtag signed with the proxy key   */
    size_t       signed_rtag_len;
    char        *cpub;          /* our DH public, Public() wire blob       */
    uint8_t     *signed_cpub;   /* our cpub signed with the proxy key       */
    size_t       signed_cpub_len;
    char        *pubpem;        /* proxy public key PEM (signed path)       */
    uint8_t     *enc;           /* encrypted response main                 */
    xrootd_gbuf  inner;
    xrootd_gbuf  outer;
} gsi_more_ctx;

static void
gsi_more_ctx_cleanup(gsi_more_ctx *x)
{
    free(x->peerblob);
    free(x->proxy);
    free(x->signed_rtag);
    free(x->signed_cpub);
    free(x->pubpem);
    free(x->enc);
    free(x->cpub);
    EVP_PKEY_free(x->mine);
    EVP_PKEY_free(x->peer);
    EVP_PKEY_free(x->pkey);
    EVP_PKEY_free(x->servpub);
    xrootd_gbuf_free(&x->inner);
    xrootd_gbuf_free(&x->outer);
}

/* Run the cleanup and return the shared failure code (-1) for early-return. */
static int
gsi_more_fail(gsi_more_ctx *x)
{
    gsi_more_ctx_cleanup(x);
    return -1;
}

/*
 * gsi_more — round 2 (kXGC_cert), standard XrdSecgsi, both DH variants.
 *
 * The server's kXGS_cert carries its session DH public either as a plain
 * kXRS_puk Public() blob (unsigned, pre-DHsigned peers) or as a kXRS_cipher blob
 * RSA-signed with the server's cert key (signed-DH, v>=10400) — we branch on
 * which bucket is present.  Either way we agree the AES session key, sign the
 * server's random tag with the proxy key (proof of possession), and send
 * kXGC_cert with our DH public (signed with the proxy key in the signed case) +
 * an encrypted main carrying the proxy chain + the signed tag + a fresh tag.
 * HasPad/useIV follow the variant (1/1 signed, 0/0 unsigned).
 */
/*
 * Choose the kXRS_md_alg (handshake digest) to echo back to the server.  The
 * server advertises a ':'-separated preference list in its round-1 kXGS_cert;
 * the client MUST reply with one of those names or the server rejects the
 * handshake (dCache: "all sender digests are unsupported: [..]").  We prefer
 * "sha256" when offered (it matches our SHA256(secret) session-key derivation),
 * otherwise fall back to the server's first listed digest, and to "sha256" if
 * the server advertised none.  Writes a NUL-terminated name into out[outcap] and
 * returns its length.
 */
static size_t
gsi_pick_md_alg(const uint8_t *sbody, uint32_t slen, char *out, size_t outcap)
{
    const uint8_t *list = NULL;
    size_t         listlen = 0, n = 0;

    if (xrootd_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_md_alg,
                               &list, &listlen) == 0 && listlen > 0) {
        /* Prefer sha256 if it appears anywhere in the offered list. */
        if (listlen >= 6) {
            for (size_t i = 0; i + 6 <= listlen; i++) {
                if (memcmp(list + i, "sha256", 6) == 0) {
                    memcpy(out, "sha256", 6);
                    out[6] = '\0';
                    return 6;
                }
            }
        }
        /* Else copy the server's first ':'-separated token verbatim. */
        while (n < listlen && n + 1 < outcap && list[n] != ':') {
            out[n] = (char) list[n];
            n++;
        }
    }

    if (n == 0) {                       /* server offered none → our default */
        memcpy(out, "sha256", 6);
        n = 6;
    }
    out[n] = '\0';
    return n;
}

static int
gsi_more(xrdc_conn *c, const uint8_t *sbody, uint32_t slen, uint8_t **payload,
         uint32_t *plen, xrdc_status *st)
{
    const uint8_t *cipher = NULL, *puk = NULL, *sx509 = NULL, *xmain = NULL;
    size_t         cipherlen = 0, puklen = 0, sx509len = 0;
    size_t         xmainlen = 0, proxylen = 0, enclen = 0, cpublen = 0;
    const uint8_t *peerpub = NULL;
    size_t         peerpublen = 0;
    int            signed_dh;
    uint8_t        aeskey[XROOTD_GSI_MAX_KEY];
    xrootd_gsi_cipher_t sesscipher;
    char           chosen_cipher[24];
    char           cipher_field[40];
    int            use_iv;
    uint8_t        newrtag[8];
    char           md_alg[32];
    size_t         md_alg_len;
    gsi_more_ctx   x;

    (void) c;
    memset(&x, 0, sizeof(x));
    xrootd_gbuf_init(&x.inner);
    xrootd_gbuf_init(&x.outer);

    /* 1. Determine the DH variant + recover the server's DH public blob. */
    signed_dh = xrootd_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_cipher,
                                       &cipher, &cipherlen) == 0;
    if (signed_dh) {
        /* The blob is RSA-signed with the server cert key; recover it. */
        if (xrootd_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_x509,
                                   &sx509, &sx509len) != 0
            || (x.servpub = cert_pubkey(sx509, sx509len)) == NULL) {
            xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: server certificate missing");
            return gsi_more_fail(&x);
        }
        x.peerblob = malloc(cipherlen + 64);
        if (x.peerblob == NULL) {
            return gsi_more_fail(&x);
        }
        peerpublen = xrootd_gsi_rsa_decrypt_public(x.servpub, cipher, cipherlen,
                                                   x.peerblob, cipherlen + 64);
        if (peerpublen == 0) {
            xrdc_status_set(st, XRDC_EAUTH, 0,
                            "gsi: verifying signed server DH parameters");
            return gsi_more_fail(&x);
        }
        peerpub = x.peerblob;
    } else if (xrootd_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_puk,
                                      &puk, &puklen) == 0) {
        peerpub = puk;
        peerpublen = puklen;
    } else {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: server DH public missing");
        return gsi_more_fail(&x);
    }

    /* Phase 52 (WS-A): choose the session cipher from the server's advertised
     * kXRS_cipher_alg list.  aes-128-cbc is the universally-supported, proven-
     * interop choice, so we PREFER it whenever the server offers it (every stock
     * XRootD server does) — this keeps our round-2 byte-identical to the legacy
     * path against stock.  Only when the server omits aes-128-cbc entirely do we
     * negotiate the first other cipher we support. */
    {
        const uint8_t *ca = NULL; size_t cal = 0;
        char           offered[128];

        snprintf(chosen_cipher, sizeof(chosen_cipher), "aes-128-cbc");
        if (xrootd_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_cipher_alg,
                                   &ca, &cal) == 0 && cal > 0
            && cal < sizeof(offered)) {
            memcpy(offered, ca, cal);
            offered[cal] = '\0';
            if (memmem(offered, cal, "aes-128-cbc", 11) == NULL) {
                (void) xrootd_gsi_cipher_pick(offered, &sesscipher, chosen_cipher);
            }
        }
        if (!xrootd_gsi_cipher_lookup(chosen_cipher, &sesscipher)) {
            (void) xrootd_gsi_cipher_lookup("aes-128-cbc", &sesscipher);
            snprintf(chosen_cipher, sizeof(chosen_cipher), "aes-128-cbc");
        }
    }

    /* 2. Agree the session key (HasPad follows the variant). */
    {
        const uint8_t *cm = NULL; size_t cml = 0;
        int peer_nopad = (xrootd_gsi_find_bucket(sbody, slen,
                              (uint32_t) kXRS_cryptomod, &cm, &cml) == 0
                          && cml >= 5
                          && memmem(cm, cml, "nopad", 5) != NULL);
        int dh_pad = signed_dh && !peer_nopad;          /* HasPad negotiation */

        x.peer = xrootd_gsi_cipher_parse_peer(peerpub, peerpublen);
        x.mine = x.peer ? xrootd_gsi_cipher_keygen_from(x.peer) : NULL;
        if (x.peer == NULL || x.mine == NULL
            || !xrootd_gsi_cipher_session_key(x.mine, x.peer, dh_pad, aeskey,
                                              sesscipher.key_len)) {
            xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: session-key agreement failed");
            return gsi_more_fail(&x);
        }

        if (getenv("XRDC_GSI_DEBUG") != NULL) {
            const uint8_t *ca = NULL, *ma = NULL; size_t cal = 0, mal = 0;
            xrootd_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_cipher_alg, &ca, &cal);
            xrootd_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_md_alg, &ma, &mal);
            fprintf(stderr, "[gsi-dbg] variant=%s peer_nopad=%d dh_pad=%d peerpublen=%zu "
                    "cryptomod=\"%.*s\" cipher_alg=\"%.*s\" md_alg=\"%.*s\"\n",
                    signed_dh ? "signed-DH" : "unsigned", peer_nopad, dh_pad, peerpublen,
                    (int) cml, cm ? (const char *) cm : "",
                    (int) cal, ca ? (const char *) ca : "",
                    (int) mal, ma ? (const char *) ma : "");
            fprintf(stderr, "[gsi-dbg] cipher=%s aeskey=", chosen_cipher);
            for (int i = 0; i < sesscipher.key_len; i++) {
                fprintf(stderr, "%02x", aeskey[i]);
            }
            fprintf(stderr, "\n");
        }
    }

    /* 3. The server has no session key yet (it needs the public we send below),
     *    so its main is in CLEAR.  When the server issued a random tag, sign it
     *    with the proxy key (proof of possession — required by stock servers).
     *    A lenient server that issues no tag simply gets no kXRS_signed_rtag. */
    x.pkey = load_proxy_key();
    if (x.pkey == NULL) {
        OPENSSL_cleanse(aeskey, sizeof(aeskey));
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: cannot load proxy private key");
        return gsi_more_fail(&x);
    }
    if (xrootd_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_main,
                               &xmain, &xmainlen) == 0) {
        const uint8_t *srtag = NULL;
        size_t         srtaglen = 0;

        if (xrootd_gsi_find_bucket(xmain, xmainlen, (uint32_t) kXRS_rtag,
                                   &srtag, &srtaglen) == 0) {
            uint8_t sig[1024];
            size_t  siglen = xrootd_gsi_rsa_sign_raw(x.pkey, srtag, srtaglen, sig);
            if (siglen == 0 || siglen > sizeof(sig)
                || (x.signed_rtag = malloc(siglen)) == NULL) {
                OPENSSL_cleanse(aeskey, sizeof(aeskey));
                xrdc_status_set(st, XRDC_EAUTH, 0,
                                "gsi: signing the server tag with the proxy key");
                return gsi_more_fail(&x);
            }
            memcpy(x.signed_rtag, sig, siglen);
            x.signed_rtag_len = siglen;
        }
    }

    /* 4. Build + encrypt the response main: proxy chain + signed tag + new tag.
     *    The inner bucket list ends with a kXRS_none terminator (xrootd_gbuf_end):
     *    a standards-compliant server (stock XrdSecgsi, dCache/xrootd4j) parses
     *    buckets until that terminator, and without it walks off the end of the
     *    decrypted buffer ("readerIndex exceeds writerIndex").  Our own server
     *    locates buckets by type (gsi_find_bucket), so the trailing terminator is
     *    harmless there. */
    x.proxy = load_proxy_pem(&proxylen);
    if (x.proxy == NULL || !xrootd_gsi_rand(newrtag, sizeof(newrtag))) {
        OPENSSL_cleanse(aeskey, sizeof(aeskey));
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: cannot load proxy chain");
        return gsi_more_fail(&x);
    }
    xrootd_gbuf_start(&x.inner, (uint32_t) kXGC_cert);
    xrootd_gbuf_bucket(&x.inner, (uint32_t) kXRS_x509, x.proxy, proxylen);
    if (x.signed_rtag != NULL) {
        xrootd_gbuf_bucket(&x.inner, (uint32_t) kXRS_signed_rtag,
                           x.signed_rtag, x.signed_rtag_len);
    }
    xrootd_gbuf_bucket(&x.inner, (uint32_t) kXRS_rtag, newrtag, sizeof(newrtag));
    xrootd_gbuf_end(&x.inner);                 /* kXRS_none terminator (see above) */
    /*
     * IV usage (XrdSecgsi): the encrypted main carries a leading IV of the
     * cipher's own length exactly when the negotiated version >= 10400 — stock
     * keys this off the peer version (`useIV = RemVers >= XrdSecgsiVersDHsigned`),
     * NOT off any cipher-name suffix.  We advertise version 10600, so the server
     * independently sets useIV=true and strips MaxIVLength() bytes; the cipher
     * name we send (below) is bare.  signed_dh tracks the same >=10400 condition.
     * The unsigned (<10400) path carries no IV.  XRDC_GSI_USEIV overrides for
     * interop debugging. */
    use_iv = signed_dh;
    {
        const char *ivov = getenv("XRDC_GSI_USEIV");
        if (ivov != NULL) { use_iv = atoi(ivov); }
    }
    if (!x.inner.err) {
        x.enc = xrootd_gsi_cipher_encrypt(&sesscipher, aeskey, x.inner.p,
                                          x.inner.len, use_iv, &enclen);
    }
    OPENSSL_cleanse(aeskey, sizeof(aeskey));
    if (x.inner.err || x.enc == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: main encrypt failed");
        return gsi_more_fail(&x);
    }

    /* 5. Outer kXGC_cert: our DH public — as kXRS_cipher (signed with the proxy
     *    key) for signed-DH, else a plain kXRS_puk. */
    x.cpub = xrootd_gsi_cipher_public(x.mine, &cpublen);
    if (x.cpub == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: cannot encode session public");
        return gsi_more_fail(&x);
    }
    xrootd_gbuf_start(&x.outer, (uint32_t) kXGC_cert);
    xrootd_gbuf_bucket(&x.outer, (uint32_t) kXRS_cryptomod, "ssl", 3);
    if (signed_dh) {
        size_t cap = cpublen + (size_t) EVP_PKEY_size(x.pkey) + 64;
        x.signed_cpub = malloc(cap);
        if (x.signed_cpub != NULL) {
            x.signed_cpub_len = xrootd_gsi_rsa_encrypt_private(
                x.pkey, (const uint8_t *) x.cpub, cpublen, x.signed_cpub, cap);
        }
        if (x.signed_cpub == NULL || x.signed_cpub_len == 0) {
            xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: signing session public");
            return gsi_more_fail(&x);
        }
        xrootd_gbuf_bucket(&x.outer, (uint32_t) kXRS_cipher,
                           x.signed_cpub, x.signed_cpub_len);
        /* The proxy public key, so the server can verify the signed DH before it
         * has decrypted our cert chain (XrdCryptosslRSA::ExportPublic). */
        {
            size_t ppl = 0;
            x.pubpem = export_pubkey_pem(x.pkey, &ppl);
            if (x.pubpem == NULL) {
                xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: export proxy pubkey");
                return gsi_more_fail(&x);
            }
            xrootd_gbuf_bucket(&x.outer, (uint32_t) kXRS_puk, x.pubpem, ppl);
        }
    } else {
        xrootd_gbuf_bucket(&x.outer, (uint32_t) kXRS_puk, x.cpub, cpublen);
    }
    /* Echo the cipher we keyed, with the "#<ivlen>" suffix when we prepended an
     * IV.  Modern stock XRootD/EOS derive useIV from the negotiated version
     * (>=10400) and tolerate a bare name, but dCache (xrootd4j) learns the IV is
     * present ONLY from this suffix — a bare name + prepended IV makes it read
     * ivlen=0 and fail ("Could not decrypt encrypted client message").  Emitting
     * the suffix whenever use_iv keeps both EOS and dCache working.  See
     * docs/10-reference/comparison/xrootd-implementations.md §5.2 and
     * tests/test_gsi_interop_guards.py. */
    if (use_iv) {
        snprintf(cipher_field, sizeof(cipher_field), "%s#%d",
                 chosen_cipher, sesscipher.iv_len);
    } else {
        snprintf(cipher_field, sizeof(cipher_field), "%s", chosen_cipher);
    }
    xrootd_gbuf_bucket(&x.outer, (uint32_t) kXRS_cipher_alg, cipher_field,
                       strlen(cipher_field));
    /* Digest-algorithm negotiation bucket.  dCache's GSI plugin reads kXRS_md_alg
     * as a StringBucket to select the handshake hash; omitting it makes
     * digestBucket null server-side and throws an NPE ("Cannot invoke
     * StringBucket.getContent() because digestBucket is null"), failing the whole
     * handshake.  sha256 matches our key derivation (SHA256(secret)) and is
     * supported by every modern GSI server (EOS/XRootD treat it as optional, so
     * adding it is interop-safe in both directions).  The exact name is chosen
     * from the server's own offered list so it can never be "unsupported". */
    md_alg_len = gsi_pick_md_alg(sbody, slen, md_alg, sizeof(md_alg));
    xrootd_gbuf_bucket(&x.outer, (uint32_t) kXRS_md_alg, md_alg, md_alg_len);
    xrootd_gbuf_bucket(&x.outer, (uint32_t) kXRS_main, x.enc, enclen);
    xrootd_gbuf_end(&x.outer);
    if (x.outer.err) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: out of memory");
        return gsi_more_fail(&x);
    }

    *payload = x.outer.p;
    *plen = (uint32_t) x.outer.len;
    x.outer.p = NULL;          /* ownership → caller */
    gsi_more_ctx_cleanup(&x);
    return 0;
}

const xrdc_sec_module *
xrdc_sec_gsi(void)
{
    static const xrdc_sec_module m = {
        "gsi",
        { 'g', 's', 'i', 0 },
        gsi_have,
        gsi_first,
        gsi_more,
        NULL,
    };
    return &m;
}
