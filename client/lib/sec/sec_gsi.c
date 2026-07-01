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
#include "../cred.h"
#include "gsi/gsi_core.h"     /* shared GSI crypto + bucket kernels (-I src) */
#include "gsi/proxy_req.h"    /* xrootd_gsi_sign_pxyreq (X.509 delegation)   */
#include "protocol/gsi.h"     /* kXGS_pxyreq / kXGC_sigpxy / kXRS_* constants */
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
gsi_have(xrdc_conn *c)
{
    char path[512];
    /* The credential store is a fast "yes" when it can confirm a proxy, but a
     * store MISS must fall through to env/default discovery — otherwise a tool
     * that attaches a store with no x509 handler (or an empty store) would skip
     * GSI entirely even though $X509_USER_PROXY is valid.  This keeps gsi_have
     * symmetric with gsi_more, which already falls back to proxy_path(). */
    if (c != NULL && c->opts.cred != NULL
        && xrdc_cred_available(c->opts.cred, XRDC_CRED_X509_PROXY)) {
        return 1;
    }
    proxy_path(path, sizeof(path));
    return access(path, R_OK) == 0;
}


/* The GSI proxy holds a private key at a predictable /tmp/x509up_u<uid>, so it is
 * opened through xrdc_credfile_bio (secret=1: no symlink, owned by euid, 0600) —
 * the shared safe reader in proxy.c. Probe-quiet: NULL just means "no usable
 * proxy" and the auth driver moves on. */
#define proxy_bio(path) xrdc_credfile_bio((path), 1)

/* Load the proxy cert chain from disk as concatenated PEM (certs only).
 * path must be the resolved proxy file path (never NULL). */
static uint8_t *
load_proxy_pem(const char *path, size_t *outlen)
{
    BIO     *in, *out;
    X509    *cert;
    BUF_MEM *bm;
    uint8_t *buf = NULL;
    int      n = 0;

    in = proxy_bio(path);
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

/* module callbacks */
static int
gsi_first(xrdc_conn *c, const char *parms, uint8_t **payload, uint32_t *plen,
          xrdc_status *st)
{
    uint32_t version = 0;
    char     crypto[16] = { 0 };
    char     ca[256]    = { 0 };
    uint8_t *buf;
    size_t   buflen = 0;
    /* Round-1 random tag (the server signs it). Its lifetime is entirely within
     * this call — it is folded into the certreq below and never read again in
     * gsi_more — so it MUST be a stack local: the async manager (xrootdfs) opens
     * several connections in parallel, and a file-static would let one thread's
     * tag clobber another's mid-handshake, corrupting the certreq. */
    uint8_t  client_rtag[8];

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

    if (!xrootd_gsi_rand(client_rtag, sizeof(client_rtag))) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: RNG failed");
        return -1;
    }

    /* clnt_opts 0x80 matches a stock client's default (delegated-proxy off). */
    buf = xrootd_gsi_build_certreq(crypto, version, ca, 0x80u,
                                   client_rtag, sizeof(client_rtag), &buflen);
    if (buf == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: cannot build certreq");
        return -1;
    }
    *payload = buf;          /* ownership → caller */
    *plen = (uint32_t) buflen;
    return 0;
}

/* Load the proxy RSA private key (the proxy PEM holds the key + the chain).
 * path must be the resolved proxy file path (never NULL). */
static EVP_PKEY *
load_proxy_key(const char *path)
{
    BIO      *in;
    EVP_PKEY *k = NULL;

    in = proxy_bio(path);
    if (in != NULL) {
        k = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
        BIO_free(in);
    }
    return k;
}

/* Resolve the proxy path (credential store first, else env/default). Shared by
 * the round-2 (kXGC_cert) and the delegation (kXGC_sigpxy) rounds. */
static void
gsi_resolve_proxy(xrdc_conn *c, char *proxy, size_t sz, xrdc_status *st)
{
    if (c != NULL && c->opts.cred != NULL) {
        xrdc_cred_view v;
        if (xrdc_cred_acquire(c->opts.cred, XRDC_CRED_X509_PROXY, 0, &v, st) == 0
            && v.path != NULL) {
            snprintf(proxy, sz, "%s", v.path);
            return;
        }
        xrdc_status_clear(st);
    }
    proxy_path(proxy, sz);
}

/* The XrdSutBuffer step immediately follows the NUL-terminated proto name
 * ("gsi\0"); read it as a big-endian u32.  0 on a malformed/short buffer. */
static uint32_t
gsi_msg_step(const uint8_t *sbody, uint32_t slen)
{
    size_t nl;

    if (sbody == NULL || slen < 8) {
        return 0;
    }
    nl = strnlen((const char *) sbody, slen) + 1;
    if (nl + 4 > (size_t) slen) {
        return 0;
    }
    return ((uint32_t) sbody[nl] << 24) | ((uint32_t) sbody[nl + 1] << 16)
         | ((uint32_t) sbody[nl + 2] << 8) | (uint32_t) sbody[nl + 3];
}

/* Re-encode a PEM X509_REQ (how the server sends kXRS_x509_req) as DER, which
 * xrootd_gsi_sign_pxyreq consumes.  0 / -1. */
static int
gsi_req_pem_to_der(const uint8_t *pem, size_t pemlen, uint8_t **der, size_t *derlen)
{
    BIO           *b = BIO_new_mem_buf(pem, (int) pemlen);
    X509_REQ      *req = b ? PEM_read_bio_X509_REQ(b, NULL, NULL, NULL) : NULL;
    int            n;
    unsigned char *out = NULL, *pp;

    BIO_free(b);
    if (req == NULL) {
        return -1;
    }
    n = i2d_X509_REQ(req, NULL);
    if (n > 0 && (out = malloc((size_t) n)) != NULL) {
        pp = out;
        if (i2d_X509_REQ(req, &pp) <= 0) {
            free(out);
            out = NULL;
        }
    }
    X509_REQ_free(req);
    if (out == NULL) {
        return -1;
    }
    *der = out;
    *derlen = (size_t) n;
    return 0;
}

/*
 * gsi_sigpxy — the X.509 delegation round (kXGS_pxyreq → kXGC_sigpxy).  The
 * server (a TPC destination / tap proxy with delegation on) asks us to sign a
 * proxy request so it can act AS US upstream.  We decrypt its request with the
 * session cipher agreed in round 2, sign it with our proxy (a key-bearing
 * delegated proxy the server can use), and return the encrypted signed proxy.
 * Gated on XRDC_GSI_DELEGATE — handing our credential to a server is opt-in,
 * mirroring the stock client's XrdSecGSIDELEGPROXY.
 */
static int
gsi_sigpxy(xrdc_conn *c, const uint8_t *sbody, uint32_t slen, uint8_t **payload,
           uint32_t *plen, xrdc_status *st)
{
    xrootd_gsi_cipher_t  cipher;
    const uint8_t       *enc = NULL, *reqpem = NULL;
    size_t               enclen = 0, reqpemlen = 0, plainlen = 0;
    uint8_t             *plain = NULL, *reqder = NULL, *signed_pem = NULL;
    uint8_t             *enc2 = NULL, *proxy_pem = NULL;
    size_t               reqderlen = 0, siglen = 0, enc2len = 0, proxy_pem_len = 0;
    EVP_PKEY            *proxy_key = NULL;
    char                 proxy[512], err[160];
    xrootd_gbuf          inner, outer;

    if (getenv("XRDC_GSI_DELEGATE") == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "gsi: server requested X.509 delegation but "
                        "XRDC_GSI_DELEGATE is not set");
        return -1;
    }
    if (!c->gsi_deleg_ready
        || !xrootd_gsi_cipher_lookup(c->gsi_deleg_cipher, &cipher)) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "gsi: no session cipher for delegation");
        return -1;
    }

    /* 1. Decrypt the server's proxy request, extract the PEM kXRS_x509_req. */
    if (xrootd_gsi_find_bucket(sbody, slen, (uint32_t) kXRS_main, &enc, &enclen)
        != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: pxyreq main missing");
        return -1;
    }
    plain = xrootd_gsi_cipher_decrypt(&cipher, c->gsi_deleg_key, enc, enclen,
                                      c->gsi_deleg_use_iv, &plainlen);
    if (plain == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: pxyreq decrypt failed");
        return -1;
    }
    if (xrootd_gsi_find_bucket(plain, plainlen, (uint32_t) kXRS_x509_req,
                              &reqpem, &reqpemlen) != 0
        || gsi_req_pem_to_der(reqpem, reqpemlen, &reqder, &reqderlen) != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: pxyreq x509_req missing/bad");
        free(plain);
        return -1;
    }
    free(plain);

    /* 2. Sign the request with our proxy → a key-bearing delegated proxy. */
    gsi_resolve_proxy(c, proxy, sizeof(proxy), st);
    proxy_key = load_proxy_key(proxy);
    proxy_pem = load_proxy_pem(proxy, &proxy_pem_len);
    err[0] = '\0';
    if (proxy_key == NULL || proxy_pem == NULL
        || xrootd_gsi_sign_pxyreq(proxy_pem, proxy_pem_len, proxy_key,
                                  reqder, reqderlen, &signed_pem, &siglen,
                                  err, sizeof(err)) != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        err[0] != '\0' ? err : "gsi: cannot sign proxy request");
        free(reqder);
        free(proxy_pem);
        EVP_PKEY_free(proxy_key);
        return -1;
    }
    free(reqder);
    free(proxy_pem);
    EVP_PKEY_free(proxy_key);

    /* 3. Inner main = { kXGC_sigpxy + kXRS_x509(signed proxy) }, AES-encrypted
     *    under the round-2 session cipher — what the server's handle_sigpxy
     *    finds after decrypting kXRS_main. */
    xrootd_gbuf_init(&inner);
    xrootd_gbuf_init(&outer);
    xrootd_gbuf_start(&inner, (uint32_t) kXGC_sigpxy);
    xrootd_gbuf_bucket(&inner, (uint32_t) kXRS_x509, signed_pem, siglen);
    xrootd_gbuf_end(&inner);
    free(signed_pem);
    if (!inner.err) {
        enc2 = xrootd_gsi_cipher_encrypt(&cipher, c->gsi_deleg_key, inner.p,
                                         inner.len, c->gsi_deleg_use_iv, &enc2len);
    }
    xrootd_gbuf_free(&inner);
    if (enc2 == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: sigpxy main encrypt failed");
        return -1;
    }

    /* 4. Outer kXGC_sigpxy = { kXRS_main(enc) + kXRS_cipher_alg }. */
    xrootd_gbuf_start(&outer, (uint32_t) kXGC_sigpxy);
    xrootd_gbuf_bucket(&outer, (uint32_t) kXRS_main, enc2, enc2len);
    xrootd_gbuf_bucket(&outer, (uint32_t) kXRS_cipher_alg, c->gsi_deleg_cipher,
                       strlen(c->gsi_deleg_cipher));
    xrootd_gbuf_end(&outer);
    free(enc2);
    if (outer.err) {
        xrootd_gbuf_free(&outer);
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: sigpxy assembly failed");
        return -1;
    }
    *payload = outer.p;              /* ownership → the auth loop (frees it) */
    *plen = (uint32_t) outer.len;
    outer.p = NULL;
    xrootd_gbuf_free(&outer);
    return 0;
}

/*
 * gsi_more — round 2 (kXGC_cert), standard XrdSecgsi, both DH variants.  The
 * full handshake (DH variant detection, session-key agreement, proof-of-
 * possession, encrypted main + outer kXGC_cert assembly) now lives in the shared
 * gsi_core kernel (xrootd_gsi_build_cert_response) so the native client and the
 * TPC destination (src/tpc/gsi_outbound_exchange.c) drive ONE implementation.
 * This wrapper only supplies the client's proxy credential (loaded from the
 * configured proxy file) and maps the kernel's error string onto xrdc_status.
 */
static int
gsi_more(xrdc_conn *c, const uint8_t *sbody, uint32_t slen, uint8_t **payload,
         uint32_t *plen, xrdc_status *st)
{
    char      proxy[512];
    uint8_t  *proxy_pem;
    size_t    proxy_pem_len = 0;
    EVP_PKEY *proxy_key;
    char      err[160];
    int       rc;

    /* A later authmore may be the X.509 delegation request (kXGS_pxyreq) rather
     * than the cert round — dispatch on the buffer's step. */
    if (gsi_msg_step(sbody, slen) == (uint32_t) kXGS_pxyreq) {
        return gsi_sigpxy(c, sbody, slen, payload, plen, st);
    }

    gsi_resolve_proxy(c, proxy, sizeof(proxy), st);

    proxy_key = load_proxy_key(proxy);
    proxy_pem = load_proxy_pem(proxy, &proxy_pem_len);
    if (proxy_key == NULL || proxy_pem == NULL) {
        free(proxy_pem);
        EVP_PKEY_free(proxy_key);
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: cannot load proxy credential");
        return -1;
    }

    /* Retain the agreed session cipher on the connection: if the server follows
     * with a kXGS_pxyreq (delegation), gsi_sigpxy reuses it to en/decrypt. */
    err[0] = '\0';
    rc = xrootd_gsi_build_cert_response_ex(sbody, slen, proxy_pem, proxy_pem_len,
                                           proxy_key, payload, plen,
                                           c ? c->gsi_deleg_key : NULL,
                                           c ? &c->gsi_deleg_keylen : NULL,
                                           c ? c->gsi_deleg_cipher : NULL,
                                           c ? sizeof(c->gsi_deleg_cipher) : 0,
                                           c ? &c->gsi_deleg_use_iv : NULL,
                                           err, sizeof(err));
    free(proxy_pem);
    EVP_PKEY_free(proxy_key);
    if (rc != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        err[0] != '\0' ? err : "gsi: round-2 failed");
        return -1;
    }
    if (c != NULL) {
        c->gsi_deleg_ready = 1;
    }
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
