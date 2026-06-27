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

    /* Resolve the proxy path: prefer the credential store when present, fall
     * back to env/default discovery so env-sourced proxies work as today. */
    if (c != NULL && c->opts.cred != NULL) {
        xrdc_cred_view v;
        if (xrdc_cred_acquire(c->opts.cred, XRDC_CRED_X509_PROXY, 0, &v, st) == 0
            && v.path != NULL) {
            snprintf(proxy, sizeof(proxy), "%s", v.path);
        } else {
            xrdc_status_clear(st);
            proxy_path(proxy, sizeof(proxy));
        }
    } else {
        proxy_path(proxy, sizeof(proxy));
    }

    proxy_key = load_proxy_key(proxy);
    proxy_pem = load_proxy_pem(proxy, &proxy_pem_len);
    if (proxy_key == NULL || proxy_pem == NULL) {
        free(proxy_pem);
        EVP_PKEY_free(proxy_key);
        xrdc_status_set(st, XRDC_EAUTH, 0, "gsi: cannot load proxy credential");
        return -1;
    }

    err[0] = '\0';
    rc = xrootd_gsi_build_cert_response(sbody, slen, proxy_pem, proxy_pem_len,
                                        proxy_key, payload, plen,
                                        err, sizeof(err));
    free(proxy_pem);
    EVP_PKEY_free(proxy_key);
    if (rc != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        err[0] != '\0' ? err : "gsi: round-2 failed");
        return -1;
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
