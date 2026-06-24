/*
 * sec_pwd.c — XRootD `pwd` (XrdSecpwd) auth module, client side — Phase 52 WS-B.
 *
 * WHAT: Drives the 2-round password exchange against our server dialect:
 *   round 1  client → kXRS_puk(client DH pub) + kXRS_user + kXRS_version;
 *            server → kXR_authmore: kXRS_puk(server DH pub) + credsreq.
 *   round 2  client → kXRS_main = DH-session-encrypted { kXRS_creds(password) };
 *            server → kXR_ok.
 * WHY:  Completes encryption-protocol parity (a client that can speak `pwd`).
 *       The password is sourced non-interactively (XRDC_PWD, or the stock
 *       XrdSecCREDS hex blob) and only DH-session-encrypted on the wire, so `pwd`
 *       is for trusted/closed networks under TLS only — preferred LAST.
 * HOW:  Reuses the shared gsi_core DH + session-cipher + bucket kernels (the same
 *       primitives the GSI module uses).  Per-connection round-1 state (our DH key
 *       + the password) is kept in file-statics; the CLI runs one connection at a
 *       time (mirrors sec_gsi.c).
 *
 * Wire reference: docs/refactor/phase-52-pwd-wire-spec.md.
 */
#include "sec.h"
#include "gsi/gsi_core.h"     /* shared DH + cipher + bucket kernels (-I src) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/crypto.h>

/* XrdSecpwd step codes + version (XrdSecProtocolpwd.hh). */
#define kXPC_normal   1000
#define kXPC_creds    1003
#define PWD_VERSION  10100
#define kOptsClntTty  0x0080
#define PWD_KEYLEN       16

/* Per-connection round-1 state (single connection at a time, like sec_gsi.c). */
static EVP_PKEY *g_pwd_key;             /* our DH keypair                       */
static uint8_t   g_pwd_pass[256];       /* the plaintext password (round 2)     */
static size_t    g_pwd_pass_len;

static int
pwd_have(void)
{
    return getenv("XRDC_PWD") != NULL || getenv("XrdSecCREDS") != NULL;
}

/* Hex-decode in place into out (cap bytes); returns bytes or -1. */
static int
pwd_unhex(const char *hex, uint8_t *out, size_t cap)
{
    size_t n = strlen(hex), i;

    if ((n % 2) != 0 || n / 2 > cap) {
        return -1;
    }
    for (i = 0; i < n; i += 2) {
        unsigned v;
        if (sscanf(hex + i, "%2x", &v) != 1) {
            return -1;
        }
        out[i / 2] = (uint8_t) v;
    }
    return (int) (n / 2);
}

/*
 * Resolve the plaintext password into g_pwd_pass.  Priority: XRDC_PWD (literal),
 * else the stock XrdSecCREDS hex blob ("&pwd""\0"<4-byte pfx><password>).
 * Returns 0 on success, -1 if none usable.
 */
static int
pwd_load_password(void)
{
    const char *p = getenv("XRDC_PWD");
    const char *creds;

    if (p != NULL && p[0] != '\0') {
        size_t l = strlen(p);
        if (l > sizeof(g_pwd_pass)) {
            l = sizeof(g_pwd_pass);
        }
        memcpy(g_pwd_pass, p, l);
        g_pwd_pass_len = l;
        return 0;
    }

    creds = getenv("XrdSecCREDS");
    if (creds != NULL && creds[0] != '\0') {
        uint8_t  raw[512];
        int      n = pwd_unhex(creds, raw, sizeof(raw));
        uint8_t *pwd;
        if (n > 9) {
            /* layout: "&pwd""\0"<4-byte pfx><password...> */
            pwd = (uint8_t *) memmem(raw, (size_t) n, "&pwd", 4);
            if (pwd != NULL) {
                size_t off = (size_t) (pwd - raw) + 5 + 4;   /* &pwd\0 + pfx */
                if (off < (size_t) n) {
                    size_t l = (size_t) n - off;
                    if (l > sizeof(g_pwd_pass)) {
                        l = sizeof(g_pwd_pass);
                    }
                    memcpy(g_pwd_pass, raw + off, l);
                    g_pwd_pass_len = l;
                    OPENSSL_cleanse(raw, sizeof(raw));
                    return 0;
                }
            }
        }
        OPENSSL_cleanse(raw, sizeof(raw));
    }
    return -1;
}

/* pwdStatus_t {ctype,action,options} → the htonl'd 4-byte word (see spec). */
static uint32_t
pwd_status_word(uint8_t ctype, uint16_t options)
{
    uint8_t img[4];
    img[0] = ctype;
    img[1] = 0;
    img[2] = (uint8_t) (options & 0xff);
    img[3] = (uint8_t) (options >> 8);
    return htonl(*(uint32_t *) img);
}

static int
pwd_first(xrdc_conn *c, const char *parms, uint8_t **payload, uint32_t *plen,
          xrdc_status *st)
{
    xrootd_gbuf  g;
    char        *pub;
    size_t       pub_len = 0;
    const char  *user;
    uint32_t     version, status;

    (void) c;
    (void) parms;

    if (pwd_load_password() != 0) {
        xrdc_status_set(st, XRDC_EAUTH, 0,
                        "pwd: no password (set XRDC_PWD or XrdSecCREDS)");
        return -1;
    }
    user = getenv("XRDC_PWD_USER");
    if (user == NULL || user[0] == '\0') {
        user = getenv("USER");
    }
    if (user == NULL || user[0] == '\0') {
        xrdc_status_set(st, XRDC_EAUTH, 0, "pwd: no username (set XRDC_PWD_USER)");
        return -1;
    }

    if (g_pwd_key != NULL) {
        EVP_PKEY_free(g_pwd_key);
        g_pwd_key = NULL;
    }
    g_pwd_key = xrootd_gsi_cipher_keygen();
    if (g_pwd_key == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "pwd: DH keygen failed");
        return -1;
    }
    pub = xrootd_gsi_cipher_public(g_pwd_key, &pub_len);
    if (pub == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "pwd: cannot encode key");
        return -1;
    }

    version = htonl(PWD_VERSION);
    status  = pwd_status_word(0 /*kpCT_normal*/, kOptsClntTty);

    xrootd_gbuf_init(&g);
    xrootd_gbuf_raw(&g, "pwd", 4);                      /* protocol name + NUL */
    xrootd_gbuf_u32(&g, kXPC_normal);                  /* step */
    xrootd_gbuf_bucket(&g, 3000 /*kXRS_cryptomod*/, "ssl", 3);
    xrootd_gbuf_bucket(&g, 3004 /*kXRS_puk*/, pub, pub_len);
    xrootd_gbuf_bucket(&g, 3014 /*kXRS_version*/, &version, sizeof(version));
    xrootd_gbuf_bucket(&g, 3008 /*kXRS_user*/, user, strlen(user));
    xrootd_gbuf_bucket(&g, 3015 /*kXRS_status*/, &status, sizeof(status));
    xrootd_gbuf_end(&g);
    free(pub);

    if (g.err) {
        xrootd_gbuf_free(&g);
        xrdc_status_set(st, XRDC_EAUTH, 0, "pwd: out of memory");
        return -1;
    }
    *payload = g.p;                  /* ownership → caller (g.p is malloc'd) */
    *plen = (uint32_t) g.len;
    return 0;
}

static int
pwd_more(xrdc_conn *c, const uint8_t *sbody, uint32_t slen, uint8_t **payload,
         uint32_t *plen, xrdc_status *st)
{
    const uint8_t       *spuk;
    size_t               spuk_len = 0, enc_len = 0;
    EVP_PKEY            *peer;
    uint8_t              key[PWD_KEYLEN];
    xrootd_gsi_cipher_t  cipher;
    xrootd_gbuf          inner, outer;
    uint8_t             *enc;
    int                  ok;

    (void) c;

    if (g_pwd_key == NULL
        || xrootd_gsi_find_bucket(sbody, slen, 3004 /*kXRS_puk*/,
                                  &spuk, &spuk_len) != 0)
    {
        xrdc_status_set(st, XRDC_EAUTH, 0, "pwd: server key missing");
        return -1;
    }
    peer = xrootd_gsi_cipher_parse_peer(spuk, spuk_len);
    if (peer == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "pwd: bad server key");
        return -1;
    }
    ok = xrootd_gsi_cipher_session_key(g_pwd_key, peer, 0, key, PWD_KEYLEN)
         && xrootd_gsi_cipher_lookup("aes-128-cbc", &cipher);
    EVP_PKEY_free(peer);
    EVP_PKEY_free(g_pwd_key);
    g_pwd_key = NULL;
    if (!ok) {
        OPENSSL_cleanse(key, sizeof(key));
        xrdc_status_set(st, XRDC_EAUTH, 0, "pwd: key agreement failed");
        return -1;
    }

    /* inner main buffer: "pwd\0" + step + kXRS_creds(password) + kXRS_none */
    xrootd_gbuf_init(&inner);
    xrootd_gbuf_raw(&inner, "pwd", 4);
    xrootd_gbuf_u32(&inner, kXPC_creds);
    xrootd_gbuf_bucket(&inner, 3010 /*kXRS_creds*/, g_pwd_pass, g_pwd_pass_len);
    xrootd_gbuf_end(&inner);
    OPENSSL_cleanse(g_pwd_pass, sizeof(g_pwd_pass));
    g_pwd_pass_len = 0;
    if (inner.err) {
        xrootd_gbuf_free(&inner);
        OPENSSL_cleanse(key, sizeof(key));
        xrdc_status_set(st, XRDC_EAUTH, 0, "pwd: out of memory");
        return -1;
    }

    enc = xrootd_gsi_cipher_encrypt(&cipher, key, inner.p, inner.len, 0, &enc_len);
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(inner.p, inner.len);
    xrootd_gbuf_free(&inner);
    if (enc == NULL) {
        xrdc_status_set(st, XRDC_EAUTH, 0, "pwd: credential encrypt failed");
        return -1;
    }

    /* outer: "pwd\0" + step + kXRS_main(enc) + kXRS_none */
    xrootd_gbuf_init(&outer);
    xrootd_gbuf_raw(&outer, "pwd", 4);
    xrootd_gbuf_u32(&outer, kXPC_creds);
    xrootd_gbuf_bucket(&outer, 3001 /*kXRS_main*/, enc, enc_len);
    xrootd_gbuf_end(&outer);
    free(enc);
    if (outer.err) {
        xrootd_gbuf_free(&outer);
        xrdc_status_set(st, XRDC_EAUTH, 0, "pwd: out of memory");
        return -1;
    }

    *payload = outer.p;
    *plen = (uint32_t) outer.len;
    return 0;
}

const xrdc_sec_module *
xrdc_sec_pwd(void)
{
    static const xrdc_sec_module m = {
        "pwd",
        { 'p', 'w', 'd', 0 },
        pwd_have,
        pwd_first,
        pwd_more,
        NULL,
    };
    return &m;
}
