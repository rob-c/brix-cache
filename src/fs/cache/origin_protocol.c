#include "cache_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared handshake/protocol/login packers */
#include "core/compat/fattr_codec.h"        /* xrdp_fattr_nvec_parse (kXR_fattr replies) */
#include "protocols/root/protocol/frame_hdr.h"        /* xrd_error_body_decode (kXR_error errnum) */
#include "auth/gsi/gsi_core.h"              /* shared XrdSecgsi handshake kernel (C-3 GSI) */
#include "protocols/root/protocol/gsi.h"              /* kXRS_x509 bucket id (origin-cert verify) */
#include "auth/sss/sss_keytab_kernel.h"     /* §14 SSS: shared keytab line grammar */
#include <stdio.h>                        /* fdopen/fgets for the keytab reader */


#if defined(__linux__)
#include <endian.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>
#include <openssl/err.h>

/* cache_origin_send_kxr_auth — frame one kXR_auth request: ClientAuthRequest header
 * (credtype = the 4-byte protocol id) + the credential payload, on the connector
 * stream. Shared by the ztn and gsi auth helpers. Returns 0, or -1 (errno set). */
static int
cache_origin_send_kxr_auth(xrootd_cache_origin_conn_t *oc, const char credtype[4],
    const u_char *payload, uint32_t plen)
{
    ClientAuthRequest req;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 1;                         /* the connector stream */
    req.requestid   = htons(kXR_auth);
    ngx_memcpy(req.credtype, credtype, 4);
    req.dlen        = htonl((kXR_int32) plen);

    if (xrootd_cache_io_send(oc, &req, sizeof(req)) != 0
        || (plen > 0 && xrootd_cache_io_send(oc, payload, plen) != 0))
    {
        return -1;
    }
    return 0;
}

/* xrootd_cache_origin_auth_ztn — present a WLCG/SciToken bearer to the origin via
 * the XrdSecztn protocol after a kXR_login returned kXR_authmore. The credential is
 * a single-round kXR_auth: credtype "ztn\0", payload "ztn\0" + <token> (the exact
 * wire format the native client's sec_token.c sends and this server's gsi/token.c
 * parses). Returns 0 on a kXR_ok auth, -1 otherwise (t error set). §14/C-3. */
static int
xrootd_cache_origin_auth_ztn(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const ngx_str_t *token)
{
    u_char           *blob;
    size_t            blen;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body;

    blen = 4 + token->len;                      /* "ztn\0" + token */
    blob = malloc(blen);
    if (blob == NULL) {
        xrootd_cache_set_error(t, kXR_NoMemory, 0,
                               "cache origin ztn payload allocation failed");
        return -1;
    }
    ngx_memcpy(blob, "ztn", 4);                 /* copies the trailing NUL too */
    ngx_memcpy(blob + 4, token->data, token->len);

    if (cache_origin_send_kxr_auth(oc, "ztn", blob, (uint32_t) blen) != 0) {
        free(blob);
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin ztn auth write failed");
        return -1;
    }
    free(blob);

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "cache origin token auth rejected");
        free(body);
        return -1;
    }
    free(body);

    if (status != kXR_ok) {
        /* ztn is single-round; a second authmore (or anything else) is a failure. */
        xrootd_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin token auth incomplete");
        return -1;
    }
    return 0;
}

/* Load the proxy cert chain as one contiguous PEM blob (certs only). The proxy is an
 * operator-configured path (trusted, like the server's own cert/key); opened
 * O_NOFOLLOW so a planted symlink cannot redirect it. malloc'd, *outlen set; NULL on
 * failure. Mirrors client/lib/sec/sec_gsi.c load_proxy_pem. */
static uint8_t *
cache_origin_load_proxy_pem(const char *path, size_t *outlen)
{
    int      fd;
    BIO     *in, *out;
    X509    *cert;
    BUF_MEM *bm;
    uint8_t *buf = NULL;
    int      n = 0;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);  /* vfs-seam-allow: config-domain X.509 proxy PEM (not export storage) */
    if (fd < 0) {
        return NULL;
    }
    in = BIO_new_fd(fd, BIO_CLOSE);
    if (in == NULL) {
        close(fd);
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
    ERR_clear_error();                          /* benign PEM EOF on the loop end */
    BIO_free(in);

    if (n > 0) {
        BIO_get_mem_ptr(out, &bm);
        buf = malloc(bm->length);
        if (buf != NULL) {
            ngx_memcpy(buf, bm->data, bm->length);
            *outlen = bm->length;
        }
    }
    BIO_free(out);
    return buf;
}

/* Load the proxy RSA private key (the proxy PEM holds the key + the chain). */
static EVP_PKEY *
cache_origin_load_proxy_key(const char *path)
{
    int       fd;
    BIO      *in;
    EVP_PKEY *k = NULL;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);  /* vfs-seam-allow: config-domain X.509 proxy key (not export storage) */
    if (fd < 0) {
        return NULL;
    }
    in = BIO_new_fd(fd, BIO_CLOSE);
    if (in == NULL) {
        close(fd);
        return NULL;
    }
    k = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    BIO_free(in);
    return k;
}

/* Extract the "gsi" protocol's parameter substring from a login advert that may
 * carry several "&P=<proto>,<parms>" entries (e.g. "&P=ztn,v:10000&P=gsi,v:10600,
 * c:ssl,ca:HASH"). Returns a pointer INTO `parms` just past "gsi," (the v:/c:/ca:
 * list xrootd_gsi_parse_parms wants), or NULL when gsi is not advertised. */
static const char *
cache_origin_gsi_parms(const char *parms, size_t plen)
{
    static const char needle[] = "gsi,";
    size_t            i;

    if (parms == NULL || plen < sizeof(needle) - 1) {
        return NULL;
    }
    for (i = 0; i + (sizeof(needle) - 1) <= plen; i++) {
        if (ngx_strncmp(parms + i, needle, sizeof(needle) - 1) == 0) {
            return parms + i + (sizeof(needle) - 1);
        }
    }
    return NULL;
}

/* xrootd_cache_origin_auth_gsi — present an X.509 proxy to the origin via the
 * in-process XrdSecgsi two-round handshake after a login advertised "&P=gsi". The
 * DH/cipher/proof-of-possession math is the SHARED gsi_core kernel (the exact
 * implementation client/lib/sec/sec_gsi.c and src/tpc/gsi/gsi_outbound_exchange.c use):
 *   round 1  client → kXGC_certreq (build_certreq); server → kXGS_cert (kXR_authmore)
 *   round 2  client → kXGC_cert (build_cert_response w/ the proxy chain + key); → kXR_ok
 * `gsi_parms` is the server's gsi v:/c:/ca: list; `proxy_path` the proxy PEM file.
 * Returns 0 on a kXR_ok auth, -1 otherwise (t error set). C-3. */
static int
xrootd_cache_origin_auth_gsi(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const char *gsi_parms, const char *proxy_path)
{
    uint32_t   version = 0;
    char       crypto[16] = { 0 };
    char       ca[256]    = { 0 };
    uint8_t    client_rtag[8];
    uint8_t   *certreq = NULL;
    size_t     certreq_len = 0;
    uint16_t   status;
    uint32_t   dlen;
    u_char    *body = NULL;
    uint8_t   *proxy_pem = NULL;
    size_t     proxy_pem_len = 0;
    EVP_PKEY  *proxy_key = NULL;
    uint8_t   *resp = NULL;
    uint32_t   resp_len = 0;
    char       err[160];
    int        rc;

    /* ---- round 1: kXGC_certreq ---- */
    xrootd_gsi_parse_parms(gsi_parms, &version, crypto, sizeof(crypto),
                           ca, sizeof(ca));
    if (crypto[0] == '\0') {
        ngx_memcpy(crypto, "ssl", 4);
    }
    version = 10600;                            /* signed-DH default, as sec_gsi.c */
    if (!xrootd_gsi_rand(client_rtag, sizeof(client_rtag))) {
        xrootd_cache_set_error(t, kXR_ServerError, 0, "cache origin gsi RNG failed");
        return -1;
    }
    certreq = xrootd_gsi_build_certreq(crypto, version, ca, 0x80u, client_rtag,
                                       sizeof(client_rtag), &certreq_len);
    if (certreq == NULL) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin gsi certreq build failed");
        return -1;
    }
    rc = cache_origin_send_kxr_auth(oc, "gsi", certreq, (uint32_t) certreq_len);
    free(certreq);
    if (rc != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin gsi certreq write failed");
        return -1;
    }

    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 1 << 16) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen, "cache origin gsi rejected");
        free(body);
        return -1;
    }
    if (status != kXR_authmore || body == NULL || dlen < 16) {
        free(body);
        xrootd_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin gsi expected kXGS_cert");
        return -1;
    }

    /* MITM protection: when the credential names a CA (cache_origin_ca_dir →
     * conf->gsi_store), the origin's server cert MUST be present in the kXGS_cert AND
     * verify against that store BEFORE we agree a shared secret with it. No store =
     * the operator opted out of origin-cert verification (unauthenticated origin). */
    if (t->conf->gsi_store != NULL) {
        const uint8_t  *srv_pem = NULL;
        size_t          srv_pem_len = 0;
        BIO            *mbio;
        X509           *srv;
        X509_STORE_CTX *sctx;
        int             ok = 0;

        if (xrootd_gsi_find_bucket(body, dlen, (uint32_t) kXRS_x509,
                                   &srv_pem, &srv_pem_len) != 0
            || srv_pem_len == 0)
        {
            free(body);
            xrootd_cache_set_error(t, kXR_NotAuthorized, 0,
                "cache origin gsi: server presented no certificate to verify");
            return -1;
        }
        mbio = BIO_new_mem_buf(srv_pem, (int) srv_pem_len);
        srv  = (mbio != NULL) ? PEM_read_bio_X509(mbio, NULL, NULL, NULL) : NULL;
        if (mbio != NULL) { BIO_free(mbio); }
        if (srv != NULL) {
            sctx = X509_STORE_CTX_new();
            if (sctx != NULL
                && X509_STORE_CTX_init(sctx, t->conf->gsi_store, srv, NULL) == 1)
            {
                X509_STORE_CTX_set_flags(sctx, X509_V_FLAG_ALLOW_PROXY_CERTS);
                ok = (X509_verify_cert(sctx) == 1);
            }
            if (sctx != NULL) { X509_STORE_CTX_free(sctx); }
            X509_free(srv);
        }
        ERR_clear_error();
        if (!ok) {
            free(body);
            xrootd_cache_set_error(t, kXR_NotAuthorized, 0,
                "cache origin gsi: server certificate verification failed");
            return -1;
        }
    }

    /* ---- round 2: kXGC_cert with the proxy chain ---- */
    proxy_pem = cache_origin_load_proxy_pem(proxy_path, &proxy_pem_len);
    proxy_key = cache_origin_load_proxy_key(proxy_path);
    if (proxy_pem == NULL || proxy_key == NULL) {
        free(proxy_pem);
        EVP_PKEY_free(proxy_key);
        free(body);
        xrootd_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin gsi cannot load proxy credential");
        return -1;
    }

    err[0] = '\0';
    rc = xrootd_gsi_build_cert_response(body, dlen, proxy_pem, proxy_pem_len,
                                        proxy_key, &resp, &resp_len,
                                        err, sizeof(err));
    free(body);
    body = NULL;
    free(proxy_pem);
    EVP_PKEY_free(proxy_key);
    if (rc != 0) {
        xrootd_cache_set_error(t, kXR_AuthFailed, 0,
                               err[0] ? err : "cache origin gsi round-2 failed");
        return -1;
    }

    rc = cache_origin_send_kxr_auth(oc, "gsi", resp, resp_len);
    free(resp);
    if (rc != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin gsi round-2 write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "cache origin gsi authentication failed");
        free(body);
        return -1;
    }
    free(body);
    if (status != kXR_ok) {
        xrootd_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin gsi authentication incomplete");
        return -1;
    }
    return 0;
}

/* cache_origin_load_sss_key — load the first usable key from an SSS keytab file into
 * *out. The keytab is an operator-configured, trusted path (opened O_NOFOLLOW so a
 * planted symlink cannot redirect it) parsed with the SHARED keytab line grammar
 * (sss_keytab_parse_line) — the exact tokenisation the server's loader uses, so a key
 * that works one side works the other. Returns 0 with *out filled, or -1 (unreadable /
 * malformed / no usable key). */
static int
cache_origin_load_sss_key(const char *path, xrootd_sss_key_t *out)
{
    int   fd;
    FILE *fp;
    char  line[1024];
    int   found = 0;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);  /* vfs-seam-allow: config-domain SSS keytab (not export storage) */
    if (fd < 0) {
        return -1;
    }
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        return -1;
    }
    ngx_memzero(out, sizeof(*out));
    while (!found && fgets(line, sizeof(line), fp) != NULL) {
        sss_keytab_entry_t entry;
        int                rc = sss_keytab_parse_line(line, &entry,
                                                      (int64_t) ngx_time());

        if (rc < 0) {                            /* malformed ⇒ fail closed */
            fclose(fp);
            return -1;
        }
        if (rc == 0) {                           /* blank / comment / expired */
            continue;
        }
        out->id      = entry.id;
        out->exp     = (time_t) entry.exp;
        out->key_len = entry.key_len;
        ngx_memcpy(out->key, entry.key, entry.key_len);
        ngx_cpystrn((u_char *) out->user,  (u_char *) entry.user,
                    sizeof(out->user));
        ngx_cpystrn((u_char *) out->group, (u_char *) entry.group,
                    sizeof(out->group));
        ngx_cpystrn((u_char *) out->name,  (u_char *) entry.name,
                    sizeof(out->name));
        found = 1;
    }
    fclose(fp);
    return found ? 0 : -1;
}

/* xrootd_cache_origin_auth_sss — present an SSS (Simple Shared Secret) credential to
 * the origin via the XrdSecsss protocol after a login advertised "&P=sss". Mints the
 * SAME kXR_auth blob the proxy path sends (xrootd_sss_build_proxy_credential): a
 * Blowfish-CFB block over a nonce + gen-time + the keytab user, keyed by the shared
 * secret. Single-round: expect kXR_ok. Returns 0, or -1 (t error set). §14. */
static int
xrootd_cache_origin_auth_sss(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const char *keytab_path)
{
    xrootd_sss_key_t  key;
    u_char            cred[2048];
    size_t            cred_len = 0;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body = NULL;

    if (cache_origin_load_sss_key(keytab_path, &key) != 0) {
        xrootd_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin SSS keytab unreadable or has no usable key");
        return -1;
    }
    if (xrootd_sss_build_proxy_credential(&key, key.user, cred, sizeof(cred),
                                          &cred_len) != NGX_OK)
    {
        xrootd_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin SSS credential build failed");
        return -1;
    }
    if (cache_origin_send_kxr_auth(oc, "sss", cred, (uint32_t) cred_len) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
            "cache origin SSS auth write failed");
        return -1;
    }
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "cache origin SSS auth rejected");
        free(body);
        return -1;
    }
    free(body);
    if (status != kXR_ok) {                      /* SSS is single-round */
        xrootd_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin SSS auth incomplete");
        return -1;
    }
    return 0;
}

/* xrootd_cache_origin_bootstrap — three-phase XRootD connection bootstrap on a
 * raw TCP/TLS socket: ClientInitHandShake → kXR_protocol negotiation (a
 * kXR_gotoTLS flag triggers a TLS upgrade when configured) → anonymous kXR_login
 * (user 'xrd', capver kXR_ver005, streamid[1]=1). When the origin demands auth
 * (kXR_authmore) and a bearer token is configured, a ztn kXR_auth completes the
 * session. Every cache fill needs a valid session before reading. Returns 0 on
 * success, -1 on any phase failure. */
int
xrootd_cache_origin_bootstrap(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc)
{
    ClientInitHandShake    hs;
    ClientProtocolRequest  pr;
    ClientLoginRequest     lr;
    uint16_t               status;
    uint32_t               dlen;
    u_char                *body;
    static const uint8_t   sid[2] = { 0, 1 };   /* cache-origin connector streamid */

    xrd_pack_handshake(&hs);

    if (xrootd_cache_io_send(oc, &hs, sizeof(hs)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin handshake write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 64) != 0) {
        return -1;
    }
    free(body);

    if (status != kXR_ok) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin handshake failed");
        return -1;
    }

    xrd_pack_protocol_request(&pr, sid, 0);

    if (xrootd_cache_io_send(oc, &pr, sizeof(pr)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin protocol write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   sizeof(ServerProtocolBody)) != 0) {
        return -1;
    }

    if (status != kXR_ok) {
        free(body);
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin protocol negotiation failed");
        return -1;
    }

    if (dlen >= sizeof(ServerProtocolBody)) {
        ServerProtocolBody *pb;
        uint32_t            flags;

        pb = (ServerProtocolBody *) body;
        flags = (uint32_t) ntohl(pb->flags);

        if ((flags & kXR_gotoTLS) && !t->conf->cache_origin_tls) {
            free(body);
            xrootd_cache_set_error(t, kXR_TLSRequired, 0,
                "cache origin requires TLS; enable xrootd_cache_origin_tls");
            return -1;
        }
    }
    free(body);

    xrd_pack_login_request(&lr, sid, (int32_t) ngx_pid, "xrd", kXR_ver005);

    if (xrootd_cache_io_send(oc, &lr, sizeof(lr)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin login write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }

    /* A kXR_ok login on an AUTHENTICATED origin still carries an auth advert:
     * body = sessid(16) + "&P=<proto>,..." (anonymous origins send only the 16-byte
     * sessid). So a kXR_ok with a "&P=" parameter block means the session is NOT yet
     * authenticated — present the configured bearer via ztn (§14/C-3). kXR_authmore
     * is the mid-protocol variant; handle it the same way. */
    if ((status == kXR_ok || status == kXR_authmore)
        && dlen > XROOTD_SESSION_ID_LEN)
    {
        const u_char *parms = body + XROOTD_SESSION_ID_LEN;
        size_t        plen  = dlen - XROOTD_SESSION_ID_LEN;
        int           needs_auth = (ngx_strlchr((u_char *) parms,
                                        (u_char *) parms + plen, '=') != NULL);
        int           has_ztn = (ngx_strnstr((u_char *) parms, "ztn", plen) != NULL);
        int           has_sss = (ngx_strnstr((u_char *) parms, "sss", plen) != NULL);
        const char   *gp = cache_origin_gsi_parms((const char *) parms, plen);
        char          gsi_parms[256];
        int           has_gsi = 0;

        /* Copy the gsi v:/c:/ca: list out of the (about-to-be-freed) body, stopping
         * at the next "&P=" entry so a co-advertised ztn block isn't mis-parsed. */
        if (gp != NULL) {
            const char *amp = gp;
            size_t      end = (size_t) ((const char *) parms + plen - gp);
            size_t      i;

            for (i = 0; i < end && amp[i] != '&'; i++) { /* find terminator */ }
            if (i >= sizeof(gsi_parms)) { i = sizeof(gsi_parms) - 1; }
            ngx_memcpy(gsi_parms, gp, i);
            gsi_parms[i] = '\0';
            has_gsi = 1;
        }

        free(body);
        if (needs_auth) {
            if (has_ztn && t->conf->cache_origin_bearer.len > 0) {
                return xrootd_cache_origin_auth_ztn(t, oc,
                                                    &t->conf->cache_origin_bearer);
            }
            if (has_gsi && t->conf->cache_origin_x509_proxy.len > 0) {
                return xrootd_cache_origin_auth_gsi(t, oc, gsi_parms,
                    (const char *) t->conf->cache_origin_x509_proxy.data);
            }
            if (has_sss && t->conf->cache_origin_sss_keytab.len > 0) {
                return xrootd_cache_origin_auth_sss(t, oc,
                    (const char *) t->conf->cache_origin_sss_keytab.data);
            }
            xrootd_cache_set_error(t, kXR_AuthFailed, 0,
                (t->conf->cache_origin_bearer.len > 0
                 || t->conf->cache_origin_x509_proxy.len > 0
                 || t->conf->cache_origin_sss_keytab.len > 0)
                    ? "cache origin auth protocol not supported (need ztn/gsi/sss)"
                    : "cache origin requires authentication (no credential set)");
            return -1;
        }
        return 0;
    }
    free(body);

    if (status == kXR_authmore) {
        if (t->conf->cache_origin_bearer.len > 0) {
            return xrootd_cache_origin_auth_ztn(t, oc, &t->conf->cache_origin_bearer);
        }
        xrootd_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin requires authentication");
        return -1;
    }
    if (status != kXR_ok) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin anonymous login failed");
        return -1;
    }

    return 0;
}

/* xrootd_cache_origin_open — kXR_open (read + kXR_retstat) of the source file:
 * parse ServerOpenBody for the fhandle and the appended stat string, so file_size
 * is known before a full download (the admission filter can reject oversized files
 * without fetching them). Returns 0 with fhandle set, -1 on error or redirect. */
int
xrootd_cache_origin_open(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, u_char fhandle[XRD_FHANDLE_LEN])
{
    size_t             pathlen, total;
    u_char            *buf;
    ClientOpenRequest *req;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body;

    pathlen = strlen(t->clean_path);
    total = sizeof(ClientOpenRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        xrootd_cache_set_error(t, kXR_NoMemory, 0,
                               "cache origin open allocation failed");
        return -1;
    }

    ngx_memzero(buf, total);
    req = (ClientOpenRequest *) buf;
    req->streamid[1] = 2;
    req->requestid = htons(kXR_open);
    /* kXR_retstat requests an ASCII stat string appended after the fhandle so we
     * can learn the file size before committing to a full download */
    {
        xrdw_open_req_t b = { .options = kXR_open_read | kXR_retstat };
        xrdw_open_req_pack(&b, ((ClientRequestHdr *) buf)->body);
    }
    req->dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(buf + sizeof(*req), t->clean_path, pathlen);

    if (xrootd_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin open write failed");
        return -1;
    }
    free(buf);

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   XROOTD_MAX_PATH + 256) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "cache origin open failed");
        free(body);
        return -1;
    }
    if (status == kXR_redirect) {
        free(body);
        xrootd_cache_set_error(t, kXR_Unsupported, 0,
                               "cache origin redirected open; direct data "
                               "server origin is required");
        return -1;
    }
    if (status != kXR_ok || dlen < sizeof(ServerOpenBody)) {
        free(body);
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin open returned invalid response");
        return -1;
    }

    ngx_memcpy(fhandle, ((ServerOpenBody *) body)->fhandle, XRD_FHANDLE_LEN);

    /*
     * If kXR_retstat was honored the stat string follows ServerOpenBody.
     * Format: "<id> <size> <flags> <modtime>" — we only need the size (field 2).
     * The body is always NUL-terminated by xrootd_cache_read_response, so
     * strtoull is safe.
     */
    if (dlen > sizeof(ServerOpenBody)) {
        const char     *stat_str = (const char *) body + sizeof(ServerOpenBody);
        const char     *p;

        p = strchr(stat_str, ' ');
        if (p != NULL) {
            char              *endp;
            unsigned long long  sv;

            errno = 0;
            sv = strtoull(p + 1, &endp, 10);
            if (errno == 0 && endp != p + 1) {
                t->file_size = (off_t) sv;
            }
        }
    }

    free(body);
    return 0;
}

/* xrootd_cache_origin_query_checksum — ask the origin for its stored digest of
 * t->clean_path (path-based kXR_query/kXR_Qcksum), returning "<algo> <hex>" split
 * into the caller buffers. Checksum-on-fill (verify.c) validates downloaded bytes
 * against this before publishing. BEST-EFFORT: an origin with no checksum or a
 * wire hiccup must NOT fail an otherwise-complete fill (data is already on disk) —
 * on ANY failure it restores t's error state and returns 0 with alg_out emptied,
 * so the caller treats it as "no origin digest" and the verify policy decides. */
int
xrootd_cache_origin_query_checksum(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, char *alg_out, size_t alg_sz,
    char *hex_out, size_t hex_sz)
{
    size_t              pathlen, total;
    u_char             *buf;
    ClientQueryRequest *req;
    uint16_t            status;
    uint32_t            dlen;
    u_char             *body;
    char               *sp;
    int                 saved_result, saved_xrd;

    if (alg_sz > 0) {
        alg_out[0] = '\0';
    }
    if (hex_sz > 0) {
        hex_out[0] = '\0';
    }

    /* The download already succeeded; never let a checksum-query failure leak an
     * error onto the task. Snapshot and restore the error triple. */
    saved_result = t->result;
    saved_xrd    = t->xrd_error;

    pathlen = strlen(t->clean_path);
    total = sizeof(ClientQueryRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        return 0;       /* best-effort: skip verification on OOM */
    }

    ngx_memzero(buf, total);
    req = (ClientQueryRequest *) buf;
    req->streamid[1] = 6;                       /* unused stream slot */
    req->requestid = htons(kXR_query);
    {
        xrdw_query_req_t b = { .infotype = kXR_Qcksum };  /* fhandle 0 ⇒ path-based */
        xrdw_query_req_pack(&b, ((ClientRequestHdr *) buf)->body);
    }
    req->dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(buf + sizeof(*req), t->clean_path, pathlen);

    if (xrootd_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        return 0;
    }
    free(buf);

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen, 512) != 0) {
        t->result    = saved_result;
        t->xrd_error = saved_xrd;
        return 0;
    }

    if (status != kXR_ok || body == NULL || dlen == 0) {
        free(body);                             /* origin has no checksum */
        return 0;
    }

    /* body is NUL-terminated "<algo> <hexvalue>". */
    sp = strchr((char *) body, ' ');
    if (sp != NULL) {
        size_t  an = (size_t) (sp - (char *) body);
        char   *hv = sp + 1;
        char   *end = hv + strlen(hv);
        size_t  hn;

        while (end > hv && (end[-1] == '\n' || end[-1] == '\r'
                            || end[-1] == ' ' || end[-1] == '\t')) {
            end--;
        }
        hn = (size_t) (end - hv);

        if (an > 0 && an < alg_sz && hn > 0 && hn < hex_sz) {
            ngx_memcpy(alg_out, body, an);
            alg_out[an] = '\0';
            ngx_memcpy(hex_out, hv, hn);
            hex_out[hn] = '\0';
        }
    }

    free(body);
    return 0;
}

/* origin_request — send a generic 24-byte ClientRequestHdr (requestid + packed
 * `body`) plus `payload`, then read the response into (*status, *rbody, *rdlen).
 * The caller owns *rbody (free it). Returns 0 (response received — check *status)
 * or -1 on a transport failure. */
static int
origin_request(xrootd_cache_fill_t *t, xrootd_cache_origin_conn_t *oc,
    uint16_t requestid, const uint8_t body[XRDW_BODY_LEN],
    const void *payload, size_t plen, uint16_t *status, u_char **rbody,
    uint32_t *rdlen, size_t rmax)
{
    size_t            total = sizeof(ClientRequestHdr) + plen;
    u_char           *buf;
    ClientRequestHdr *req;

    buf = malloc(total);
    if (buf == NULL) {
        return -1;
    }
    ngx_memzero(buf, sizeof(ClientRequestHdr));
    req = (ClientRequestHdr *) buf;
    req->streamid[1] = 8;                       /* unused stream slot */
    req->requestid   = htons(requestid);
    ngx_memcpy(req->body, body, XRDW_BODY_LEN);
    req->dlen = htonl((kXR_int32) plen);
    if (plen > 0) {
        ngx_memcpy(buf + sizeof(ClientRequestHdr), payload, plen);
    }

    if (xrootd_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        return -1;
    }
    free(buf);

    *rbody = NULL;
    return xrootd_cache_read_response(t, oc, status, rbody, rdlen, rmax);
}

/* Map a non-ok origin response to errno. A failure is a kXR_error frame whose
 * body is [int32 errnum][msg]; decode the kXR errnum (kXR_NotFound, …) from it.
 * (Some servers may also place the kXR code directly in the status word.) */
static int
origin_status_errno(uint16_t status, const u_char *body, uint32_t dlen)
{
    int errcode = (int) status;

    if (status == kXR_error) {
        const char *m = NULL;
        size_t      ml = 0;
        (void) xrd_error_body_decode(body, dlen, &errcode, &m, &ml);
    }
    switch (errcode) {
    case kXR_NotFound:      return ENOENT;
    case kXR_NotAuthorized: return EACCES;
    case kXR_isDirectory:   return EISDIR;
    default:                return EIO;
    }
}

/* xrootd_cache_origin_rename — kXR_mv old→new on the origin. Wire payload is
 * "src ' ' dst" with arg1len=len(src). Returns 0, or -1 with errno set. */
int
xrootd_cache_origin_rename(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const char *src, const char *dst)
{
    uint8_t   body[XRDW_BODY_LEN];
    size_t    sl = strlen(src), dl = strlen(dst), total = sl + 1 + dl;
    char     *payload;
    uint16_t  status;
    uint32_t  dlen;
    u_char   *rbody;
    int       rc;

    if (sl == 0 || sl > 0x7fff) {
        errno = EINVAL;
        return -1;
    }
    payload = malloc(total);
    if (payload == NULL) {
        errno = ENOMEM;
        return -1;
    }
    ngx_memcpy(payload, src, sl);
    payload[sl] = ' ';
    ngx_memcpy(payload + sl + 1, dst, dl);

    {
        xrdw_twopath_req_t b = { .arg1len = (int16_t) sl };
        xrdw_twopath_req_pack(&b, body);
    }
    rc = origin_request(t, oc, kXR_mv, body, payload, total, &status, &rbody,
                        &dlen, 256);
    free(payload);
    if (rc != 0) {
        errno = EIO;
        return -1;
    }
    if (status != kXR_ok) {
        errno = origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    free(rbody);
    return 0;
}

/* xrootd_cache_origin_rm — kXR_rm <path> on the origin (delete a file). The rm
 * request carries no params (the 16-byte body is reserved/zero); the path is the
 * payload. Returns 0, or -1 with errno set (ENOENT when the origin reports the
 * path already gone, so a best-effort reclaim/evict is idempotent). */
int
xrootd_cache_origin_rm(xrootd_cache_fill_t *t, xrootd_cache_origin_conn_t *oc,
    const char *path)
{
    uint8_t   body[XRDW_BODY_LEN];
    size_t    pl = (path != NULL) ? strlen(path) : 0;
    uint16_t  status;
    uint32_t  dlen;
    u_char   *rbody = NULL;
    int       rc;

    if (pl == 0 || pl > 0x7fff) {
        errno = EINVAL;
        return -1;
    }
    ngx_memzero(body, sizeof(body));            /* kXR_rm params are reserved */
    rc = origin_request(t, oc, kXR_rm, body, path, pl, &status, &rbody,
                        &dlen, 256);
    if (rc != 0) {
        errno = EIO;
        return -1;
    }
    if (status != kXR_ok) {
        errno = origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    free(rbody);
    return 0;
}

/* Build "<path>\0[int16 rc=0]<name>\0" (+ "[int32 BE vlen]<value>") for a single-
 * attribute fattr request. Returns a malloc'd buffer + *plen, or NULL (OOM). */
static u_char *
origin_fattr_payload(const char *path, const char *name, const void *val,
    size_t vlen, int with_value, size_t *plen)
{
    size_t   pn = strlen(path), nn = strlen(name);
    size_t   need = pn + 1 + 2 + nn + 1 + (with_value ? 4 + vlen : 0);
    u_char  *buf, *p;

    buf = malloc(need);
    if (buf == NULL) {
        return NULL;
    }
    p = buf;
    ngx_memcpy(p, path, pn); p += pn; *p++ = 0;
    *p++ = 0; *p++ = 0;                          /* nvec int16 rc=0 */
    ngx_memcpy(p, name, nn); p += nn; *p++ = 0;
    if (with_value) {
        uint32_t vbe = htonl((uint32_t) vlen);
        ngx_memcpy(p, &vbe, 4); p += 4;
        if (vlen > 0) { ngx_memcpy(p, val, vlen); p += vlen; }
    }
    *plen = (size_t) (p - buf);
    return buf;
}

/* xrootd_cache_origin_getfattr — kXR_fattr Get of ONE attribute on `path`. Copies
 * the value into buf[cap] and returns its length, 0 if absent, or -1 (errno). */
ssize_t
xrootd_cache_origin_getfattr(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const char *path, const char *name,
    void *buf, size_t cap)
{
    uint8_t   body[XRDW_BODY_LEN];
    u_char   *payload, *rbody = NULL, *after;
    size_t    plen, next;
    uint16_t  status, rc = 0;
    uint32_t  dlen, vlen;

    payload = origin_fattr_payload(path, name, NULL, 0, 0, &plen);
    if (payload == NULL) { errno = ENOMEM; return -1; }
    {
        xrdw_fattr_req_t b = { .subcode = kXR_fattrGet, .numattr = 1 };
        xrdw_fattr_req_pack(&b, body);
    }
    if (origin_request(t, oc, kXR_fattr, body, payload, plen, &status, &rbody,
                       &dlen, 65536) != 0)
    {
        free(payload);
        errno = EIO;
        return -1;
    }
    free(payload);
    if (status != kXR_ok) {
        errno = origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    if (rbody == NULL || dlen < 2
        || xrdp_fattr_nvec_parse(rbody, dlen, 2, &rc, NULL, NULL, &next) != 0)
    {
        free(rbody);
        errno = EIO;
        return -1;
    }
    if (rc != 0) {                               /* attribute not present */
        free(rbody);
        errno = ENODATA;
        return -1;
    }
    after = rbody + next;
    if (after + 4 > rbody + dlen) { free(rbody); errno = EIO; return -1; }
    ngx_memcpy(&vlen, after, 4); vlen = ntohl(vlen); after += 4;
    if (after + vlen > rbody + dlen) { vlen = (uint32_t) (rbody + dlen - after); }
    if (buf != NULL && cap > 0) {
        ngx_memcpy(buf, after, (vlen < cap) ? vlen : cap);
    }
    free(rbody);
    return (ssize_t) vlen;
}

/* xrootd_cache_origin_listfattr — kXR_fattr List on `path`; copies the NUL-
 * separated name list into buf[cap]. Returns the byte count, or -1 (errno). */
ssize_t
xrootd_cache_origin_listfattr(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const char *path, void *buf, size_t cap)
{
    uint8_t   body[XRDW_BODY_LEN];
    size_t    pn = strlen(path);
    u_char   *payload, *rbody = NULL;
    uint16_t  status;
    uint32_t  dlen;

    payload = malloc(pn + 1);
    if (payload == NULL) { errno = ENOMEM; return -1; }
    ngx_memcpy(payload, path, pn); payload[pn] = 0;
    {
        xrdw_fattr_req_t b = { .subcode = kXR_fattrList, .numattr = 0 };
        xrdw_fattr_req_pack(&b, body);
    }
    if (origin_request(t, oc, kXR_fattr, body, payload, pn + 1, &status, &rbody,
                       &dlen, 65536) != 0)
    {
        free(payload);
        errno = EIO;
        return -1;
    }
    free(payload);
    if (status != kXR_ok) {
        errno = origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    if (buf != NULL && cap > 0 && dlen > 0) {
        ngx_memcpy(buf, rbody, (dlen < cap) ? dlen : cap);
    }
    free(rbody);
    return (ssize_t) dlen;
}

/* Shared Set/Del: build payload, send, parse the per-attribute rc. 0 / -1. */
static int
origin_fattr_set_or_del(xrootd_cache_fill_t *t, xrootd_cache_origin_conn_t *oc,
    const char *path, const char *name, const void *val, size_t vlen,
    int with_value, uint8_t subcode)
{
    uint8_t   body[XRDW_BODY_LEN];
    u_char   *payload, *rbody = NULL;
    size_t    plen, next;
    uint16_t  status, rc = 0;
    uint32_t  dlen;

    payload = origin_fattr_payload(path, name, val, vlen, with_value, &plen);
    if (payload == NULL) { errno = ENOMEM; return -1; }
    {
        xrdw_fattr_req_t b = { .subcode = subcode, .numattr = 1 };
        xrdw_fattr_req_pack(&b, body);
    }
    if (origin_request(t, oc, kXR_fattr, body, payload, plen, &status, &rbody,
                       &dlen, 4096) != 0)
    {
        free(payload);
        errno = EIO;
        return -1;
    }
    free(payload);
    if (status != kXR_ok) {
        errno = origin_status_errno(status, rbody, dlen);
        free(rbody);
        return -1;
    }
    if (rbody == NULL || dlen < 2
        || xrdp_fattr_nvec_parse(rbody, dlen, 2, &rc, NULL, NULL, &next) != 0)
    {
        free(rbody);
        errno = EIO;
        return -1;
    }
    free(rbody);
    if (rc != 0) {
        errno = (subcode == kXR_fattrDel) ? ENODATA : EIO;
        return -1;
    }
    return 0;
}

int
xrootd_cache_origin_setfattr(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const char *path, const char *name,
    const void *val, size_t vlen)
{
    return origin_fattr_set_or_del(t, oc, path, name, val, vlen, 1,
                                   kXR_fattrSet);
}

int
xrootd_cache_origin_delfattr(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const char *path, const char *name)
{
    return origin_fattr_set_or_del(t, oc, path, name, NULL, 0, 0, kXR_fattrDel);
}

/* xrootd_cache_origin_open_write — kXR_open (update + delete + mkpath) to mirror a
 * local file onto the origin: truncate the destination and create missing parent
 * dirs (where supported) for an atomic write-through replacement. Returns 0 with
 * fhandle set, -1 on error or redirect. */
int
xrootd_cache_origin_open_write(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const char *path, uint16_t mode_bits,
    u_char fhandle[XRD_FHANDLE_LEN])
{
    size_t             pathlen, total;
    u_char            *buf;
    ClientOpenRequest *req;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body;

    if (path == NULL || path[0] == '\0') {
        xrootd_cache_set_error(t, kXR_ArgInvalid, 0,
                               "write-through origin path missing");
        return -1;
    }

    pathlen = strlen(path);
    total = sizeof(ClientOpenRequest) + pathlen;

    buf = malloc(total);
    if (buf == NULL) {
        xrootd_cache_set_error(t, kXR_NoMemory, 0,
                               "write-through origin open allocation failed");
        return -1;
    }

    ngx_memzero(buf, total);
    req = (ClientOpenRequest *) buf;
    req->streamid[1] = 2;
    req->requestid = htons(kXR_open);
    /*
     * Replace the origin copy atomically from the write-through point of view:
     * open for update, create missing parents if the origin supports mkpath,
     * and truncate the destination before streaming the local contents.
     */
    {
        xrdw_open_req_t b = {
            .mode = (uint16_t) (mode_bits != 0 ? mode_bits : 0644),
            .options = kXR_open_updt | kXR_delete | kXR_mkpath
        };
        xrdw_open_req_pack(&b, ((ClientRequestHdr *) buf)->body);
    }
    req->dlen = htonl((kXR_int32) pathlen);
    ngx_memcpy(buf + sizeof(*req), path, pathlen);

    if (xrootd_cache_io_send(oc, buf, total) != 0) {
        free(buf);
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin open write failed");
        return -1;
    }
    free(buf);

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   XROOTD_MAX_PATH + 256) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "write-through origin open failed");
        free(body);
        return -1;
    }
    if (status == kXR_redirect) {
        free(body);
        xrootd_cache_set_error(t, kXR_Unsupported, 0,
                               "write-through origin redirected open; direct "
                               "data server origin is required");
        return -1;
    }
    /* A kXR_open reply is a bare 4-byte fhandle; the cpsize/cptype trailer of
     * ServerOpenBody (12 bytes) only follows when kXR_compress or kXR_retstat was
     * requested — and the write-through open requests neither.  Require only the
     * fhandle (XRD_FHANDLE_LEN), not the full struct, or a conformant origin's
     * minimal 4-byte response is wrongly rejected (which aborted the flush and
     * left the origin file half-written). The cache never uses cpsize/cptype. */
    if (status != kXR_ok || dlen < XRD_FHANDLE_LEN) {
        free(body);
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin open invalid response");
        return -1;
    }

    ngx_memcpy(fhandle, ((ServerOpenBody *) body)->fhandle, XRD_FHANDLE_LEN);
    free(body);
    return 0;
}

/* xrootd_cache_origin_close_file — send kXR_close for the fhandle and discard the
 * reply (close status only matters for errors, which don't invalidate data already
 * written to disk). Every opened file must be closed before reconnect/finish. */
void
xrootd_cache_origin_close_file(xrootd_cache_origin_conn_t *oc,
    const u_char fhandle[XRD_FHANDLE_LEN])
{
    ClientCloseRequest req;
    uint16_t           rsp_status;
    uint32_t           dlen;
    u_char            *body;
    xrootd_cache_fill_t dummy;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 2;
    req.requestid = htons(kXR_close);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.dlen = 0;

    (void) xrootd_cache_io_send(oc, &req, sizeof(req));

    ngx_memzero(&dummy, sizeof(dummy));
    dummy.result = NGX_OK;
    body = NULL;
    if (xrootd_cache_read_response(&dummy, oc, &rsp_status, &body, &dlen,
                                   4096) == 0) {
        free(body);
    }
}

/* xrootd_cache_origin_write_chunk — kXR_write a payload at a big-endian 64-bit
 * offset (htobe64, XRootD wire format); the reply must be kXR_ok with dlen=0.
 * Returns 0 on success, -1 on error. */
int
xrootd_cache_origin_write_chunk(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t offset, const u_char *data, size_t len)
{
    ClientWriteRequest req;
    uint16_t           status;
    uint32_t           dlen;
    u_char            *body;

    if (len > INT32_MAX) {
        xrootd_cache_set_error(t, kXR_ArgTooLong, 0,
                               "write-through origin write too large");
        return -1;
    }

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 3;
    req.requestid = htons(kXR_write);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.offset = (kXR_int64) htobe64(offset);
    req.dlen = htonl((kXR_int32) len);

    if (xrootd_cache_io_send(oc, &req, sizeof(req)) != 0
        || (len > 0 && xrootd_cache_io_send(oc, data, len) != 0))
    {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin write failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   4096) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "write-through origin write rejected");
        free(body);
        return -1;
    }

    free(body);
    if (status != kXR_ok || dlen != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin write invalid response");
        return -1;
    }

    return 0;
}

/* xrootd_cache_origin_truncate — kXR_truncate the origin file to a big-endian
 * 64-bit offset (used before write_chunk when the destination is larger than the
 * source); the reply must be kXR_ok. Returns 0 on success, -1 on error. */
int
xrootd_cache_origin_truncate(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    uint64_t length)
{
    ClientTruncateRequest req;
    uint16_t              status;
    uint32_t              dlen;
    u_char               *body;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 4;
    req.requestid = htons(kXR_truncate);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.offset = (kXR_int64) htobe64(length);
    req.dlen = 0;

    if (xrootd_cache_io_send(oc, &req, sizeof(req)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin truncate send failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   4096) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "write-through origin truncate failed");
        free(body);
        return -1;
    }

    free(body);
    if (status != kXR_ok) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin truncate invalid response");
        return -1;
    }

    return 0;
}

/* xrootd_cache_origin_sync — kXR_sync the origin file (fsync equivalent) after
 * streaming all chunks, so the mirrored content survives an origin crash before
 * close; the reply must be kXR_ok. Returns 0 on success, -1 on error. */
int
xrootd_cache_origin_sync(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN])
{
    ClientSyncRequest req;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 5;
    req.requestid = htons(kXR_sync);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.dlen = 0;

    if (xrootd_cache_io_send(oc, &req, sizeof(req)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "write-through origin sync send failed");
        return -1;
    }

    body = NULL;
    if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                   4096) != 0) {
        return -1;
    }

    if (status == kXR_error) {
        xrootd_cache_set_origin_error(t, body, dlen,
                                      "write-through origin sync failed");
        free(body);
        return -1;
    }

    free(body);
    if (status != kXR_ok) {
        xrootd_cache_set_error(t, kXR_ServerError, 0,
                               "write-through origin sync invalid response");
        return -1;
    }

    return 0;
}

/* Positional write into a fill sink: a driver staged-write handle (driver-backed
 * cache) or a raw POSIX fd. Keeps the origin read loop backend-agnostic. */
int
xrootd_cache_sink_pwrite(xrootd_cache_sink_t *sink, const void *buf, size_t len,
    off_t off)
{
    if (sink->mem != NULL) {
        /* In-memory sink: a positional copy into the caller's buffer, bounds-
         * checked against mem_cap. Used by the root:// remote driver's pread. */
        if (off < 0 || (size_t) off + len > sink->mem_cap) {
            errno = EINVAL;
            return -1;
        }
        ngx_memcpy(sink->mem + off, buf, len);
        return 0;
    }
    if (sink->staged != NULL) {
        ssize_t n = sink->staged->inst->driver->staged_write(sink->staged, buf,
                                                             len, off);
        return (n == (ssize_t) len) ? 0 : -1;
    }
    return xrootd_cache_fd_write_all(sink->fd, buf, len, off);
}

/* xrootd_cache_origin_read_chunk — kXR_read at (offset, rlen), writing each reply
 * payload to the sink via xrootd_cache_sink_pwrite and looping over kXR_oksofar
 * until the final kXR_ok. dlen is bounded (<= want, accumulated *got within
 * request bounds) to prevent overflow. Sets *got; returns 0 / -1. */
int
xrootd_cache_origin_read_chunk(xrootd_cache_fill_t *t,
    xrootd_cache_origin_conn_t *oc, const u_char fhandle[XRD_FHANDLE_LEN],
    xrootd_cache_sink_t *sink, uint64_t read_off, uint64_t dst_off,
    size_t want, size_t *got)
{
    ClientReadRequest req;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body;

    *got = 0;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 3;
    req.requestid = htons(kXR_read);
    ngx_memcpy(req.fhandle, fhandle, XRD_FHANDLE_LEN);
    req.offset = (kXR_int64) htobe64(read_off);
    req.rlen = htonl((kXR_int32) want);
    req.dlen = 0;

    if (xrootd_cache_io_send(oc, &req, sizeof(req)) != 0) {
        xrootd_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin read write failed");
        return -1;
    }

    for (;;) {
        body = NULL;
        if (xrootd_cache_read_response(t, oc, &status, &body, &dlen,
                                       XROOTD_CACHE_FETCH_CHUNK) != 0) {
            return -1;
        }

        if (status == kXR_error) {
            xrootd_cache_set_origin_error(t, body, dlen,
                                          "cache origin read failed");
            free(body);
            return -1;
        }

        if (status != kXR_ok && status != kXR_oksofar) {
            free(body);
            xrootd_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin read returned invalid status");
            return -1;
        }

        if ((size_t) dlen > want || *got > want - (size_t) dlen) {
            free(body);
            xrootd_cache_set_error(t, kXR_ServerError, 0,
                                   "cache origin read returned too much data");
            return -1;
        }

        if (dlen > 0) {
            /* Write at dst_off + bytes already written this call (*got). dst_off
             * is the caller's WRITE base, decoupled from the origin READ offset:
             * the whole-file fetch passes dst_off==read_off (absolute), a slice
             * fill passes a 0-relative base. Using *got alone restarts at 0 each
             * 1 MiB chunk, so multi-chunk whole-file fetches overwrote at offset 0
             * (corrupting any file > XROOTD_CACHE_FETCH_CHUNK → adler32 mismatch). */
            if (xrootd_cache_sink_pwrite(sink, body, dlen,
                                         (off_t) (dst_off + *got)) != 0) {
                free(body);
                xrootd_cache_set_syserror(t, kXR_IOError,
                                          "cache file write failed");
                return -1;
            }
            *got += (size_t) dlen;
        }

        free(body);

        if (status == kXR_ok) {
            return 0;
        }
    }
}

