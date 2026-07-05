/*
 * cache/origin_auth.c — origin-side authentication for cache fills.
 *
 * Split out of origin_protocol.c: the ztn (WLCG bearer), GSI (X.509 proxy), and
 * SSS auth handshakes a cache node performs against its upstream origin, plus
 * their credential-loading helpers.  Keeping the auth handshake (~430 lines) in
 * its own file leaves origin_protocol.c focused on the data/namespace protocol,
 * and lets the security-sensitive origin-auth path be reviewed on its own.
 *
 * The three brix_cache_origin_auth_{ztn,gsi,sss}() entry points are declared in
 * cache_internal.h and called from brix_cache_origin_bootstrap().
 */

#include "cache_internal.h"
#include "protocols/root/protocol/bootstrap_pack.h"   /* shared handshake/login packers */
#include "protocols/root/protocol/frame_hdr.h"        /* xrd_error_body_decode */
#include "auth/gsi/gsi_core.h"              /* shared XrdSecgsi handshake kernel */
#include "protocols/root/protocol/gsi.h"              /* kXRS_x509 bucket id */
#include "auth/sss/sss_keytab_kernel.h"     /* §14 SSS keytab line grammar */
#include <stdio.h>                        /* fdopen/fgets for the keytab reader */
#include <endian.h>
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

/* Frame one kXR_auth request (ClientAuthRequest header, credtype = the 4-byte
 * protocol id, + credential payload) on the connector stream.  Shared by the ztn
 * and gsi auth helpers.  Returns 0, or -1 (errno set). */
static int
cache_origin_send_kxr_auth(brix_cache_origin_conn_t *oc, const char credtype[4],
    const u_char *payload, uint32_t plen)
{
    ClientAuthRequest req;

    ngx_memzero(&req, sizeof(req));
    req.streamid[1] = 1;                         /* the connector stream */
    req.requestid   = htons(kXR_auth);
    ngx_memcpy(req.credtype, credtype, 4);
    req.dlen        = htonl((kXR_int32) plen);

    if (brix_cache_io_send(oc, &req, sizeof(req)) != 0
        || (plen > 0 && brix_cache_io_send(oc, payload, plen) != 0))
    {
        return -1;
    }
    return 0;
}

/* brix_cache_origin_auth_ztn — present a WLCG/SciToken bearer to the origin via
 * the XrdSecztn protocol after a kXR_login returned kXR_authmore. The credential is
 * a single-round kXR_auth: credtype "ztn\0", payload "ztn\0" + <token> (the exact
 * wire format the native client's sec_token.c sends and this server's gsi/token.c
 * parses). Returns 0 on a kXR_ok auth, -1 otherwise (t error set). §14/C-3. */
int
brix_cache_origin_auth_ztn(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const ngx_str_t *token)
{
    u_char           *blob;
    size_t            blen;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body;

    blen = 4 + token->len;                      /* "ztn\0" + token */
    blob = malloc(blen);
    if (blob == NULL) {
        brix_cache_set_error(t, kXR_NoMemory, 0,
                               "cache origin ztn payload allocation failed");
        return -1;
    }
    ngx_memcpy(blob, "ztn", 4);                 /* copies the trailing NUL too */
    ngx_memcpy(blob + 4, token->data, token->len);

    if (cache_origin_send_kxr_auth(oc, "ztn", blob, (uint32_t) blen) != 0) {
        free(blob);
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin ztn auth write failed");
        return -1;
    }
    free(blob);

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "cache origin token auth rejected");
        free(body);
        return -1;
    }
    free(body);

    if (status != kXR_ok) {
        /* ztn is single-round; a second authmore (or anything else) is a failure. */
        brix_cache_set_error(t, kXR_AuthFailed, 0,
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

/* brix_cache_origin_auth_gsi — present an X.509 proxy to the origin via the
 * in-process XrdSecgsi two-round handshake after a login advertised "&P=gsi". The
 * DH/cipher/proof-of-possession math is the SHARED gsi_core kernel (the exact
 * implementation client/lib/sec/sec_gsi.c and src/tpc/gsi/gsi_outbound_exchange.c use):
 *   round 1  client → kXGC_certreq (build_certreq); server → kXGS_cert (kXR_authmore)
 *   round 2  client → kXGC_cert (build_cert_response w/ the proxy chain + key); → kXR_ok
 * `gsi_parms` is the server's gsi v:/c:/ca: list; `proxy_path` the proxy PEM file.
 * Returns 0 on a kXR_ok auth, -1 otherwise (t error set). C-3. */
int
brix_cache_origin_auth_gsi(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *gsi_parms, const char *proxy_path)
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
    brix_gsi_parse_parms(gsi_parms, &version, crypto, sizeof(crypto),
                           ca, sizeof(ca));
    if (crypto[0] == '\0') {
        ngx_memcpy(crypto, "ssl", 4);
    }
    version = 10600;                            /* signed-DH default, as sec_gsi.c */
    if (!brix_gsi_rand(client_rtag, sizeof(client_rtag))) {
        brix_cache_set_error(t, kXR_ServerError, 0, "cache origin gsi RNG failed");
        return -1;
    }
    certreq = brix_gsi_build_certreq(crypto, version, ca, 0x80u, client_rtag,
                                       sizeof(client_rtag), &certreq_len);
    if (certreq == NULL) {
        brix_cache_set_error(t, kXR_ServerError, 0,
                               "cache origin gsi certreq build failed");
        return -1;
    }
    rc = cache_origin_send_kxr_auth(oc, "gsi", certreq, (uint32_t) certreq_len);
    free(certreq);
    if (rc != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin gsi certreq write failed");
        return -1;
    }

    if (brix_cache_read_response(t, oc, &status, &body, &dlen, 1 << 16) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen, "cache origin gsi rejected");
        free(body);
        return -1;
    }
    if (status != kXR_authmore || body == NULL || dlen < 16) {
        free(body);
        brix_cache_set_error(t, kXR_AuthFailed, 0,
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

        if (brix_gsi_find_bucket(body, dlen, (uint32_t) kXRS_x509,
                                   &srv_pem, &srv_pem_len) != 0
            || srv_pem_len == 0)
        {
            free(body);
            brix_cache_set_error(t, kXR_NotAuthorized, 0,
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
            brix_cache_set_error(t, kXR_NotAuthorized, 0,
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
        brix_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin gsi cannot load proxy credential");
        return -1;
    }

    err[0] = '\0';
    rc = brix_gsi_build_cert_response(body, dlen, proxy_pem, proxy_pem_len,
                                        proxy_key, &resp, &resp_len,
                                        err, sizeof(err));
    free(body);
    body = NULL;
    free(proxy_pem);
    EVP_PKEY_free(proxy_key);
    if (rc != 0) {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
                               err[0] ? err : "cache origin gsi round-2 failed");
        return -1;
    }

    rc = cache_origin_send_kxr_auth(oc, "gsi", resp, resp_len);
    free(resp);
    if (rc != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
                               "cache origin gsi round-2 write failed");
        return -1;
    }

    body = NULL;
    if (brix_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "cache origin gsi authentication failed");
        free(body);
        return -1;
    }
    free(body);
    if (status != kXR_ok) {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
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
cache_origin_load_sss_key(const char *path, brix_sss_key_t *out)
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

/* brix_cache_origin_auth_sss — present an SSS (Simple Shared Secret) credential to
 * the origin via the XrdSecsss protocol after a login advertised "&P=sss". Mints the
 * SAME kXR_auth blob the proxy path sends (brix_sss_build_proxy_credential): a
 * Blowfish-CFB block over a nonce + gen-time + the keytab user, keyed by the shared
 * secret. Single-round: expect kXR_ok. Returns 0, or -1 (t error set). §14. */
int
brix_cache_origin_auth_sss(brix_cache_fill_t *t,
    brix_cache_origin_conn_t *oc, const char *keytab_path)
{
    brix_sss_key_t  key;
    u_char            cred[2048];
    size_t            cred_len = 0;
    uint16_t          status;
    uint32_t          dlen;
    u_char           *body = NULL;

    if (cache_origin_load_sss_key(keytab_path, &key) != 0) {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin SSS keytab unreadable or has no usable key");
        return -1;
    }
    if (brix_sss_build_proxy_credential(&key, key.user, cred, sizeof(cred),
                                          &cred_len) != NGX_OK)
    {
        brix_cache_set_error(t, kXR_AuthFailed, 0,
            "cache origin SSS credential build failed");
        return -1;
    }
    if (cache_origin_send_kxr_auth(oc, "sss", cred, (uint32_t) cred_len) != 0) {
        brix_cache_set_error(t, kXR_ServerError, errno,
            "cache origin SSS auth write failed");
        return -1;
    }
    if (brix_cache_read_response(t, oc, &status, &body, &dlen, 4096) != 0) {
        return -1;
    }
    if (status == kXR_error) {
        brix_cache_set_origin_error(t, body, dlen,
                                      "cache origin SSS auth rejected");
        free(body);
        return -1;
    }
    free(body);
    if (status != kXR_ok) {                      /* SSS is single-round */
        brix_cache_set_error(t, kXR_AuthFailed, 0,
                               "cache origin SSS auth incomplete");
        return -1;
    }
    return 0;
}
