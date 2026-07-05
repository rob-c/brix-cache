/*
 * client_unittest.c — end-to-end test of the CVMFS-brix client assembler:
 * genuine signed whitelist + manifest + cert, a zlib-compressed real SQLite
 * catalog, and a content object, all served through a mock transport. Proves the
 * whole stack (trust chain → catalog resolve → content read) composes.
 *
 * Compiles without nginx:
 *   gcc -Wall -Wextra -Werror -I shared -o /tmp/cvmfs_client_ut \
 *       shared/cvmfs/client/client_unittest.c shared/cvmfs/client/client.c \
 *       shared/cvmfs/fetch/fetch.c shared/cvmfs/object/object.c \
 *       shared/cvmfs/failover/failover.c shared/cvmfs/catalog/catalog.c \
 *       shared/cvmfs/grammar/hash.c shared/cvmfs/grammar/classify.c \
 *       shared/cvmfs/signature/manifest.c shared/cvmfs/signature/whitelist.c \
 *       shared/cvmfs/signature/verify.c shared/cvmfs/config/repo.c \
 *       shared/cache/cas_store.c \
 *       -lsqlite3 -lcrypto -lz && /tmp/cvmfs_client_ut
 * Exit 0 = all checks pass.
 */
#define _GNU_SOURCE
#include "cvmfs/client/client.h"
#include "cvmfs/object/object.h"
#include "cvmfs/signature/verify.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <sqlite3.h>
#include <zlib.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_checks, g_failed;
#define CHECK(cond, name) do {                                    \
    g_checks++;                                                   \
    if (cond) { printf("  ok   %s\n", name); }                    \
    else      { printf("  FAIL %s (line %d)\n", name, __LINE__); g_failed++; } \
} while (0)

static void rm_rf(const char *p) {
    char cmd[600]; snprintf(cmd, sizeof(cmd), "rm -rf '%s'", p);
    if (system(cmd) != 0) {}
}

static unsigned char *zlib_of(const unsigned char *src, size_t n, size_t *outn) {
    uLongf cap = compressBound(n);
    unsigned char *buf = malloc(cap);
    compress(buf, &cap, src, n);
    *outn = cap;
    return buf;
}

/* CVMFS-style signature: RAW RSA-PKCS#1-v1.5 over msg (the printed hash text),
 * no SHA-1 DigestInfo — matches real CVMFS. */
static size_t cvmfs_sign(EVP_PKEY *pk, const unsigned char *msg, size_t mlen,
                         unsigned char *sig, size_t cap) {
    EVP_PKEY_CTX *sc = EVP_PKEY_CTX_new(pk, NULL);
    EVP_PKEY_sign_init(sc); EVP_PKEY_CTX_set_rsa_padding(sc, RSA_PKCS1_PADDING);
    size_t sl = cap; EVP_PKEY_sign(sc, sig, &sl, msg, mlen);
    EVP_PKEY_CTX_free(sc);
    return sl;
}

/* ---- fixture: object registry for the mock transport -------------------- */
typedef struct { char rel[256]; unsigned char *bytes; size_t len; } mock_obj_t;
typedef struct { mock_obj_t obj[8]; int n; } mock_reg_t;

static void reg_add(mock_reg_t *r, const char *rel, unsigned char *bytes, size_t len) {
    snprintf(r->obj[r->n].rel, sizeof(r->obj[r->n].rel), "%s", rel);
    r->obj[r->n].bytes = bytes; r->obj[r->n].len = len; r->n++;
}

static int mock_transport(const char *proxy, const char *host, const char *rel,
                          unsigned char *out, size_t outcap, size_t *outlen, void *ud) {
    (void) proxy; (void) host;
    mock_reg_t *r = ud;
    for (int i = 0; i < r->n; i++) {
        if (strcmp(rel, r->obj[i].rel) == 0) {
            if (r->obj[i].len > outcap) return -1;
            memcpy(out, r->obj[i].bytes, r->obj[i].len);
            *outlen = r->obj[i].len;
            return 0;
        }
    }
    return -1;   /* 404 */
}

/* build "data/<2>/<rest><suffix>" for a hash */
static void obj_rel(const cvmfs_hash_t *h, char suffix, char *out, size_t n) {
    char op[160];
    cvmfs_hash_to_object_path(h, suffix, op, sizeof(op));
    snprintf(out, n, "data/%s", op);
}

int main(void) {
    char cache_dir[] = "/tmp/brix_cl_cache.XXXXXX";
    char tmp_dir[]   = "/tmp/brix_cl_tmp.XXXXXX";
    if (!mkdtemp(cache_dir) || !mkdtemp(tmp_dir)) { perror("mkdtemp"); return 2; }

    /* keys + cert */
    EVP_PKEY *master = EVP_RSA_gen(2048);
    EVP_PKEY *certpk = EVP_RSA_gen(2048);
    X509 *x = X509_new();
    X509_set_pubkey(x, certpk);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_sign(x, certpk, EVP_sha256());
    BIO *cb = BIO_new(BIO_s_mem()); PEM_write_bio_X509(cb, x);
    char *cert_pem = NULL; long cert_len = BIO_get_mem_data(cb, &cert_pem);

    BIO *mb = BIO_new(BIO_s_mem()); PEM_write_bio_PUBKEY(mb, master);
    char *master_pem = NULL; long master_len = BIO_get_mem_data(mb, &master_pem);

    /* content object for "/hello" — CVMFS object identity = hash of the STORED
     * (compressed) bytes, so key the object by hash(zlib(content)). */
    const unsigned char content[] = "Hello from CVMFS-brix — battle-tested against evil networks!\n";
    size_t content_n = sizeof(content) - 1;
    size_t z_content_n; unsigned char *z_content = zlib_of(content, content_n, &z_content_n);
    cvmfs_hash_t content_h; cvmfs_object_hash(CVMFS_HASH_SHA1, z_content, z_content_n, &content_h);

    /* build a real SQLite catalog: root "" + file "/hello" */
    char catdb[512]; snprintf(catdb, sizeof(catdb), "%s/build.cat", tmp_dir);
    sqlite3 *db; sqlite3_open(catdb, &db);
    sqlite3_exec(db,
        "CREATE TABLE catalog (md5path_1 INTEGER, md5path_2 INTEGER, parent_1 INTEGER,"
        " parent_2 INTEGER, hardlinks INTEGER, hash BLOB, size INTEGER, mode INTEGER,"
        " mtime INTEGER, flags INTEGER, name TEXT, symlink TEXT, uid INTEGER, gid INTEGER,"
        " xattr BLOB, PRIMARY KEY(md5path_1,md5path_2));"
        "CREATE TABLE nested_catalogs (path TEXT, sha1 TEXT, size INTEGER, PRIMARY KEY(path));"
        "CREATE TABLE properties (key TEXT, value TEXT, PRIMARY KEY(key));"
        "CREATE TABLE chunks (md5path_1 INTEGER, md5path_2 INTEGER, offset INTEGER,"
        " size INTEGER, hash BLOB, PRIMARY KEY(md5path_1,md5path_2,offset));", NULL, NULL, NULL);
    {
        int64_t rm1, rm2; cvmfs_catalog_md5path("", &rm1, &rm2);
        int64_t hm1, hm2; cvmfs_catalog_md5path("/hello", &hm1, &hm2);
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db, "INSERT INTO catalog VALUES (?,?,?,?,1,?,?,?,1,?,?,?,0,0,NULL)", -1, &st, NULL);
        /* root dir */
        sqlite3_bind_int64(st,1,rm1); sqlite3_bind_int64(st,2,rm2);
        sqlite3_bind_int64(st,3,rm1); sqlite3_bind_int64(st,4,rm2);
        sqlite3_bind_null(st,5); sqlite3_bind_int64(st,6,0); sqlite3_bind_int64(st,7,040755);
        sqlite3_bind_int64(st,8,CVMFS_FLAG_DIR); sqlite3_bind_text(st,9,"",-1,SQLITE_STATIC);
        sqlite3_bind_null(st,10); sqlite3_step(st); sqlite3_reset(st);
        /* /hello file */
        sqlite3_bind_int64(st,1,hm1); sqlite3_bind_int64(st,2,hm2);
        sqlite3_bind_int64(st,3,rm1); sqlite3_bind_int64(st,4,rm2);
        sqlite3_bind_blob(st,5,content_h.bytes,20,SQLITE_STATIC);
        sqlite3_bind_int64(st,6,(int64_t)content_n); sqlite3_bind_int64(st,7,0100644);
        sqlite3_bind_int64(st,8,CVMFS_FLAG_FILE); sqlite3_bind_text(st,9,"hello",-1,SQLITE_STATIC);
        sqlite3_bind_null(st,10); sqlite3_step(st);
        sqlite3_finalize(st);
    }
    sqlite3_close(db);

    /* read catalog bytes, hash, compress */
    FILE *f = fopen(catdb, "rb"); fseek(f, 0, SEEK_END); long csz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *catbytes = malloc(csz); if (fread(catbytes, 1, csz, f) != (size_t)csz) {}
    fclose(f);
    /* compressed CAS objects, each keyed by hash-of-compressed (real CVMFS). */
    size_t z_cat_n;  unsigned char *z_cat  = zlib_of(catbytes, csz, &z_cat_n);
    size_t z_cert_n; unsigned char *z_cert = zlib_of((const unsigned char *)cert_pem, cert_len, &z_cert_n);
    cvmfs_hash_t cat_h;  cvmfs_object_hash(CVMFS_HASH_SHA1, z_cat, z_cat_n, &cat_h);
    cvmfs_hash_t cert_h; cvmfs_object_hash(CVMFS_HASH_SHA1, z_cert, z_cert_n, &cert_h);

    /* whitelist: expiry + cert fingerprint, signed by master over printed hash */
    char fp[64]; cvmfs_cert_fingerprint((unsigned char *)cert_pem, cert_len, fp, sizeof(fp));
    char wl_body[512];
    int wlbn = snprintf(wl_body, sizeof(wl_body),
        "20991231235959\nNtest.cern.ch\n%s\n--\n", fp);
    const char wl_hash[] = "2222222222222222222222222222222222222222";
    unsigned char wl_sig[512];
    size_t wl_sl = cvmfs_sign(master, (const unsigned char *)wl_hash, strlen(wl_hash), wl_sig, sizeof(wl_sig));
    unsigned char whitelist[1024]; size_t wn = 0;
    memcpy(whitelist, wl_body, wlbn); wn = wlbn;
    memcpy(whitelist + wn, wl_hash, strlen(wl_hash)); wn += strlen(wl_hash);
    whitelist[wn++] = '\n';
    memcpy(whitelist + wn, wl_sig, wl_sl); wn += wl_sl;

    /* manifest: C=catalog, X=cert, signed by cert key over printed hash */
    char cat_hex[64], cert_hex[64];
    cvmfs_hash_to_hex(&cat_h, 0, cat_hex, sizeof(cat_hex));
    cvmfs_hash_to_hex(&cert_h, 0, cert_hex, sizeof(cert_hex));
    char man_body[512];
    int mbn = snprintf(man_body, sizeof(man_body),
        "C%s\nB%ld\nX%s\nS1\nNtest.cern.ch\nT1700000000\nD240\n--\n",
        cat_hex, csz, cert_hex);
    const char man_hash[] = "1111111111111111111111111111111111111111";
    unsigned char man_sig[512];
    size_t man_sl = cvmfs_sign(certpk, (const unsigned char *)man_hash, strlen(man_hash), man_sig, sizeof(man_sig));
    unsigned char manifest[1024]; size_t mn = 0;
    memcpy(manifest, man_body, mbn); mn = mbn;
    memcpy(manifest + mn, man_hash, strlen(man_hash)); mn += strlen(man_hash);
    manifest[mn++] = '\n';
    memcpy(manifest + mn, man_sig, man_sl); mn += man_sl;

    /* register mock objects */
    mock_reg_t reg; memset(&reg, 0, sizeof(reg));
    reg_add(&reg, ".cvmfswhitelist", whitelist, wn);
    reg_add(&reg, ".cvmfspublished", manifest, mn);
    char rel_cert[256], rel_cat[256], rel_content[256];
    obj_rel(&cert_h, 'X', rel_cert, sizeof(rel_cert));
    obj_rel(&cat_h,  'C', rel_cat, sizeof(rel_cat));
    obj_rel(&content_h, 0, rel_content, sizeof(rel_content));
    reg_add(&reg, rel_cert, z_cert, z_cert_n);
    reg_add(&reg, rel_cat, z_cat, z_cat_n);
    reg_add(&reg, rel_content, z_content, z_content_n);

    /* ---- mount ---- */
    cvmfs_client_t *cl = calloc(1, sizeof(*cl));
    cvmfs_repo_config_defaults("test.cern.ch", &cl->config);
    cvmfs_failover_init(&cl->fo, 60);
    cvmfs_failover_add_host(&cl->fo, "http://s1.test.cern.ch");
    long now = 1700000100;

    int mrc = cvmfs_client_mount(cl, "test.cern.ch",
                                 (unsigned char *)master_pem, master_len,
                                 cache_dir, tmp_dir, 0, -1, mock_transport, &reg, now);
    CHECK(mrc == 0, "mount: trust chain verified + root catalog loaded");

    /* ---- resolve ---- */
    cvmfs_dirent_t e;
    CHECK(cvmfs_client_resolve(cl, "/hello", &e, now) == 1
          && (e.flags & CVMFS_FLAG_FILE) && e.size == content_n,
          "resolve /hello");
    CHECK(cvmfs_client_resolve(cl, "/nope", &e, now) == 0, "resolve absent → 0");

    /* ---- read ---- */
    unsigned char rbuf[256]; size_t rn = 0;
    int rrc = cvmfs_client_read(cl, "/hello", 0, sizeof(rbuf), rbuf, &rn, now);
    CHECK(rrc == 0 && rn == content_n && memcmp(rbuf, content, content_n) == 0,
          "read /hello byte-exact");

    size_t rn2 = 0;
    cvmfs_client_read(cl, "/hello", 6, 5, rbuf, &rn2, now);
    CHECK(rn2 == 5 && memcmp(rbuf, content + 6, 5) == 0, "read partial range");

    /* ---- magic xattrs ---- */
    char xb[128]; int xl;
    xl = cvmfs_client_getxattr(cl, "/", "user.fqrn", xb, sizeof(xb), now);
    if (xl > 0 && xl < (int)sizeof(xb)) xb[xl] = 0;
    CHECK(xl > 0 && strcmp(xb, "test.cern.ch") == 0, "xattr user.fqrn");

    xl = cvmfs_client_getxattr(cl, "/", "user.revision", xb, sizeof(xb), now);
    if (xl > 0) xb[xl] = 0;
    CHECK(strcmp(xb, "1") == 0, "xattr user.revision");

    char content_hex[64]; cvmfs_hash_to_hex(&content_h, 0, content_hex, sizeof(content_hex));
    xl = cvmfs_client_getxattr(cl, "/hello", "user.hash", xb, sizeof(xb), now);
    if (xl > 0) xb[xl] = 0;
    CHECK(strcmp(xb, content_hex) == 0, "xattr user.hash = file content hash");

    xl = cvmfs_client_getxattr(cl, "/hello", "user.nchunks", xb, sizeof(xb), now);
    if (xl > 0) xb[xl] = 0;
    CHECK(strcmp(xb, "1") == 0, "xattr user.nchunks");

    CHECK(cvmfs_client_getxattr(cl, "/", "user.bogus", xb, sizeof(xb), now) == -1,
          "unknown xattr → -1");                          /* negative */

    char lb[256]; int ll = cvmfs_client_listxattr(lb, sizeof(lb));
    CHECK(ll > 0 && memmem(lb, ll, "user.revision", 13) != NULL, "listxattr includes revision");

    /* ---- TTL refresh (manifest D=240) ---- */
    CHECK(cvmfs_client_refresh(cl, now + 10) == 0, "refresh not due before TTL");
    CHECK(cvmfs_client_refresh(cl, now + 300) == 0,
          "refresh due past TTL re-verifies, same revision → 0");

    /* ---- tamper negative: forge the manifest signature, mount must fail ---- */
    manifest[mn - 1] ^= 0xff;
    cvmfs_client_t *cl2 = calloc(1, sizeof(*cl2));
    cvmfs_repo_config_defaults("test.cern.ch", &cl2->config);
    cvmfs_failover_init(&cl2->fo, 60);
    cvmfs_failover_add_host(&cl2->fo, "http://s1.test.cern.ch");
    char cache2[] = "/tmp/brix_cl_cache2.XXXXXX"; (void)!mkdtemp(cache2);
    int mrc2 = cvmfs_client_mount(cl2, "test.cern.ch",
                                  (unsigned char *)master_pem, master_len,
                                  cache2, tmp_dir, 0, -1, mock_transport, &reg, now);
    CHECK(mrc2 != 0, "mount rejects forged manifest signature");  /* security-neg */
    rm_rf(cache2);

    cvmfs_client_umount(cl);
    free(cl); free(cl2);
    free(catbytes); free(z_cat); free(z_cert); free(z_content);
    BIO_free(cb); BIO_free(mb); X509_free(x); EVP_PKEY_free(master); EVP_PKEY_free(certpk);
    rm_rf(cache_dir); rm_rf(tmp_dir);
    printf("%d checks, %d failed\n", g_checks, g_failed);
    return g_failed ? 1 : 0;
}
