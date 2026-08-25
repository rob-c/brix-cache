/* brixcvmfs_repo.c — `brixcvmfs repo` family: Stratum-0 repository lifecycle
 * (phase-96 S3). Unprivileged, tool-surface only (G14): no FUSE, no root.
 *
 *   brixcvmfs repo mkfs   <fqrn> <repo_dir> [keys_dir]   — mint a repository
 *   brixcvmfs repo info   <repo_dir> [keys_dir]          — parse + verify
 *   brixcvmfs repo resign <repo_dir> [keys_dir]          — re-sign trust chain
 *
 * mkfs creates the full on-disk shape the read stack verifies: RSA master +
 * certificate keys (generated once, reused when present), an empty root
 * catalog (revision 1) CAS-stored under data/, the certificate object, the
 * reflog, and the signed .cvmfspublished / .cvmfswhitelist pair. `info` is the
 * local fsck-lite: it re-runs the whole trust chain (whitelist sig → expiry →
 * fingerprint membership → manifest sig → body binding) and exits non-zero on
 * any break. `resign` refreshes both signatures + whitelist expiry in place.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L         /* gmtime_r under -std=c11 */
#endif
#include "cvmfs/signature/sign.h"
#include "cvmfs/signature/manifest.h"
#include "cvmfs/signature/whitelist.h"
#include "cvmfs/signature/verify.h"
#include "cvmfs/catalog/catalog_write.h"
#include "cvmfs/object/object_write.h"
#include "cvmfs/object/object.h"
#include "cvmfs/reflog/reflog.h"
#include "brixcvmfs_errline.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define REPO_TTL_S       240
#define WHITELIST_DAYS   30

static int rp_err(const char *what, const char *detail) {
    return brixcvmfs_emit_err("repo", what, detail, 1);
}

static unsigned char *rp_read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n < 0) { fclose(f); return NULL; }
    rewind(f);
    unsigned char *buf = malloc(n > 0 ? (size_t) n : 1);
    if (buf == NULL) { fclose(f); return NULL; }
    int ok = n == 0 || fread(buf, 1, (size_t) n, f) == (size_t) n;
    fclose(f);
    if (!ok) { free(buf); return NULL; }
    *len = (size_t) n;
    return buf;
}

static int rp_write_file(const char *path, const void *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) return -1;
    int ok = len == 0 || fwrite(buf, 1, len, f) == len;
    ok = fclose(f) == 0 && ok;
    return ok ? 0 : -1;
}

/* ---- key material -------------------------------------------------------- */

static int rp_write_pem(const char *path, EVP_PKEY *pk, int private) {
    FILE *f = fopen(path, "w");
    if (f == NULL) return -1;
    int ok = private ? PEM_write_PrivateKey(f, pk, NULL, NULL, 0, NULL, NULL)
                     : PEM_write_PUBKEY(f, pk);
    return fclose(f) == 0 && ok == 1 ? 0 : -1;
}

/* Self-signed X.509 for the repo signing key, CN=<fqrn>. */
static int rp_write_cert(const char *path, EVP_PKEY *pk, const char *fqrn) {
    X509 *x = X509_new();
    if (x == NULL) return -1;
    ASN1_INTEGER_set(X509_get_serialNumber(x), (long) getpid());
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3650L * 86400);
    X509_set_pubkey(x, pk);
    X509_NAME *name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *) fqrn, -1, -1, 0);
    X509_set_issuer_name(x, name);
    int ok = X509_sign(x, pk, EVP_sha256()) != 0;
    FILE *f = ok ? fopen(path, "w") : NULL;
    if (f != NULL) {
        ok = PEM_write_X509(f, x) == 1;
        ok = fclose(f) == 0 && ok;
    } else {
        ok = 0;
    }
    X509_free(x);
    return ok ? 0 : -1;
}

typedef struct {
    char masterkey[512], masterpub[512], certkey[512], cert[512];
} rp_keypaths_t;

static void rp_key_paths(const char *keys_dir, const char *fqrn, rp_keypaths_t *p) {
    snprintf(p->masterkey, sizeof(p->masterkey), "%s/%s.masterkey", keys_dir, fqrn);
    snprintf(p->masterpub, sizeof(p->masterpub), "%s/%s.pub", keys_dir, fqrn);
    snprintf(p->certkey, sizeof(p->certkey), "%s/%s.key", keys_dir, fqrn);
    snprintf(p->cert, sizeof(p->cert), "%s/%s.crt", keys_dir, fqrn);
}

/* Load the key pair from keys_dir, generating any missing piece (mkfs), or
 * failing when generation is not allowed (resign). */
static int rp_load_keys(const char *keys_dir, const char *fqrn, int generate,
                        EVP_PKEY **master, EVP_PKEY **certpk) {
    rp_keypaths_t p;
    rp_key_paths(keys_dir, fqrn, &p);

    *master = cvmfs_sign_load_key(p.masterkey);
    *certpk = cvmfs_sign_load_key(p.certkey);
    if (*master != NULL && *certpk != NULL) return 0;
    if (!generate) {
        EVP_PKEY_free(*master);
        EVP_PKEY_free(*certpk);
        return rp_err("signing keys missing under", keys_dir);
    }

    if (mkdir(keys_dir, 0700) != 0 && errno != EEXIST)
        return rp_err("cannot create keys dir", keys_dir);
    if (*master == NULL) {
        *master = EVP_RSA_gen(2048);
        if (*master == NULL || rp_write_pem(p.masterkey, *master, 1) != 0
            || rp_write_pem(p.masterpub, *master, 0) != 0)
            return rp_err("master key generation failed", NULL);
    }
    if (*certpk == NULL) {
        *certpk = EVP_RSA_gen(2048);
        if (*certpk == NULL || rp_write_pem(p.certkey, *certpk, 1) != 0
            || rp_write_cert(p.cert, *certpk, fqrn) != 0)
            return rp_err("certificate generation failed", NULL);
    }
    return 0;
}

/* ---- signed-artifact emission -------------------------------------------- */

static int rp_write_signed(const char *path, const char *body, int blen,
                           EVP_PKEY *key, int sha1_digestinfo) {
    unsigned char art[8192];
    size_t alen = 0;
    if (blen <= 0
        || cvmfs_sign_artifact((const unsigned char *) body, (size_t) blen, key,
                               sha1_digestinfo, art, sizeof(art), &alen) != 0)
        return -1;
    return rp_write_file(path, art, alen);
}

static int rp_write_manifest(const char *repo_dir, const cvmfs_manifest_wr_t *m,
                             EVP_PKEY *certpk) {
    char body[2048], path[600];
    int  blen = cvmfs_manifest_body(m, body, sizeof(body));
    snprintf(path, sizeof(path), "%s/.cvmfspublished", repo_dir);
    return rp_write_signed(path, body, blen, certpk, 1);   /* manifest: DigestInfo */
}

static int rp_write_whitelist(const char *repo_dir, const char *fqrn,
                              const unsigned char *cert_pem, size_t cert_len,
                              EVP_PKEY *master) {
    char fp[1][60];
    if (cvmfs_cert_fingerprint(cert_pem, cert_len, fp[0], sizeof(fp[0])) != 0)
        return -1;

    time_t    exp = time(NULL) + WHITELIST_DAYS * 86400L;
    struct tm tm_utc;
    char      expiry[16];
    gmtime_r(&exp, &tm_utc);
    strftime(expiry, sizeof(expiry), "%Y%m%d%H%M%S", &tm_utc);

    char body[2048], path[600];
    int  blen = cvmfs_whitelist_body(NULL, expiry, fqrn, (const char (*)[60]) fp, 1,
                                     body, sizeof(body));
    snprintf(path, sizeof(path), "%s/.cvmfswhitelist", repo_dir);
    return rp_write_signed(path, body, blen, master, 0);   /* whitelist: raw */
}

/* ---- mkfs ---------------------------------------------------------------- */

/* Mint the empty revision-1 root catalog and CAS-store it. */
static int rp_store_root_catalog(const char *repo_dir, cvmfs_objstore_t *store,
                                 cvmfs_hash_t *out, size_t *stored_len) {
    char tmp[600];
    snprintf(tmp, sizeof(tmp), "%s/.brix.catalog.tmp", repo_dir);
    unlink(tmp);

    cvmfs_catwriter_t *w = cvmfs_catwriter_create(tmp);
    if (w == NULL) return -1;
    cvmfs_catrow_t root;
    memset(&root, 0, sizeof(root));
    root.path = "";
    root.flags = CVMFS_FLAG_DIR;
    root.mode = 040755;
    root.size = 4096;
    root.mtime = (int64_t) time(NULL);
    char now[32];
    snprintf(now, sizeof(now), "%ld", (long) time(NULL));
    if (cvmfs_catwriter_insert(w, &root) != 0
        || cvmfs_catwriter_set_property(w, "revision", "1") != 0
        || cvmfs_catwriter_set_property(w, "schema", "2.5") != 0
        || cvmfs_catwriter_set_property(w, "schema_revision", "2") != 0
        || cvmfs_catwriter_set_property(w, "last_modified", now) != 0
        || cvmfs_catwriter_update_counters(w) != 0) {
        cvmfs_catwriter_abort(w);
        unlink(tmp);
        return -1;
    }
    if (cvmfs_catwriter_commit(w) != 0) { unlink(tmp); return -1; }

    size_t         plain_len = 0;
    unsigned char *plain = rp_read_file(tmp, &plain_len);
    unlink(tmp);
    if (plain == NULL) return -1;
    int rc = cvmfs_object_store(store, plain, plain_len, 'C', 1, out, stored_len);
    free(plain);
    return rc;
}

/* Seed .cvmfsreflog with the root anchors and compute the 'Y' checksum. */
static int rp_seed_reflog(const char *repo_dir, const cvmfs_hash_t *cat,
                          const cvmfs_hash_t *cert, cvmfs_hash_t *checksum) {
    char path[600];
    snprintf(path, sizeof(path), "%s/.cvmfsreflog", repo_dir);
    cvmfs_reflog_t *r = cvmfs_reflog_open(path);
    if (r == NULL) return -1;
    int64_t now = (int64_t) time(NULL);
    int rc = cvmfs_reflog_add(r, cat, CVMFS_REFLOG_CATALOG, now);
    if (rc == 0) rc = cvmfs_reflog_add(r, cert, CVMFS_REFLOG_CERTIFICATE, now);
    if (cvmfs_reflog_close(r) != 0) rc = -1;
    if (rc == 0) rc = cvmfs_reflog_checksum(path, checksum);
    return rc;
}

/* Emit the revision-1 objects + signed trust chain into an opened store. */
static int rp_mkfs_emit(const char *fqrn, const char *repo_dir,
                        cvmfs_objstore_t *store, const unsigned char *cert_pem,
                        size_t cert_len, EVP_PKEY *master, EVP_PKEY *certpk,
                        cvmfs_hash_t *root_out) {
    cvmfs_manifest_wr_t m;
    memset(&m, 0, sizeof(m));
    size_t csize = 0;
    if (rp_store_root_catalog(repo_dir, store, &m.root_catalog, &csize) != 0)
        return rp_err("root catalog emission failed", NULL);
    if (cvmfs_object_store(store, cert_pem, cert_len, 'X', 1,
                           &m.certificate, NULL) != 0)
        return rp_err("certificate object store failed", NULL);
    if (rp_seed_reflog(repo_dir, &m.root_catalog, &m.certificate,
                       &m.reflog_checksum) != 0)
        return rp_err("reflog seed failed", NULL);
    m.catalog_size = (long) csize;
    m.revision = 1;
    m.fqrn = fqrn;
    m.timestamp = (long) time(NULL);
    m.ttl = REPO_TTL_S;
    if (rp_write_manifest(repo_dir, &m, certpk) != 0
        || rp_write_whitelist(repo_dir, fqrn, cert_pem, cert_len, master) != 0)
        return rp_err("trust-chain signing failed", NULL);
    *root_out = m.root_catalog;
    return 0;
}

static int rp_mkfs(const char *fqrn, const char *repo_dir, const char *keys_dir) {
    char manifest_path[600];
    snprintf(manifest_path, sizeof(manifest_path), "%s/.cvmfspublished", repo_dir);
    if (access(manifest_path, F_OK) == 0)
        return rp_err("repository already published at", repo_dir);
    if (mkdir(repo_dir, 0755) != 0 && errno != EEXIST)
        return rp_err("cannot create repo dir", repo_dir);

    EVP_PKEY *master = NULL, *certpk = NULL;
    if (rp_load_keys(keys_dir, fqrn, 1, &master, &certpk) != 0) return 1;

    rp_keypaths_t kp;
    rp_key_paths(keys_dir, fqrn, &kp);
    size_t         cert_len = 0;
    unsigned char *cert_pem = rp_read_file(kp.cert, &cert_len);

    cvmfs_objstore_t store;
    int rc = cert_pem != NULL && cvmfs_objstore_open(&store, repo_dir) == 0 ? 0 : 1;

    cvmfs_hash_t root;
    if (rc == 0)
        rc = rp_mkfs_emit(fqrn, repo_dir, &store, cert_pem, cert_len,
                          master, certpk, &root);
    if (rc == 0) {
        char hex[64];
        cvmfs_hash_to_hex(&root, 0, hex, sizeof(hex));
        printf("repository %s created at %s\n  revision 1, root catalog %s\n"
               "  keys in %s (public key: %s.pub)\n", fqrn, repo_dir, hex,
               keys_dir, fqrn);
    }

    if (cert_pem != NULL) cvmfs_objstore_close(&store);
    free(cert_pem);
    EVP_PKEY_free(master);
    EVP_PKEY_free(certpk);
    return rc;
}

/* ---- info (trust-chain fsck) --------------------------------------------- */

/* Load + parse the manifest; artifact buffer is returned for parse lifetime. */
static unsigned char *rp_load_manifest(const char *repo_dir, cvmfs_manifest_t *m) {
    char path[600];
    snprintf(path, sizeof(path), "%s/.cvmfspublished", repo_dir);
    size_t         len = 0;
    unsigned char *buf = rp_read_file(path, &len);
    if (buf == NULL) return NULL;
    if (cvmfs_manifest_parse(buf, len, m) != 0) { free(buf); return NULL; }
    return buf;
}

/* Pull + inflate the certificate object named by the manifest. */
static unsigned char *rp_load_cert_object(const char *repo_dir, const cvmfs_manifest_t *m,
                                          size_t *cert_len) {
    cvmfs_objstore_t store;
    if (cvmfs_objstore_open(&store, repo_dir) != 0) return NULL;
    unsigned char  stored[65536];
    unsigned char *pem = NULL;
    long           n = cvmfs_object_read_stored(&store, &m->certificate, 'X',
                                                stored, sizeof(stored));
    if (n > 0) {
        pem = malloc(65536);
        if (pem != NULL
            && cvmfs_object_inflate(stored, (size_t) n, pem, 65536, cert_len) != 0) {
            free(pem);
            pem = NULL;
        }
    }
    cvmfs_objstore_close(&store);
    return pem;
}

/* Verify whitelist sig + expiry + cert-fingerprint membership. 0 = trusted. */
static int rp_check_whitelist(const char *repo_dir, const char *keys_dir,
                              const cvmfs_manifest_t *m,
                              const unsigned char *cert_pem, size_t cert_len) {
    char path[600];
    snprintf(path, sizeof(path), "%s/.cvmfswhitelist", repo_dir);
    size_t         wlen = 0;
    unsigned char *wbuf = rp_read_file(path, &wlen);
    if (wbuf == NULL) return rp_err("whitelist missing", path);

    rp_keypaths_t kp;
    rp_key_paths(keys_dir, m->repo_name, &kp);
    size_t         plen = 0;
    unsigned char *pub = rp_read_file(kp.masterpub, &plen);

    cvmfs_whitelist_t w;
    char              fp[60];
    int rc = pub == NULL ? rp_err("master public key missing", kp.masterpub)
        : cvmfs_whitelist_parse(wbuf, wlen, &w) != 0 ? rp_err("whitelist unparsable", NULL)
        : cvmfs_verify_whitelist(&w, pub, plen) != 0 ? rp_err("whitelist signature INVALID", NULL)
        : cvmfs_whitelist_expired(&w, (long) time(NULL)) ? rp_err("whitelist EXPIRED", NULL)
        : cvmfs_cert_fingerprint(cert_pem, cert_len, fp, sizeof(fp)) != 0
          || !cvmfs_whitelist_lists_fp(&w, fp) ? rp_err("certificate not whitelisted", NULL)
        : 0;
    free(pub);
    free(wbuf);
    return rc;
}

static int rp_info(const char *repo_dir, const char *keys_dir) {
    cvmfs_manifest_t m;
    unsigned char   *mbuf = rp_load_manifest(repo_dir, &m);
    if (mbuf == NULL) return rp_err("no parsable .cvmfspublished in", repo_dir);

    char root_hex[64], cert_hex[64];
    cvmfs_hash_to_hex(&m.root_catalog, 0, root_hex, sizeof(root_hex));
    cvmfs_hash_to_hex(&m.certificate, 0, cert_hex, sizeof(cert_hex));
    printf("repository ...... %s\n", m.repo_name);
    printf("revision ........ %ld\n", m.revision);
    printf("root catalog .... %s (%ld bytes stored)\n", root_hex, m.catalog_size);
    printf("certificate ..... %s\n", cert_hex);
    printf("published ....... %ld  (ttl %lds)\n", m.timestamp, m.ttl);

    size_t         cert_len = 0;
    unsigned char *cert_pem = rp_load_cert_object(repo_dir, &m, &cert_len);
    int rc;
    if (cert_pem == NULL) {
        rc = rp_err("certificate object unreadable", cert_hex);
    } else if (cvmfs_verify_manifest(&m, cert_pem, cert_len) != 0) {
        rc = rp_err("manifest signature INVALID", NULL);
    } else {
        rc = rp_check_whitelist(repo_dir, keys_dir, &m, cert_pem, cert_len);
    }
    if (rc == 0) {
        cvmfs_hash_t y;
        char reflog[600];
        snprintf(reflog, sizeof(reflog), "%s/.cvmfsreflog", repo_dir);
        if (m.reflog_checksum.len > 0
            && (cvmfs_reflog_checksum(reflog, &y) != 0 || !cvmfs_hash_eq(&y, &m.reflog_checksum)))
            rc = rp_err("reflog checksum mismatch (tamper or partial publish)", NULL);
    }
    printf("trust chain ..... %s\n", rc == 0 ? "OK" : "BROKEN");
    free(cert_pem);
    free(mbuf);
    return rc;
}

/* ---- resign -------------------------------------------------------------- */

static int rp_resign(const char *repo_dir, const char *keys_dir) {
    cvmfs_manifest_t m;
    unsigned char   *mbuf = rp_load_manifest(repo_dir, &m);
    if (mbuf == NULL) return rp_err("no parsable .cvmfspublished in", repo_dir);

    EVP_PKEY *master = NULL, *certpk = NULL;
    if (rp_load_keys(keys_dir, m.repo_name, 0, &master, &certpk) != 0) {
        free(mbuf);
        return 1;
    }

    cvmfs_manifest_wr_t wr;
    memset(&wr, 0, sizeof(wr));
    wr.root_catalog = m.root_catalog;
    wr.catalog_size = m.catalog_size;
    wr.certificate = m.certificate;
    wr.revision = m.revision;
    wr.fqrn = m.repo_name;
    wr.timestamp = (long) time(NULL);
    wr.ttl = m.ttl;
    wr.history = m.history;
    char reflog[600];
    snprintf(reflog, sizeof(reflog), "%s/.cvmfsreflog", repo_dir);
    if (access(reflog, F_OK) == 0
        && cvmfs_reflog_checksum(reflog, &wr.reflog_checksum) != 0) {
        free(mbuf);
        EVP_PKEY_free(master);
        EVP_PKEY_free(certpk);
        return rp_err("reflog checksum failed", reflog);
    }

    rp_keypaths_t kp;
    rp_key_paths(keys_dir, m.repo_name, &kp);
    size_t         cert_len = 0;
    unsigned char *cert_pem = rp_read_file(kp.cert, &cert_len);
    int rc = cert_pem == NULL ? rp_err("certificate missing", kp.cert)
        : rp_write_manifest(repo_dir, &wr, certpk) != 0 ? rp_err("manifest resign failed", NULL)
        : rp_write_whitelist(repo_dir, m.repo_name, cert_pem, cert_len, master) != 0
            ? rp_err("whitelist resign failed", NULL)
        : 0;
    if (rc == 0)
        printf("re-signed %s (revision %ld, whitelist +%dd)\n",
               m.repo_name, m.revision, WHITELIST_DAYS);
    free(cert_pem);
    free(mbuf);
    EVP_PKEY_free(master);
    EVP_PKEY_free(certpk);
    return rc;
}

/* ---- dispatch ------------------------------------------------------------ */

/* brixcvmfs_publish.c / brixcvmfs_admin.c — always linked alongside this file. */
int brixcvmfs_txn_main(int argc, char **argv);
int brixcvmfs_admin_main(int argc, char **argv);

/* argv[idx] when present, else "<repo>/keys" rendered into buf. */
static const char *rp_keys_arg(int argc, char **argv, int idx, const char *repo,
                               char *buf, size_t buflen) {
    if (argc > idx) return argv[idx];
    snprintf(buf, buflen, "%s/keys", repo);
    return buf;
}

static int rp_cmd_in(const char *cmd, const char *const *set) {
    for (size_t i = 0; set[i] != NULL; i++)
        if (strcmp(cmd, set[i]) == 0) return 1;
    return 0;
}

int brixcvmfs_repo_main(int argc, char **argv) {
    /* argv[0] = "repo" after the front-end shift. */
    static const char *const txn_cmds[] =
        { "transaction", "abort", "publish", "fsck", NULL };
    static const char *const admin_cmds[] = { "gc", "tag", NULL };
    const char *cmd = argc >= 2 ? argv[1] : "";
    char kb[600];

    if (rp_cmd_in(cmd, txn_cmds))
        return brixcvmfs_txn_main(argc, argv);
    if (rp_cmd_in(cmd, admin_cmds))
        return brixcvmfs_admin_main(argc, argv);
    if (strcmp(cmd, "mkfs") == 0 && (argc == 4 || argc == 5))
        return rp_mkfs(argv[2], argv[3],
                       rp_keys_arg(argc, argv, 4, argv[3], kb, sizeof(kb)));
    if (strcmp(cmd, "info") == 0 && (argc == 3 || argc == 4))
        return rp_info(argv[2], rp_keys_arg(argc, argv, 3, argv[2], kb, sizeof(kb)));
    if (strcmp(cmd, "resign") == 0 && (argc == 3 || argc == 4))
        return rp_resign(argv[2], rp_keys_arg(argc, argv, 3, argv[2], kb, sizeof(kb)));
    fprintf(stderr,
        "usage: brixcvmfs repo mkfs        <fqrn> <repo_dir> [keys_dir]\n"
        "       brixcvmfs repo info        <repo_dir> [keys_dir]\n"
        "       brixcvmfs repo resign      <repo_dir> [keys_dir]\n"
        "       brixcvmfs repo transaction <repo_dir>\n"
        "       brixcvmfs repo abort       <repo_dir>\n"
        "       brixcvmfs repo publish     <repo_dir> [keys_dir]"
        " [--chunk-size N] [--dirtab F]\n"
        "       brixcvmfs repo fsck        <repo_dir> [--data]\n"
        "       brixcvmfs repo gc          <repo_dir> [keys_dir]"
        " (--keep N | --keep-since T) [--grace S]\n"
        "       brixcvmfs repo tag         add|list|rollback ...\n");
    return 2;
}

#ifdef BRIXCVMFS_REPO_STANDALONE
/* Test-build entry (tests/cmdscripts/cvmfs_repo_cli.py): argv[0] plays the
 * "repo" slot, so `repotool mkfs <fqrn> <dir>` maps straight through. */
int main(int argc, char **argv) {
    return brixcvmfs_repo_main(argc, argv);
}
#endif
