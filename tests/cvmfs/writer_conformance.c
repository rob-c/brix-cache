/*
 * writer_conformance.c — drives the PRODUCT writers (sign.c, object_write.c,
 * catalog_write.c) with externally supplied inputs so the phase-96 agreement
 * guard (tests/cmdscripts/cvmfs_writer_conformance.py) can byte-compare the
 * output against repo_forge.py given an identical input.
 *
 * Modes:
 *   manifest  <certkey.pem> <out> <Chex> <B> <Xhex> <S> <fqrn> <T> <D>
 *   whitelist <masterkey.pem> <out> <created14> <expiry14> <fqrn> <fp>...
 *   cas       <repo_dir> <suffix|-> <compress:0|1> <infile>   → "<hex> <stored>"
 *   catalog   <db_path>          (row spec on stdin, TAB-separated:
 *       row\t<path>\t<flags>\t<mode>\t<size>\t<mtime>\t<uid>\t<gid>\t<linkcount>\t<group>\t<hash|->\t<symlink|->
 *       nested\t<path>\t<sha1hex>\t<size>
 *       chunk\t<path>\t<offset>\t<size>\t<sha1hex>
 *       prop\t<key>\t<value>)
 */
#include "cvmfs/signature/sign.h"
#include "cvmfs/catalog/catalog_write.h"
#include "cvmfs/object/object_write.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int die(const char *msg) {
    fprintf(stderr, "writer_conformance: %s\n", msg);
    return 1;
}

static unsigned char *slurp(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    rewind(f);
    unsigned char *buf = malloc(n > 0 ? (size_t) n : 1);
    if (buf != NULL && n > 0 && fread(buf, 1, (size_t) n, f) != (size_t) n) {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    if (buf != NULL) *len = (size_t) n;
    return buf;
}

static int spit(const char *path, const unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (f == NULL) return -1;
    int ok = fwrite(buf, 1, len, f) == len;
    return fclose(f) == 0 && ok ? 0 : -1;
}

static int sign_to(const char *keypath, const char *out, const char *body, int blen,
                   int sha1_digestinfo) {
    EVP_PKEY *key = cvmfs_sign_load_key(keypath);
    unsigned char art[8192];
    size_t alen = 0;
    int rc = blen > 0 && key != NULL
          && cvmfs_sign_artifact((const unsigned char *) body, (size_t) blen, key,
                                 sha1_digestinfo, art, sizeof(art), &alen) == 0
          && spit(out, art, alen) == 0 ? 0 : 1;
    EVP_PKEY_free(key);
    return rc != 0 ? die("sign/write failed") : 0;
}

static int do_manifest(int argc, char **argv) {
    if (argc != 11) return die("manifest arg count");
    cvmfs_manifest_wr_t m;
    memset(&m, 0, sizeof(m));
    if (cvmfs_hash_parse(argv[4], strlen(argv[4]), &m.root_catalog) != 0
        || cvmfs_hash_parse(argv[6], strlen(argv[6]), &m.certificate) != 0)
        return die("bad hash arg");
    m.catalog_size = atol(argv[5]);
    m.revision = atol(argv[7]);
    m.fqrn = argv[8];
    m.timestamp = atol(argv[9]);
    m.ttl = atol(argv[10]);
    char body[2048];
    return sign_to(argv[2], argv[3], body, cvmfs_manifest_body(&m, body, sizeof(body)),
                   1);                     /* manifest: DigestInfo scheme */
}

static int do_whitelist(int argc, char **argv) {
    if (argc < 7 || argc - 7 > 16) return die("whitelist arg count");
    char fps[16][60];
    size_t nfp = (size_t) (argc - 7);
    for (size_t i = 0; i < nfp; i++)
        snprintf(fps[i], sizeof(fps[i]), "%s", argv[7 + i]);
    char body[2048];
    int blen = cvmfs_whitelist_body(argv[4], argv[5], argv[6],
                                    (const char (*)[60]) fps, nfp,
                                    body, sizeof(body));
    return sign_to(argv[2], argv[3], body, blen, 0);   /* whitelist: raw */
}

static int do_cas(int argc, char **argv) {
    if (argc != 6) return die("cas arg count");
    size_t plen = 0;
    unsigned char *plain = slurp(argv[5], &plen);
    if (plain == NULL) return die("cannot read input file");
    cvmfs_objstore_t store;
    cvmfs_hash_t hash;
    size_t stored = 0;
    char suffix = argv[3][0] == '-' ? 0 : argv[3][0];
    int rc = cvmfs_objstore_open(&store, argv[2]) == 0
          && cvmfs_object_store(&store, plain, plen, suffix, atoi(argv[4]),
                                &hash, &stored) == 0 ? 0 : 1;
    free(plain);
    if (rc != 0) return die("cas store failed");
    char hex[64];
    cvmfs_hash_to_hex(&hash, 0, hex, sizeof(hex));
    printf("%s %zu\n", hex, stored);
    cvmfs_objstore_close(&store);
    return 0;
}

/* Split `line` on TABs in place (empty fields preserved). Returns field count. */
static int split_tabs(char *line, char **fields, int cap) {
    int n = 0;
    char *p = line;
    while (n < cap) {
        fields[n++] = p;
        char *tab = strchr(p, '\t');
        if (tab == NULL) break;
        *tab = '\0';
        p = tab + 1;
    }
    return n;
}

static int spec_row(cvmfs_catwriter_t *w, char **f, int n) {
    if (n != 12) return -1;
    cvmfs_catrow_t r;
    memset(&r, 0, sizeof(r));
    cvmfs_hash_t h;
    r.path = f[1];
    r.flags = (uint32_t) strtoul(f[2], NULL, 10);
    r.mode = (uint32_t) strtoul(f[3], NULL, 10);
    r.size = strtoull(f[4], NULL, 10);
    r.mtime = strtoll(f[5], NULL, 10);
    r.uid = (uint32_t) strtoul(f[6], NULL, 10);
    r.gid = (uint32_t) strtoul(f[7], NULL, 10);
    r.linkcount = (uint32_t) strtoul(f[8], NULL, 10);
    r.hardlink_group = (uint32_t) strtoul(f[9], NULL, 10);
    if (strcmp(f[10], "-") != 0) {
        if (cvmfs_hash_parse(f[10], strlen(f[10]), &h) != 0) return -1;
        r.hash = &h;
    }
    if (strcmp(f[11], "-") != 0) r.symlink = f[11];
    return cvmfs_catwriter_insert(w, &r);
}

static int spec_line(cvmfs_catwriter_t *w, char *line) {
    char *f[12];
    int n = split_tabs(line, f, 12);
    if (n < 1 || f[0][0] == '\0') return 0;                    /* blank line */
    if (strcmp(f[0], "row") == 0) return spec_row(w, f, n);
    if (strcmp(f[0], "nested") == 0 && n == 4)
        return cvmfs_catwriter_set_nested(w, f[1], f[2], strtoull(f[3], NULL, 10));
    if (strcmp(f[0], "chunk") == 0 && n == 5) {
        cvmfs_hash_t h;
        if (cvmfs_hash_parse(f[4], strlen(f[4]), &h) != 0) return -1;
        return cvmfs_catwriter_add_chunk(w, f[1], strtoull(f[2], NULL, 10),
                                        strtoull(f[3], NULL, 10), &h);
    }
    if (strcmp(f[0], "prop") == 0 && n == 3)
        return cvmfs_catwriter_set_property(w, f[1], f[2]);
    return -1;
}

static int do_catalog(int argc, char **argv) {
    if (argc != 3) return die("catalog arg count");
    cvmfs_catwriter_t *w = cvmfs_catwriter_create(argv[2]);
    if (w == NULL) return die("catwriter create failed");
    char line[4096];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (spec_line(w, line) != 0) {
            cvmfs_catwriter_abort(w);
            return die("bad spec line");
        }
    }
    if (cvmfs_catwriter_update_counters(w) != 0 || cvmfs_catwriter_commit(w) != 0)
        return die("catalog commit failed");
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "manifest") == 0) return do_manifest(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "whitelist") == 0) return do_whitelist(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "cas") == 0) return do_cas(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "catalog") == 0) return do_catalog(argc, argv);
    return die("usage: manifest|whitelist|cas|catalog ...");
}
