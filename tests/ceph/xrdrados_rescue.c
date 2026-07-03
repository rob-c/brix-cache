/*
 * xrdrados_rescue.c — offline pure-RADOS recovery tool (operator utility).
 *
 * WHAT: Enumerates and extracts objects from a flat RADOS pool — the block-only
 *       `ceph` backend's storage, or any pool of opaque objects — with no
 *       namespace service. It lists object keys, stats them, reads their bytes and
 *       xattrs, and bulk-extracts objects under a key prefix to local files. For
 *       pools that hold the `ceph` driver's data (object key == logical path) this
 *       recovers the files directly.
 *
 * It is the flat-pool counterpart to xrdcephfs_rescue (which understands the
 * CephFS layout). Both reuse sd_ceph's connection + oid layer.
 *
 * USAGE:
 *   xrdrados_rescue <pool> ls   [prefix]
 *   xrdrados_rescue <pool> stat <key>
 *   xrdrados_rescue <pool> get  <key> <local_file>
 *   xrdrados_rescue <pool> cp   <prefix> <local_dir>   (extract all under prefix)
 *   (env CEPH_CONF overrides /etc/ceph/ceph.conf)
 *
 * BUILD (in the librados build container):
 *   gcc -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH -I src/fs/backend -I src/fs/backend/rados \
 *     -include tests/ceph/ngx_shim.h tests/ceph/xrdrados_rescue.c \
 *     src/fs/backend/rados/sd_ceph.c src/fs/backend/rados/sd_ceph_compat.c \
 *     -lrados -o xrdrados_rescue
 */
#include "sd.h"
#include "rados/sd_ceph.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <rados/librados.h>

void *ngx_pcalloc(ngx_pool_t *pool, size_t size) { (void) pool; return calloc(1, size); }
void *ngx_pnalloc(ngx_pool_t *pool, size_t size) { (void) pool; return malloc(size); }

/* Stream one object's bytes (by oid) to a FILE* in 1 MiB reads. 0 / -1. */
static int
extract_object(sd_ceph_conn_t *c, const char *oid, FILE *out)
{
    char    buf[1u << 20];
    off_t   off = 0;
    ssize_t n;

    while ((n = sd_ceph_oid_read(c, oid, buf, sizeof(buf), off)) > 0) {
        if (fwrite(buf, 1, (size_t) n, out) != (size_t) n) { return -1; }
        off += n;
        if ((size_t) n < sizeof(buf)) { break; }   /* short read ⇒ end of object */
    }
    return (n < 0) ? -1 : 0;
}

/* Iterate every object in the pool, invoking cb(key, ctx) for those matching the
 * (optional) prefix. Returns 0, or -1/errno on a RADOS error. */
typedef int (*obj_cb)(const char *key, void *ctx);
static int
for_each_object(sd_ceph_conn_t *c, const char *prefix, obj_cb cb, void *ctx)
{
    rados_ioctx_t           ioctx = sd_ceph_conn_ioctx(c);
    rados_list_ctx_t        lc;
    size_t                  plen = (prefix != NULL) ? strlen(prefix) : 0;
    int                     rc;

    if (rados_nobjects_list_open(ioctx, &lc) < 0) { return -1; }
    for (;;) {
        const char *entry = NULL, *nspace = NULL;
        size_t      klen = 0;

        rc = rados_nobjects_list_next2(lc, &entry, NULL, &nspace, &klen, NULL, NULL);
        if (rc == -ENOENT) { rc = 0; break; }           /* end of listing */
        if (rc < 0) { break; }
        if (entry == NULL) { continue; }
        if (plen == 0 || strncmp(entry, prefix, plen) == 0) {
            if (cb(entry, ctx) != 0) { rc = -1; break; }
        }
    }
    rados_nobjects_list_close(lc);
    if (rc < 0 && errno == 0) { errno = EIO; }
    return rc < 0 ? -1 : 0;
}

static int print_key(const char *key, void *ctx) { (void) ctx; printf("%s\n", key); return 0; }

/* cp callback context: connection + destination directory. */
typedef struct { sd_ceph_conn_t *c; const char *dst; int fails; } cp_ctx_t;

/* Replace '/' in a key with '_' so a path-like key becomes one local filename
 * (flat extraction; the operator can re-layout afterwards). */
static void
flatten_key(const char *key, char *out, size_t cap)
{
    size_t i;
    for (i = 0; key[i] != '\0' && i + 1 < cap; i++) {
        out[i] = (key[i] == '/') ? '_' : key[i];
    }
    out[i] = '\0';
}

static int
cp_one(const char *key, void *ctx)
{
    cp_ctx_t *cc = ctx;
    char      name[1024], path[2048];
    FILE     *out;

    flatten_key(key, name, sizeof(name));
    snprintf(path, sizeof(path), "%s/%s", cc->dst, name);
    out = fopen(path, "wb");
    if (out == NULL) { fprintf(stderr, "create %s: %s\n", path, strerror(errno));
                       cc->fails++; return 0; }
    if (extract_object(cc->c, key, out) != 0) {
        fprintf(stderr, "extract %s failed\n", key); cc->fails++;
    } else {
        printf("  %s -> %s\n", key, path);
    }
    fclose(out);
    return 0;
}

int
main(int argc, char **argv)
{
    brix_sd_ceph_conf_t conf;
    sd_ceph_conn_t       *c;
    const char           *cmd;
    int                   err = 0, rc = 0;

    if (argc < 3) {
        fprintf(stderr,
            "usage: %s <pool> <ls|stat|get|cp> [args]\n", argv[0]);
        return 2;
    }
    memset(&conf, 0, sizeof(conf));
    conf.pool      = argv[1];
    conf.conf_file = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";

    c = sd_ceph_conn_create(&conf, NULL, &err);
    if (c == NULL) { fprintf(stderr, "connect %s: %s\n", argv[1], strerror(err)); return 1; }

    cmd = argv[2];
    if (strcmp(cmd, "ls") == 0) {
        rc = for_each_object(c, (argc > 3) ? argv[3] : NULL, print_key, NULL);
        if (rc != 0) { fprintf(stderr, "list failed: %s\n", strerror(errno)); rc = 1; }
    } else if (strcmp(cmd, "stat") == 0) {
        uint64_t sz = 0; time_t mt = 0;
        if (argc < 4) { fprintf(stderr, "stat needs <key>\n"); rc = 2; }
        else if (sd_ceph_oid_stat(c, argv[3], &sz, &mt) != 0) {
            fprintf(stderr, "stat %s: %s\n", argv[3], strerror(errno)); rc = 1;
        } else {
            printf("key:   %s\nsize:  %llu\nmtime: %lld\n",
                   argv[3], (unsigned long long) sz, (long long) mt);
        }
    } else if (strcmp(cmd, "get") == 0) {
        if (argc < 5) { fprintf(stderr, "get needs <key> <local_file>\n"); rc = 2; }
        else {
            FILE *out = fopen(argv[4], "wb");
            if (out == NULL) { fprintf(stderr, "create %s: %s\n", argv[4], strerror(errno)); rc = 1; }
            else { rc = (extract_object(c, argv[3], out) == 0) ? 0 : 1; fclose(out); }
        }
    } else if (strcmp(cmd, "cp") == 0) {
        if (argc < 5) { fprintf(stderr, "cp needs <prefix> <local_dir>\n"); rc = 2; }
        else {
            cp_ctx_t cc = { c, argv[4], 0 };
            if (mkdir(argv[4], 0755) != 0 && errno != EEXIST) {
                fprintf(stderr, "mkdir %s: %s\n", argv[4], strerror(errno)); rc = 1;
            } else {
                rc = for_each_object(c, argv[3], cp_one, &cc);
                rc = (rc == 0 && cc.fails == 0) ? 0 : 1;
            }
        }
    } else {
        fprintf(stderr, "unknown command '%s'\n", cmd);
        rc = 2;
    }

    sd_ceph_conn_destroy(c);
    return rc;
}
