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
 * BUILD: `make -C client ceph-tools` (dep-gated), or by hand where
 * librados-devel exists:
 *   gcc -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH -I src/fs/backend -I src/fs/backend/rados \
 *     -include client/apps/ceph/ngx_shim.h client/apps/ceph/xrdrados_rescue.c \
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

/* ---- List every object key (optionally prefix-filtered) to stdout ----
 *
 * WHAT: Runs the `ls [prefix]` subcommand: prints one matching object key per
 *       line. Returns 0 on success, 1 on a RADOS listing error.
 *
 * WHY: Splitting the per-command body out of main() keeps each subcommand a
 *      single-purpose unit and holds main()'s branching under the complexity cap.
 *
 * HOW:
 *   1. Pass argv[3] as the prefix when present, else NULL (list-all).
 *   2. Walk the pool via for_each_object() with the print_key callback.
 *   3. On error, report strerror(errno) and normalise the status to 1.
 */
static int
cmd_ls(sd_ceph_conn_t *c, int argc, char **argv)
{
    int rc = for_each_object(c, (argc > 3) ? argv[3] : NULL, print_key, NULL);
    if (rc != 0) { fprintf(stderr, "list failed: %s\n", strerror(errno)); rc = 1; }
    return rc;
}

/* ---- Print size + mtime for one object key ----
 *
 * WHAT: Runs the `stat <key>` subcommand: prints key/size/mtime. Returns 0 on
 *       success, 2 on missing argument, 1 on a stat failure.
 *
 * WHY: Isolates the stat formatting and its argument/error handling from the
 *      other subcommands so each stays independently reviewable.
 *
 * HOW:
 *   1. Require argv[3] (the key); otherwise emit usage and return 2.
 *   2. Query sd_ceph_oid_stat(); on failure report strerror(errno), return 1.
 *   3. On success print key, size (unsigned long long), mtime (long long).
 */
static int
cmd_stat(sd_ceph_conn_t *c, int argc, char **argv)
{
    uint64_t sz = 0; time_t mt = 0;
    if (argc < 4) { fprintf(stderr, "stat needs <key>\n"); return 2; }
    if (sd_ceph_oid_stat(c, argv[3], &sz, &mt) != 0) {
        fprintf(stderr, "stat %s: %s\n", argv[3], strerror(errno)); return 1;
    }
    printf("key:   %s\nsize:  %llu\nmtime: %lld\n",
           argv[3], (unsigned long long) sz, (long long) mt);
    return 0;
}

/* ---- Extract one object's bytes to a named local file ----
 *
 * WHAT: Runs the `get <key> <local_file>` subcommand: streams the object into
 *       the file. Returns 0 on success, 2 on missing args, 1 on open/read error.
 *
 * WHY: Keeps the single-object extraction path (open target, stream, close)
 *      self-contained and off main()'s branch ladder.
 *
 * HOW:
 *   1. Require both argv[3] (key) and argv[4] (local file); else return 2.
 *   2. Open the target for binary write; on failure report and return 1.
 *   3. Stream via extract_object(), map success to 0 / failure to 1, close.
 */
static int
cmd_get(sd_ceph_conn_t *c, int argc, char **argv)
{
    FILE *out;
    int   rc;
    if (argc < 5) { fprintf(stderr, "get needs <key> <local_file>\n"); return 2; }
    out = fopen(argv[4], "wb");
    if (out == NULL) { fprintf(stderr, "create %s: %s\n", argv[4], strerror(errno)); return 1; }
    rc = (extract_object(c, argv[3], out) == 0) ? 0 : 1;
    fclose(out);
    return rc;
}

/* ---- Bulk-extract every object under a prefix into a local directory ----
 *
 * WHAT: Runs the `cp <prefix> <local_dir>` subcommand: creates the directory and
 *       writes each matching object to a flattened filename. Returns 0 when all
 *       objects extracted cleanly, 2 on missing args, 1 on mkdir/extraction fail.
 *
 * WHY: Groups the destination setup and the per-object copy fan-out into one
 *      unit, preserving the "0 only if every object succeeded" contract.
 *
 * HOW:
 *   1. Require argv[3] (prefix) and argv[4] (local dir); else return 2.
 *   2. mkdir the destination, tolerating EEXIST; other errors report + return 1.
 *   3. Walk matching objects via for_each_object()+cp_one accumulating failures.
 *   4. Return 0 only when the walk succeeded and cc.fails is zero, else 1.
 */
static int
cmd_cp(sd_ceph_conn_t *c, int argc, char **argv)
{
    cp_ctx_t cc;
    int      rc;
    if (argc < 5) { fprintf(stderr, "cp needs <prefix> <local_dir>\n"); return 2; }
    cc.c = c; cc.dst = argv[4]; cc.fails = 0;
    if (mkdir(argv[4], 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", argv[4], strerror(errno)); return 1;
    }
    rc = for_each_object(c, argv[3], cp_one, &cc);
    return (rc == 0 && cc.fails == 0) ? 0 : 1;
}

/* ---- Dispatch a parsed subcommand to its handler ----
 *
 * WHAT: Maps the command word to cmd_ls/cmd_stat/cmd_get/cmd_cp and returns that
 *       handler's status; returns 2 for an unknown command.
 *
 * WHY: Keeps the command-name branch ladder in one small function so main() is a
 *      flat connect → dispatch → destroy sequence within the complexity cap.
 *
 * HOW:
 *   1. Compare cmd against each known verb in turn.
 *   2. Delegate to the matching handler, forwarding argc/argv unchanged.
 *   3. On no match, report the unknown command and return 2.
 */
static int
run_command(sd_ceph_conn_t *c, const char *cmd, int argc, char **argv)
{
    if (strcmp(cmd, "ls") == 0)   { return cmd_ls(c, argc, argv); }
    if (strcmp(cmd, "stat") == 0) { return cmd_stat(c, argc, argv); }
    if (strcmp(cmd, "get") == 0)  { return cmd_get(c, argc, argv); }
    if (strcmp(cmd, "cp") == 0)   { return cmd_cp(c, argc, argv); }
    fprintf(stderr, "unknown command '%s'\n", cmd);
    return 2;
}

int
main(int argc, char **argv)
{
    brix_sd_ceph_conf_t conf;
    sd_ceph_conn_t       *c;
    int                   err = 0, rc;

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

    rc = run_command(c, argv[2], argc, argv);

    sd_ceph_conn_destroy(c);
    return rc;
}
