/*
 * xrdceph_migrate.c — migrate a flat RADOS pool into a real filesystem tree
 * (copy-through-mount). Operator utility.
 *
 * WHAT: Reads every object from a flat `ceph`-backend pool (object key == logical
 *       path) and writes it as a file at the corresponding path beneath a
 *       destination directory, recreating parent directories and carrying user
 *       xattrs (including `user.XrdCks.*` checksums-at-rest). When the destination
 *       is a mounted CephFS, the MDS allocates inodes and builds the namespace —
 *       i.e. this performs the spike's copy-through-mount migration (the only sound
 *       way: CephFS keys data by MDS-allocated inode, so an in-place "upgrade" is
 *       impossible; the bytes must be rewritten through the fs).
 *
 * USAGE:
 *   xrdceph_migrate <pool> <dest_dir>            (dest_dir is a CephFS mount point)
 *   (env CEPH_CONF overrides /etc/ceph/ceph.conf)
 *
 * The destination is treated as a plain directory, so this is verifiable against a
 * local folder; pointing it at a CephFS mount is what makes it a migration.
 *
 * BUILD: `make -C client ceph-tools` (dep-gated), or by hand where
 * librados-devel exists:
 *   gcc -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH -I src/fs/backend -I src/fs/backend/rados \
 *     -include client/apps/ceph/ngx_shim.h client/apps/ceph/xrdceph_migrate.c \
 *     src/fs/backend/rados/sd_ceph.c src/fs/backend/rados/sd_ceph_compat.c \
 *     -lrados -o xrdceph_migrate
 */
#include "sd.h"
#include "rados/sd_ceph.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include <rados/librados.h>

void *ngx_pcalloc(ngx_pool_t *pool, size_t size) { (void) pool; return calloc(1, size); }
void *ngx_pnalloc(ngx_pool_t *pool, size_t size) { (void) pool; return malloc(size); }

/* mkdir -p for every parent directory of `path` (path itself is a file). */
static int
mkdirs_for(const char *path)
{
    char  tmp[4096];
    char *s;

    snprintf(tmp, sizeof(tmp), "%s", path);
    for (s = tmp + 1; *s != '\0'; s++) {
        if (*s == '/') {
            *s = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) { return -1; }
            *s = '/';
        }
    }
    return 0;
}

/* Carry every user xattr from the RADOS object `oid` onto the open dest fd. Best
 * effort: a per-xattr failure is logged but does not fail the file. */
static void
carry_xattrs(sd_ceph_conn_t *c, const char *oid, int fd)
{
    char    names[8192];
    ssize_t n = sd_ceph_oid_listxattr(c, oid, names, sizeof(names));
    ssize_t p;

    if (n <= 0) { return; }
    for (p = 0; p < n; p += (ssize_t) strlen(names + p) + 1) {
        const char *name = names + p;
        char        val[65536];
        ssize_t     vlen;

        if (name[0] == '\0') { break; }
        vlen = sd_ceph_oid_getxattr(c, oid, name, val, sizeof(val));
        if (vlen < 0) { continue; }
        if (fsetxattr(fd, name, val, (size_t) vlen, 0) != 0) {
            fprintf(stderr, "  warn: xattr %s on %s: %s\n", name, oid, strerror(errno));
        }
    }
}

/* Stream object `oid` to the already-open dest fd in 1 MiB reads. 0 / -1. */
static int
stream_object(sd_ceph_conn_t *c, const char *oid, int fd)
{
    char    buf[1u << 20];
    off_t   off = 0;
    ssize_t n;

    while ((n = sd_ceph_oid_read(c, oid, buf, sizeof(buf), off)) > 0) {
        ssize_t w = 0;
        while (w < n) {
            ssize_t k = write(fd, buf + w, (size_t) (n - w));
            if (k < 0) { if (errno == EINTR) { continue; } return -1; }
            w += k;
        }
        off += n;
        if ((size_t) n < sizeof(buf)) { break; }
    }
    return (n < 0) ? -1 : 0;
}

/* ---- Connect to the RADOS pool and prepare the destination + object list ----
 *
 * WHAT: Connects to `pool` (honouring CEPH_CONF), ensures `dest` exists as a
 *       directory, and opens a whole-pool object-list cursor. On success returns
 *       0 with `*conn_out` set to a live connection and `*lc_out` to an open list
 *       cursor; on any failure prints a diagnostic, tears down anything already
 *       acquired, and returns -1 with `*conn_out` left NULL.
 *
 * WHY: Keeps main's orchestration flat by confining all one-time acquisition and
 *      its error/cleanup ladder to a single owner, so the migration loop can
 *      assume a ready source and destination.
 *
 * HOW:
 *   1. Zero a conf, point it at `pool` and the CEPH_CONF (or default) conf file.
 *   2. Create the ceph connection; on failure print and return -1.
 *   3. mkdir(dest) tolerating EEXIST; on real failure destroy the conn, return -1.
 *   4. Open the object-list cursor over the connection's ioctx; on failure
 *      destroy the conn, return -1.
 *   5. Publish the connection and cursor to the out-params and return 0.
 */
static int
open_source_and_dest(const char *pool, const char *dest,
                     sd_ceph_conn_t **conn_out, rados_list_ctx_t *lc_out)
{
    brix_sd_ceph_conf_t conf;
    sd_ceph_conn_t     *c;
    int                 err = 0;

    *conn_out = NULL;

    memset(&conf, 0, sizeof(conf));
    conf.pool      = pool;
    conf.conf_file = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";

    c = sd_ceph_conn_create(&conf, NULL, &err);
    if (c == NULL) { fprintf(stderr, "connect %s: %s\n", pool, strerror(err)); return -1; }

    if (mkdir(dest, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", dest, strerror(errno));
        sd_ceph_conn_destroy(c);
        return -1;
    }
    if (rados_nobjects_list_open(sd_ceph_conn_ioctx(c), lc_out) < 0) {
        fprintf(stderr, "list open: %s\n", strerror(errno));
        sd_ceph_conn_destroy(c);
        return -1;
    }

    *conn_out = c;
    return 0;
}

/* ---- Copy one RADOS object to its file under the destination tree ----
 *
 * WHAT: Materialises object `entry` as a file at its logical path beneath `dest`,
 *       recreating parent directories, carrying user xattrs, and adding the
 *       object's byte size to `*bytes`. Returns 0 on success (and prints the
 *       `src -> dst` progress line); returns -1 on any failure after printing a
 *       diagnostic. Best-effort xattr carry never fails the file.
 *
 * WHY: Isolates the whole per-object copy pipeline behind one call so the driver
 *      loop only accounts success/failure — one nameable responsibility per unit
 *      and no cleanup ladder leaking into main.
 *
 * HOW:
 *   1. Build the destination path, dropping a leading '/' so the key is relative.
 *   2. mkdir -p its parents; on failure print and return -1.
 *   3. Open the destination file for writing; on failure print and return -1.
 *   4. Stream the object bytes to the fd; on failure print, close, return -1.
 *   5. Carry user xattrs (best effort), then close the file.
 *   6. Add the object size to `*bytes` — from the object stat, else the written
 *      file's stat — print the progress line, and return 0.
 */
static int
migrate_one_object(sd_ceph_conn_t *c, const char *dest, const char *entry,
                   unsigned long long *bytes)
{
    char        path[4096];
    struct stat sb;
    FILE       *out;
    int         fd;
    uint64_t    sz = 0;

    /* object key is the logical path; drop a leading '/' to make it relative */
    snprintf(path, sizeof(path), "%s/%s", dest,
             (entry[0] == '/') ? entry + 1 : entry);

    if (mkdirs_for(path) != 0) {
        fprintf(stderr, "mkdirs for %s: %s\n", path, strerror(errno));
        return -1;
    }
    out = fopen(path, "wb");
    if (out == NULL) {
        fprintf(stderr, "create %s: %s\n", path, strerror(errno));
        return -1;
    }
    fd = fileno(out);

    if (stream_object(c, entry, fd) != 0) {
        fprintf(stderr, "copy %s failed\n", entry);
        fclose(out);
        return -1;
    }
    carry_xattrs(c, entry, fd);
    fclose(out);

    if (sd_ceph_oid_stat(c, entry, &sz, NULL) == 0) { *bytes += sz; }
    else if (stat(path, &sb) == 0) { *bytes += (uint64_t) sb.st_size; }

    printf("  %s -> %s\n", entry, path);
    return 0;
}

/* ---- Drive the whole-pool copy loop, tallying files/bytes/failures ----
 *
 * WHAT: Iterates every object in the open list cursor `lc`, copying each into the
 *       `dest` tree via migrate_one_object() and accumulating the counts into
 *       `*files`, `*bytes`, and `*fails`. Returns when the cursor is exhausted or
 *       a fatal list error occurs (the latter counted as one failure).
 *
 * WHY: Separates the iteration/accounting policy from the per-object copy so main
 *      stays a short, linear sequence of named steps.
 *
 * HOW:
 *   1. Advance the cursor; stop cleanly on -ENOENT (exhausted).
 *   2. On a negative list error, print it, count one failure, and stop.
 *   3. Skip empty/NULL keys.
 *   4. Copy the object; bump `*files` on success or `*fails` on failure.
 */
static void
migrate_pool(sd_ceph_conn_t *c, const char *dest, rados_list_ctx_t lc,
             unsigned long long *files, unsigned long long *bytes,
             unsigned long long *fails)
{
    for (;;) {
        const char *entry = NULL;
        int         rc;

        rc = rados_nobjects_list_next2(lc, &entry, NULL, NULL, NULL, NULL, NULL);
        if (rc == -ENOENT) { break; }
        if (rc < 0) { fprintf(stderr, "list next: %d\n", rc); (*fails)++; break; }
        if (entry == NULL || entry[0] == '\0') { continue; }

        if (migrate_one_object(c, dest, entry, bytes) == 0) { (*files)++; }
        else { (*fails)++; }
    }
}

int
main(int argc, char **argv)
{
    sd_ceph_conn_t   *c;
    rados_list_ctx_t  lc;
    const char       *dest;
    unsigned long long files = 0, bytes = 0, fails = 0;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <pool> <dest_dir>\n", argv[0]);
        return 2;
    }
    dest = argv[2];

    if (open_source_and_dest(argv[1], dest, &c, &lc) != 0) { return 1; }

    migrate_pool(c, dest, lc, &files, &bytes, &fails);

    rados_nobjects_list_close(lc);
    sd_ceph_conn_destroy(c);

    printf("migrated %llu file(s), %llu byte(s) into %s (%llu failure(s))\n",
           files, bytes, dest, fails);
    return (fails == 0) ? 0 : 1;
}
