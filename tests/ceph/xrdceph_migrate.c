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
 * BUILD (in the librados build container):
 *   gcc -DXRDPROTO_NO_NGX -DBRIX_HAVE_CEPH -I src/fs/backend -I src/fs/backend/rados \
 *     -include tests/ceph/ngx_shim.h tests/ceph/xrdceph_migrate.c \
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

int
main(int argc, char **argv)
{
    brix_sd_ceph_conf_t conf;
    sd_ceph_conn_t       *c;
    rados_ioctx_t         ioctx;
    rados_list_ctx_t      lc;
    const char           *dest;
    int                   err = 0, rc;
    unsigned long long    files = 0, bytes = 0, fails = 0;

    if (argc < 3) {
        fprintf(stderr, "usage: %s <pool> <dest_dir>\n", argv[0]);
        return 2;
    }
    dest = argv[2];

    memset(&conf, 0, sizeof(conf));
    conf.pool      = argv[1];
    conf.conf_file = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";

    c = sd_ceph_conn_create(&conf, NULL, &err);
    if (c == NULL) { fprintf(stderr, "connect %s: %s\n", argv[1], strerror(err)); return 1; }
    ioctx = sd_ceph_conn_ioctx(c);

    if (mkdir(dest, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir %s: %s\n", dest, strerror(errno));
        sd_ceph_conn_destroy(c);
        return 1;
    }
    if (rados_nobjects_list_open(ioctx, &lc) < 0) {
        fprintf(stderr, "list open: %s\n", strerror(errno));
        sd_ceph_conn_destroy(c);
        return 1;
    }

    for (;;) {
        const char *entry = NULL;
        char        path[4096];
        struct stat sb;
        FILE       *out;
        int         fd;
        uint64_t    sz = 0;

        rc = rados_nobjects_list_next2(lc, &entry, NULL, NULL, NULL, NULL, NULL);
        if (rc == -ENOENT) { break; }
        if (rc < 0) { fprintf(stderr, "list next: %d\n", rc); fails++; break; }
        if (entry == NULL || entry[0] == '\0') { continue; }

        /* object key is the logical path; drop a leading '/' to make it relative */
        snprintf(path, sizeof(path), "%s/%s", dest,
                 (entry[0] == '/') ? entry + 1 : entry);

        if (mkdirs_for(path) != 0) {
            fprintf(stderr, "mkdirs for %s: %s\n", path, strerror(errno)); fails++; continue;
        }
        out = fopen(path, "wb");
        if (out == NULL) { fprintf(stderr, "create %s: %s\n", path, strerror(errno));
                           fails++; continue; }
        fd = fileno(out);

        if (stream_object(c, entry, fd) != 0) {
            fprintf(stderr, "copy %s failed\n", entry); fails++; fclose(out); continue;
        }
        carry_xattrs(c, entry, fd);
        fclose(out);

        if (sd_ceph_oid_stat(c, entry, &sz, NULL) == 0) { bytes += sz; }
        else if (stat(path, &sb) == 0) { bytes += (uint64_t) sb.st_size; }
        files++;
        printf("  %s -> %s\n", entry, path);
    }

    rados_nobjects_list_close(lc);
    sd_ceph_conn_destroy(c);

    printf("migrated %llu file(s), %llu byte(s) into %s (%llu failure(s))\n",
           files, bytes, dest, fails);
    return (fails == 0) ? 0 : 1;
}
