/*
 * cephfs_rados_poc.c — SPIKE proof-of-concept: resolve a CephFS path to bytes
 * using PURE RADOS (no mount, no MDS calls, no libcephfs) — only librados omap
 * reads on the metadata pool + object reads on the data pool.
 *
 * Demonstrates the cephfs-rados read path:
 *   1. start at the root dir inode (0x1).
 *   2. for each path component, read omap key "<name>_head" from the dir object
 *      "<dirino_hex>.00000000" in the metadata pool; the value is a Ceph-encoded
 *      primary dentry — extract the child inode (LE u64 at a reef-pinned offset).
 *   3. read the file's data objects "<ino_hex>.<idx_hex8>" from the data pool,
 *      idx = 0,1,2,... until ENOENT; concatenate.
 *
 * CAVEAT (the spike's whole point): step 2 reads the inode number at a fixed
 * offset that is CEPH-VERSION-SPECIFIC (validated against reef). A production
 * reader needs a real versioned inode_t decoder. Also: only works on
 * MDS-FLUSHED metadata (run `ceph tell mds.<id> flush journal` first); un-
 * flushed dentries live in the MDS journal, not the dir omap.
 *
 *   gcc -D_FILE_OFFSET_BITS=64 cephfs_rados_poc.c -lrados -o poc && \
 *     ./poc <meta_pool> <data_pool> <path>
 */
#include <rados/librados.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* reef primary-dentry layout: first(8) + type(1,'i'=0x69) + ... ; child ino is a
 * little-endian u64 at this offset. VERSION-PINNED — see caveat above. */
#define DENTRY_TYPE_OFF   8
#define DENTRY_INO_OFF    31

static uint64_t le64(const unsigned char *p)
{
    uint64_t v = 0; int i;
    for (i = 0; i < 8; i++) { v |= (uint64_t) p[i] << (8 * i); }
    return v;
}

/* read omap key "<name>_head" from dir object "<ino>.00000000" → child ino. */
static int
lookup_child(rados_ioctx_t meta, uint64_t dirino, const char *name, uint64_t *out)
{
    char                dir_oid[64], key[300];
    const char         *keys[1];
    rados_omap_iter_t   it = NULL;
    rados_read_op_t     op;
    int                 prval = 0, rc, found = 0;
    char               *k = NULL, *v = NULL;
    size_t              vlen = 0;

    snprintf(dir_oid, sizeof(dir_oid), "%llx.00000000", (unsigned long long) dirino);
    snprintf(key, sizeof(key), "%s_head", name);
    keys[0] = key;

    op = rados_create_read_op();
    rados_read_op_omap_get_vals_by_keys(op, keys, 1, &it, &prval);
    rc = rados_read_op_operate(op, meta, dir_oid, 0);
    if (rc < 0) { rados_release_read_op(op); errno = -rc; return -1; }
    if (it && rados_omap_get_next(it, &k, &v, &vlen) == 0 && k && v) {
        if (vlen > DENTRY_INO_OFF + 8
            && (unsigned char) v[DENTRY_TYPE_OFF] == 0x69 /* 'i' primary */) {
            *out = le64((const unsigned char *) v + DENTRY_INO_OFF);
            found = 1;
        }
    }
    if (it) { rados_omap_get_end(it); }
    rados_release_read_op(op);
    return found ? 0 : 1;
}

int
main(int argc, char **argv)
{
    rados_t        cl;
    rados_ioctx_t  meta, data;
    uint64_t       ino = 1;             /* CephFS root inode */
    char          *path, *save = NULL, *comp;
    const char    *conf = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";
    unsigned char *buf = NULL;
    size_t         total = 0;
    uint64_t       idx;
    int            rc;

    if (argc != 4) { fprintf(stderr, "usage: %s <meta_pool> <data_pool> <path>\n", argv[0]); return 2; }

    if (rados_create(&cl, "admin") < 0 || rados_conf_read_file(cl, conf) < 0
        || rados_connect(cl) < 0) { fprintf(stderr, "rados connect failed\n"); return 1; }
    if (rados_ioctx_create(cl, argv[1], &meta) < 0
        || rados_ioctx_create(cl, argv[2], &data) < 0) { fprintf(stderr, "ioctx failed\n"); return 1; }

    /* 1+2: walk the path through dir omaps */
    path = strdup(argv[3]);
    for (comp = strtok_r(path, "/", &save); comp; comp = strtok_r(NULL, "/", &save)) {
        uint64_t child;
        rc = lookup_child(meta, ino, comp, &child);
        if (rc != 0) { fprintf(stderr, "resolve: '%s' not found under ino %llx\n",
                                comp, (unsigned long long) ino); return 1; }
        printf("  %-12s -> ino %llx\n", comp, (unsigned long long) child);
        ino = child;
    }
    free(path);
    printf("resolved %s -> ino 0x%llx\n", argv[3], (unsigned long long) ino);

    /* 3: read data objects until ENOENT */
    {
    size_t   chunk_cap = 8u << 20;
    char    *chunk = malloc(chunk_cap);
    for (idx = 0; ; idx++) {
        char     oid[64];
        int      n;

        snprintf(oid, sizeof(oid), "%llx.%08llx", (unsigned long long) ino,
                 (unsigned long long) idx);
        n = rados_read(data, oid, chunk, chunk_cap, 0);
        if (n == -ENOENT) { break; }
        if (n < 0) { fprintf(stderr, "read %s: %d\n", oid, n); return 1; }
        buf = realloc(buf, total + n);
        memcpy(buf + total, chunk, n);
        total += n;
        if (n == 0) { break; }
    }
    free(chunk);
    }
    printf("read %zu bytes via pure RADOS (%llu data objects)\n",
           total, (unsigned long long) idx);
    if (total >= 16) {
        printf("  head: %.8s ... tail: %.8s\n", buf, buf + total - 8);
    }
    free(buf);
    rados_ioctx_destroy(meta); rados_ioctx_destroy(data); rados_shutdown(cl);
    return 0;
}
