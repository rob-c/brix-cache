/*
 * striper_to_cephfs2.cpp — HARDENED near-in-place migration spike.
 *
 * Over striper_to_cephfs.c it adds the two things needed to de-risk real
 * Glasgow/RAL geometries:
 *   1. TRUE SERVER-SIDE re-key via librados C++ ObjectWriteOperation::copy_from
 *      (OSD→OSD; the file bytes never transit this host).
 *   2. stripe_count > 1 support, by ENUMERATING the existing striper data objects
 *      and re-keying each by its object index. Striper and CephFS share Ceph's
 *      striping algorithm, so a given (stripe_unit, stripe_count, object_size)
 *      maps an offset to the SAME object index in both; only the object NAME
 *      differs (<soid>.<idx:016x> vs <ino>.<idx:08x>). So once the CephFS file's
 *      layout is set to match, the migration is a per-index name re-key for any
 *      stripe_count — no RAID0 byte remapping required.
 *
 * The MDS still owns all metadata (we create the file, it allocates the inode +
 * builds the namespace/backtrace); we only move data-object names + set the size.
 *
 *   g++ -D_FILE_OFFSET_BITS=64 striper_to_cephfs2.cpp -lrados -lcephfs -o s2c2
 *   ./s2c2 <striper_pool> <soid> <cephfs_data_pool> <cephfs_path>
 */
#include <rados/librados.hpp>
#include <cephfs/libcephfs.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>

static long
xattr_num(librados::IoCtx &io, const std::string &oid, const char *name, long dflt)
{
    ceph::bufferlist bl;
    if (io.getxattr(oid, name, bl) < 0) { return dflt; }
    std::string s(bl.c_str(), bl.length());
    return strtol(s.c_str(), nullptr, 10);
}

/* Is `name` a data stripe of `soid` (== soid + "." + 16 hex)? If so parse the
 * object index into *idx and return true. */
static bool
parse_stripe(const std::string &soid, const std::string &name, unsigned long *idx)
{
    std::string pfx = soid + ".";
    if (name.size() != pfx.size() + 16 || name.compare(0, pfx.size(), pfx) != 0) {
        return false;
    }
    std::string hex = name.substr(pfx.size());
    for (char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { return false; }
    }
    *idx = strtoul(hex.c_str(), nullptr, 16);
    return true;
}

static int
set_layout(struct ceph_mount_info *cm, int fd, const char *attr, long v)
{
    char val[32];
    snprintf(val, sizeof(val), "%ld", v);
    return ceph_fsetxattr(cm, fd, attr, val, strlen(val), 0);
}

int
main(int argc, char **argv)
{
    const char *conf = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";

    if (argc != 5) {
        fprintf(stderr, "usage: %s <striper_pool> <soid> <cephfs_data_pool> <cephfs_path>\n", argv[0]);
        return 2;
    }
    std::string spool = argv[1], soid = argv[2], dpool = argv[3], cpath = argv[4];

    librados::Rados cluster;
    librados::IoCtx src, dst;
    if (cluster.init("admin") < 0 || cluster.conf_read_file(conf) < 0
        || cluster.connect() < 0) { fprintf(stderr, "rados connect\n"); return 1; }
    if (cluster.ioctx_create(spool.c_str(), src) < 0
        || cluster.ioctx_create(dpool.c_str(), dst) < 0) { fprintf(stderr, "ioctx\n"); return 1; }

    std::string first = soid + ".0000000000000000";
    long object_size  = xattr_num(src, first, "striper.layout.object_size", 4194304);
    long stripe_unit  = xattr_num(src, first, "striper.layout.stripe_unit", object_size);
    long stripe_count = xattr_num(src, first, "striper.layout.stripe_count", 1);
    long total        = xattr_num(src, first, "striper.size", -1);
    if (total < 0) { fprintf(stderr, "no striper.size on %s\n", first.c_str()); return 1; }
    printf("source layout: object_size=%ld stripe_unit=%ld stripe_count=%ld size=%ld\n",
           object_size, stripe_unit, stripe_count, total);

    /* ---- MDS: create the file with a layout matching the striper geometry ---- */
    struct ceph_mount_info *cm;
    if (ceph_create(&cm, "admin") < 0 || ceph_conf_read_file(cm, conf) < 0
        || ceph_mount(cm, "/") < 0) { fprintf(stderr, "cephfs mount\n"); return 1; }
    {
        std::string dir = cpath;
        size_t slash = dir.find_last_of('/');
        if (slash != std::string::npos && slash != 0) {
            ceph_mkdirs(cm, dir.substr(0, slash).c_str(), 0755);
        }
    }
    int fd = ceph_open(cm, cpath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { fprintf(stderr, "ceph_open %s: %d\n", cpath.c_str(), fd); return 1; }
    set_layout(cm, fd, "ceph.file.layout.object_size", object_size);
    set_layout(cm, fd, "ceph.file.layout.stripe_unit", stripe_unit);
    set_layout(cm, fd, "ceph.file.layout.stripe_count", stripe_count);
    ceph_close(cm, fd);

    struct ceph_statx stx;
    if (ceph_statx(cm, cpath.c_str(), &stx, CEPH_STATX_INO, 0) != 0) { fprintf(stderr, "statx\n"); return 1; }
    unsigned long long ino = (unsigned long long) stx.stx_ino;
    printf("MDS allocated inode 0x%llx for %s\n", ino, cpath.c_str());

    /* ---- enumerate + server-side re-key every striper data object ---- */
    int nrekey = 0;
    for (auto it = src.nobjects_begin(); it != src.nobjects_end(); ++it) {
        std::string   name = it->get_oid();
        unsigned long idx;
        if (!parse_stripe(soid, name, &idx)) { continue; }

        uint64_t psize = 0; time_t pmt = 0;
        if (src.stat(name, &psize, &pmt) < 0) { fprintf(stderr, "stat %s\n", name.c_str()); return 1; }
        uint64_t ver = src.get_last_version();

        char dstname[64];
        snprintf(dstname, sizeof(dstname), "%llx.%08lx", ino, idx);

        librados::ObjectWriteOperation op;
        op.copy_from(name, src, ver, 0);          /* OSD→OSD; bytes skip this host */
        int rc = dst.operate(dstname, &op);
        if (rc < 0) { fprintf(stderr, "copy_from %s -> %s: %d\n", name.c_str(), dstname, rc); return 1; }

        /* the striper metadata xattrs ride along on object 0 — strip them so the
         * CephFS data object is clean (the MDS owns layout/backtrace). */
        if (idx == 0) {
            const char *junk[] = { "striper.layout.object_size", "striper.layout.stripe_unit",
                                   "striper.layout.stripe_count", "striper.size", "lock.striper.lock" };
            for (const char *j : junk) { dst.rmxattr(dstname, j); }
        }
        printf("  copy_from %s -> %s (%llu bytes, v%llu)\n",
               name.c_str(), dstname, (unsigned long long) psize, (unsigned long long) ver);
        nrekey++;
    }
    printf("re-keyed %d data object(s) server-side\n", nrekey);

    if (ceph_truncate(cm, cpath.c_str(), total) != 0) { fprintf(stderr, "truncate\n"); return 1; }
    ceph_unmount(cm); ceph_release(cm);

    /* ---- verify with a fresh client ---- */
    int rc = 1;
    {
        struct ceph_mount_info *vm;
        if (ceph_create(&vm, "admin") < 0 || ceph_conf_read_file(vm, conf) < 0
            || ceph_mount(vm, "/") < 0) { fprintf(stderr, "verify mount\n"); return 1; }
        int vfd = ceph_open(vm, cpath.c_str(), O_RDONLY, 0);
        if (vfd < 0) { fprintf(stderr, "verify open %d\n", vfd); return 1; }
        char  *rb = (char *) malloc(total);
        long   got = 0; ssize_t n;
        while (got < total && (n = ceph_read(vm, vfd, rb + got, total - got, got)) > 0) { got += n; }
        ceph_close(vm, vfd);

        /* strong check: every 8-byte word must equal its own offset, so a
         * scrambled stripe interleave (not just a wrong head/tail) is caught. */
        long badoff = -1;
        for (long o = 0; o + 8 <= total; o += 8) {
            uint64_t v;
            memcpy(&v, rb + o, 8);
            if (v != (uint64_t) o) { badoff = o; break; }
        }
        printf("readback: size=%ld pattern=%s\n", got,
               badoff < 0 ? "OK (every word == offset)" : "MISMATCH");
        if (got == total && badoff < 0) {
            printf("RESULT: PASS — CephFS serves the server-side re-keyed striper "
                   "data, byte-exact incl. stripe interleave\n");
            rc = 0;
        } else {
            printf("RESULT: FAIL — size %ld/%ld, first bad word @ offset %ld\n",
                   got, total, badoff);
        }
        free(rb);
        ceph_unmount(vm); ceph_release(vm);
    }
    return rc;
}
