/*
 * spike_cephfs_to_striper.cpp — REVERSE migration spike (Lancaster/Manchester):
 * turn a CephFS file into a stock-XrdCeph (libradosstriper) object so it can be
 * served by XrdCeph after CephFS is retired.
 *
 * CephFS data objects are <ino>.<objno8>; libradosstriper wants <soid>.<stripe16>
 * with the striper layout + size xattrs on the first object. Both use Ceph
 * striping, so object index i maps 1:1; only the name + the metadata-xattr location
 * differ. This re-keys each CephFS object into the striper name (copy_from, OSD to
 * OSD, in-cluster) and stamps the striper xattrs, then verifies libradosstriper
 * reads it byte-exact. (A zero-move/redirect reverse is not viable: CephFS actively
 * owns its data objects and unlinking the file purges them.)
 *
 *   g++ -std=c++17 -D_FILE_OFFSET_BITS=64 spike_cephfs_to_striper.cpp \
 *       -lrados -lradosstriper -lcephfs -o s_rev
 *   ./s_rev <cephfs_path> <cephfs_data_pool> <striper_pool> <soid>
 */
#include <rados/librados.hpp>
#include <radosstriper/libradosstriper.h>
#include <cephfs/libcephfs.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <vector>

static long cephfs_laynum(struct ceph_mount_info *cm, const char *path, const char *attr, long dflt)
{
    char buf[64];
    int n = ceph_getxattr(cm, path, attr, buf, sizeof(buf) - 1);
    if (n <= 0) { return dflt; }
    buf[n] = '\0';
    return strtol(buf, nullptr, 10);
}

int main(int argc, char **argv)
{
    const char *conf = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";
    if (argc != 5) { fprintf(stderr, "usage: %s <cephfs_path> <cephfs_data_pool> <striper_pool> <soid>\n", argv[0]); return 2; }
    std::string cpath = argv[1], cdpool = argv[2], spool = argv[3], soid = argv[4];

    /* ---- read CephFS file identity + layout ---- */
    struct ceph_mount_info *cm;
    if (ceph_create(&cm, "admin") < 0 || ceph_conf_read_file(cm, conf) < 0 || ceph_mount(cm, "/") < 0) {
        fprintf(stderr, "cephfs mount\n"); return 1; }
    struct ceph_statx stx;
    if (ceph_statx(cm, cpath.c_str(), &stx, CEPH_STATX_INO | CEPH_STATX_SIZE, 0) != 0) { fprintf(stderr, "statx\n"); return 1; }
    unsigned long long ino = (unsigned long long) stx.stx_ino;
    long total = (long) stx.stx_size;
    long os = cephfs_laynum(cm, cpath.c_str(), "ceph.file.layout.object_size", 4194304);
    long su = cephfs_laynum(cm, cpath.c_str(), "ceph.file.layout.stripe_unit", os);
    long sc = cephfs_laynum(cm, cpath.c_str(), "ceph.file.layout.stripe_count", 1);
    printf("CephFS %s: ino=0x%llx size=%ld layout os=%ld su=%ld sc=%ld\n", cpath.c_str(), ino, total, os, su, sc);
    ceph_unmount(cm); ceph_release(cm);

    /* ---- re-key each CephFS data object into the striper name ---- */
    librados::Rados cl; librados::IoCtx cd, sp;
    if (cl.init("admin") < 0 || cl.conf_read_file(conf) < 0 || cl.connect() < 0) { fprintf(stderr, "rados\n"); return 1; }
    cl.ioctx_create(cdpool.c_str(), cd);
    cl.ioctx_create(spool.c_str(), sp);

    char pfx[32]; snprintf(pfx, sizeof(pfx), "%llx.", ino);
    int n = 0;
    for (auto it = cd.nobjects_begin(); it != cd.nobjects_end(); ++it) {
        std::string name = it->get_oid();
        if (name.compare(0, strlen(pfx), pfx) != 0) { continue; }
        unsigned long idx = strtoul(name.c_str() + strlen(pfx), nullptr, 16);
        uint64_t psz = 0; time_t pmt = 0; cd.stat(name, &psz, &pmt); uint64_t ver = cd.get_last_version();
        char dst[64]; snprintf(dst, sizeof(dst), "%s.%016lx", soid.c_str(), idx);
        librados::ObjectWriteOperation op; op.copy_from(name, cd, ver, 0);
        if (sp.operate(dst, &op) < 0) { fprintf(stderr, "copy_from %s -> %s\n", name.c_str(), dst); return 1; }
        /* strip the CephFS backtrace/layout xattrs that rode along */
        for (const char *j : { "parent", "layout" }) sp.rmxattr(dst, j);
        n++;
    }

    /* ---- stamp the striper metadata xattrs on the first object ---- */
    std::string first = soid + ".0000000000000000";
    auto setx = [&](const char *k, long v){ char b[32]; int l = snprintf(b, sizeof(b), "%ld", v);
        ceph::bufferlist bl; bl.append(b, l); sp.setxattr(first, k, bl); };
    setx("striper.layout.object_size", os);
    setx("striper.layout.stripe_unit", su);
    setx("striper.layout.stripe_count", sc);
    setx("striper.size", total);
    printf("re-keyed %d object(s) into striper soid '%s' + stamped striper xattrs\n", n, soid.c_str());
    cd.close(); sp.close(); cl.shutdown();

    /* ---- verify libradosstriper (XrdCeph) reads it byte-exact ---- */
    rados_t rc; rados_ioctx_t rio; rados_striper_t st;
    rados_create(&rc, "admin"); rados_conf_read_file(rc, conf); rados_connect(rc);
    rados_ioctx_create(rc, spool.c_str(), &rio); rados_striper_create(rio, &st);
    std::vector<char> b(total);
    int got = rados_striper_read(st, soid.c_str(), b.data(), total, 0);
    long bad = -1;
    for (long o = 0; o + 8 <= got; o += 8) { unsigned long long v; memcpy(&v, b.data() + o, 8); if (v != (unsigned long long) o) { bad = o; break; } }
    printf("libradosstriper read '%s': got=%d/%ld pattern=%s\n", soid.c_str(), got, total, (got == total && bad < 0) ? "OK byte-exact" : "BAD");
    printf("RESULT: %s\n", (got == total && bad < 0) ? "PASS — CephFS file is now a working XrdCeph striper object" : "FAIL");
    rados_striper_destroy(st); rados_ioctx_destroy(rio); rados_shutdown(rc);
    return (got == total && bad < 0) ? 0 : 1;
}
