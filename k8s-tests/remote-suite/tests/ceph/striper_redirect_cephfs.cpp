/*
 * striper_redirect_cephfs.cpp — SPIKE for Q2: can CephFS serve existing
 * libradosstriper data with NO data copy, by pointing the MDS-allocated data
 * object names at the striper objects via RADOS object REDIRECTS?
 *
 * Per file: the MDS builds the namespace (empty file + matching layout → inode),
 * then for each CephFS data object name <ino>.<objno> we create a REDIRECT stub in
 * the CephFS data pool pointing at the existing striper object <soid>.<stripe> in
 * the striper pool (rados set_redirect — a metadata op, no bytes copied), then set
 * the size via the MDS. We then read the file with a fresh CephFS client and check
 * it is byte-exact — i.e. whether the CephFS read path follows RADOS redirects.
 *
 * This is the only TRUE zero-copy route (the data stays as the single striper
 * copy); it is experimental/unsupported under CephFS — this spike is exactly to
 * find out empirically whether reef serves it.
 *
 *   g++ -std=c++17 -D_FILE_OFFSET_BITS=64 striper_redirect_cephfs.cpp \
 *       -lrados -lcephfs -o s_redir
 *   ./s_redir <striper_pool> <soid> <cephfs_data_pool> <cephfs_path>
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

static bool
parse_stripe(const std::string &soid, const std::string &name, unsigned long *idx)
{
    std::string pfx = soid + ".";
    if (name.size() != pfx.size() + 16 || name.compare(0, pfx.size(), pfx) != 0) { return false; }
    for (size_t i = pfx.size(); i < name.size(); i++) { if (!isxdigit((unsigned char) name[i])) { return false; } }
    *idx = strtoul(name.substr(pfx.size()).c_str(), nullptr, 16);
    return true;
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
    if (cluster.init("admin") < 0 || cluster.conf_read_file(conf) < 0 || cluster.connect() < 0) {
        fprintf(stderr, "rados connect\n"); return 1; }
    if (cluster.ioctx_create(spool.c_str(), src) < 0 || cluster.ioctx_create(dpool.c_str(), dst) < 0) {
        fprintf(stderr, "ioctx\n"); return 1; }

    std::string first = soid + ".0000000000000000";
    long os = xattr_num(src, first, "striper.layout.object_size", -1);
    long su = xattr_num(src, first, "striper.layout.stripe_unit", os);
    long sc = xattr_num(src, first, "striper.layout.stripe_count", 1);
    long total = xattr_num(src, first, "striper.size", -1);
    if (os <= 0 || total < 0) { fprintf(stderr, "not a striper object set\n"); return 1; }
    printf("source: os=%ld su=%ld sc=%ld size=%ld\n", os, su, sc, total);

    /* MDS: namespace + matching layout */
    struct ceph_mount_info *cm;
    if (ceph_create(&cm, "admin") < 0 || ceph_conf_read_file(cm, conf) < 0 || ceph_mount(cm, "/") < 0) {
        fprintf(stderr, "cephfs mount\n"); return 1; }
    {
        std::string d = cpath; size_t s = d.find_last_of('/');
        if (s != std::string::npos && s != 0) { ceph_mkdirs(cm, d.substr(0, s).c_str(), 0755); }
    }
    int fd = ceph_open(cm, cpath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { fprintf(stderr, "ceph_open %d\n", fd); return 1; }
    auto setlay = [&](const char *a, long v){ char b[32]; snprintf(b,sizeof(b),"%ld",v); ceph_fsetxattr(cm,fd,a,b,strlen(b),0); };
    setlay("ceph.file.layout.object_size", os);
    setlay("ceph.file.layout.stripe_unit", su);
    setlay("ceph.file.layout.stripe_count", sc);
    ceph_close(cm, fd);
    struct ceph_statx stx;
    if (ceph_statx(cm, cpath.c_str(), &stx, CEPH_STATX_INO, 0) != 0) { fprintf(stderr, "statx\n"); return 1; }
    unsigned long long ino = (unsigned long long) stx.stx_ino;
    printf("MDS inode 0x%llx for %s\n", ino, cpath.c_str());

    /* redirect each CephFS data object name at the existing striper object */
    int n = 0;
    for (auto it = src.nobjects_begin(); it != src.nobjects_end(); ++it) {
        unsigned long idx; std::string name = it->get_oid();
        if (!parse_stripe(soid, name, &idx)) { continue; }
        uint64_t psize = 0; time_t pmt = 0;
        if (src.stat(name, &psize, &pmt) < 0) { fprintf(stderr, "stat %s\n", name.c_str()); return 1; }
        uint64_t ver = src.get_last_version();

        char stub[64]; snprintf(stub, sizeof(stub), "%llx.%08lx", ino, idx);
        { librados::ObjectWriteOperation cop; cop.create(false); dst.operate(stub, &cop); }
        librados::ObjectWriteOperation rop;
        rop.set_redirect(name, src, ver, 0);
        int rc = dst.operate(stub, &rop);
        if (rc < 0) { fprintf(stderr, "set_redirect %s -> %s: %d\n", stub, name.c_str(), rc); return 1; }
        printf("  redirect %s -> %s/%s (%llu bytes)\n", stub, spool.c_str(), name.c_str(),
               (unsigned long long) psize);
        n++;
    }
    printf("created %d redirect stub(s) (no data copied)\n", n);

    if (ceph_truncate(cm, cpath.c_str(), total) != 0) { fprintf(stderr, "truncate\n"); return 1; }
    ceph_unmount(cm); ceph_release(cm);

    /* verify via a fresh CephFS client: does the read follow the redirects? */
    int rc = 1;
    {
        struct ceph_mount_info *vm;
        if (ceph_create(&vm, "admin") < 0 || ceph_conf_read_file(vm, conf) < 0 || ceph_mount(vm, "/") < 0) {
            fprintf(stderr, "verify mount\n"); return 1; }
        int vfd = ceph_open(vm, cpath.c_str(), O_RDONLY, 0);
        if (vfd < 0) { fprintf(stderr, "verify open %d\n", vfd); return 1; }
        char *rb = (char *) malloc(total);
        long got = 0; ssize_t r;
        while (got < total && (r = ceph_read(vm, vfd, rb + got, total - got, got)) > 0) { got += r; }
        ceph_close(vm, vfd);
        long bad = -1;
        for (long o = 0; o + 8 <= got; o += 8) { uint64_t v; memcpy(&v, rb + o, 8); if (v != (uint64_t) o) { bad = o; break; } }
        printf("CephFS readback: size=%ld/%ld pattern=%s\n", got, total,
               bad < 0 ? "OK (word==offset)" : "MISMATCH");
        if (got == total && bad < 0) {
            printf("RESULT: PASS — CephFS reads through RADOS redirects; ZERO-COPY works\n");
            rc = 0;
        } else {
            printf("RESULT: FAIL — CephFS did not serve the redirected data (size %ld/%ld, bad@%ld)\n",
                   got, total, bad);
        }
        free(rb);
        ceph_unmount(vm); ceph_release(vm);
    }
    src.close(); dst.close(); cluster.shutdown();
    return rc;
}
