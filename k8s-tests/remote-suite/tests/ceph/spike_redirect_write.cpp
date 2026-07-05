/*
 * spike_redirect_write.cpp — does writing to a redirect-migrated CephFS file
 * corrupt data or touch the SOURCE striper pool? Writes a marker into the middle
 * of object index 1 of an already redirect-migrated file, then checks:
 *   1. the whole file reads back correct (marker where written, original
 *      word==offset pattern everywhere else) — no corruption;
 *   2. the SOURCE striper object for that index is byte-identical before/after
 *      (adler32) — a write must only promote the CephFS stub, never the source.
 *
 *   g++ -std=c++17 -D_FILE_OFFSET_BITS=64 spike_redirect_write.cpp -lrados -lcephfs -o s_wr
 *   ./s_wr <striper_pool> <soid> <cephfs_path>
 */
#include <rados/librados.hpp>
#include <cephfs/libcephfs.h>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <fcntl.h>
#include <string>
#include <vector>

static unsigned long adler(const unsigned char *d, size_t n)
{
    unsigned long a = 1, b = 0;
    while (n) { size_t k = n < 5552 ? n : 5552; n -= k; while (k--) { a += *d++; b += a; } a %= 65521; b %= 65521; }
    return (b << 16) | a;
}
static long xnum(librados::IoCtx &io, const std::string &o, const char *n, long d)
{
    ceph::bufferlist bl; if (io.getxattr(o, n, bl) < 0) return d;
    std::string s(bl.c_str(), bl.length()); return strtol(s.c_str(), 0, 10);
}

int main(int argc, char **argv)
{
    const char *conf = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf";
    if (argc != 4) { fprintf(stderr, "usage: %s <striper_pool> <soid> <cephfs_path>\n", argv[0]); return 2; }
    std::string spool = argv[1], soid = argv[2], cpath = argv[3];
    const char *MARK = "OVERWRITE-HERE!!";       /* exactly 16 bytes */

    librados::Rados cl; librados::IoCtx src;
    if (cl.init("admin") < 0 || cl.conf_read_file(conf) < 0 || cl.connect() < 0) { fprintf(stderr, "rados\n"); return 1; }
    cl.ioctx_create(spool.c_str(), src);
    std::string first = soid + ".0000000000000000";
    long os = xnum(src, first, "striper.layout.object_size", 4194304);
    long total = xnum(src, first, "striper.size", -1);
    if (total < (long) os * 2) { fprintf(stderr, "need a >=2-object file for this test\n"); return 1; }
    long woff = os + 4096;                         /* inside object index 1 */

    /* source object 1 adler32 BEFORE the write */
    std::string srcobj1 = soid + ".0000000000000001";
    ceph::bufferlist sb; src.read(srcobj1, sb, os, 0);
    unsigned long src_before = adler((const unsigned char *) sb.c_str(), sb.length());

    /* write the marker through CephFS */
    struct ceph_mount_info *cm;
    ceph_create(&cm, "admin"); ceph_conf_read_file(cm, conf); ceph_mount(cm, "/");
    int fd = ceph_open(cm, cpath.c_str(), O_RDWR, 0);
    if (fd < 0) { fprintf(stderr, "open %d\n", fd); return 1; }
    if (ceph_write(cm, fd, MARK, 16, woff) != 16) { fprintf(stderr, "write\n"); return 1; }
    ceph_fsync(cm, fd, 0);
    ceph_close(cm, fd);
    ceph_unmount(cm); ceph_release(cm);

    /* read the whole file back with a fresh client */
    struct ceph_mount_info *vm;
    ceph_create(&vm, "admin"); ceph_conf_read_file(vm, conf); ceph_mount(vm, "/");
    int vfd = ceph_open(vm, cpath.c_str(), O_RDONLY, 0);
    std::vector<char> rb(total); long got = 0; ssize_t n;
    while (got < total && (n = ceph_read(vm, vfd, rb.data() + got, total - got, got)) > 0) got += n;
    ceph_close(vm, vfd); ceph_unmount(vm); ceph_release(vm);

    /* verify: marker where written, word==offset everywhere else */
    int ok = (got == total);
    if (memcmp(rb.data() + woff, MARK, 16) != 0) { ok = 0; printf("  marker NOT found at %ld\n", woff); }
    for (long o = 0; o + 8 <= total; o += 8) {
        if (o >= woff && o < woff + 16) continue;  /* the overwritten region */
        unsigned long long v; memcpy(&v, rb.data() + o, 8);
        if (v != (unsigned long long) o) { ok = 0; printf("  corruption: word@%ld != offset\n", o); break; }
    }

    /* source object 1 adler32 AFTER — must be unchanged */
    ceph::bufferlist sa; src.read(srcobj1, sa, os, 0);
    unsigned long src_after = adler((const unsigned char *) sa.c_str(), sa.length());
    int src_intact = (src_before == src_after);

    printf("file readback: %s\n", ok ? "OK (marker applied, rest intact)" : "CORRUPT");
    printf("source object 1 adler32: before=%08lx after=%08lx -> %s\n",
           src_before, src_after, src_intact ? "UNCHANGED" : "MODIFIED!");
    printf("RESULT: %s\n", (ok && src_intact)
           ? "PASS — write promotes the stub only; data correct, source untouched"
           : "FAIL");
    src.close(); cl.shutdown();
    return (ok && src_intact) ? 0 : 1;
}
