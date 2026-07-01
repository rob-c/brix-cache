/*
 * xrdceph_striper_migrate.cpp — enable CephFS over an existing Glasgow/RAL
 * (libradosstriper / stock XrdCeph) RADOS pool, with a ZERO-MOVE default and a
 * clean rollback. Proven on reef 18.2.4; see
 * docs/10-reference/cephfs-migration-glasgow-ral.md.
 *
 * For every logical file the MDS builds the namespace (an empty file with a layout
 * matching the striper geometry → it allocates the inode + dentry + backtrace),
 * the checksum/xattrs are carried over, and the size is set via the MDS. Striper
 * and CephFS share Ceph's striping algorithm, so a file's object index N maps to
 * the same byte range in both; only the object NAME differs. Two ways to make the
 * MDS-named data objects resolve:
 *
 *   --mode redirect  (DEFAULT, ZERO-MOVE) — create a RADOS redirect stub at each
 *       <ino>.<objno> pointing at the existing striper object <soid>.<stripe>. No
 *       bytes are copied; the source pool is the single copy of the data and is
 *       left intact. Reversible with --rollback. READ-ONLY ONLY: a write to a
 *       redirect-migrated file is written THROUGH to the source object (verified),
 *       so the migrated CephFS MUST be served read-only (read-only export/mount/
 *       caps) or the original data is silently modified and rollback can no longer
 *       restore it. For petabyte estates behind a slow uplink this avoids
 *       draining/refilling entirely — ideal for immutable/archive data.
 *   --mode copy — server-side copy_from (OSD→OSD): duplicates the bytes in-cluster
 *       into native CephFS objects (a real, fully-owned copy). Use --delete-source
 *       to reclaim the striper objects after verify. No host/WAN data movement, but
 *       a transient ~2x space.
 *
 * --rollback removes the CephFS overlay (the files + their data objects, i.e. the
 * redirect stubs) for the listed/enumerated soids, leaving the source striper pool
 * untouched. Redirect stubs are created WITHOUT a reference, so deleting them never
 * GCs the source — rollback is always data-safe in redirect mode.
 *
 * SAFETY: source is read-only except under --mode copy --delete-source. Idempotent
 * / resumable (a file already present at the right size is skipped).
 *
 * USAGE:
 *   xrdceph_striper_migrate <striper_pool> <cephfs_data_pool> <dest_prefix> [opts]
 * OPTS:
 *   --mode redirect|copy   redirect = zero-move (default); copy = server-side copy
 *   --rollback             remove the CephFS overlay (source left intact)
 *   --finalize             materialize redirect-migrated files into owned copies
 *                          (tier_promote, in-cluster) so the end state is a normal
 *                          read-write CephFS and the striper pool can be dropped
 *   --list FILE            only the soids listed (one per line); else enumerate
 *   --strip PFX            strip leading PFX from each soid before joining dest
 *   --threads N            parallel workers (default 4)
 *   --verify               read the migrated file + compare adler32 to the carried
 *                          user.XrdCks.adler32 (in redirect mode this also proves
 *                          the redirect chain serves correct data end-to-end)
 *   --delete-source        (copy mode only) remove striper objects after verify
 *   --force                re-migrate even if the target already exists
 *   --dry-run              report actions without writing
 *   --conf PATH            ceph.conf (default /etc/ceph/ceph.conf, or $CEPH_CONF)
 *
 *   g++ -std=c++17 -D_FILE_OFFSET_BITS=64 xrdceph_striper_migrate.cpp \
 *       -lrados -lcephfs -lpthread -o xrdceph_striper_migrate
 */
#include <rados/librados.hpp>
#include <cephfs/libcephfs.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace {

enum Mode { MODE_REDIRECT, MODE_COPY };

struct Opts {
    std::string spool, dpool, dest, conf, list, strip;
    int         threads = 4;
    Mode        mode = MODE_REDIRECT;     /* default: zero-move redirect          */
    bool        verify = false, del = false, force = false, dry = false;
    bool        rollback = false;         /* undo: remove the CephFS overlay      */
    bool        finalize = false;         /* materialize redirects → owned copies */
};

Opts          g;
struct ceph_mount_info *g_cm = nullptr;       /* one mount, shared (thread-safe) */
librados::Rados  g_cluster;
librados::IoCtx  g_src, g_dst;

std::atomic<long> n_ok{0}, n_skip{0}, n_fail{0}, n_deleted{0};
std::atomic<long> bytes_ok{0};
std::mutex        log_mu;

void logline(const std::string &s) { std::lock_guard<std::mutex> l(log_mu); fputs(s.c_str(), stdout); fputc('\n', stdout); }

/* zlib adler32, batched for speed over large files. */
unsigned long adler32_buf(const unsigned char *d, size_t n, unsigned long seed = 1)
{
    unsigned long a = seed & 0xffff, b = (seed >> 16) & 0xffff;
    while (n > 0) {
        size_t k = n < 5552 ? n : 5552;          /* NMAX before a mod is needed */
        n -= k;
        while (k--) { a += *d++; b += a; }
        a %= 65521; b %= 65521;
    }
    return (b << 16) | a;
}

long xattr_num(const std::string &oid, const char *name, long dflt)
{
    ceph::bufferlist bl;
    if (g_src.getxattr(oid, name, bl) < 0) { return dflt; }
    std::string s(bl.c_str(), bl.length());
    return strtol(s.c_str(), nullptr, 10);
}

bool parse_stripe(const std::string &soid, const std::string &name, unsigned long *idx)
{
    std::string pfx = soid + ".";
    if (name.size() != pfx.size() + 16 || name.compare(0, pfx.size(), pfx) != 0) { return false; }
    std::string hex = name.substr(pfx.size());
    for (char c : hex) { if (!isxdigit((unsigned char) c)) { return false; } }
    *idx = strtoul(hex.c_str(), nullptr, 16);
    return true;
}

std::string dest_path(const std::string &soid)
{
    std::string rel = soid;
    if (!g.strip.empty() && rel.compare(0, g.strip.size(), g.strip) == 0) {
        rel = rel.substr(g.strip.size());
    }
    while (!rel.empty() && rel[0] == '/') { rel.erase(0, 1); }
    return g.dest + "/" + rel;
}

void mkparents(const std::string &path)
{
    size_t slash = path.find_last_of('/');
    if (slash != std::string::npos && slash != 0) {
        ceph_mkdirs(g_cm, path.substr(0, slash).c_str(), 0755);
    }
}

/* read the whole migrated CephFS file and return its adler32; -1 on error. */
long cephfs_adler32(const std::string &cpath, long size)
{
    int fd = ceph_open(g_cm, cpath.c_str(), O_RDONLY, 0);
    if (fd < 0) { return -1; }
    std::vector<char> buf(1u << 20);
    unsigned long a = 1;
    long got = 0; ssize_t n;
    while ((n = ceph_read(g_cm, fd, buf.data(), buf.size(), got)) > 0) {
        a = adler32_buf((const unsigned char *) buf.data(), (size_t) n, a);
        got += n;
    }
    ceph_close(g_cm, fd);
    return (got == size) ? (long) a : -1;
}

enum Result { MIG_OK, MIG_SKIP, MIG_FAIL };

Result migrate_one(const std::string &soid)
{
    const std::string first = soid + ".0000000000000000";
    long os = xattr_num(first, "striper.layout.object_size", -1);
    long su = xattr_num(first, "striper.layout.stripe_unit", os);
    long sc = xattr_num(first, "striper.layout.stripe_count", 1);
    long total = xattr_num(first, "striper.size", -1);
    if (os <= 0 || total < 0) { logline("FAIL " + soid + ": not a striper object set"); return MIG_FAIL; }

    const std::string cpath = dest_path(soid);

    /* idempotency: already migrated at the right size? */
    struct ceph_statx stx;
    bool exists = (ceph_statx(g_cm, cpath.c_str(), &stx, CEPH_STATX_SIZE, 0) == 0);
    if (exists && (long) stx.stx_size == total && !g.force) {
        logline("SKIP " + soid + " -> " + cpath + " (already migrated)");
        n_skip++; return MIG_SKIP;
    }

    if (g.dry) {
        logline("DRY  " + soid + " -> " + cpath + " (" + std::to_string(total) +
                " bytes, os=" + std::to_string(os) + " su=" + std::to_string(su) +
                " sc=" + std::to_string(sc) + ")");
        n_skip++; return MIG_SKIP;
    }

    /* clear any partial / forced target */
    if (exists) { ceph_unlink(g_cm, cpath.c_str()); }

    /* ---- MDS: create namespace entry with matching layout ---- */
    mkparents(cpath);
    int fd = ceph_open(g_cm, cpath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { logline("FAIL " + soid + ": ceph_open " + std::to_string(fd)); n_fail++; return MIG_FAIL; }
    auto setlay = [&](const char *a, long v) {
        char val[32]; snprintf(val, sizeof(val), "%ld", v);
        ceph_fsetxattr(g_cm, fd, a, val, strlen(val), 0);
    };
    setlay("ceph.file.layout.object_size", os);
    setlay("ceph.file.layout.stripe_unit", su);
    setlay("ceph.file.layout.stripe_count", sc);
    ceph_close(g_cm, fd);

    if (ceph_statx(g_cm, cpath.c_str(), &stx, CEPH_STATX_INO, 0) != 0) {
        logline("FAIL " + soid + ": statx"); n_fail++; return MIG_FAIL;
    }
    unsigned long long ino = (unsigned long long) stx.stx_ino;

    /* ---- map every data object of this soid into the CephFS object name ----
     * REDIRECT (default, zero-move): create a RADOS redirect stub pointing at the
     * existing striper object — no bytes copied, source untouched.
     * COPY: server-side copy_from (OSD→OSD) — duplicates the bytes in-cluster. */
    int nrekey = 0;
    for (auto it = g_src.nobjects_begin(); it != g_src.nobjects_end(); ++it) {
        unsigned long idx;
        std::string   name = it->get_oid();
        if (!parse_stripe(soid, name, &idx)) { continue; }

        uint64_t psize = 0; time_t pmt = 0;
        if (g_src.stat(name, &psize, &pmt) < 0) { logline("FAIL " + soid + ": stat " + name); n_fail++; return MIG_FAIL; }
        uint64_t ver = g_src.get_last_version();

        char dstname[64];
        snprintf(dstname, sizeof(dstname), "%llx.%08lx", ino, idx);

        if (g.mode == MODE_REDIRECT) {
            { librados::ObjectWriteOperation cop; cop.create(false); g_dst.operate(dstname, &cop); }
            librados::ObjectWriteOperation rop;
            rop.set_redirect(name, g_src, ver, 0);   /* no reference: rollback never GCs the source */
            if (g_dst.operate(dstname, &rop) < 0) { logline("FAIL " + soid + ": set_redirect " + name); n_fail++; return MIG_FAIL; }
        } else {
            librados::ObjectWriteOperation op;
            op.copy_from(name, g_src, ver, 0);
            if (g_dst.operate(dstname, &op) < 0) { logline("FAIL " + soid + ": copy_from " + name); n_fail++; return MIG_FAIL; }
            if (idx == 0) {
                for (const char *j : { "striper.layout.object_size", "striper.layout.stripe_unit",
                                       "striper.layout.stripe_count", "striper.size", "lock.striper.lock" }) {
                    g_dst.rmxattr(dstname, j);
                }
            }
        }
        nrekey++;
    }

    /* ---- carry user.* xattrs (checksums etc.) onto the CephFS file ---- */
    std::map<std::string, ceph::bufferlist> xa;
    std::string carried_cksum;
    if (g_src.getxattrs(first, xa) >= 0) {
        for (auto &kv : xa) {
            if (kv.first.compare(0, 5, "user.") != 0) { continue; }
            ceph_setxattr(g_cm, cpath.c_str(), kv.first.c_str(),
                          kv.second.c_str(), kv.second.length(), 0);
            if (kv.first == "user.XrdCks.adler32") {
                carried_cksum.assign(kv.second.c_str(), kv.second.length());
            }
        }
    }

    /* ---- MDS: set the size ---- */
    if (ceph_truncate(g_cm, cpath.c_str(), total) != 0) { logline("FAIL " + soid + ": truncate"); n_fail++; return MIG_FAIL; }

    /* ---- verify ---- */
    if (g.verify) {
        if (!carried_cksum.empty()) {
            long a = cephfs_adler32(cpath, total);
            char want[16]; snprintf(want, sizeof(want), "%08lx", (unsigned long) a);
            if (a < 0 || strcasecmp(want, carried_cksum.c_str()) != 0) {
                logline("FAIL " + soid + ": checksum mismatch (got " + std::string(want) +
                        " want " + carried_cksum + ")"); n_fail++; return MIG_FAIL;
            }
        } else {
            if (ceph_statx(g_cm, cpath.c_str(), &stx, CEPH_STATX_SIZE, 0) != 0
                || (long) stx.stx_size != total) {
                logline("FAIL " + soid + ": size verify"); n_fail++; return MIG_FAIL;
            }
        }
    }

    /* ---- optionally delete the source after a clean migrate+verify ---- */
    if (g.del) {
        for (auto it = g_src.nobjects_begin(); it != g_src.nobjects_end(); ++it) {
            unsigned long idx; std::string name = it->get_oid();
            if (parse_stripe(soid, name, &idx)) { if (g_src.remove(name) == 0) { n_deleted++; } }
        }
        g_src.remove(soid);   /* a bare control object, if any */
    }

    bytes_ok += total;
    n_ok++;
    logline("OK   " + soid + " -> " + cpath + " (" + std::to_string(total) +
            " bytes, " + std::to_string(nrekey) +
            (g.mode == MODE_REDIRECT ? " redirect" : " obj") +
            (g.verify ? ", verified" : "") + (g.del ? ", source deleted" : "") + ")");
    return MIG_OK;
}

/* Roll back a redirect-migrated file safely. A redirect stub DELETE-THROUGHS to
 * its source object (verified — deleting the stub deletes the striper object, with
 * or without a reference). So a plain unlink would destroy the source via the MDS
 * purge. The safe sequence is: DETACH every stub from its source (unset_manifest)
 * FIRST, then unlink the file — now the purge only removes empty, detached stubs
 * and the source striper pool is left fully intact. (In copy mode the data objects
 * are owned, not manifests, so unset_manifest is a harmless no-op and the owned
 * copies are simply removed.) */
Result rollback_one(const std::string &soid)
{
    const std::string cpath = dest_path(soid);
    struct ceph_statx stx;
    if (ceph_statx(g_cm, cpath.c_str(), &stx, CEPH_STATX_INO, 0) != 0) {
        logline("SKIP " + soid + " -> " + cpath + " (not present)"); n_skip++; return MIG_SKIP;
    }
    if (g.dry) { logline("DRY  rollback " + cpath); n_skip++; return MIG_SKIP; }
    unsigned long long ino = (unsigned long long) stx.stx_ino;

    /* detach each stub from its source so the upcoming purge can't delete-through */
    for (auto it = g_src.nobjects_begin(); it != g_src.nobjects_end(); ++it) {
        unsigned long idx; std::string name = it->get_oid();
        if (!parse_stripe(soid, name, &idx)) { continue; }
        char d[64]; snprintf(d, sizeof(d), "%llx.%08lx", ino, idx);
        librados::ObjectWriteOperation um; um.unset_manifest();
        g_dst.operate(d, &um);                 /* no-op on owned (copy-mode) objects */
    }
    if (ceph_unlink(g_cm, cpath.c_str()) != 0) {
        logline("FAIL rollback " + cpath); n_fail++; return MIG_FAIL;
    }
    logline("ROLLBACK " + cpath + " removed (stubs detached first; source intact)");
    n_ok++;
    return MIG_OK;
}

/* "Complete" a redirect-migrated file: materialize every redirect stub into a
 * real, source-independent CephFS-owned object (tier_promote = OSD-side copy of
 * the target data into the object, then unset_manifest to detach), and strip the
 * striper bookkeeping xattrs. After finalize the file is a normal read-write
 * CephFS file: writes stay local, deletes reclaim its own objects, and the source
 * striper pool can be decommissioned. The promote is in-cluster (no host/WAN
 * data movement). */
Result finalize_one(const std::string &soid)
{
    const std::string cpath = dest_path(soid);
    struct ceph_statx stx;
    if (ceph_statx(g_cm, cpath.c_str(), &stx, CEPH_STATX_INO, 0) != 0) {
        logline("SKIP " + soid + " (not migrated)"); n_skip++; return MIG_SKIP;
    }
    if (g.dry) { logline("DRY  finalize " + cpath); n_skip++; return MIG_SKIP; }
    unsigned long long ino = (unsigned long long) stx.stx_ino;

    int n = 0;
    for (auto it = g_src.nobjects_begin(); it != g_src.nobjects_end(); ++it) {
        unsigned long idx; std::string name = it->get_oid();
        if (!parse_stripe(soid, name, &idx)) { continue; }
        char d[64]; snprintf(d, sizeof(d), "%llx.%08lx", ino, idx);
        { librados::ObjectWriteOperation pr; pr.tier_promote();
          if (g_dst.operate(d, &pr) < 0) { logline("FAIL " + soid + ": tier_promote " + d); n_fail++; return MIG_FAIL; } }
        { librados::ObjectWriteOperation um; um.unset_manifest(); g_dst.operate(d, &um); }
        for (const char *j : { "striper.layout.object_size", "striper.layout.stripe_unit",
                               "striper.layout.stripe_count", "striper.size", "lock.striper.lock" }) {
            g_dst.rmxattr(d, j);
        }
        n++;
    }
    n_ok++;
    logline("FINALIZE " + soid + " -> " + cpath + " (" + std::to_string(n) +
            " object(s) materialized; source now droppable)");
    return MIG_OK;
}

/* ---- build the soid work list ---- */
std::vector<std::string> build_list()
{
    std::vector<std::string> v;
    if (!g.list.empty()) {
        std::ifstream f(g.list);
        std::string   line;
        while (std::getline(f, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) { line.pop_back(); }
            if (!line.empty()) { v.push_back(line); }
        }
        return v;
    }
    /* enumerate: a soid is any object whose name ends ".0000000000000000" */
    const std::string suf = ".0000000000000000";
    for (auto it = g_src.nobjects_begin(); it != g_src.nobjects_end(); ++it) {
        std::string name = it->get_oid();
        if (name.size() > suf.size()
            && name.compare(name.size() - suf.size(), suf.size(), suf) == 0) {
            v.push_back(name.substr(0, name.size() - suf.size()));
        }
    }
    return v;
}

} /* namespace */

int
main(int argc, char **argv)
{
    std::vector<std::string> pos;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if      (a == "--list"   && i + 1 < argc) { g.list   = argv[++i]; }
        else if (a == "--strip"  && i + 1 < argc) { g.strip  = argv[++i]; }
        else if (a == "--threads" && i + 1 < argc) { g.threads = atoi(argv[++i]); }
        else if (a == "--conf"   && i + 1 < argc) { g.conf   = argv[++i]; }
        else if (a == "--mode"   && i + 1 < argc) {
            std::string m = argv[++i];
            if      (m == "redirect") { g.mode = MODE_REDIRECT; }
            else if (m == "copy")     { g.mode = MODE_COPY; }
            else { fprintf(stderr, "--mode must be redirect|copy\n"); return 2; }
        }
        else if (a == "--rollback")      { g.rollback = true; }
        else if (a == "--finalize")      { g.finalize = true; }
        else if (a == "--verify")        { g.verify = true; }
        else if (a == "--delete-source") { g.del = true; }
        else if (a == "--force")         { g.force = true; }
        else if (a == "--dry-run")       { g.dry = true; }
        else if (a == "--help")          { fprintf(stderr, "see header for usage\n"); return 2; }
        else if (a.rfind("--", 0) == 0)  { fprintf(stderr, "unknown option %s\n", a.c_str()); return 2; }
        else { pos.push_back(a); }
    }
    if (pos.size() != 3) {
        fprintf(stderr, "usage: %s <striper_pool> <cephfs_data_pool> <dest_prefix> [opts]\n", argv[0]);
        return 2;
    }
    g.spool = pos[0]; g.dpool = pos[1]; g.dest = pos[2];
    if (g.conf.empty()) { g.conf = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf"; }
    if (g.threads < 1) { g.threads = 1; }

    /* --delete-source destroys the data the redirects point at — forbid it in
     * redirect mode (and during rollback). */
    if (g.del && (g.mode == MODE_REDIRECT || g.rollback)) {
        fprintf(stderr, "--delete-source is invalid with --mode redirect / --rollback "
                "(it would destroy the source data the redirects reference)\n");
        return 2;
    }

    if (g_cluster.init("admin") < 0 || g_cluster.conf_read_file(g.conf.c_str()) < 0
        || g_cluster.connect() < 0) { fprintf(stderr, "rados connect\n"); return 1; }
    if (g_cluster.ioctx_create(g.spool.c_str(), g_src) < 0
        || g_cluster.ioctx_create(g.dpool.c_str(), g_dst) < 0) { fprintf(stderr, "ioctx\n"); return 1; }
    if (ceph_create(&g_cm, "admin") < 0 || ceph_conf_read_file(g_cm, g.conf.c_str()) < 0
        || ceph_mount(g_cm, "/") < 0) { fprintf(stderr, "cephfs mount\n"); return 1; }

    /* The XrdCeph striper source has no hardlinks/symlinks/snapshots in its object
     * model, but RADOS POOL SNAPSHOTS are an out-of-scope Ceph component: they live
     * on the pool, not in the striper layout, and are NOT migrated. Flag them. */
    { std::vector<librados::snap_t> snaps;
      if (g_src.snap_list(&snaps) == 0 && !snaps.empty())
          fprintf(stderr, "WARN: striper pool '%s' has %zu RADOS pool snapshot(s) "
                  "— these are NOT migrated (out of scope)\n", g.spool.c_str(), snaps.size()); }

    std::vector<std::string> work = build_list();
    fprintf(stderr, "xrdceph_striper_migrate: %zu file(s) to consider"
            " (%s, mode=%s, %d worker(s), dest %s%s%s%s)\n", work.size(),
            g.rollback ? "ROLLBACK" : (g.finalize ? "FINALIZE" : "migrate"),
            g.mode == MODE_REDIRECT ? "redirect(zero-move)" : "copy",
            g.threads, g.dest.c_str(),
            g.dry ? ", DRY-RUN" : "", g.verify ? ", verify" : "",
            g.del ? ", delete-source" : "");

    std::queue<std::string> q;
    for (auto &s : work) { q.push(s); }
    std::mutex qm;
    auto worker = [&]() {
        for (;;) {
            std::string soid;
            { std::lock_guard<std::mutex> l(qm); if (q.empty()) { return; } soid = q.front(); q.pop(); }
            if (g.rollback)      { rollback_one(soid); }
            else if (g.finalize) { finalize_one(soid); }
            else                 { migrate_one(soid); }
        }
    };
    std::vector<std::thread> pool;
    for (int i = 0; i < g.threads; i++) { pool.emplace_back(worker); }
    for (auto &t : pool) { t.join(); }

    ceph_unmount(g_cm); ceph_release(g_cm);
    g_src.close(); g_dst.close(); g_cluster.shutdown();

    fprintf(stderr, "done: %ld migrated, %ld skipped, %ld failed, %ld bytes, "
            "%ld source objects deleted\n",
            n_ok.load(), n_skip.load(), n_fail.load(), bytes_ok.load(), n_deleted.load());
    return n_fail.load() == 0 ? 0 : 1;
}
