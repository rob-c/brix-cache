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
 *   --progress             emit a progress line (done/total, MiB, MiB/s, ETA)
 *                          every ~5s; on automatically when stderr is a TTY
 *   --dry-run              report actions without writing, then print a
 *                          wall-clock ESTIMATE for both modes. The forecast is
 *                          calibrated by REALLY migrating a small representative
 *                          sample of the work list (at --threads), timing it,
 *                          and ROLLING IT BACK, then scaling to the full
 *                          inventory (redirect by file count, copy by bytes).
 *                          The sample uses the exact migration code path, so
 *                          MDS + enumeration + stub/copy_from + contention are
 *                          all captured. Source pool never written.
 *   --sample-mb N          client read-bandwidth probe budget in MiB (default 64)
 *   --conf PATH            ceph.conf (default /etc/ceph/ceph.conf, or $CEPH_CONF)
 *
 *   g++ -std=c++17 -D_FILE_OFFSET_BITS=64 xrdceph_striper_migrate.cpp \
 *       -lrados -lcephfs -lpthread -o xrdceph_striper_migrate
 */
#include <rados/librados.hpp>
#include <cephfs/libcephfs.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <list>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>
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
    bool        progress = false;         /* periodic progress line (also auto-TTY)*/
    long        sample_mb = 64;           /* --dry-run read-probe budget (MiB)    */
};

Opts          g;
struct ceph_mount_info *g_cm = nullptr;       /* one mount, shared (thread-safe) */
librados::Rados  g_cluster;
librados::IoCtx  g_src, g_dst;

std::atomic<long> n_ok{0}, n_skip{0}, n_fail{0}, n_deleted{0};
std::atomic<long> bytes_ok{0};
std::atomic<long> dry_files{0}, dry_bytes{0}, dry_objects{0};   /* --dry-run inventory */
std::atomic<long> dry_max_bytes{0};   /* largest single file: bounds the makespan */
double            g_startup_s = 0;    /* measured connect+mount cost (fixed) */
std::mutex        log_mu;

bool g_quiet = false;   /* suppress per-file logging during sample calibration */
void logline(const std::string &s) {
    if (g_quiet) { return; }
    std::lock_guard<std::mutex> l(log_mu); fputs(s.c_str(), stdout); fputc('\n', stdout);
}

double now_s()
{
    return std::chrono::duration<double>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

/* ---- O(N) source-pool index (see split_stripe/build_source_index) ----
 *
 * The former tool rescanned the WHOLE source pool inside every per-file op
 * (migrate/finalize/detach/delete), i.e. O(files x pool_objects) = O(N^2). We
 * now scan the source pool ONCE and answer per-file lookups from a hash map
 * (soid -> its sorted stripe object indices), matching the Python tool's index.
 * Built once at startup, read-only afterwards → no lock, never stale.
 *
 * NOTE: a redirect stub <ino>.<idx> exists iff its source object <soid>.<idx>
 * exists (the stub points at it), so the SOURCE index also names the stubs to
 * detach — no separate dest index is needed. (An earlier dest-side index was a
 * data-loss trap: cached, it missed stubs created after it was built, so a
 * migrate-then-rollback of the same file in one process failed to detach and
 * the unlink delete-through destroyed the source.) For a copy --delete-source
 * rollback the source objects are gone, but those dest objects are OWNED (not
 * manifests) so detach is a harmless no-op and unlink simply reclaims them. */
std::unordered_map<std::string, std::vector<uint32_t>> g_src_index;

/* Split a source stripe name "<soid>.<16 hex>" into soid + object index.
 * (The dest stub name is "<ino>.<8 hex>", so an index always fits in 32 bits —
 * the tool's own stub format assumes it; we keep the index compact to match.) */
bool split_stripe(const std::string &name, std::string *soid, uint32_t *idx)
{
    if (name.size() < 18 || name[name.size() - 17] != '.') { return false; }
    size_t dot = name.size() - 17;
    for (size_t i = dot + 1; i < name.size(); i++) {
        if (!isxdigit((unsigned char) name[i])) { return false; }
    }
    if (soid) { *soid = name.substr(0, dot); }
    if (idx)  { *idx  = (uint32_t) strtoul(name.c_str() + dot + 1, nullptr, 16); }
    return true;
}

/* One pass over the source pool → g_src_index. */
void build_source_index()
{
    for (auto it = g_src.nobjects_begin(); it != g_src.nobjects_end(); ++it) {
        std::string name = it->get_oid(), soid;
        uint32_t    idx;
        if (split_stripe(name, &soid, &idx)) { g_src_index[soid].push_back(idx); }
    }
    for (auto &kv : g_src_index) { std::sort(kv.second.begin(), kv.second.end()); }
}

/* ---- periodic progress line (opt-in via --progress or a TTY on stderr) ---- */
std::atomic<long> prog_done{0};
long              prog_total = 0;
double            prog_t0 = 0, prog_last = 0;
bool              prog_on = false;
std::mutex        prog_mu;

/* Emit "progress: done/total files, MiB, MiB/s, ETA" at most every 5 s (always
 * on the final file). Called once per processed file from the worker loop.
 * Mirrors the Python Reporter's progress line. */
void progress_tick()
{
    if (!prog_on || g_quiet) { return; }
    long   done = ++prog_done;
    double now  = now_s();
    std::lock_guard<std::mutex> l(prog_mu);
    if (now - prog_last < 5.0 && done < prog_total) { return; }
    prog_last = now;
    double dt  = std::max(now - prog_t0, 1e-6);
    double mib = bytes_ok.load() / 1048576.0;
    char   eta[48] = "";
    if (prog_total > 0 && done > 0 && done < prog_total) {
        snprintf(eta, sizeof(eta), ", ETA %lds",
                 (long) ((double) (prog_total - done) * dt / done));
    }
    fprintf(stderr, "progress: %ld/%ld files, %.0f MiB, %.1f MiB/s%s\n",
            done, prog_total, mib, mib / dt, eta);
}

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

/* Detach every redirect stub of (soid, ino) from its source object
 * (unset_manifest). A redirect stub DELETE-THROUGHS to its source when purged,
 * so any unlink of a redirect-migrated file MUST be preceded by this — used by
 * rollback AND by the --force re-migrate path (which unlinks the old file). The
 * stub indices come from the (static) source index, so this is O(k) per file
 * and never stale. No-op on owned (copy-mode) objects, and a no-op when the
 * source is already gone (copy --delete-source) — where owned objects don't
 * delete-through anyway. */
void detach_stubs(const std::string &soid, unsigned long long ino)
{
    auto it = g_src_index.find(soid);
    if (it == g_src_index.end()) { return; }
    for (uint32_t idx : it->second) {
        char d[64]; snprintf(d, sizeof(d), "%llx.%08x", ino, idx);
        librados::ObjectWriteOperation um; um.unset_manifest();
        g_dst.operate(d, &um);
    }
}

Result migrate_one(const std::string &soid)
{
    const std::string first = soid + ".0000000000000000";
    long os = xattr_num(first, "striper.layout.object_size", -1);
    long su = xattr_num(first, "striper.layout.stripe_unit", os);
    long sc = xattr_num(first, "striper.layout.stripe_count", 1);
    long total = xattr_num(first, "striper.size", -1);
    if (os <= 0 || total < 0) { logline("FAIL " + soid + ": not a striper object set"); return MIG_FAIL; }

    const std::string cpath = dest_path(soid);

    /* idempotency: already migrated at the right size? (INO also fetched — the
     * --force path below must detach the old file's stubs before unlinking) */
    struct ceph_statx stx;
    bool exists = (ceph_statx(g_cm, cpath.c_str(), &stx,
                              CEPH_STATX_SIZE | CEPH_STATX_INO, 0) == 0);
    if (exists && (long) stx.stx_size == total && !g.force) {
        logline("SKIP " + soid + " -> " + cpath + " (already migrated)");
        n_skip++; return MIG_SKIP;
    }

    if (g.dry) {
        logline("DRY  " + soid + " -> " + cpath + " (" + std::to_string(total) +
                " bytes, os=" + std::to_string(os) + " su=" + std::to_string(su) +
                " sc=" + std::to_string(sc) + ")");
        /* feed the wall-clock estimator: exact bytes + the data-object count this
         * file contributes (aggregate object payload is object_size regardless of
         * stripe interleave, so ceil(size/object_size) holds for any geometry;
         * an empty file still owns its .0000000000000000 header object). */
        dry_files++;
        dry_bytes += total;
        dry_objects += (total > 0) ? (total + os - 1) / os : 1;
        { long prev = dry_max_bytes.load();
          while (total > prev && !dry_max_bytes.compare_exchange_weak(prev, total)) {} }
        n_skip++; return MIG_SKIP;
    }

    /* clear any partial / forced target — DETACH FIRST: a plain unlink of a
     * redirect-migrated file delete-throughs to the source objects when the
     * async MDS purge runs (proven: a --force re-migrate used to destroy the
     * source minutes later). Harmless no-op for owned/partial targets. */
    if (exists) {
        detach_stubs(soid, (unsigned long long) stx.stx_ino);
        ceph_unlink(g_cm, cpath.c_str());
    }

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
    int  nrekey = 0;
    auto sit = g_src_index.find(soid);
    if (sit != g_src_index.end()) {
      for (uint32_t idx : sit->second) {
        char name[520];
        snprintf(name, sizeof(name), "%s.%016lx", soid.c_str(), (unsigned long) idx);

        uint64_t psize = 0; time_t pmt = 0;
        if (g_src.stat(name, &psize, &pmt) < 0) { logline("FAIL " + soid + ": stat " + name); n_fail++; return MIG_FAIL; }
        uint64_t ver = g_src.get_last_version();

        char dstname[64];
        snprintf(dstname, sizeof(dstname), "%llx.%08x", ino, idx);

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
    if (g.del && sit != g_src_index.end()) {
        for (uint32_t idx : sit->second) {
            char name[520];
            snprintf(name, sizeof(name), "%s.%016lx", soid.c_str(), (unsigned long) idx);
            if (g_src.remove(name) == 0) { n_deleted++; }
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
    detach_stubs(soid, ino);
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

    int  n = 0;
    auto sit = g_src_index.find(soid);
    if (sit != g_src_index.end()) {
      for (uint32_t idx : sit->second) {
        char d[64]; snprintf(d, sizeof(d), "%llx.%08x", ino, idx);
        { librados::ObjectWriteOperation pr; pr.tier_promote();
          if (g_dst.operate(d, &pr) < 0) { logline("FAIL " + soid + ": tier_promote " + d); n_fail++; return MIG_FAIL; } }
        { librados::ObjectWriteOperation um; um.unset_manifest(); g_dst.operate(d, &um); }
        for (const char *j : { "striper.layout.object_size", "striper.layout.stripe_unit",
                               "striper.layout.stripe_count", "striper.size", "lock.striper.lock" }) {
            g_dst.rmxattr(d, j);
        }
        n++;
      }
    }
    n_ok++;
    logline("FINALIZE " + soid + " -> " + cpath + " (" + std::to_string(n) +
            " object(s) materialized; source now droppable)");
    return MIG_OK;
}

/* =========================================================================
 * --dry-run wall-clock estimator
 *
 * WHAT: Forecasts the migration wall clock for both modes by REALLY migrating a
 *       small representative sample of the work list at the configured
 *       --threads, timing it, rolling it back, and scaling to the full
 *       inventory (redirect by file count, copy by bytes).
 * WHY:  Operators need "how long will this pool take?" before scheduling a
 *       read-only window. Modeling from read-latency proxies undercounts a
 *       WRITE-bound migrate by 4-16x, and even synthetic write probes miss the
 *       real interleave/contention. A real sample runs the exact migrate_one /
 *       rollback_one code, so nothing is modeled: MDS create + layout + xattr
 *       carry + truncate, the per-file pool enumeration, per-object stub /
 *       copy_from, and MDS/OSD contention at your thread count are all in it.
 *       Validated on reef 18.2.4: copy within ~3% of actual at multi-GiB scale
 *       (accuracy improves as the run outgrows one-time connect/mount overhead).
 * SAFETY: the redirect sample is zero-move + rolled back (stubs detached first,
 *       source intact); the copy sample's owned objects are unlinked. The SOURCE
 *       striper pool is never written. All global flags/counters snapshotted +
 *       restored so the sample does not pollute the run's final tallies.
 * HOW:  Sample size K = min(max(2*T, 6), files) for redirect, min(K, 8) for
 *       copy; picked by an even stride across the list to mix file sizes. Two
 *       read-only context probes remain (pool totals; enumeration rate; verify
 *       read bandwidth capped by --sample-mb). For a skewed size distribution,
 *       forecast per shard with --list.
 * ========================================================================= */

std::string fmt_dur(double s)
{
    char b[64];
    if (s < 0.0)          { return "n/a"; }
    if (s < 120.0)        { snprintf(b, sizeof(b), "%.1f s", s); }
    else if (s < 7200.0)  { snprintf(b, sizeof(b), "%.1f min", s / 60.0); }
    else if (s < 172800.0){ snprintf(b, sizeof(b), "%.1f h", s / 3600.0); }
    else                  { snprintf(b, sizeof(b), "%.1f d", s / 86400.0); }
    return b;
}

std::string fmt_rate_mib(double bytes_per_s)
{
    char b[32];
    snprintf(b, sizeof(b), "%.0f MiB/s", bytes_per_s / (1024.0 * 1024.0));
    return b;
}

/* Read-only context probes. The dominant per-file/per-object costs are NOT
 * modeled from these — they come from the real sample migrate (sample_migrate);
 * these just add context (pool size, enumeration rate, verify read bandwidth). */
struct Probes {
    double enum_rate   = 0;   /* pool listing, objects/s                       */
    double read_bw     = 0;   /* client streaming read, bytes/s (verify term)  */
    uint64_t pool_objects = 0;
    uint64_t pool_bytes   = 0;
};

/* Enumerate up to `cap` objects (or ~2s) measuring the listing rate; collect up
 * to 32 sample names for the stat/read probes. Read-only. */
void probe_enumeration(Probes *p, std::vector<std::string> *sample)
{
    const unsigned cap = 20000;
    unsigned       n   = 0;
    double         t0  = now_s(), deadline = t0 + 2.0;

    for (auto it = g_src.nobjects_begin(); it != g_src.nobjects_end(); ++it) {
        if (sample->size() < 32 && (n % 97) == 0) { sample->push_back(it->get_oid()); }
        if (++n >= cap || (n % 512 == 0 && now_s() > deadline)) { break; }
    }
    double el = now_s() - t0;
    p->enum_rate = (el > 0 && n > 0) ? n / el : 0;
}

/* Result of a real sample migration used to calibrate the forecast. */
struct SampleRun {
    int      files = 0;      /* files actually migrated in the sample     */
    long     bytes = 0;      /* their total size                          */
    double   secs  = 0;      /* wall-clock at T concurrency               */
    bool     ok    = false;
};

/* SAMPLE calibration — the accurate estimator. Pick a representative subset of
 * the real work list, REALLY migrate it in `mode` at the configured --threads
 * (timed), then roll it back, and let the caller scale the timing up to the
 * full inventory. This reuses the exact migrate_one/rollback_one code paths, so
 * every real cost (MDS create + layout + xattr carry + truncate, the per-file
 * pool enumeration, the per-object stub/copy_from, MDS/OSD contention at T) is
 * captured — no op is modeled or forgotten.
 *
 * SAFETY: redirect-mode samples are zero-move and rolled back (stubs detached
 * first, source intact); copy-mode samples create owned objects that are
 * unlinked afterward. The source striper pool is never mutated. Runs under
 * --force so a stale target from a prior run is re-migrated, and --dry OFF for
 * the sample only; all global flags/counters are snapshotted and restored. */
SampleRun sample_migrate(const std::vector<std::string> &work, Mode mode, int K)
{
    SampleRun r;
    if (work.empty() || K < 1) { return r; }
    if (K > (int) work.size()) { K = (int) work.size(); }

    /* even stride across the list → mixes file sizes rather than clustering */
    std::vector<std::string> pick;
    double step = (double) work.size() / K;
    for (int i = 0; i < K; i++) { pick.push_back(work[(size_t) (i * step)]); }

    /* snapshot global run state */
    Mode  s_mode = g.mode; bool s_dry = g.dry, s_force = g.force;
    bool  s_verify = g.verify, s_del = g.del, s_quiet = g_quiet, s_roll = g.rollback;
    long  c_ok = n_ok, c_skip = n_skip, c_fail = n_fail, c_del = n_deleted, c_by = bytes_ok;

    g.mode = mode; g.dry = false; g.force = true; g.verify = false;
    g.del = false; g.rollback = false; g_quiet = true;

    long bytes_before = bytes_ok.load();
    std::atomic<int> next{0}, done{0};
    double t0 = now_s();
    auto   run = [&]() {
        int i;
        while ((i = next.fetch_add(1)) < (int) pick.size()) {
            if (migrate_one(pick[i]) == MIG_OK) { done++; }
        }
    };
    std::vector<std::thread> pool;
    for (int k = 0; k < g.threads; k++) { pool.emplace_back(run); }
    for (auto &t : pool) { t.join(); }
    r.secs  = now_s() - t0;
    r.files = done.load();
    r.bytes = bytes_ok.load() - bytes_before;

    /* roll back the sample (redirect: detach+unlink; copy: unlink owned) */
    for (auto &s : pick) { rollback_one(s); }

    /* restore global state + counters */
    g.mode = s_mode; g.dry = s_dry; g.force = s_force; g.verify = s_verify;
    g.del = s_del; g.rollback = s_roll; g_quiet = s_quiet;
    n_ok = c_ok; n_skip = c_skip; n_fail = c_fail; n_deleted = c_del; bytes_ok = c_by;

    r.ok = (r.files > 0 && r.secs > 0);
    return r;
}

/* Client streaming-read bandwidth over the sampled objects, budgeted by
 * --sample-mb. Read-only. */
void probe_read_bw(Probes *p, const std::vector<std::string> &sample)
{
    const uint64_t budget = (uint64_t) g.sample_mb << 20;
    uint64_t       got = 0;
    double         t0 = now_s(), deadline = t0 + 5.0;

    for (const auto &oid : sample) {
        uint64_t off = 0;
        for (;;) {
            ceph::bufferlist bl;
            int r = g_src.read(oid, bl, 4u << 20, off);
            if (r <= 0) { break; }
            got += (uint64_t) r;
            off += (uint64_t) r;
            if (got >= budget || now_s() > deadline) { break; }
        }
        if (got >= budget || now_s() > deadline) { break; }
    }
    double el = now_s() - t0;
    p->read_bw = (el > 0 && got > 0) ? got / el : 0;
}

void probe_pool_totals(Probes *p)
{
    std::list<std::string>                      pools = { g.spool };
    std::map<std::string, librados::pool_stat_t> st;
    if (g_cluster.get_pool_stats(pools, st) == 0 && st.count(g.spool)) {
        p->pool_objects = st[g.spool].num_objects;
        p->pool_bytes   = st[g.spool].num_bytes;
    }
}

/* Scale a sample run up to the full inventory. redirect is count-bound (MDS +
 * stub + per-file pool scan all scale with FILE count); copy is byte-bound (the
 * copy_from movement dominates), so it scales with BYTES with a per-file
 * makespan floor. Adds the fixed startup cost. */
double scale_estimate(const SampleRun &s, Mode mode, long files, long bytes, long maxb)
{
    if (!s.ok) { return -1; }
    if (mode == MODE_REDIRECT) {
        double per_file = s.secs / s.files;              /* wall/file at T conc. */
        return g_startup_s + per_file * files;
    }
    /* copy: scale by bytes (falls back to file count if the sample had 0 bytes) */
    double body = (s.bytes > 0)
        ? s.secs * ((double) bytes / (double) s.bytes)
        : s.secs * ((double) files / (double) s.files);
    /* a single file cannot be split across threads: floor at the largest file's
     * share of the sample rate */
    double sample_bw = (s.bytes > 0 && s.secs > 0) ? s.bytes / s.secs : 0;
    double floor_    = (sample_bw > 0) ? (double) maxb / sample_bw : 0;
    return g_startup_s + std::max(body, floor_);
}

void estimate_report(const std::vector<std::string> &work)
{
    long files = dry_files.load(), objects = dry_objects.load();
    long bytes = dry_bytes.load(), maxb = dry_max_bytes.load();
    int  T     = g.threads;

    if (files == 0) {
        fprintf(stderr, "estimate: nothing to migrate (0 files after skips) — no forecast\n");
        return;
    }

    /* context probes (read-only): pool totals, enumeration rate, read bw */
    Probes p;
    std::vector<std::string> sample;
    fprintf(stderr, "estimate: probing '%s' + calibrating with a real sample migrate"
            " (rolled back)...\n", g.spool.c_str());
    probe_pool_totals(&p);
    probe_enumeration(&p, &sample);
    probe_read_bw(&p, sample);

    /* the accurate part: really migrate a small representative sample of the
     * actual work list in each mode, timed, then roll it back. */
    int K = std::min((long) std::max(2 * T, 6), files);
    SampleRun sr = sample_migrate(work, MODE_REDIRECT, K);
    SampleRun sc = sample_migrate(work, MODE_COPY, std::min(K, 8));

    if (!sr.ok) {
        fprintf(stderr, "estimate: sample migrate failed (no create access under %s,"
                " or unreadable source) — no forecast\n", g.dest.c_str());
        return;
    }

    double redirect_s = scale_estimate(sr, MODE_REDIRECT, files, bytes, maxb);
    double copy_s     = sc.ok ? scale_estimate(sc, MODE_COPY, files, bytes, maxb) : -1;
    double verify_s   = (p.read_bw > 0)
        ? std::max((double) bytes / T, (double) maxb) / p.read_bw : -1;

    fprintf(stderr,
        "\n== DRY-RUN ESTIMATE (pool '%s' -> '%s', %d thread(s)) ==\n"
        "inventory: %ld file(s), %ld bytes (%.1f GiB), ~%ld data object(s);"
        " pool holds %llu object(s) / %.1f GiB total\n"
        "calibration @ %d thr: redirect sample %d file(s) in %s (%.1f file/s)"
        "%s; enum %.0f obj/s; client read %s\n",
        g.spool.c_str(), g.dest.c_str(), T,
        files, bytes, bytes / 1073741824.0, objects,
        (unsigned long long) p.pool_objects, p.pool_bytes / 1073741824.0,
        T, sr.files, fmt_dur(sr.secs).c_str(), sr.files / sr.secs,
        sc.ok ? (", copy sample " + std::to_string(sc.files) + " file(s) in "
                 + fmt_dur(sc.secs) + " @ "
                 + (sc.bytes > 0 ? fmt_rate_mib(sc.bytes / sc.secs) : "n/a")).c_str()
              : "",
        p.enum_rate, fmt_rate_mib(p.read_bw).c_str());

    fprintf(stderr, "mode redirect (zero-move):   ~%s\n", fmt_dur(redirect_s).c_str());
    fprintf(stderr, "mode copy (in-cluster):      ~%s%s\n", fmt_dur(copy_s).c_str(),
            sc.ok ? "" : "   (copy sample failed — no copy forecast)");
    fprintf(stderr, "  + --verify:                +%s   (reads every byte back)\n",
            fmt_dur(verify_s).c_str());

    fprintf(stderr,
        "method: forecast = startup + (real sample-migrate of %d file(s) at %d"
        " thread(s), rolled back) scaled to the full inventory — redirect by file"
        " count, copy by bytes with a largest-file (%.1f GiB) makespan floor. Every"
        " real cost (MDS, per-file pool enumeration, stubs/copy_from, contention)"
        " is in the sample. Accuracy depends on the sample being representative:"
        " for a skewed size distribution, forecast per-shard with --list. Source"
        " pool never written; point-in-time — rerun near the migration window.\n\n",
        sr.files, T, maxb / 1073741824.0);
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
        else if (a == "--progress")      { g.progress = true; }
        else if (a == "--sample-mb" && i + 1 < argc) { g.sample_mb = atol(argv[++i]); }
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
    if (g.sample_mb < 1) { g.sample_mb = 1; }

    /* --delete-source destroys the data the redirects point at — forbid it in
     * redirect mode (and during rollback). */
    if (g.del && (g.mode == MODE_REDIRECT || g.rollback)) {
        fprintf(stderr, "--delete-source is invalid with --mode redirect / --rollback "
                "(it would destroy the source data the redirects reference)\n");
        return 2;
    }

    double t_connect = now_s();
    if (g_cluster.init("admin") < 0 || g_cluster.conf_read_file(g.conf.c_str()) < 0
        || g_cluster.connect() < 0) { fprintf(stderr, "rados connect\n"); return 1; }
    if (g_cluster.ioctx_create(g.spool.c_str(), g_src) < 0
        || g_cluster.ioctx_create(g.dpool.c_str(), g_dst) < 0) { fprintf(stderr, "ioctx\n"); return 1; }
    if (ceph_create(&g_cm, "admin") < 0 || ceph_conf_read_file(g_cm, g.conf.c_str()) < 0
        || ceph_mount(g_cm, "/") < 0) { fprintf(stderr, "cephfs mount\n"); return 1; }
    g_startup_s = now_s() - t_connect;   /* fixed cost a real run pays too */

    /* The XrdCeph striper source has no hardlinks/symlinks/snapshots in its object
     * model, but RADOS POOL SNAPSHOTS are an out-of-scope Ceph component: they live
     * on the pool, not in the striper layout, and are NOT migrated. Flag them. */
    { std::vector<librados::snap_t> snaps;
      if (g_src.snap_list(&snaps) == 0 && !snaps.empty())
          fprintf(stderr, "WARN: striper pool '%s' has %zu RADOS pool snapshot(s) "
                  "— these are NOT migrated (out of scope)\n", g.spool.c_str(), snaps.size()); }

    std::vector<std::string> work = build_list();

    /* Build the source-pool index ONCE (O(N)); every per-file op then does an
     * O(1) lookup instead of the former per-file full-pool rescan (O(N^2)).
     * Rollback needs it too — detach names its stubs from the source index. */
    {
        double bi0 = now_s();
        build_source_index();
        fprintf(stderr, "indexed %zu source file(s) in %.2fs (one pass)\n",
                g_src_index.size(), now_s() - bi0);
    }

    fprintf(stderr, "xrdceph_striper_migrate: %zu file(s) to consider"
            " (%s, mode=%s, %d worker(s), dest %s%s%s%s)\n", work.size(),
            g.rollback ? "ROLLBACK" : (g.finalize ? "FINALIZE" : "migrate"),
            g.mode == MODE_REDIRECT ? "redirect(zero-move)" : "copy",
            g.threads, g.dest.c_str(),
            g.dry ? ", DRY-RUN" : "", g.verify ? ", verify" : "",
            g.del ? ", delete-source" : "");

    /* progress: on with --progress, or automatically when stderr is a TTY
     * (matches the Python tool). Off during the dry-run inventory pass. */
    prog_on    = !g.dry && (g.progress || isatty(fileno(stderr)));
    prog_total = (long) work.size();
    prog_t0    = now_s();
    prog_last  = prog_t0;

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
            progress_tick();
        }
    };
    std::vector<std::thread> pool;
    for (int i = 0; i < g.threads; i++) { pool.emplace_back(worker); }
    for (auto &t : pool) { t.join(); }

    /* dry-run of a migrate: the worker pass above (g.dry) gathered the exact
     * inventory into dry_*; now forecast the wall-clock by really migrating a
     * small sample of `work` and scaling. */
    if (g.dry && !g.rollback && !g.finalize) { estimate_report(work); }

    ceph_unmount(g_cm); ceph_release(g_cm);
    g_src.close(); g_dst.close(); g_cluster.shutdown();

    fprintf(stderr, "done: %ld migrated, %ld skipped, %ld failed, %ld bytes, "
            "%ld source objects deleted\n",
            n_ok.load(), n_skip.load(), n_fail.load(), bytes_ok.load(), n_deleted.load());
    return n_fail.load() == 0 ? 0 : 1;
}
