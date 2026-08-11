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
 *   --config PATH          site profile (or $XRDCEPH_MIGRATE_CONF): flat
 *                          key = value lines supplying striper_pool/data_pool/
 *                          dest_prefix/strip/conf/client/fs_name once per site.
 *                          Precedence: explicit CLI > file > default. Give the
 *                          full 3 positionals or NONE (the file supplies them).
 *
 *   g++ -std=c++17 -D_FILE_OFFSET_BITS=64 xrdceph_striper_migrate.cpp \
 *       -lrados -lcephfs -lpthread -o xrdceph_striper_migrate
 */
#include <rados/librados.hpp>

#include "xrdceph_migrate_config.h"
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

#include "xrdceph_striper_internal.hpp"

namespace stripermig {

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
unsigned long adler32_buf(const unsigned char *d, size_t n, unsigned long seed)
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

static int
parse_cli_value_option(const std::string &a, int *i, int argc, char **argv)
{
    if (a == "--list"   && *i + 1 < argc) { g.list = argv[++(*i)]; return 1; }
    if (a == "--strip"  && *i + 1 < argc) { g.strip = argv[++(*i)]; return 1; }
    if (a == "--threads" && *i + 1 < argc) { g.threads = atoi(argv[++(*i)]); return 1; }
    if (a == "--conf"   && *i + 1 < argc) { g.conf = argv[++(*i)]; return 1; }
    if (a == "--config" && *i + 1 < argc) { g.config = argv[++(*i)]; return 1; }
    if (a == "--sample-mb" && *i + 1 < argc) { g.sample_mb = atol(argv[++(*i)]); return 1; }
    return 0;
}

static int
parse_cli_mode_option(const std::string &a, int *i, int argc, char **argv)
{
    if (a != "--mode") { return 0; }
    if (*i + 1 >= argc) { fprintf(stderr, "--mode must be redirect|copy\n"); return -1; }
    std::string m = argv[++(*i)];
    if (m == "redirect") { g.mode = MODE_REDIRECT; return 1; }
    if (m == "copy") { g.mode = MODE_COPY; return 1; }
    fprintf(stderr, "--mode must be redirect|copy\n");
    return -1;
}

static int
parse_cli_flag_option(const std::string &a)
{
    if (a == "--rollback") { g.rollback = true; return 1; }
    if (a == "--finalize") { g.finalize = true; return 1; }
    if (a == "--verify") { g.verify = true; return 1; }
    if (a == "--delete-source") { g.del = true; return 1; }
    if (a == "--force") { g.force = true; return 1; }
    if (a == "--dry-run") { g.dry = true; return 1; }
    if (a == "--progress") { g.progress = true; return 1; }
    return 0;
}

static int
parse_cli_args(int argc, char **argv, std::vector<std::string> *pos)
{
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        int mode_rc;
        if (parse_cli_value_option(a, &i, argc, argv)) { continue; }
        mode_rc = parse_cli_mode_option(a, &i, argc, argv);
        if (mode_rc < 0) { return 2; }
        if (mode_rc > 0) { continue; }
        if (parse_cli_flag_option(a)) { continue; }
        if (a == "--help") { fprintf(stderr, "see header for usage\n"); return 2; }
        if (a.rfind("--", 0) == 0) { fprintf(stderr, "unknown option %s\n", a.c_str()); return 2; }
        pos->push_back(a);
    }
    return 0;
}

static int
resolve_required_config(const std::vector<std::string> &pos, const char *prog,
                        const xrdceph_migrate_cfg &cfg)
{
    if (pos.size() != 3 && pos.size() != 0) {
        fprintf(stderr, "usage: %s <striper_pool> <cephfs_data_pool> <dest_prefix> [opts]\n"
                "       (give all three positionals, or none with --config)\n", prog);
        return 2;
    }
    if (pos.size() == 3) { g.spool = pos[0]; g.dpool = pos[1]; g.dest = pos[2]; }
    g.spool  = xrdceph_migrate_cfg_resolve(g.spool,  cfg, "striper_pool");
    g.dpool  = xrdceph_migrate_cfg_resolve(g.dpool,  cfg, "data_pool");
    g.dest   = xrdceph_migrate_cfg_resolve(g.dest,   cfg, "dest_prefix");
    g.strip  = xrdceph_migrate_cfg_resolve(g.strip,  cfg, "strip");
    g.client = xrdceph_migrate_cfg_resolve("", cfg, "client", "admin");
    g.fsname = xrdceph_migrate_cfg_resolve("", cfg, "fs_name");
    for (auto req : { std::make_pair("striper_pool", &g.spool),
                      std::make_pair("data_pool",    &g.dpool),
                      std::make_pair("dest_prefix",  &g.dest) }) {
        if (req.second->empty()) {
            fprintf(stderr, "missing %s: pass positionals or set it in --config\n",
                    req.first);
            return 2;
        }
    }
    if (g.conf.empty()) { g.conf = xrdceph_migrate_cfg_resolve("", cfg, "conf"); }
    if (g.conf.empty()) { g.conf = getenv("CEPH_CONF") ? getenv("CEPH_CONF") : "/etc/ceph/ceph.conf"; }
    return 0;
}

static int
resolve_config(const std::vector<std::string> &pos, const char *prog)
{
    if (g.config.empty() && getenv("XRDCEPH_MIGRATE_CONF") != NULL) {
        g.config = getenv("XRDCEPH_MIGRATE_CONF");
    }
    xrdceph_migrate_cfg cfg;
    if (!g.config.empty() && !xrdceph_migrate_cfg_load(g.config, &cfg)) {
        return 2;
    }
    int rc = resolve_required_config(pos, prog, cfg);
    if (rc != 0) { return rc; }
    if (g.threads < 1) { g.threads = 1; }
    if (g.sample_mb < 1) { g.sample_mb = 1; }
    if (g.del && (g.mode == MODE_REDIRECT || g.rollback)) {
        fprintf(stderr, "--delete-source is invalid with --mode redirect / --rollback "
                "(it would destroy the source data the redirects reference)\n");
        return 2;
    }
    return 0;
}

static int
init_cluster_and_fs()
{
    double t_connect = now_s();
    if (g_cluster.init(g.client.c_str()) < 0 || g_cluster.conf_read_file(g.conf.c_str()) < 0
        || g_cluster.connect() < 0) { fprintf(stderr, "rados connect\n"); return 1; }
    if (g_cluster.ioctx_create(g.spool.c_str(), g_src) < 0
        || g_cluster.ioctx_create(g.dpool.c_str(), g_dst) < 0) { fprintf(stderr, "ioctx\n"); return 1; }
    if (ceph_create(&g_cm, g.client.c_str()) < 0 || ceph_conf_read_file(g_cm, g.conf.c_str()) < 0) {
        fprintf(stderr, "cephfs init\n"); return 1;
    }
    if (!g.fsname.empty() && ceph_select_filesystem(g_cm, g.fsname.c_str()) < 0) {
        fprintf(stderr, "cephfs select filesystem '%s'\n", g.fsname.c_str()); return 1;
    }
    if (ceph_mount(g_cm, "/") < 0) { fprintf(stderr, "cephfs mount\n"); return 1; }
    g_startup_s = now_s() - t_connect;   /* fixed cost a real run pays too */
    return 0;
}

static void
run_worker_pool(const std::vector<std::string> &work)
{
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
}

/* Warn about out-of-scope RADOS pool snapshots on the source pool. */
static void
warn_pool_snapshots()
{
    std::vector<librados::snap_t> snaps;
    if (g_src.snap_list(&snaps) == 0 && !snaps.empty()) {
        fprintf(stderr, "WARN: striper pool '%s' has %zu RADOS pool snapshot(s) "
                "— these are NOT migrated (out of scope)\n", g.spool.c_str(), snaps.size());
    }
}

/* Build the source-pool index once (O(N)) and report the timing. */
static void
index_source_pool()
{
    double bi0 = now_s();
    build_source_index();
    fprintf(stderr, "indexed %zu source file(s) in %.2fs (one pass)\n",
            g_src_index.size(), now_s() - bi0);
}

/* Arm the periodic progress line: on with --progress or a TTY, off during dry-run. */
static void
setup_progress(long total)
{
    prog_on    = !g.dry && (g.progress || isatty(fileno(stderr)));
    prog_total = total;
    prog_t0    = now_s();
    prog_last  = prog_t0;
}

} /* namespace stripermig */

using namespace stripermig;

int
main(int argc, char **argv)
{
    std::vector<std::string> pos;
    int rc = parse_cli_args(argc, argv, &pos);
    if (rc != 0) { return rc; }
    /* site profile: explicit CLI > config file > built-in default; full
     * positional arity or NONE (a partial mix is ambiguous and refused). */
    rc = resolve_config(pos, argv[0]);
    if (rc != 0) { return rc; }

    rc = init_cluster_and_fs();
    if (rc != 0) { return rc; }

    /* The XrdCeph striper source has no hardlinks/symlinks/snapshots in its object
     * model, but RADOS POOL SNAPSHOTS are an out-of-scope Ceph component: they live
     * on the pool, not in the striper layout, and are NOT migrated. Flag them. */
    warn_pool_snapshots();

    std::vector<std::string> work = build_list();

    /* Build the source-pool index ONCE (O(N)); every per-file op then does an
     * O(1) lookup instead of the former per-file full-pool rescan (O(N^2)).
     * Rollback needs it too — detach names its stubs from the source index. */
    index_source_pool();

    fprintf(stderr, "xrdceph_striper_migrate: %zu file(s) to consider"
            " (%s, mode=%s, %d worker(s), dest %s%s%s%s)\n", work.size(),
            g.rollback ? "ROLLBACK" : (g.finalize ? "FINALIZE" : "migrate"),
            g.mode == MODE_REDIRECT ? "redirect(zero-move)" : "copy",
            g.threads, g.dest.c_str(),
            g.dry ? ", DRY-RUN" : "", g.verify ? ", verify" : "",
            g.del ? ", delete-source" : "");

    setup_progress((long) work.size());

    run_worker_pool(work);

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
