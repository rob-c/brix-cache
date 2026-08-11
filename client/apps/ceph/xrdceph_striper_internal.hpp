/*
 * xrdceph_striper_internal.hpp — shared contract of the striper-migrate tool,
 * split from the single 1092-line xrdceph_striper_migrate.cpp at phase-103:
 * main/CLI TU + engine TU (migrate/rollback/finalize) + estimator TU.  The
 * former anonymous namespace became `stripermig` so the TUs link; every body
 * was lifted verbatim.  Not a public header: private to apps/ceph/.
 */
#pragma once

#include <rados/librados.hpp>
#include <cephfs/libcephfs.h>

#include <atomic>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace stripermig {

enum Mode { MODE_REDIRECT, MODE_COPY };

struct Opts {
    std::string spool, dpool, dest, conf, list, strip;
    std::string config;                   /* --config site profile path           */
    std::string client = "admin";         /* ceph client id (config key `client`) */
    std::string fsname;                   /* CephFS fs name (empty = default fs)  */
    int         threads = 4;
    Mode        mode = MODE_REDIRECT;     /* default: zero-move redirect          */
    bool        verify = false, del = false, force = false, dry = false;
    bool        rollback = false;         /* undo: remove the CephFS overlay      */
    bool        finalize = false;         /* materialize redirects → owned copies */
    bool        progress = false;         /* periodic progress line (also auto-TTY)*/
    long        sample_mb = 64;           /* --dry-run read-probe budget (MiB)    */
};

enum Result { MIG_OK, MIG_SKIP, MIG_FAIL };

/* Striper geometry + total size carried on the .0 header object. */
struct StriperLayout {
    long os, su, sc, total;
};

/* ---- globals (defined in xrdceph_striper_migrate.cpp) ---- */
extern Opts g;
extern struct ceph_mount_info *g_cm;
extern librados::Rados  g_cluster;
extern librados::IoCtx  g_src, g_dst;
extern std::atomic<long> n_ok, n_skip, n_fail, n_deleted;
extern std::atomic<long> bytes_ok;
extern std::atomic<long> dry_files, dry_bytes, dry_objects, dry_max_bytes;
extern double            g_startup_s;
extern std::mutex        log_mu;
extern bool              g_quiet;
extern std::unordered_map<std::string, std::vector<uint32_t>> g_src_index;

/* ---- shared helpers (defined in xrdceph_striper_migrate.cpp) ---- */
void logline(const std::string &s);
double now_s();
unsigned long adler32_buf(const unsigned char *d, size_t n,
                          unsigned long seed = 1);
long xattr_num(const std::string &oid, const char *name, long dflt);
std::string dest_path(const std::string &soid);
void mkparents(const std::string &path);
long cephfs_adler32(const std::string &cpath, long size);
void detach_stubs(const std::string &soid, unsigned long long ino);

/* ---- engine (xrdceph_striper_engine.cpp) ---- */
Result migrate_one(const std::string &soid);
Result rollback_one(const std::string &soid);
Result finalize_one(const std::string &soid);

/* ---- --dry-run estimator (xrdceph_striper_estimate.cpp) ---- */
void estimate_report(const std::vector<std::string> &work);

} /* namespace stripermig */
