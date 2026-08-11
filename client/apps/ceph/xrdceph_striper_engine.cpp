/*
 * xrdceph_striper_engine.cpp — the per-file engine: migrate_one (namespace
 * entry + data-object mapping + xattr carry + verify), rollback_one and
 * finalize_one.  Split verbatim from xrdceph_striper_migrate.cpp (phase-103);
 * see that file's header comment for the tool's contract.
 */
#include "xrdceph_striper_internal.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <map>

namespace stripermig {


/* Read the striper layout xattrs off the header object; false if not a set. */
static bool read_striper_layout(const std::string &first, StriperLayout *l)
{
    l->os    = xattr_num(first, "striper.layout.object_size", -1);
    l->su    = xattr_num(first, "striper.layout.stripe_unit", l->os);
    l->sc    = xattr_num(first, "striper.layout.stripe_count", 1);
    l->total = xattr_num(first, "striper.size", -1);
    return l->os > 0 && l->total >= 0;
}

/* --dry-run accounting for one file: record it in the estimator inventory. */
static void dry_account(const std::string &soid, const std::string &cpath,
                        const StriperLayout &l)
{
    logline("DRY  " + soid + " -> " + cpath + " (" + std::to_string(l.total) +
            " bytes, os=" + std::to_string(l.os) + " su=" + std::to_string(l.su) +
            " sc=" + std::to_string(l.sc) + ")");
    /* feed the wall-clock estimator: exact bytes + the data-object count this
     * file contributes (aggregate object payload is object_size regardless of
     * stripe interleave, so ceil(size/object_size) holds for any geometry;
     * an empty file still owns its .0000000000000000 header object). */
    dry_files++;
    dry_bytes += l.total;
    dry_objects += (l.total > 0) ? (l.total + l.os - 1) / l.os : 1;
    { long prev = dry_max_bytes.load();
      while (l.total > prev && !dry_max_bytes.compare_exchange_weak(prev, l.total)) {} }
}

/* MDS: create the namespace entry with a matching layout; returns the new inode
 * (via *ino) or MIG_FAIL. */
static Result create_namespace_entry(const std::string &soid, const std::string &cpath,
                                     const StriperLayout &l, unsigned long long *ino)
{
    mkparents(cpath);
    int fd = ceph_open(g_cm, cpath.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) { logline("FAIL " + soid + ": ceph_open " + std::to_string(fd)); n_fail++; return MIG_FAIL; }
    auto setlay = [&](const char *a, long v) {
        char val[32]; snprintf(val, sizeof(val), "%ld", v);
        ceph_fsetxattr(g_cm, fd, a, val, strlen(val), 0);
    };
    setlay("ceph.file.layout.object_size", l.os);
    setlay("ceph.file.layout.stripe_unit", l.su);
    setlay("ceph.file.layout.stripe_count", l.sc);
    ceph_close(g_cm, fd);

    struct ceph_statx stx;
    if (ceph_statx(g_cm, cpath.c_str(), &stx, CEPH_STATX_INO, 0) != 0) {
        logline("FAIL " + soid + ": statx"); n_fail++; return MIG_FAIL;
    }
    *ino = (unsigned long long) stx.stx_ino;
    return MIG_OK;
}

/* Map every data object of this soid into the CephFS object name — REDIRECT
 * (zero-move stub) or COPY (server-side copy_from). Returns the object count via
 * *nrekey or MIG_FAIL. */
static Result map_data_objects(const std::string &soid, unsigned long long ino,
                               int *nrekey)
{
    *nrekey = 0;
    auto sit = g_src_index.find(soid);
    if (sit == g_src_index.end()) { return MIG_OK; }
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
        (*nrekey)++;
    }
    return MIG_OK;
}

/* Carry user.* xattrs (checksums etc.) onto the CephFS file; returns the carried
 * user.XrdCks.adler32 value (empty if none) for the verify phase. */
static std::string carry_user_xattrs(const std::string &first, const std::string &cpath)
{
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
    return carried_cksum;
}

/* Read the migrated file back and confirm it matches (checksum if carried, else
 * size). Returns MIG_OK or MIG_FAIL. */
static Result verify_migrated(const std::string &soid, const std::string &cpath,
                              long total, const std::string &carried_cksum)
{
    if (!carried_cksum.empty()) {
        long a = cephfs_adler32(cpath, total);
        char want[16]; snprintf(want, sizeof(want), "%08lx", (unsigned long) a);
        if (a < 0 || strcasecmp(want, carried_cksum.c_str()) != 0) {
            logline("FAIL " + soid + ": checksum mismatch (got " + std::string(want) +
                    " want " + carried_cksum + ")"); n_fail++; return MIG_FAIL;
        }
        return MIG_OK;
    }
    struct ceph_statx stx;
    if (ceph_statx(g_cm, cpath.c_str(), &stx, CEPH_STATX_SIZE, 0) != 0
        || (long) stx.stx_size != total) {
        logline("FAIL " + soid + ": size verify"); n_fail++; return MIG_FAIL;
    }
    return MIG_OK;
}

/* Remove the source striper objects after a clean copy+verify (copy mode only). */
static void delete_source_objects(const std::string &soid)
{
    auto sit = g_src_index.find(soid);
    if (sit == g_src_index.end()) { return; }
    for (uint32_t idx : sit->second) {
        char name[520];
        snprintf(name, sizeof(name), "%s.%016lx", soid.c_str(), (unsigned long) idx);
        if (g_src.remove(name) == 0) { n_deleted++; }
    }
    g_src.remove(soid);   /* a bare control object, if any */
}

/* Set the size, verify, optionally delete the source, and log OK. */
static Result finish_migrate(const std::string &soid, const std::string &cpath,
                             long total, int nrekey, const std::string &carried_cksum)
{
    /* ---- MDS: set the size ---- */
    if (ceph_truncate(g_cm, cpath.c_str(), total) != 0) { logline("FAIL " + soid + ": truncate"); n_fail++; return MIG_FAIL; }

    if (g.verify && verify_migrated(soid, cpath, total, carried_cksum) != MIG_OK) { return MIG_FAIL; }

    if (g.del) { delete_source_objects(soid); }

    bytes_ok += total;
    n_ok++;
    logline("OK   " + soid + " -> " + cpath + " (" + std::to_string(total) +
            " bytes, " + std::to_string(nrekey) +
            (g.mode == MODE_REDIRECT ? " redirect" : " obj") +
            (g.verify ? ", verified" : "") + (g.del ? ", source deleted" : "") + ")");
    return MIG_OK;
}

Result migrate_one(const std::string &soid)
{
    const std::string first = soid + ".0000000000000000";
    StriperLayout l;
    if (!read_striper_layout(first, &l)) { logline("FAIL " + soid + ": not a striper object set"); return MIG_FAIL; }

    const std::string cpath = dest_path(soid);

    /* idempotency: already migrated at the right size? (INO also fetched — the
     * --force path below must detach the old file's stubs before unlinking) */
    struct ceph_statx stx;
    bool exists = (ceph_statx(g_cm, cpath.c_str(), &stx,
                              CEPH_STATX_SIZE | CEPH_STATX_INO, 0) == 0);
    if (exists && (long) stx.stx_size == l.total && !g.force) {
        logline("SKIP " + soid + " -> " + cpath + " (already migrated)");
        n_skip++; return MIG_SKIP;
    }

    if (g.dry) {
        dry_account(soid, cpath, l);
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

    unsigned long long ino;
    if (create_namespace_entry(soid, cpath, l, &ino) != MIG_OK) { return MIG_FAIL; }

    int nrekey = 0;
    if (map_data_objects(soid, ino, &nrekey) != MIG_OK) { return MIG_FAIL; }

    std::string carried_cksum = carry_user_xattrs(first, cpath);

    return finish_migrate(soid, cpath, l.total, nrekey, carried_cksum);
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

} /* namespace stripermig */
