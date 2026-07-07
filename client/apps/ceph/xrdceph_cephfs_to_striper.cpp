/*
 * xrdceph_cephfs_to_striper.cpp — REVERSE migration (Lancaster/Manchester):
 * expose an UNMOUNTED CephFS as stock-XrdCeph (libradosstriper) storage, zero-move
 * via RADOS redirects, then finalize to a self-owned XrdCeph layout and drop CephFS.
 *
 * REQUIRES THE CEPHFS TO BE QUIESCED/UNMOUNTED (MDS down or fs failed, journal
 * flushed): the namespace is walked directly from RADOS (no mount), and the MDS
 * must not be mutating objects underneath us.
 *
 * Default (ZERO-MOVE redirect): walk the CephFS namespace from the metadata pool;
 * for each file create striper-named redirect stubs <soid>.<stripe16> in the target
 * pool pointing at the CephFS data objects <ino>.<objno8> in the data pool, and
 * stamp the striper layout + size xattrs so libradosstriper (XrdCeph) can read
 * <soid> = the file path. No data is copied; CephFS data is the single copy.
 * Reversible with --rollback (detaches stubs first, like the forward tool).
 *
 * --finalize: materialize each stub into an OWNED striper object (tier_promote,
 * in-cluster), decoupling from CephFS so the whole CephFS (metadata + data pools)
 * can be torn down.
 *
 *   g++ -std=c++17 -D_FILE_OFFSET_BITS=64 xrdceph_cephfs_to_striper.cpp \
 *       src/fs/backend/rados/cephfs_layout.c src/fs/backend/rados/cephfs_denc.c \
 *       -I src/fs/backend/rados -lrados -lradosstriper -o xrdceph_cephfs_to_striper
 *
 *   xrdceph_cephfs_to_striper <meta_pool> <cephfs_data_pool> <striper_pool> [opts]
 * OPTS:
 *   --assume-quiesced   REQUIRED safety assertion (fs unmounted, journal flushed)
 *   --finalize          materialize redirects into owned striper objects
 *   --rollback          remove the striper overlay (detaches stubs; CephFS intact)
 *   --strip PFX         strip a leading path prefix when forming the soid
 *   --threads N         parallel workers for the per-file step (default 4)
 *   --verify            libradosstriper-read each soid + check user.XrdCks.adler32
 *   --delete-source     (finalize only) delete the CephFS data objects after verify
 *   --dry-run           report actions, write nothing
 *   --conf PATH         ceph.conf (default /etc/ceph/ceph.conf or $CEPH_CONF)
 *   --config PATH       site profile (or $XRDCEPH_MIGRATE_CONF): flat
 *                       key = value lines supplying meta_pool/data_pool/
 *                       striper_pool/strip/conf/client once per site.
 *                       Precedence: explicit CLI > file > default. Give the
 *                       full 3 positionals or NONE (the file supplies them).
 */
#include <rados/librados.hpp>
#include <radosstriper/libradosstriper.h>

#include "xrdceph_migrate_config.h"
extern "C" {
#include "cephfs_layout.h"
}

#include <atomic>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

#define CEPHFS_ROOT_INO 1ull

struct Opts {
    std::string meta, cdata, spool, conf, strip;
    std::string config;                 /* --config site profile path            */
    std::string client = "admin";       /* ceph client id (config key `client`)  */
    int  threads = 4;
    bool quiesced = false, finalize = false, rollback = false;
    bool verify = false, del = false, dry = false, report_only = false;
};
Opts g;
librados::Rados g_cl;
librados::IoCtx g_meta, g_cdata, g_sp;

/* a file discovered by the namespace walk */
struct FileEnt {
    std::string soid;       /* logical path (the XrdCeph object id)          */
    uint64_t    ino;
    uint32_t    object_size, stripe_unit, stripe_count;
    uint64_t    size;
    std::string cksum;      /* user.XrdCks.adler32 (carried), or empty       */
};

std::atomic<long> n_ok{0}, n_skip{0}, n_fail{0}, n_bytes{0};
std::mutex log_mu;
void logline(const std::string &s){ std::lock_guard<std::mutex> l(log_mu); fputs(s.c_str(),stdout); fputc('\n',stdout); }

unsigned long adler(const unsigned char*d,size_t n){ unsigned long a=1,b=0; while(n){size_t k=n<5552?n:5552;n-=k;while(k--){a+=*d++;b+=a;}a%=65521;b%=65521;} return (b<<16)|a; }

/* ---- pass 1: map every CephFS data object: ino -> sorted object indices ---- */
std::unordered_map<uint64_t, std::vector<unsigned long>> g_objs;
void
index_data_pool()
{
    for (auto it = g_cdata.nobjects_begin(); it != g_cdata.nobjects_end(); ++it) {
        std::string name = it->get_oid();              /* "<ino_hex>.<objno_hex8>" */
        size_t dot = name.find('.');
        if (dot == std::string::npos) { continue; }
        uint64_t ino = strtoull(name.substr(0,dot).c_str(), nullptr, 16);
        unsigned long objno = strtoul(name.substr(dot+1).c_str(), nullptr, 16);
        g_objs[ino].push_back(objno);
    }
}

/* ---- pass 2: walk the CephFS namespace from RADOS (cephfs_layout) ----
 * Besides collecting the migratable regular files, the walk CLASSIFIES and REPORTS
 * every CephFS component this tool does not (or cannot safely) handle, so an
 * operator sees exactly what will and will not migrate before committing. */
std::vector<FileEnt> g_files;

struct Unhandled {
    long files = 0;             /* plain regular files queued for migration       */
    long dirs = 0;
    long hardlink_files = 0;    /* primary regular files with nlink>1 (UNVERIFIED)*/
    long hardlink_aliases = 0;  /* remote dentries — extra names (NOT migrated)   */
    long symlinks = 0;          /* skipped (no data objects)                      */
    long special = 0;           /* fifo/socket/device — skipped (no data)         */
    long otherpool = 0;         /* file data in a non-target data pool — skipped  */
    long snap_dentries = 0;     /* non-_head dir entries => snapshots present      */
    long frag_trunc = 0;        /* directory fragtree exceeded decoder cap         */
    long xattr_trunc = 0;       /* inode xattr set exceeded decoder cap            */
} g_un;
int64_t g_data_pool_id = -1;
uint64_t g_snaptable_last_snap = 0;   /* >=2 => CephFS snapshots have been created */
int g_warn_budget = 400;

/* Decode the SnapServer table (mds_snaptable) just enough to read `last_snap`: an
 * MDSTable persists as [version: u64][ENCODE_START frame][last_snap: u64 ...]. A
 * last_snap >= 2 means at least one CephFS snapshot has been created (snapid 1 is
 * reserved) — i.e. .snap data may exist that this tool does NOT migrate. */
void check_snaptable()
{
    ceph::bufferlist bl;
    if (g_meta.read("mds_snaptable", bl, 1u<<20, 0) <= 0) { return; }
    cephfs_denc_t d; cephfs_denc_init(&d, bl.c_str(), bl.length());
    cephfs_denc_skip(&d, 8);                       /* MDSTable version (u64) */
    cephfs_denc_frame_t f; cephfs_denc_start(&d, &f);
    uint64_t last = cephfs_denc_u64(&d);
    if (cephfs_denc_ok(&d)) { g_snaptable_last_snap = last; }
}
void warn(const std::string &s){ if (g_warn_budget-- > 0) logline(s);
    else if (g_warn_budget == -1) logline("  ... (further per-item warnings suppressed; see final summary)"); }

/* a dir-omap key not ending in "_head" whose last '_'-segment is hex is a
 * snapshotted dentry (CephFS keys are "<name>_<snapid>") => snapshots exist. */
static bool is_snap_dentry(const std::string &key)
{
    size_t us = key.rfind('_');
    if (us == std::string::npos || us + 1 >= key.size()) { return false; }
    if (key.compare(us+1, std::string::npos, "head") == 0) { return false; }
    for (size_t i = us+1; i < key.size(); i++) { if (!isxdigit((unsigned char)key[i])) return false; }
    return true;
}

void
walk(uint64_t dirino, const uint32_t *frags, uint32_t nfrags, const std::string &path)
{
    for (uint32_t f = 0; f < nfrags; f++) {
        char oid[64]; snprintf(oid,sizeof(oid),"%llx.%08x",(unsigned long long)dirino,frags[f]);
        std::string start; bool more = true;
        while (more) {
            std::map<std::string,ceph::bufferlist> kv;
            if (g_meta.omap_get_vals2(oid, start, 1024, &kv, &more) < 0) { break; }
            for (auto &e : kv) {
                start = e.first;
                const std::string &key = e.first;
                if (key.size() < 6 || key.compare(key.size()-5,5,"_head") != 0) {
                    if (is_snap_dentry(key)) { g_un.snap_dentries++; }   /* snapshot present */
                    continue;
                }
                std::string name = key.substr(0, key.size()-5);
                std::string child = path + "/" + name;
                cephfs_dentry_t dn;
                if (cephfs_decode_dentry(e.second.c_str(), e.second.length(), &dn) != 0) {
                    warn("WARN undecodable dentry, skipped: " + child); continue;
                }

                if (dn.kind == CEPHFS_DENTRY_REMOTE) {              /* hardlink alias */
                    g_un.hardlink_aliases++;
                    warn("HARDLINK-ALIAS (UNVERIFIED, NOT migrated): " + child +
                         " -> ino 0x" + std::to_string(dn.remote_ino));
                    continue;
                }
                /* PRIMARY */
                uint32_t typ = dn.inode.mode & CEPHFS_S_IFMT;
                if (cephfs_mode_is_dir(dn.inode.mode)) {
                    g_un.dirs++;
                    if (dn.frags_truncated) { g_un.frag_trunc++;
                        warn("WARN directory fragtree truncated (listing may be partial): " + child); }
                    uint32_t nf = dn.nfrags ? dn.nfrags : 1;
                    walk(dn.inode.ino, dn.frag_enc, nf, child);
                    continue;
                }
                if (cephfs_mode_is_link(dn.inode.mode)) {
                    g_un.symlinks++;
                    warn("SYMLINK (skipped — XrdCeph has no symlinks): " + child);
                    continue;
                }
                if (!cephfs_mode_is_reg(dn.inode.mode)) {
                    g_un.special++;
                    char mb[16]; snprintf(mb,sizeof(mb),"0%o",(unsigned)typ);
                    warn(std::string("SPECIAL FILE (type ")+mb+
                         ", skipped — no data objects): " + child);
                    continue;
                }
                /* regular file */
                if (g_data_pool_id >= 0 && dn.inode.layout.pool_id != g_data_pool_id) {
                    g_un.otherpool++;
                    warn("OTHER-POOL file (skipped — data in pool id " +
                         std::to_string(dn.inode.layout.pool_id) + ", not the target data pool): " + child);
                    continue;
                }
                if (dn.xattrs_truncated) { g_un.xattr_trunc++;
                    warn("WARN inode xattr set truncated (some xattrs not carried): " + child); }
                if (dn.inode.nlink > 1) {
                    g_un.hardlink_files++;
                    warn("HARDLINKED FILE nlink=" + std::to_string(dn.inode.nlink) +
                         " (UNVERIFIED: primary path migrates, the other " +
                         std::to_string(dn.inode.nlink-1) + " name(s) will be ABSENT in XrdCeph): " + child);
                }
                FileEnt fe;
                fe.soid = child.substr(1);             /* drop leading '/' */
                fe.ino = dn.inode.ino;
                fe.object_size = dn.inode.layout.object_size;
                fe.stripe_unit = dn.inode.layout.stripe_unit;
                fe.stripe_count = dn.inode.layout.stripe_count;
                fe.size = dn.inode.size;
                for (uint32_t x = 0; x < dn.nxattrs; x++) {
                    if (dn.xattrs[x].name_len == 19
                        && memcmp(dn.xattrs[x].name,"user.XrdCks.adler32",19)==0) {
                        fe.cksum.assign(dn.xattrs[x].val, dn.xattrs[x].val_len);
                    }
                }
                if (!g.strip.empty() && fe.soid.compare(0,g.strip.size(),g.strip)==0)
                    fe.soid = fe.soid.substr(g.strip.size());
                g_files.push_back(fe);
                g_un.files++;
            }
        }
    }
}

/* print the classification summary of what will / will not migrate. */
void
report_unhandled()
{
    fprintf(stderr,
      "\n==== CephFS namespace classification ====\n"
      "  regular files to migrate : %ld\n"
      "  directories              : %ld\n"
      "  -- NOT handled / flagged --\n"
      "  hardlinked files         : %ld  (UNVERIFIED — primary path migrates; alias names dropped)\n"
      "  hardlink alias dentries  : %ld  (skipped — XrdCeph has no hardlinks)\n"
      "  symlinks                 : %ld  (skipped — no data objects)\n"
      "  special files (dev/fifo) : %ld  (skipped — no data objects)\n"
      "  files in other data pools: %ld  (skipped — data not in the target pool)\n"
      "  snapshotted dir entries  : %ld  (CoW-diverged; SNAPSHOT DATA IS NOT MIGRATED)\n"
      "  SnapServer last_snap     : %llu %s\n"
      "  truncated fragtrees      : %ld\n"
      "  truncated xattr sets     : %ld\n"
      "  NOTE: RADOS pool snapshots, RBD/RGW pools, additional CephFS file systems,\n"
      "        and CephFS snapshots (.snap) are OUT OF SCOPE for this tool.\n"
      "=========================================\n\n",
      g_un.files, g_un.dirs, g_un.hardlink_files, g_un.hardlink_aliases,
      g_un.symlinks, g_un.special, g_un.otherpool, g_un.snap_dentries,
      (unsigned long long)g_snaptable_last_snap,
      g_snaptable_last_snap>=2 ? "(SNAPSHOTS HAVE BEEN CREATED — .snap data NOT migrated)" : "(no snapshots)",
      g_un.frag_trunc, g_un.xattr_trunc);
}

/* ---- striper xattr stamp ---- */
void stamp(const std::string &first, const FileEnt &fe)
{
    auto sx=[&](const char*k,long v){ char b[32]; int l=snprintf(b,sizeof(b),"%ld",v); ceph::bufferlist bl; bl.append(b,l); g_sp.setxattr(first,k,bl); };
    sx("striper.layout.object_size", fe.object_size);
    sx("striper.layout.stripe_unit", fe.stripe_unit);
    sx("striper.layout.stripe_count", fe.stripe_count);
    sx("striper.size", (long)fe.size);
    if (!fe.cksum.empty()) { ceph::bufferlist bl; bl.append(fe.cksum); g_sp.setxattr(first,"user.XrdCks.adler32",bl); }
}

/* verify via libradosstriper read + adler32 (if a checksum was carried) */
int verify_striper(const FileEnt &fe)
{
    rados_t rc; rados_ioctx_t io; rados_striper_t st;
    if (rados_create(&rc,g.client.c_str())<0||rados_conf_read_file(rc,g.conf.c_str())<0||rados_connect(rc)<0) return -1;
    rados_ioctx_create(rc,g.spool.c_str(),&io); rados_striper_create(io,&st);
    std::vector<char> b(fe.size?fe.size:1);
    int got = rados_striper_read(st, fe.soid.c_str(), b.data(), fe.size, 0);
    int ok = (got==(int)fe.size);
    if (ok && !fe.cksum.empty()) {
        char want[16]; snprintf(want,sizeof(want),"%08lx",adler((const unsigned char*)b.data(),got));
        ok = (strcasecmp(want, fe.cksum.c_str())==0);
    }
    rados_striper_destroy(st); rados_ioctx_destroy(io); rados_shutdown(rc);
    return ok?0:-1;
}

enum R { OK, SKIP, FAIL };

R process(const FileEnt &fe)
{
    auto objs = g_objs.find(fe.ino);
    if (objs == g_objs.end()) { logline("FAIL "+fe.soid+": no data objects for ino"); n_fail++; return FAIL; }
    std::string first = fe.soid + ".0000000000000000";

    if (g.rollback) {
        if (g.dry) { logline("DRY  rollback "+fe.soid); n_skip++; return SKIP; }
        for (unsigned long idx : objs->second) {
            char s[1100]; snprintf(s,sizeof(s),"%s.%016lx",fe.soid.c_str(),idx);
            librados::ObjectWriteOperation um; um.unset_manifest(); g_sp.operate(s,&um);  /* detach */
            g_sp.remove(s);
        }
        logline("ROLLBACK "+fe.soid+" striper overlay removed (CephFS data intact)");
        n_ok++; return OK;
    }

    /* idempotency (redirect mode only — finalize intentionally re-touches the
     * already-stamped soid): skip if the striper soid is already stamped at size. */
    if (!g.finalize) {
        ceph::bufferlist bl;
        if (g_sp.getxattr(first,"striper.size",bl) >= 0 && bl.length()>0) {
            std::string s(bl.c_str(),bl.length());
            if (strtoul(s.c_str(),0,10)==fe.size) { logline("SKIP "+fe.soid+" (already present)"); n_skip++; return SKIP; }
        }
    }

    if (g.dry) {
        logline(std::string("DRY  ")+(g.finalize?"finalize ":"redirect ")+fe.soid+
                " ("+std::to_string(fe.size)+" bytes, "+std::to_string(objs->second.size())+" obj)");
        n_skip++; return SKIP;
    }

    for (unsigned long idx : objs->second) {
        char src[64]; snprintf(src,sizeof(src),"%llx.%08lx",(unsigned long long)fe.ino,idx);
        char dst[1100]; snprintf(dst,sizeof(dst),"%s.%016lx",fe.soid.c_str(),idx);
        if (g.finalize) {
            /* materialize an existing redirect stub into an owned object */
            { librados::ObjectWriteOperation pr; pr.tier_promote();
              if (g_sp.operate(dst,&pr)<0){ logline("FAIL "+fe.soid+": tier_promote"); n_fail++; return FAIL; } }
            { librados::ObjectWriteOperation um; um.unset_manifest(); g_sp.operate(dst,&um); }
        } else {
            /* zero-move: redirect the striper name at the CephFS data object */
            uint64_t psz=0; time_t pmt=0;
            if (g_cdata.stat(src,&psz,&pmt)<0){ logline("FAIL "+fe.soid+": stat "+src); n_fail++; return FAIL; }
            uint64_t ver=g_cdata.get_last_version();
            { librados::ObjectWriteOperation cr; cr.create(false); g_sp.operate(dst,&cr); }
            librados::ObjectWriteOperation rd; rd.set_redirect(src, g_cdata, ver, 0);
            if (g_sp.operate(dst,&rd)<0){ logline("FAIL "+fe.soid+": set_redirect"); n_fail++; return FAIL; }
        }
    }
    stamp(first, fe);

    if (g.verify && verify_striper(fe)!=0) { logline("FAIL "+fe.soid+": verify"); n_fail++; return FAIL; }

    if (g.finalize && g.del) {                          /* drop the CephFS data objects */
        for (unsigned long idx : objs->second) {
            char src[64]; snprintf(src,sizeof(src),"%llx.%08lx",(unsigned long long)fe.ino,idx);
            g_cdata.remove(src);
        }
    }
    n_bytes += fe.size; n_ok++;
    logline(std::string("OK   ")+(g.finalize?"finalize ":"redirect ")+fe.soid+
            " ("+std::to_string(fe.size)+" bytes, "+std::to_string(objs->second.size())+" obj"+
            (g.verify?", verified":"")+(g.finalize&&g.del?", cephfs data deleted":"")+")");
    return OK;
}

} /* namespace */

int
main(int argc, char **argv)
{
    std::vector<std::string> pos;
    for (int i=1;i<argc;i++){ std::string a=argv[i];
        if      (a=="--strip"  && i+1<argc) g.strip=argv[++i];
        else if (a=="--threads"&& i+1<argc) g.threads=atoi(argv[++i]);
        else if (a=="--conf"   && i+1<argc) g.conf=argv[++i];
        else if (a=="--config" && i+1<argc) g.config=argv[++i];
        else if (a=="--assume-quiesced") g.quiesced=true;
        else if (a=="--finalize") g.finalize=true;
        else if (a=="--rollback") g.rollback=true;
        else if (a=="--verify")   g.verify=true;
        else if (a=="--delete-source") g.del=true;
        else if (a=="--dry-run")  g.dry=true;
        else if (a=="--report-only") g.report_only=true;
        else if (a.rfind("--",0)==0){ fprintf(stderr,"unknown option %s\n",a.c_str()); return 2; }
        else pos.push_back(a);
    }
    /* site profile: explicit CLI > config file > default; full positional
     * arity or NONE (a partial mix is ambiguous and refused). */
    if (g.config.empty() && getenv("XRDCEPH_MIGRATE_CONF") != NULL) {
        g.config = getenv("XRDCEPH_MIGRATE_CONF");
    }
    xrdceph_migrate_cfg cfg;
    if (!g.config.empty() && !xrdceph_migrate_cfg_load(g.config, &cfg)) { return 2; }
    if (pos.size()!=3 && pos.size()!=0){
        fprintf(stderr,"usage: %s <meta_pool> <cephfs_data_pool> <striper_pool> [opts]\n"
                "       (give all three positionals, or none with --config)\n",argv[0]);
        return 2;
    }
    if (pos.size()==3){ g.meta=pos[0]; g.cdata=pos[1]; g.spool=pos[2]; }
    g.meta   = xrdceph_migrate_cfg_resolve(g.meta,  cfg, "meta_pool");
    g.cdata  = xrdceph_migrate_cfg_resolve(g.cdata, cfg, "data_pool");
    g.spool  = xrdceph_migrate_cfg_resolve(g.spool, cfg, "striper_pool");
    g.strip  = xrdceph_migrate_cfg_resolve(g.strip, cfg, "strip");
    g.client = xrdceph_migrate_cfg_resolve("", cfg, "client", "admin");
    for (auto req : { std::make_pair("meta_pool", &g.meta),
                      std::make_pair("data_pool", &g.cdata),
                      std::make_pair("striper_pool", &g.spool) }) {
        if (req.second->empty()) {
            fprintf(stderr, "missing %s: pass positionals or set it in --config\n", req.first);
            return 2;
        }
    }
    if (g.conf.empty()) g.conf = xrdceph_migrate_cfg_resolve("", cfg, "conf");
    if (g.conf.empty()) g.conf=getenv("CEPH_CONF")?getenv("CEPH_CONF"):"/etc/ceph/ceph.conf";
    if (g.threads<1) g.threads=1;
    if (!g.quiesced){ fprintf(stderr,"refusing to run: pass --assume-quiesced (CephFS MUST be unmounted / fs failed, journal flushed)\n"); return 2; }
    if (g.del && !g.finalize){ fprintf(stderr,"--delete-source is only valid with --finalize\n"); return 2; }

    if (g_cl.init(g.client.c_str())<0||g_cl.conf_read_file(g.conf.c_str())<0||g_cl.connect()<0){ fprintf(stderr,"rados connect\n"); return 1; }
    g_cl.ioctx_create(g.meta.c_str(),g_meta);
    g_cl.ioctx_create(g.cdata.c_str(),g_cdata);
    g_cl.ioctx_create(g.spool.c_str(),g_sp);
    g_data_pool_id = g_cdata.get_id();              /* to flag files in other pools */

    /* warn about RADOS pool-level snapshots — not a CephFS namespace object, so the
     * walk can't see them; they are not migrated. */
    { std::vector<librados::snap_t> snaps;
      if (g_cdata.snap_list(&snaps)==0 && !snaps.empty())
          fprintf(stderr,"WARN: data pool '%s' has %zu RADOS pool snapshot(s) — NOT migrated\n",
                  g.cdata.c_str(), snaps.size()); }

    check_snaptable();
    fprintf(stderr,"indexing CephFS data pool...\n"); index_data_pool();
    fprintf(stderr,"walking CephFS namespace...\n");
    { uint32_t root_frag=0; walk(CEPHFS_ROOT_INO,&root_frag,1,""); }
    report_unhandled();
    if (g.report_only) {
        fprintf(stderr,"--report-only: inventory complete, nothing migrated.\n");
        g_meta.close(); g_cdata.close(); g_sp.close(); g_cl.shutdown();
        return 0;
    }
    fprintf(stderr,"xrdceph_cephfs_to_striper: %zu file(s) (%s, %d worker(s)%s%s)\n",
            g_files.size(), g.rollback?"ROLLBACK":(g.finalize?"FINALIZE":"redirect(zero-move)"),
            g.threads, g.dry?", DRY-RUN":"", g.verify?", verify":"");

    std::queue<FileEnt> q; for (auto&f:g_files) q.push(f); std::mutex qm;
    auto worker=[&](){ for(;;){ FileEnt fe; { std::lock_guard<std::mutex> l(qm); if(q.empty())return; fe=q.front(); q.pop(); } process(fe); } };
    std::vector<std::thread> pool; for(int i=0;i<g.threads;i++) pool.emplace_back(worker);
    for(auto&t:pool) t.join();

    g_meta.close(); g_cdata.close(); g_sp.close(); g_cl.shutdown();
    fprintf(stderr,"done: %ld ok, %ld skipped, %ld failed, %ld bytes\n", n_ok.load(),n_skip.load(),n_fail.load(),n_bytes.load());
    return n_fail.load()==0?0:1;
}
