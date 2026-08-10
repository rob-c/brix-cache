/*
 * copy_internal.h - private split contract for copy.c and its Phase-38 siblings.
 * Not a public API: include only from client/lib/.  See docs/refactor/phase-38-file-size-unix-modularity.md.
 */
#ifndef BRIX_COPY_INTERNAL_H
#define BRIX_COPY_INTERNAL_H

#include "brix.h"
#include "auth/cred/cred.h"                 
#include "fs/vfs.h"                  
#include "protocols/shared/zip.h"                  
#include "core/compat/host_format.h"  
#include "core/compat/hex.h"          
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>     
#include <errno.h>
#include <dirent.h>    
#include <sys/stat.h>  
#include <signal.h>    
#include <stdatomic.h> 
#define XRDC_COPY_CHUNK  (8u * 1024u * 1024u)
#define XRDC_CK_OK          0    
#define XRDC_CK_MISMATCH  (-1)   
#define XRDC_CK_UNVERIFIED  1    
extern volatile sig_atomic_t g_brix_copy_quit;

typedef ssize_t (*pump_src_fn)(void *ctx, uint8_t *buf, int64_t off, size_t cap,
                               brix_status *st);

typedef int (*pump_sink_fn)(void *ctx, const uint8_t *buf, int64_t off, size_t n,
                            brix_status *st);

#define XRDC_RESILIENT_FLOOR (256u * 1024u)
typedef struct {
    brix_conn  *c;
    brix_file  *f;
    int         pgrw;
    /* resilient download source only (zero for upload sink / non-resilient): */
    int         resilient;
    const char *path;        /* source/dest path, for reopen */
    const char *opaque;      /* compress opaque or NULL */
    int         max_stall_ms;
    size_t      cur_chunk;   /* adaptive read size (shrinks on loss) */
    int         posc;        /* resilient upload sink only: posc flag for reopen */
    /* Phase 94 parallel upload: when non-NULL with n>0, the upload sink spreads
     * write chunks round-robin across the primary + bound secondaries; a chunk
     * that a secondary won't take falls back to the resilient primary path, so a
     * server that does not service bound writes (old / gateway) never fails. */
    brix_streamset *ss;
    unsigned        rr_next;    /* round-robin cursor over primary+secondaries */
    unsigned        sec_writes; /* chunks actually carried by a secondary stream */
    unsigned        sec_reads;  /* download: chunks actually read on a secondary  */
} pump_remote_t;

typedef struct {
    brix_vfs_file *vf;
} pump_local_t;

#define XRDC_WEB_TIMEOUT_MS 300000   /* 5 min per-read ceiling for big files */
typedef struct { brix_conn *c; brix_file *f; brix_status *st; } zip_remote_ctx;

typedef struct { int fd; } unzip_sink_ctx;

typedef struct { int fd; uint64_t off; } zipw_local_sink;

typedef struct { brix_conn *c; brix_file *f; uint64_t off; brix_status *st; } zipw_remote_sink;


/* copy.c */
void copy_signal_handler(int sig);

/* copy_local.c */
/*
 * The invariant inputs of one resilient-open retry loop — the connection, the
 * path being opened, the compress opaque (NULL if none), and the stall
 * deadline. Shared by the Phase-38 download (copy_local.c) and upload
 * (copy_upload.c) split siblings; consumed by csctx_reopen_home / the
 * direction-specific open helpers.
 */
typedef struct {
    brix_conn  *c;
    const char *path;
    const char *opaque;      /* compress opaque or NULL */
    uint64_t    deadline_ns; /* absolute retry cutoff (brix_mono_ns scale) */
} copy_stream_ctx_t;

int make_temp_path(const char *dst, char *out, size_t outsz);
int open_download_temp(const char *dst, char *tmp, size_t tmpsz, brix_status *st);
int atomic_dest_finish(const char *tmp, const char *dest, int rc, brix_status *st);
/* resilient reopen/retry helpers (copy_local.c); shared with the Phase-38
 * upload split sibling (copy_upload.c). */
void csctx_reopen_home(brix_conn *c, brix_status *st);
int csctx_retry_gate(const brix_status *st, uint64_t deadline_ns, unsigned *attempt);

/* copy_pump.c */
int write_all(int fd, const uint8_t *buf, size_t n, brix_status *st);

/* copy.c */
int copy_stall_ms(const brix_copy_opts *o, int dflt);

/* copy_pump.c */
int pump_remote_reopen(pump_remote_t *r, brix_status *st);
ssize_t pump_src_remote(void *ctx, uint8_t *buf, int64_t off, size_t cap, brix_status *st);
int pump_sink_reopen(pump_remote_t *r, brix_status *st);
int pump_sink_remote(void *ctx, const uint8_t *buf, int64_t off, size_t n, brix_status *st);
ssize_t pump_src_local(void *ctx, uint8_t *buf, int64_t off, size_t cap, brix_status *st);
int pump_sink_local(void *ctx, const uint8_t *buf, int64_t off, size_t n, brix_status *st);
ssize_t pump_src_local_vfs(void *ctx, uint8_t *buf, int64_t off, size_t cap, brix_status *st);
int pump_sink_local_vfs(void *ctx, const uint8_t *buf, int64_t off, size_t n, brix_status *st);
int transfer_pump(pump_src_fn src, void *sctx, pump_sink_fn sink, void *kctx, int64_t expected, const brix_copy_opts *o, int64_t progress_total, brix_status *st);

/* §7.13 --xrate pacing (copy_pump.c): sleep so `moved` bytes since t0 respect
 * o->xrate_bps; fail past the 3 s grace when below o->xrate_min_bps.  cap()
 * shrinks a read so paced transfers step in ~250 ms slices. */
int    brix_pump_pace(const brix_copy_opts *o, uint64_t t0_ns, int64_t moved,
                      brix_status *st);
size_t brix_pump_pace_cap(const brix_copy_opts *o, size_t cap);

/* copy_local.c */

/*
 * WHAT: The invariant inputs of one resilient download-body stream — the
 *       caller-owned control connection, the source URL, the source stat info
 *       (its size drives the pump + progress), the transfer options, and the
 *       bound-streams set to attach after the redirect.
 * WHY:  download_stream_body previously took these five stable inputs plus the
 *       per-callsite (sink, sinkctx) pump pair as eight positional parameters,
 *       over the 5-parameter gate.  Bundling the invariants that every caller
 *       shares into one struct leaves only the varying pump pair (and the st
 *       out-param) as free arguments, keeping the extern under the gate without
 *       altering what it does.
 * HOW:  Each caller fills one of these (all pointers borrowed for the call's
 *       duration, none owned by the callee) and passes it by const pointer; the
 *       body reads c/su/si/o/ss exactly as it read the former parameters.  The
 *       (sink, sinkctx) sink and the brix_status out-param stay separate because
 *       they vary per callsite / follow the out-param convention.
 */
typedef struct {
    brix_conn            *c;   /* caller-owned control connection            */
    const brix_url       *su;  /* remote source URL (path + opaque source)   */
    const brix_statinfo  *si;  /* source stat (si->size drives pump/progress)*/
    const brix_copy_opts *o;   /* transfer options                           */
    brix_streamset       *ss;  /* bound secondary-stream set to attach       */
} download_body_ctx;

int download_stream_body(const download_body_ctx *j, pump_sink_fn sink, void *sinkctx, brix_status *st);

/* copy.c */
int resilient_setup(brix_conn *c, const brix_url *su, const brix_opts *co, brix_statinfo *si, int max_stall_ms, brix_status *st);

/*
 * WHAT: The invariant inputs of one local download — the (caller-owned) control
 *       connection, the source/destination URLs, the source stat info, the
 *       options, and the bound-streams set.
 * WHY:  copy_download runs the transfer down two branches (stdout / local file)
 *       that both thread the same six inputs into their body + cksum helpers.
 *       Bundling them into one shared struct keeps every download helper
 *       under the 5-parameter gate and makes the branch bodies a flat sequence.
 * HOW:  Populated once by copy_download after resilient_setup; passed by const
 *       pointer to download_to_stdout / download_to_local_file, which read
 *       su/du/si/o and pass c/ss through to download_stream_body.
 */
typedef struct {
    brix_conn            *c;
    const brix_url       *su;
    const brix_url       *du;
    const brix_statinfo  *si;
    const brix_copy_opts *o;
    brix_streamset       *ss;
    const brix_opts      *co;  /* connection options (cred store) — the xcp
                                * engine dials its own replica connections */
} download_job_t;


/* copy_local.c */
int copy_download(const brix_url *su, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
/* Shared with copy_local_parallel.c: fold the checksum verdict into the transfer
 * rc after a good download (local_path NULL ≡ stdout). */
int download_reconcile_cksum(const download_job_t *job, const char *local_path, brix_status *st);

/* copy_local_parallel.c — the phase-94 concurrent striped download. Returns 1
 * when it handled the transfer (verdict in *out_rc), 0 when not eligible and the
 * caller should run the serial pump. */
int copy_download_parallel(const download_job_t *job, int *out_rc, brix_status *st);
/* Shared with copy_xcp.c: commit (fsync+rename) a successful concurrent
 * download and reconcile its checksum, or abort the temp — always closes vf. */
int download_commit_or_abort(const download_job_t *job, brix_vfs_file *vf,
                             int rc, brix_status *st);

/* copy_xcp.c — the phase-100 extreme copy (multi-source block-stealing
 * download, --sources N). Same handled?/fall-through contract as
 * copy_download_parallel; runs BEFORE it in copy_download. */
int copy_download_xcp(const download_job_t *job, int *out_rc, brix_status *st);

/* copy_l2l.c — §7.17 local→local copy (file://↔local, and the '-' stdio
 * endpoints). Reuses the transfer pump; file dst is atomic temp+rename. */
int brix_copy_local_to_local(const brix_url *su, const brix_url *du,
                             const brix_copy_opts *o, brix_status *st);

/* copy_continue.c — §7.6 --continue byte-offset resume; same handled? contract.
 * Runs FIRST in copy_download (before even the destination-exists check: an
 * existing partial is the mode's input, not an error). */
int copy_download_continue(const download_job_t *job, int *out_rc,
                           brix_status *st);

/* copy_metalink.c — phase-100 metalink virtual redirector. */
int copy_is_metalink_src(const char *src, const brix_copy_opts *o);
int copy_metalink_run(const char *src, const char *dst, const brix_copy_opts *o,
                      const brix_opts *co, brix_status *st);

/* copy.c — one classified single-source dispatch (everything brix_copy does
 * AFTER the metalink branch); the mirror-failover loop re-enters here. */
int copy_dispatch_one(const char *src, const char *dst, const brix_copy_opts *o,
                      const brix_opts *co, brix_status *st);

/*
 * WHAT: The invariant inputs of one resilient upload-body stream — the source
 *       URL (its path is the local checksum source), the destination URL, the
 *       transfer options, the connection options (carry the credential store),
 *       and the known source size (total; -1 for stdin / unknown).
 * WHY:  upload_stream_body previously took these five stable inputs plus the
 *       per-callsite (src, srcctx) pump pair as eight positional parameters,
 *       over the 5-parameter gate.  Bundling the shared invariants into one
 *       struct leaves only the varying pump pair (and the st out-param) free,
 *       keeping the extern under the gate with no behaviour change.
 * HOW:  Each caller fills one of these (pointers borrowed for the call, not
 *       owned) and passes it by const pointer; the body reads su/du/o/co/total
 *       exactly as it read the former parameters.  The (src, srcctx) source and
 *       the brix_status out-param stay separate (per-callsite / out-param).
 */
typedef struct {
    const brix_url       *su;    /* source URL (su->path = local cksum source) */
    const brix_url       *du;    /* remote destination URL                     */
    const brix_copy_opts *o;     /* transfer options                           */
    const brix_opts      *co;    /* connection options (co->cred store)        */
    int64_t               total; /* known source size, -1 = stdin / unknown    */
} upload_body_ctx;

int upload_stream_body(const upload_body_ctx *j, pump_src_fn src, void *srcctx, brix_status *st);
int copy_upload(const brix_url *su, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

/* copy_remote.c */
int r2r_teardown(brix_conn *sc, brix_conn *dc, brix_file *sf, brix_file *df, int src_up, int dst_up, int sopen, int dopen, int rc, brix_status *st);
int r2r_stream_body(brix_conn *sc, brix_conn *dc, brix_file *sf, brix_file *df, const brix_statinfo *si, const brix_copy_opts *o, brix_status *st);
int copy_remote_to_remote(const brix_url *su, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int cksum_verify(brix_conn *c, const char *remote_path, const char *local_path, const char *spec, int silent, brix_status *st);
int gen_tpc_key(char *out, size_t outsz);
int tpc_teardown(brix_conn *sc, brix_conn *dc, brix_file *sf, brix_file *df, char *src_opaque, char *dst_opaque, int su_up, int du_up, int sopen, int dopen, int rc, brix_status *st);
int copy_tpc(const brix_url *su, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

/* copy.c */
int copy_one_r2l(brix_conn *c, const char *rpath, const char *lpath, int64_t expected_size, brix_status *st);
int copy_one_l2r(brix_conn *c, const char *lpath, const char *rpath, const brix_copy_opts *o, brix_status *st);

/* copy_recursive.c */

/* Per-directory state threaded through the recursive tree walkers (one frame
 * per directory level).  For the download walk rpath is the SOURCE and lpath
 * the DESTINATION; for the upload walk lpath is the SOURCE and rpath the
 * DESTINATION.  Bundling the per-directory invariants keeps every walker
 * helper (and the walkers themselves) under the 5-parameter gate. */
typedef struct {
    brix_conn            *c;      /* open control connection                 */
    const char           *rpath;  /* remote directory being walked           */
    const char           *lpath;  /* local directory being walked            */
    const char           *rel;    /* directory path relative to the copy root */
    const brix_copy_opts *o;
    brix_status          *st;
} copy_walk_ctx;

/* One recursive-copy request (both endpoints + direction + options), built by
 * the copy dispatcher for copy_recursive. */
typedef struct {
    const brix_url       *su;       /* source URL                              */
    const brix_url       *du;       /* destination URL                         */
    int                   download; /* 1 = remote tree → local, 0 = local → remote */
    const brix_copy_opts *o;
    const brix_opts      *co;
} copy_recurse_req;

/* The invariant inputs of one web_auth_headers call (endpoint, method being
 * signed, credential sources, status out), bundled so the auth-header builder
 * and its per-scheme helpers stay under the 5-parameter gate. */
typedef struct {
    const brix_weburl    *u;       /* target endpoint                        */
    const char           *method;  /* HTTP method being signed (S3 only)     */
    const brix_copy_opts *o;       /* explicit credential opts (may be NULL) */
    const brix_opts      *co;      /* carries the credential store (co->cred) */
    brix_status          *st;
} web_auth_ctx;

/* One web-download request (source endpoint, local destination, stdout flag,
 * options), built by the web-copy dispatcher for copy_web_download. */
typedef struct {
    const brix_weburl    *su;        /* web source endpoint                  */
    const brix_url       *du;        /* local destination (unused for stdout) */
    int                   to_stdout; /* 1 = stream body to stdout            */
    const brix_copy_opts *o;
    const brix_opts      *co;
} web_dl_req;

int copy_tree_download(const copy_walk_ctx *w);
int copy_tree_upload(const copy_walk_ctx *w);
/* shared recursive-walk helpers (copy_recursive.c); used across the Phase-38
 * download/upload split siblings (copy_recursive_ul.c). */
int dirent_is_dot(const char *name);
int rel_join(const char *rel, const char *name, char *out, size_t outsz);
int path_join(const char *dir, const char *name, char *out, size_t outsz);
int sync_cksum_match(brix_conn *c, const char *rpath, const char *lpath,
                     const brix_copy_opts *o);
void mirror_delete_remote(brix_conn *c, const char *rpath, const char *lpath,
                          const char *rel, const brix_copy_opts *o);
int recursive_dest_root(const char *dstdir, const char *srcpath, char *out, size_t outsz);
int copy_recursive(const copy_recurse_req *rq, brix_status *st);
int web_auth_headers(const web_auth_ctx *a, char *hdrs, size_t hdrsz);
int copy_web_download(const web_dl_req *rq, brix_status *st);

/* copy_local.c */
int copy_web_upload(const brix_url *su, const brix_weburl *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int copy_web(const char *src, const char *dst, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

/* copy_zip.c */
ssize_t zip_remote_pread(void *vctx, uint64_t off, void *buf, size_t len);
int unzip_sink_write(void *sc, const uint8_t *d, size_t l);
int copy_unzip(const brix_url *su, const char *archive_path, const char *member, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int unzip_member_from_src(const char *src, const brix_url *su, char *member, size_t member_sz, char *arch, size_t arch_sz);
int zipw_local_write(void *cx, const void *d, size_t n);
int zipw_remote_write(void *cx, const void *d, size_t n);
ssize_t zipw_local_pread(void *cx, uint64_t off, void *buf, size_t len);
const char * zip_member_basename(const char *p);
int zip_read_seed(brix_zip_pread_fn pr, void *ctx, uint64_t size, uint64_t *base, uint8_t **seed_cd, size_t *seed_len, size_t *seed_n, brix_status *st);
int zip_emit_member(brix_zip_writer *w, const char *member, int srcfd, brix_status *st);
int copy_zip_store_local(const char *member, int srcfd, const brix_url *du, int append, brix_status *st);
int copy_zip_store_remote(const char *member, int srcfd, const brix_url *du, int append, const brix_opts *co, brix_status *st);

/* copy_block.c */
int copy_remote_to_block(const char *src_url, const char *dst_url, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int copy_block_to_remote(const char *src_url, const char *dst_url, const brix_copy_opts *o, const brix_opts *co, brix_status *st);
int copy_vfs_to_vfs(const char *src_url, const char *dst_url, const brix_copy_opts *o, brix_status *st);
int copy_block(const char *src, const char *dst, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

/* copy_gsiftp.c — gsiftp:// / ftp:// single-file transfer (exactly one endpoint
 * may be a GridFTP URL; the other is local). */
int copy_gsiftp(const char *src, const char *dst, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

/* copy_zip.c */
int copy_zip_store(const brix_url *su, const brix_url *du, const brix_copy_opts *o, const brix_opts *co, brix_status *st);

#endif /* BRIX_COPY_INTERNAL_H */
