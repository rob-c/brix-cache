#ifndef BRIX_FS_BACKEND_CACHE_SD_CACHE_INTERNAL_H
#define BRIX_FS_BACKEND_CACHE_SD_CACHE_INTERNAL_H

/*
 * sd_cache_internal.h — shared internal state for the read-through cache driver.
 *
 * The per-export instance state (inst->state) is split into this header so it is
 * visible to both the vtable adapters (sd_cache.c) and the admission/policy +
 * metrics helpers (sd_cache_policy.c) without either file re-declaring it.  This
 * is a driver-private header: it is not part of the sd_cache public surface
 * (sd_cache.h).
 */

#include "fs/backend/sd.h"       /* brix_sd_instance_t */
#include "fs/backend/cache/sd_cache.h" /* brix_sd_cache_peer_t (F8 mesh)   */
#include "fs/cache/cstore.h"     /* brix_cstore_t */
#include "fs/tier/tier.h"        /* brix_cache_policy_t */

#include <limits.h>              /* PATH_MAX (sd_cache_partial_t) */

/* Per-export instance state (inst->state). */
typedef struct {
    brix_sd_instance_t  *source;         /* the tier below (stage | backend)    */
    brix_sd_instance_t  *cold;           /* phase-85 F7 OPTIONAL cold store tier
                                          * (borrowed, registry-owned); NULL =
                                          * no cold tier. A miss tries a verified
                                          * promote from here before the origin;
                                          * the evictor demotes into it.        */
    /* phase-85 F8 sibling mesh: the rendezvous ring (copies of the registry's
     * members; instances borrowed). n_peers == 0 means no mesh. A miss whose
     * ring owner is a non-self member tries one verified fill from that
     * sibling before the origin. */
    brix_sd_cache_peer_t peers[BRIX_SD_CACHE_MAX_PEERS];
    int                   n_peers;
    int                   peer_self;
    /* phase-87 G12 dynamic swarm ring: when non-NULL this immutable ring
     * REPLACES the static ring above in the fill spine. Published on the
     * event loop with a barrier, read once per fill on worker threads;
     * `volatile` keeps the compiler from caching the pointer. A published
     * ring is never freed (see brix_sd_cache_ring_swap). */
    const brix_sd_cache_ring_t *volatile dyn_ring;
    brix_cstore_t        cstore;
    brix_cache_policy_t  policy;
    ngx_log_t             *log;
    /* Background block prefetch (sd_cache_prefetch.c): detached thread-pool
     * jobs in flight for this export. Event-loop-only mutation — bumped when a
     * job posts (read_advise) and dropped in its completion callback — so no
     * atomic is needed; policy.prefetch_jobs caps it. */
    ngx_uint_t            prefetch_active;
} sd_cache_inst_state;

#define SD_CACHE_ST(inst)   ((sd_cache_inst_state *) (inst)->state)
#define SD_CACHE_SRC(inst)  (SD_CACHE_ST(inst)->source)

/* ---- cross-file entry points (phase-79 size split) ----------------------- *
 * sd_cache.c was one 1404-line file. It is split by concept into the vtable
 * adapters + lifecycle + async-offload seam (sd_cache.c), the whole-file fill
 * spine (sd_cache_fill.c), the slice/partial machinery + partial byte slots
 * (sd_cache_partial.c), and the namespace/xattr/dir/staged forwarders
 * (sd_cache_forward.c). Exactly the functions defined in one unit but called
 * from another are declared here and made non-static; nothing below is part of
 * the public surface (sd_cache.h). */

/* ---- whole-file fill spine (sd_cache_fill.c) ----------------------------- */

/* Fill `key` from the source into the cache store and record its cinfo. NGX_OK
 * (cached or stale-served), NGX_DECLINED (admission), NGX_ERROR. `cred` may be
 * NULL (service-credential path). Called by the interposed read-open miss path
 * and the async fill-key entrypoint in sd_cache.c.
 *
 * `allow_pt` opts this fill into the phase-92 store-then-evict passthrough: an
 * admission-declined object within the passthrough cap is filled anyway and the
 * call returns NGX_OK with *out_pt=1, signalling the caller to evict the key
 * once it has served the object as a transient hit. When `allow_pt` is 0 (or
 * the policy has passthrough off / the object exceeds the cap) an admission
 * decline still returns NGX_DECLINED. `out_pt` may be NULL. */
ngx_int_t sd_cache_fill(sd_cache_inst_state *st, const char *key,
    const brix_sd_cred_t *cred, int allow_pt, int *out_pt);

/* Emit the unified guard-core audit line (signal=cvmfs_tamper) for a fill whose
 * bytes failed CVMFS integrity verification. `actor` is the fill SOURCE that
 * served the bad bytes — the origin tier, or a mesh sibling (phase-85 F8) —
 * and its last-answering authority rides the ip field (the tamper actor is
 * upstream, not a client); NULL falls back to st->source. Thread-safe (fill
 * pool). Called from the verify mismatch paths in sd_cache_fill.c. */
void sd_cache_guard_tamper(sd_cache_inst_state *st,
    brix_sd_instance_t *actor, const char *key);

/* ---- CVMFS manifest/whitelist signature verify (sd_cache_manifest.c) ----- */

/* Phase-85 F1: verify a MANIFEST-class staged fill before commit when the
 * repo master public key is configured (policy.cvmfs_master_pub):
 *   .cvmfspublished — full chain: whitelist sig vs master key → whitelist not
 *   expired → manifest cert fingerprint ∈ whitelist → manifest sig vs cert
 *   (whitelist + certificate fetched through the fill's source tier);
 *   .cvmfswhitelist — signature vs master key + expiry.
 * Returns NGX_OK (verified, or key is not a signed-metadata shape / verify not
 * configured — commit proceeds); NGX_ERROR (verification definitively FAILED —
 * the caller emits signal=cvmfs_tamper, quarantines, aborts, EBADMSG); or
 * NGX_DECLINED (the chain could not be evaluated — sibling fetch / part read
 * failed; the caller fails the fill closed with EIO, NO tamper signal, so an
 * origin outage never feeds the maxretry=1 tamper jail). `pp` is the staged
 * part path. */
ngx_int_t sd_cache_verify_manifest(sd_cache_inst_state *st, const char *key,
    const char *pp);

/* ---- slice / partial caching (sd_cache_partial.c) ------------------------ */

/* Per-object partial-serve state (obj->state of a slice partial object). Lives
 * here (driver-private) so the background prefetch executor
 * (sd_cache_prefetch.c) can consult the bitmap and snapshot the key/credential
 * without re-declaring the layout partial.c owns. */
typedef struct {
    brix_sd_instance_t *source;
    brix_sd_obj_t      *src_obj;          /* lazily opened on the first miss   */
    int                   cache_fd;         /* the RW (sparse) cache object      */
    off_t                 size;
    uint32_t              block_size;
    uint32_t              mode;             /* origin perm bits recorded in cinfo */
    uint64_t              mtime;
    uint64_t              nblocks;
    uint8_t              *bitmap;           /* present blocks (in-memory mirror) */
    size_t                bitmap_len;
    /* Rolling background-prefetch frontier for THIS handle (first block not
     * yet queued by an earlier WILLNEED hint). The serve engines re-hint the
     * window off the read cursor on every sequential read; this ratchet makes
     * repeated hints over already-queued blocks a no-op, so speculation runs
     * as a continuous runway bounded by policy.prefetch_window ahead of the
     * cursor — never re-posted, never compounding. Event-loop only. */
    uint64_t              prefetch_next_blk;
    ngx_log_t            *log;
    char                  key[1024];
    char                  cache_path[PATH_MAX];   /* for cinfo record_block      */
    /* Per-user credential copies for deferred (range-fill) source opens.
     * A partial-fill block may be filled on a later pread after the request
     * context — and its brix_sd_cred_t — is gone; embedding NUL-terminated
     * copies here ensures later opens can still authenticate as the owner.
     * cred_proxy[0] == '\0' means no per-user credential (service cred). */
    char                  cred_proxy[1024];     /* x509_proxy path, or "" */
    char                  cred_key[128];        /* ucred key stem, or ""  */
    char                  cred_principal[512];  /* principal string, or "" */
} sd_cache_partial_t;

/* Build a partial-serve object for `key` (slice mode) — on-demand block fills
 * from the source. Returns the new object or NULL with *err_out set. */
brix_sd_obj_t *sd_cache_partial_open(brix_sd_instance_t *inst,
    sd_cache_inst_state *st, const char *key, const brix_sd_cred_t *cred,
    int *err_out);

/* Fetch block `blk` from the source into the cache object + mark it present.
 * Safe off the event loop (pure driver pread/pwrite + cinfo record — the same
 * doctrine as brix_sd_cache_fill_key) PROVIDED the sd_cache_partial_t is owned
 * by the calling thread (the prefetch executor opens its own). Returns 0/-1. */
int sd_cache_fill_block(sd_cache_partial_t *p, uint64_t blk);

/* Decorator byte slots, reached only for a slice partial object (wired into the
 * driver vtable in sd_cache.c). */
ssize_t   sd_cache_pread(brix_sd_obj_t *obj, void *buf, size_t len, off_t off);
ngx_int_t sd_cache_close(brix_sd_obj_t *obj);
ngx_int_t sd_cache_fstat(brix_sd_obj_t *obj, brix_sd_stat_t *out);
ngx_fd_t  sd_cache_read_sendfile_fd(brix_sd_obj_t *obj, off_t off, size_t len,
    unsigned want_zerocopy);

/* ---- background block prefetch (sd_cache_prefetch.c) --------------------- *
 * The read_advise vtable slot for a slice partial object: a WILLNEED hint
 * posts a detached thread-pool job that fills the hinted range's ABSENT blocks
 * from the source ahead of the reads (audit §4.1). EVENT-LOOP ONLY (the
 * in-flight accounting on sd_cache_inst_state is unsynchronised). Advisory:
 * always NGX_OK. */
ngx_int_t sd_cache_read_advise(brix_sd_obj_t *obj, off_t off, size_t len,
    int advice);

/* ---- namespace / xattr / dir / staged forwarders (sd_cache_forward.c) ---- *
 * Delegating vtable slots wired into the driver in sd_cache.c. */
ngx_int_t sd_cache_stat(brix_sd_instance_t *inst, const char *path,
    brix_sd_stat_t *out);
ngx_int_t sd_cache_unlink(brix_sd_instance_t *inst, const char *path,
    int is_dir);
ngx_int_t sd_cache_mkdir(brix_sd_instance_t *inst, const char *path,
    mode_t mode);
ngx_int_t sd_cache_rename(brix_sd_instance_t *inst, const char *src,
    const char *dst, int noreplace);
ngx_int_t sd_cache_server_copy(brix_sd_instance_t *inst, const char *src,
    const char *dst, off_t *bytes_out);
ngx_int_t sd_cache_setattr(brix_sd_instance_t *inst, const char *path,
    const brix_sd_setattr_t *attr);
brix_sd_dir_t *sd_cache_opendir(brix_sd_instance_t *inst, const char *path,
    int *err_out);
ngx_int_t sd_cache_readdir(brix_sd_dir_t *d, brix_sd_dirent_t *out);
ngx_int_t sd_cache_closedir(brix_sd_dir_t *d);
ssize_t   sd_cache_getxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, void *buf, size_t cap);
ssize_t   sd_cache_listxattr(brix_sd_instance_t *inst, const char *path,
    void *buf, size_t cap);
ngx_int_t sd_cache_setxattr(brix_sd_instance_t *inst, const char *path,
    const char *name, const void *val, size_t len, int flags);
ngx_int_t sd_cache_removexattr(brix_sd_instance_t *inst, const char *path,
    const char *name);
brix_sd_staged_t *sd_cache_staged_open(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, int *err_out);
brix_sd_staged_t *sd_cache_staged_open_cred(brix_sd_instance_t *inst,
    const char *final_path, mode_t mode, const brix_sd_cred_t *cred,
    int *err_out);
ssize_t   sd_cache_staged_write(brix_sd_staged_t *st, const void *buf,
    size_t len, off_t off);
ngx_int_t sd_cache_staged_commit(brix_sd_staged_t *st, int noreplace);
void      sd_cache_staged_abort(brix_sd_staged_t *st);

#endif /* BRIX_FS_BACKEND_CACHE_SD_CACHE_INTERNAL_H */
