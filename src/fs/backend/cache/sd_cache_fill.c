/*
 * sd_cache_fill.c — the whole-file fill spine of the read-through cache.
 *
 * WHAT: Pulls a COMPLETE object from the wrapped source into the cache store and
 *       records its cinfo. Owns the four fill phases (acquire -> pump -> verify
 *       -> commit) and the sd_cache_fill orchestrator the interposed read-open
 *       and the async-offload entrypoint both drive.
 *
 * WHY:  Split from sd_cache.c (phase-79) to keep every cache file under the
 *       ~500-line, one-concept-per-file cap. The fill spine is the single path
 *       that populates the cache; isolating it keeps the origin-read / stale-serve
 *       / verify / cinfo-publish logic reviewable apart from the vtable adapters
 *       (sd_cache.c), the slice/partial machinery (sd_cache_partial.c), and the
 *       namespace/staged forwarders (sd_cache_forward.c).
 *
 * HOW:  cache_fill_acquire (source open + admission + staged fill-open) -> pump
 *       (origin read loop) -> verify (phase-68 cvmfs-cas) -> commit (publish +
 *       cinfo). sd_cache.c reaches sd_cache_fill (miss-serve and the async
 *       fill-key) through sd_cache_internal.h. The admission/policy +
 *       repo-metrics helpers it calls live in sd_cache_policy.c. Phase-85 F7:
 *       the same spine runs the cold-tier PROMOTE (cold store as the fill
 *       source, from_cold=1). The integrity-verify phase is split into
 *       sd_cache_fill_verify.c and the eviction-seam hot->cold copy
 *       (brix_sd_cache_demote) into sd_cache_fill_demote.c.
 */
#include "sd_cache.h"
#include "sd_cache_internal.h"    /* sd_cache_inst_state + SD_CACHE_ST/SRC */
#include "sd_cache_policy.h"      /* admission + repo-metrics (split out) */
#include "sd_cache_fill_internal.h"     /* sd_cache_fill_state_t + SD_CACHE_CHUNK
                                         * + cache_fill_verify (split out)     */
#include "protocols/cvmfs/classify.h"   /* phase-68 manifest-TTL stamping */
#include "observability/metrics/metrics.h"        /* phase-68 T16 counters */
#include "observability/metrics/metrics_macros.h"
#include "fs/cache/cstore.h"
#include "fs/cache/gcas.h"              /* phase-87 G13 post-commit publish  */
#include "fs/backend/http/sd_http.h"    /* per-upstream fill attribution     */
#include "fs/backend/xroot/sd_xroot.h"  /* brix_sd_xroot_query_checksum      */
#include "fs/path/path.h"               /* brix_sanitize_log_string          */
#include "net/guard/guard.h"            /* signal=cvmfs_tamper audit line    */
#include "core/compat/checksum.h"       /* brix_checksum_hex_name_fd         */
#include "core/fnv.h"                    /* BRIX_FNV1A64_* hash constants     */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>


/* ---- the fill spine (source -> cache store) ------------------------------- *
 * SD_CACHE_CHUNK + sd_cache_fill_state_t live in sd_cache_fill_internal.h so
 * the verify phase (sd_cache_fill_verify.c) shares the same per-attempt state. */

/* Acquire everything a fill needs: source object, stat snapshot, staged store
 * object, and the move buffer.
 *
 * WHAT: Opens the source for `key`, snapshots its stat, checks admission, and
 *       opens the staged cache-store object (which takes the fill lock — the
 *       O_EXCL + dead-owner-reclaim logic lives in the cstore layer, frozen).
 *
 * WHY:  The acquire phase concentrates all the "can this fill happen at all?"
 *       decisions so the pump/commit phases run against a fully-provisioned
 *       state and can stay linear.
 *
 * HOW:  brix_sd_open_maybe_cred so drivers with an open_cred slot use the
 *       per-user proxy. Returns NGX_OK (fs populated), NGX_DONE (stale copy
 *       served — caller reports success without filling), NGX_DECLINED
 *       (admission declined), or NGX_ERROR with errno set; every failure path
 *       releases whatever it had already acquired. */
/* Open the fill source and snapshot its stat into fs. Returns NGX_OK,
 * NGX_DONE (a stale copy may be served instead — caller reports success without
 * filling), or NGX_ERROR with errno set. */
static ngx_int_t
cache_fill_open_src(sd_cache_inst_state *st, const char *key,
    const brix_sd_cred_t *cred, sd_cache_fill_state_t *fs)
{
    brix_sd_instance_t *src = fs->src;
    int                 err = 0;

    fs->so = brix_sd_open_maybe_cred(src, key, BRIX_SD_O_READ, 0, cred, &err);
    if (fs->so == NULL) {
        /* A cold-tier or mesh-sibling miss is NOT an origin outage — never
         * stale-serve it; the orchestrator falls back to the origin fill. */
        if (!fs->from_cold && !fs->from_peer
            && sd_cache_stale_serve_ok(st, key))
        {
            return NGX_DONE;            /* bounded stale-if-error (phase-68) */
        }
        errno = err ? err : EIO;
        return NGX_ERROR;
    }
    /* Every op on the OPEN OBJECT dispatches through so->driver, NOT src->driver:
     * a decorator source (sd_stage) legitimately returns the tier-below's object
     * from a read open ("read byte-I/O bypasses the decorator"), so the object's
     * vtable can differ from the instance's — dispatching object ops through the
     * instance vtable reinterprets a foreign object state (type confusion). */
    if (fs->so->driver->pread == NULL) {
        brix_sd_obj_release(fs->so);
        errno = ENOSYS;
        return NGX_ERROR;
    }
    /* open() does not guarantee a populated snap (the posix driver fstats lazily),
     * so fstat the object for an accurate size/mtime/mode - the cinfo validity and
     * the cached file's permission bits both depend on it. */
    fs->snap = fs->so->snap;
    if (fs->so->driver->fstat != NULL) {
        (void) fs->so->driver->fstat(fs->so, &fs->snap);
    }
    return NGX_OK;
}


/* Admission for the just-opened source. NGX_OK to proceed (possibly as a
 * passthrough fill), NGX_DECLINED when the object must not be cached at all.
 *
 * phase-92 store-then-evict passthrough: a caller that opted in (fs->allow_pt —
 * the HTTP shared cache-fill plane) can still be served a remote object the
 * admission policy declined, by filling it under a separate spool cap, serving
 * the coalesced waiters through the normal cache-hit reenter, then evicting the
 * key. The gate is deliberately narrow: only a size-known source within the
 * passthrough cap qualifies, so a path-filtered object, an oversized object, or
 * a size-unknown (no Content-Length) origin still declines to the 502 slow-path.
 * fs->allow_pt is set in exactly ONE place — the shared HTTP cache-fill worker
 * — so WebDAV, S3 AND cvmfs all inherit the opt-in by routing through it; only
 * the root:// stream plane's own fill passes allow_pt = 0, leaving its decline
 * unchanged. Pinned by tests/test_cache_passthrough_planes.py. */
static ngx_int_t
cache_fill_admit_src(sd_cache_inst_state *st, const char *key,
    sd_cache_fill_state_t *fs)
{
    off_t pt_cap;

    if (sd_cache_admit(&st->policy, key, fs->snap.size)) {
        return NGX_OK;
    }
    pt_cap = sd_cache_passthrough_cap(&st->policy);
    if (fs->allow_pt && st->policy.passthrough && fs->snap.size >= 0
        && (pt_cap == 0 || fs->snap.size <= pt_cap))
    {
        fs->passthrough = 1;
        return NGX_OK;
    }
    return NGX_DECLINED;                /* too big / filtered - do not cache */
}


static ngx_int_t
cache_fill_acquire(sd_cache_inst_state *st, const char *key,
    const brix_sd_cred_t *cred, sd_cache_fill_state_t *fs)
{
    mode_t    fmode;
    ngx_int_t rc;

    if (fs->src->driver->open == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
    rc = cache_fill_open_src(st, key, cred, fs);
    if (rc != NGX_OK) {
        return rc;
    }
    /* SECURITY + correctness: the physical cache-store object is a svc-owned
     * artifact that aggregates MANY users' bytes under one tree. Per-user
     * authorization is enforced at the protocol gate (open_cache.c), and the
     * CLIENT-FACING mode is carried in the cinfo record and served by
     * sd_cache_stat() — decoupled from this physical mode. So force 0600:
     *   - owner rw is REQUIRED (XATTR meta_mode stores user.xrd.cinfo ON this
     *     object; Linux refuses user.* xattrs on a non-writable inode — a
     *     read-only 0444 source would otherwise block cinfo persistence, G3);
     *   - NO group/other bits, so a mapped low-priv uid cannot read another
     *     user's cached bytes by direct filesystem access (the source mode's
     *     0644 previously leaked here). snap.mode still reaches clients via the
     *     cinfo record (ci.mode below, served by sd_cache_stat). */
    fmode = S_IRUSR | S_IWUSR;          /* 0600 — svc-owned cache artifact */

    if (cache_fill_admit_src(st, key, fs) == NGX_DECLINED) {
        brix_sd_obj_release(fs->so);
        return NGX_DECLINED;
    }

    fs->staged = brix_cstore_fill_open(&st->cstore, key, fmode);
    if (fs->staged == NULL) {
        ngx_log_error(NGX_LOG_WARN, st->log, errno,
            "sd_cache: fill_open on the cache store failed for \"%s\" - not cached",
            key);
        brix_sd_obj_release(fs->so);
        return NGX_ERROR;
    }
    fs->buf = malloc(SD_CACHE_CHUNK);
    if (fs->buf == NULL) {
        brix_cstore_fill_abort(fs->staged);
        brix_sd_obj_release(fs->so);
        errno = ENOMEM;
        return NGX_ERROR;
    }
    return NGX_OK;
}

/*
 * WHAT: Release every resource owned by an in-progress cache fill.
 * WHY: Keep all error paths consistent and prevent partial staged objects.
 * HOW: Free the transfer buffer, abort the staged object, and release source.
 */
static void
cache_fill_abort(sd_cache_fill_state_t *fs)
{
    free(fs->buf);
    fs->buf = NULL;
    brix_cstore_fill_abort(fs->staged);
    brix_sd_obj_release(fs->so);
    fs->so = NULL;
}


/*
 * WHAT: Finish a failed origin fill while preserving its causal errno.
 * WHY: Cleanup and stale probing can overwrite network/read errors with ENOENT.
 * HOW: Abort resources, serve bounded stale data only for direct-origin fills,
 *      otherwise restore the supplied errno and report an error.
 */
static ngx_int_t
cache_fill_fail(sd_cache_inst_state *st, const char *key,
    sd_cache_fill_state_t *fs, int error)
{
    cache_fill_abort(fs);
    if (!fs->from_cold && !fs->from_peer && sd_cache_stale_serve_ok(st, key)) {
        return NGX_DONE;
    }
    errno = error;
    return NGX_ERROR;
}


/* Pump the source object's bytes into the staged store object.
 *
 * WHAT: The origin read loop — pread from the source, fill_write to the staged
 *       object, chunk by chunk, advancing fs->off.
 *
 * WHY:  The pump is the fill's only long-running phase; isolating it keeps the
 *       read-error / stale-serve / errno-preservation logic in one place.
 *
 * HOW:  On success frees the move buffer and closes the source (the staged
 *       object stays open for verify/commit) and returns NGX_OK. On a read or
 *       write failure it releases EVERYTHING (buffer, staged fill, source) and
 *       returns NGX_DONE if a bounded stale copy can be served, else NGX_ERROR
 *       with the READ's errno preserved. */
static ngx_int_t
cache_fill_pump(sd_cache_inst_state *st, const char *key,
    sd_cache_fill_state_t *fs)
{
    for ( ;; ) {
        ssize_t r = fs->so->driver->pread(fs->so, fs->buf, SD_CACHE_CHUNK,
                                          fs->off);

        if (r < 0) {
            int read_err = errno;      /* capture BEFORE any cleanup call */

            if (read_err == EINTR) {
                continue;
            }
            return cache_fill_fail(st, key, fs, read_err);
        }
        if (r == 0) {
            /* Clean EOF. If the source declared its size, an EOF short of that
             * size is a TRUNCATED transfer — the origin (or an in-path actor)
             * cut the fill mid-stream. Committing fs->off bytes as a whole-file
             * COMPLETE object would poison the cache with a permanently-short
             * copy served as a valid hit to every subsequent client. Fail
             * closed exactly like a mid-fill read error: release everything,
             * serve a bounded stale copy if one exists, else EIO so the next
             * read refetches. A size-unknown source (snap.size <= 0, e.g. an
             * HTTP origin with no Content-Length) has no lower bound to check
             * against, so a clean EOF is the only completion signal available. */
            if (fs->snap.size > 0 && fs->off < fs->snap.size) {
                ngx_log_error(NGX_LOG_ERR, st->log, 0,
                    "sd_cache: origin truncated fill for \"%s\" at %O of %O "
                    "bytes - not caching the short object", key,
                    (off_t) fs->off, (off_t) fs->snap.size);
                return cache_fill_fail(st, key, fs, EIO);
            }
            break;
        }
        if (brix_cstore_fill_write(fs->staged, fs->buf, (size_t) r,
                                   fs->off) < 0)
        {
            cache_fill_abort(fs);
            return NGX_ERROR;
        }
        fs->off += r;
        if (fs->snap.size > 0 && fs->off >= fs->snap.size) {
            break;               /* size known: skip the EOF-probe round-trip */
        }
    }
    free(fs->buf);
    fs->buf = NULL;
    /* Capture the origin's advertised content digest BEFORE releasing the source
     * object — the query needs a live, open object. Only the xroot source offers
     * an in-band digest (kXR_Qcksum); other backends (http/s3/posix) leave alg/hex
     * empty and the verify phase decides best-effort/require on that. Skipped
     * entirely unless a digest-verify policy is in force, so an OFF/CVMFS-CAS fill
     * pays no round-trip. Mirrors the fetch.c commit-then-verify pattern. */
    if ((st->policy.verify == BRIX_CACHE_VERIFY_BESTEFFORT
         || st->policy.verify == BRIX_CACHE_VERIFY_REQUIRE)
        && ngx_strcmp(brix_sd_backend_name(fs->src), "xroot") == 0)
    {
        brix_sd_xroot_query_checksum(fs->so, fs->origin_alg,
            sizeof(fs->origin_alg), fs->origin_hex, sizeof(fs->origin_hex));
    }
    brix_sd_obj_release(fs->so);
    fs->so = NULL;
    return NGX_OK;
}

/* Publish the staged object and record its cinfo.
 *
 * WHAT: Accounts the upstream fill, commits (renames) the staged object into
 *       the store, and stores the whole-file COMPLETE cinfo built from the
 *       source stat snapshot (the fstat mode fix — origin perms in ci.mode).
 *
 * WHY:  The commit phase is the fill's publication point; everything before it
 *       is invisible to readers, so all bookkeeping that describes a
 *       SUCCESSFUL fill belongs here.
 *
 * HOW:  Whole-file COMPLETE cinfo (the 1 MiB granule keys validity; the present
 *       bitmap is all-set). A partial/slice fill is section 6.5 / SP2. A failed
 *       cinfo store is only a WARN — the object is cached but unrecorded, a
 *       safe miss (refill) next time. */
static ngx_int_t
cache_fill_commit(sd_cache_inst_state *st, const char *key,
    sd_cache_fill_state_t *fs)
{
    brix_cache_cinfo_t  ci;

    if (!fs->from_cold && !fs->from_peer) {
        /* a cold promote or a sibling fetch moved zero origin-WAN bytes */
        sd_cache_note_origin_bytes(st, key, fs->off);  /* WAN in, this attempt */
        sd_cache_note_upstream(st, 1, fs->off, sd_cache_ms_since(&fs->t0));
    }

    if (brix_cstore_fill_commit(fs->staged) != NGX_OK) {
        /* Failed commit keeps the handle valid — abort to release it. */
        brix_cstore_fill_abort(fs->staged);
        return NGX_ERROR;
    }

    ngx_memzero(&ci, sizeof(ci));
    ci.magic      = BRIX_CACHE_CINFO_MAGIC;
    ci.version    = BRIX_CACHE_CINFO_VERSION;
    ci.block_size = BRIX_CACHE_DIRTY_BLOCK;
    ci.size       = (uint64_t) fs->off;
    ci.mtime      = (uint64_t) fs->snap.mtime;
    ci.mode       = (uint32_t) (fs->snap.mode & 0777); /* origin perms — served back
                                                        * so a read-only source is not
                                                        * masked by the owner-writable
                                                        * physical store object. */
    ci.nblocks    = brix_cache_cinfo_nblocks((uint64_t) fs->off, ci.block_size);
    ci.flags      = BRIX_CINFO_F_COMPLETE
                  | (fs->verified ? BRIX_CINFO_F_VERIFIED : 0);
    ci.filled_at  = (uint64_t) time(NULL);
    if (fs->verified && fs->cks_alg[0] != '\0' && fs->cks_hex[0] != '\0') {
        /* The verified digest — the producer side of xrdckverify --cache.
         * Only a MATCHED digest is recorded; an unverified fill leaves the
         * fields empty rather than asserting bytes nobody checked. */
        ngx_cpystrn((u_char *) ci.cks_alg, (u_char *) fs->cks_alg,
                    sizeof(ci.cks_alg));
        ci.cks_alg_len = (uint8_t) ngx_strlen(ci.cks_alg);
        ngx_cpystrn((u_char *) ci.cks_hex, (u_char *) fs->cks_hex,
                    sizeof(ci.cks_hex));
        ci.cks_len = (uint8_t) ngx_strlen(ci.cks_hex);
        /* Also seed the CHECKSUM CACHE the read path consults. The cinfo records
         * provenance for the cache's own bookkeeping; a client's kXR_Qcksum /
         * Want-Digest never looks there, and a cache HIT is served by the store's
         * driver, so it never reaches the origin's query_checksum slot either —
         * without this the first such request re-reads the whole cached file to
         * re-derive a digest this fill just proved. */
        brix_cstore_seed_checksum(&st->cstore, key, fs->cks_alg, fs->cks_hex);
    }
    if (st->policy.cvmfs_manifest_ttl > 0
        && sd_cache_is_manifest_key(st->policy.verify, key))
    {
        brix_cache_cinfo_set_expires(&ci,
            (time_t) ci.filled_at + st->policy.cvmfs_manifest_ttl);
    }

    if (brix_cstore_cinfo_store(&st->cstore, key, &ci) != NGX_OK) {
        /* The object is cached but unrecorded - a safe miss (refill) next time. */
        ngx_log_error(NGX_LOG_WARN, st->log, errno,
            "sd_cache: cinfo store failed for \"%s\" - will refill on next read",
            key);
    }

    if (st->policy.global_cas && fs->verified
        && st->policy.verify == BRIX_CACHE_VERIFY_CVMFS_CAS)
    {
        /* phase-87 G13: only cvmfs-cas binds the KEY's hash to the bytes
         * (best-effort/require verify an origin-advertised digest instead) —
         * with that proof, collapse byte-identical cross-repo copies. */
        brix_gcas_publish(&st->cstore, key);
    }
    return NGX_OK;
}

/* One fill attempt from the tier `src` (the wrapped source, the cold store on
 * a phase-85 F7 promote, or a mesh sibling on a phase-85 F8 peer fetch):
 * acquire (source open + admission + staged fill-open) -> pump (read loop) ->
 * verify (phase-68 cvmfs-cas) -> commit (publish + cinfo). NGX_DONE from
 * acquire/pump means a bounded stale copy was served — reported as NGX_OK
 * without caching (origin attempts only; a cold or peer attempt never
 * stale-serves so its failure falls back to the origin). */
static ngx_int_t
sd_cache_fill_attempt(sd_cache_inst_state *st, const char *key,
    const brix_sd_cred_t *cred, brix_sd_instance_t *src, int from_cold,
    int from_peer, int allow_pt, int *out_pt)
{
    sd_cache_fill_state_t  fs;
    ngx_int_t              rc;

    ngx_memzero(&fs, sizeof(fs));
    fs.src       = src;
    fs.from_cold = from_cold;
    fs.from_peer = from_peer;
    fs.allow_pt  = allow_pt;
    (void) clock_gettime(CLOCK_MONOTONIC, &fs.t0);

    rc = cache_fill_acquire(st, key, cred, &fs);
    if (rc == NGX_DONE) {
        return NGX_OK;                  /* bounded stale-if-error (phase-68) */
    }
    if (rc != NGX_OK) {
        return rc;                      /* NGX_DECLINED or NGX_ERROR */
    }

    rc = cache_fill_pump(st, key, &fs);
    if (rc == NGX_DONE) {
        return NGX_OK;                  /* bounded stale-if-error (phase-68) */
    }
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    if (cache_fill_verify(st, key, &fs) != NGX_OK) {
        return NGX_ERROR;
    }
    rc = cache_fill_commit(st, key, &fs);
    if (rc == NGX_OK && fs.passthrough && out_pt != NULL) {
        *out_pt = 1;            /* phase-92: serve-then-evict — caller drops key */
    }
    return rc;
}

/* Rendezvous (highest-random-weight) owner of `key` over the peer ring:
 * FNV-1a 64 over "<label>\n<key>", owner = argmax across members. Every mesh
 * node carries the IDENTICAL member list with identical labels, so all nodes
 * agree on the owner with no coordination. The scheme (FNV-1a 64, offset
 * 14695981039346656037, prime 1099511628211, '\n' separator, ties to the
 * lower index) is mirrored bit-for-bit by tests/test_cvmfs_peer_mesh.py —
 * change both together or not at all. */
static uint64_t
sd_cache_hrw_fnv1a64(const char *label, const char *key)
{
    uint64_t     h = BRIX_FNV1A64_OFFSET_BASIS;
    const char  *p;

    for (p = label; *p != '\0'; p++) {
        h = (h ^ (uint64_t) (unsigned char) *p) * BRIX_FNV1A64_PRIME;
    }
    h = (h ^ (uint64_t) '\n') * BRIX_FNV1A64_PRIME;
    for (p = key; *p != '\0'; p++) {
        h = (h ^ (uint64_t) (unsigned char) *p) * BRIX_FNV1A64_PRIME;
    }
    return h;
}

static int
sd_cache_peer_owner(const brix_sd_cache_peer_t *peers, int n,
    const char *key)
{
    int       i, owner = 0;
    uint64_t  best = 0, w;

    for (i = 0; i < n; i++) {
        w = sd_cache_hrw_fnv1a64(peers[i].label, key);
        if (i == 0 || w > best) {
            best  = w;
            owner = i;
        }
    }
    return owner;
}

/* Fill `key` into the cache store and record its cinfo.
 *
 * WHAT: Pulls the object `key` into the cache store, building a whole-file
 *       cinfo on success. With a cold store tier attached (phase-85 F7) a
 *       verified PROMOTE from the cold copy is attempted first; with a sibling
 *       mesh attached (phase-85 F8) the key's rendezvous-owning peer is tried
 *       next; the origin (st->source) is the fallback and the only tier that
 *       stale-serves.
 *
 * WHY:  The fill spine is the single path that populates the cache; threading
 *       the caller's per-user `cred` here ensures the source open uses the
 *       correct identity rather than the service credential. Routing the
 *       promote through the SAME spine means a cold object passes the identical
 *       cvmfs-cas / manifest-signature verify gate as an origin fill — a
 *       corrupt cold copy can never publish.
 *
 * HOW:  Cold attempt (when st->cold): any failure but admission silently falls
 *       back to the origin; success drops the cold copy (move semantics).
 *       Peer attempt (when the ring owner of `key` is a non-self member with a
 *       built instance): one verified fetch from that sibling; any failure but
 *       admission silently falls back to the origin. Only the configured ring
 *       members are ever contacted (allowlist by construction — no request-
 *       derived authority reaches a peer fetch). Returns NGX_OK (object cached
 *       + cinfo stored, or stale-served), NGX_DECLINED (policy declined), or
 *       NGX_ERROR (failure). */
ngx_int_t
sd_cache_fill(sd_cache_inst_state *st, const char *key,
    const brix_sd_cred_t *cred, int allow_pt, int *out_pt)
{
    if (out_pt != NULL) {
        *out_pt = 0;
    }
    if (st->cold != NULL) {
        ngx_int_t rc = sd_cache_fill_attempt(st, key, cred, st->cold, 1, 0,
            allow_pt, out_pt);

        if (rc == NGX_OK) {
            /* Promoted: the hot tier owns the object now — drop the cold copy
             * (best-effort; a leftover is simply re-evicted or re-demoted). */
            if (st->cold->driver->unlink != NULL) {
                (void) st->cold->driver->unlink(st->cold, key, 0);
            }
            ngx_log_error(NGX_LOG_INFO, st->log, 0,
                "sd_cache: promoted \"%s\" from the cold tier", key);
            return NGX_OK;
        }
        if (rc == NGX_DECLINED) {
            return rc;          /* admission policy — identical for the origin */
        }
        /* cold miss / outage / corrupt copy: fall back to the origin fill */
    }

    {
        /* phase-87 G12: a swarm-published dynamic ring replaces the static
         * brix_cache_peers ring. ONE pointer load — the swarm plane swaps
         * rings on the event loop while fills run here on worker threads,
         * and a published ring is immutable and never freed. */
        const brix_sd_cache_ring_t *ring = st->dyn_ring;
        const brix_sd_cache_peer_t *peers;
        int                          n, self;

        if (ring != NULL) {
            peers = ring->peers;
            n     = ring->n;
            self  = ring->self;
        } else {
            peers = st->peers;
            n     = st->n_peers;
            self  = st->peer_self;
        }

        if (n > 0) {
            int owner = sd_cache_peer_owner(peers, n, key);

            if (owner != self && peers[owner].inst != NULL) {
                ngx_int_t rc = sd_cache_fill_attempt(st, key, cred,
                    peers[owner].inst, 0, 1, allow_pt, out_pt);

                if (rc == NGX_OK) {
                    ngx_log_error(NGX_LOG_INFO, st->log, 0,
                        "sd_cache: filled \"%s\" from mesh sibling %s",
                        key, peers[owner].label);
                    return NGX_OK;
                }
                if (rc == NGX_DECLINED) {
                    return rc;  /* admission policy — identical for the origin */
                }
                /* sibling miss / outage / corrupt copy: fall back to origin */
            }
        }
    }

    return sd_cache_fill_attempt(st, key, cred, st->source, 0, 0,
        allow_pt, out_pt);
}
