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
static ngx_int_t
cache_fill_acquire(sd_cache_inst_state *st, const char *key,
    const brix_sd_cred_t *cred, sd_cache_fill_state_t *fs)
{
    brix_sd_instance_t *src = fs->src;
    mode_t              fmode;
    int                 err = 0;

    if (src->driver->open == NULL) {
        errno = ENOSYS;
        return NGX_ERROR;
    }
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

    if (!sd_cache_admit(&st->policy, key, fs->snap.size)) {
        brix_sd_obj_release(fs->so);
        return NGX_DECLINED;            /* too big / filtered - do not cache */
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
            free(fs->buf);
            brix_cstore_fill_abort(fs->staged);
            brix_sd_obj_release(fs->so);
            if (!fs->from_cold && !fs->from_peer
                && sd_cache_stale_serve_ok(st, key))
            {
                return NGX_DONE;        /* bounded stale-if-error (phase-68) */
            }
            /* Restore the READ's errno. sd_cache_stale_serve_ok() (and the
             * cleanup calls) stat the absent cache entry and leave errno
             * ENOENT — propagating that would make the fill layer classify a
             * merely-broken origin connection (EIO/ETIMEDOUT) as the origin's
             * definitive 404, turning a transient network fault into a
             * cached, client-poisoning "not found" instead of a retry. */
            errno = read_err;
            return NGX_ERROR;
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
                free(fs->buf);
                brix_cstore_fill_abort(fs->staged);
                brix_sd_obj_release(fs->so);
                if (!fs->from_cold && !fs->from_peer
                    && sd_cache_stale_serve_ok(st, key))
                {
                    return NGX_DONE;    /* bounded stale-if-error (phase-68) */
                }
                errno = EIO;
                return NGX_ERROR;
            }
            break;
        }
        if (brix_cstore_fill_write(fs->staged, fs->buf, (size_t) r,
                                   fs->off) < 0)
        {
            free(fs->buf);
            brix_cstore_fill_abort(fs->staged);
            brix_sd_obj_release(fs->so);
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
    }
    if (st->policy.cvmfs_manifest_ttl > 0 && sd_cache_is_manifest_key(key)) {
        brix_cache_cinfo_set_expires(&ci,
            (time_t) ci.filled_at + st->policy.cvmfs_manifest_ttl);
    }

    if (brix_cstore_cinfo_store(&st->cstore, key, &ci) != NGX_OK) {
        /* The object is cached but unrecorded - a safe miss (refill) next time. */
        ngx_log_error(NGX_LOG_WARN, st->log, errno,
            "sd_cache: cinfo store failed for \"%s\" - will refill on next read",
            key);
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
    int from_peer)
{
    sd_cache_fill_state_t  fs;
    ngx_int_t              rc;

    ngx_memzero(&fs, sizeof(fs));
    fs.src       = src;
    fs.from_cold = from_cold;
    fs.from_peer = from_peer;
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
    return cache_fill_commit(st, key, &fs);
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
sd_cache_peer_owner(const sd_cache_inst_state *st, const char *key)
{
    int       i, owner = 0;
    uint64_t  best = 0, w;

    for (i = 0; i < st->n_peers; i++) {
        w = sd_cache_hrw_fnv1a64(st->peers[i].label, key);
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
    const brix_sd_cred_t *cred)
{
    if (st->cold != NULL) {
        ngx_int_t rc = sd_cache_fill_attempt(st, key, cred, st->cold, 1, 0);

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

    if (st->n_peers > 0) {
        int owner = sd_cache_peer_owner(st, key);

        if (owner != st->peer_self && st->peers[owner].inst != NULL) {
            ngx_int_t rc = sd_cache_fill_attempt(st, key, cred,
                st->peers[owner].inst, 0, 1);

            if (rc == NGX_OK) {
                ngx_log_error(NGX_LOG_INFO, st->log, 0,
                    "sd_cache: filled \"%s\" from mesh sibling %s",
                    key, st->peers[owner].label);
                return NGX_OK;
            }
            if (rc == NGX_DECLINED) {
                return rc;      /* admission policy — identical for the origin */
            }
            /* sibling miss / outage / corrupt copy: fall back to the origin */
        }
    }

    return sd_cache_fill_attempt(st, key, cred, st->source, 0, 0);
}
