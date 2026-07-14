#include "core/ngx_brix_module.h"

/*
 * buffers_scratch.c — per-connection scratch- and read-buffer lifecycle for the
 * synchronous read paths and nginx thread-pool AIO completions.
 *
 * Split from buffers.c (phase-79 file-size cap): this file owns the reusable
 * heap-backed buffer machinery — the grow-on-demand pool scratch, the
 * per-in-flight read pool acquire/release, and the between-request trim — while
 * buffers.c / buffers_sendfile.c own the response-chain builders that consume
 * those buffers. Keeping the buffer lifecycle separate from chain assembly keeps
 * each file focused and under the 500-line cap.
 */

/*
 * brix_get_pool_scratch — return a reusable scratch buffer from the
 * connection pool, growing it only when the current allocation is too small.
 *
 * The caller owns one buffer slot (*slot / *slot_size) anchored in the
 * connection pool.  On first call *slot is NULL and ngx_palloc allocates it.
 * On subsequent calls, if *slot_size >= need, the existing buffer is returned
 * without a new allocation — critical for preventing unbounded pool growth
 * during long xrdcp sessions.
 *
 * When the buffer must grow, the old one is freed with ngx_pfree (which is a
 * no-op if the pool does not track the block, so it is always safe to call).
 *
 * NOTE: need==0 is clamped to 1 to satisfy ngx_palloc's precondition.
 */
u_char *
brix_get_pool_scratch(ngx_pool_t *pool, u_char **slot, size_t *slot_size,
    size_t need)
{
    u_char *p;

    if (need == 0) {
        need = 1;
    }

    if (*slot != NULL && *slot_size >= need) {
        return *slot;
    }

    /*
     * Phase 31: scratch buffers are raw heap allocations (ngx_alloc/ngx_free),
     * NOT pool allocations.  The earlier pool-backed version corrupted memory
     * when brix_trim_scratch() freed and re-grew rd.read_scratch: ngx_pfree/
     * ngx_palloc churn nginx's pool large-allocation list while stale pointers
     * (the reused read_aio_task->databuf, read_fast_body_buf) still referenced
     * the old block — a use-after-free triggered by a large kXR_read followed by
     * a large kXR_readv.  Raw heap allocation has no such pool lifecycle: the
     * ctx owns the buffer and frees it explicitly on disconnect (mirroring how
     * payload_buf is handled in src/connection/recv.c).
     */
    p = ngx_alloc(need, pool->log);
    if (p == NULL) {
        return NULL;
    }

    if (*slot != NULL) {
        ngx_free(*slot);
    }

    *slot = p;
    *slot_size = need;
    return p;
}


/*
 * brix_release_read_buffer — return a response data buffer to the pool,
 * unless it is one of the reusable per-connection scratch slots.
 *
 * The scratch slots (rd.read_scratch / rd.read_hdr_scratch / rd.write_scratch) are
 * long-lived raw heap allocations (see brix_get_pool_scratch) that must NOT
 * be freed on every response — they are reused across requests and freed once
 * at disconnect.  Any OTHER buffer reaching here (e.g. a dirlist response) is a
 * single-request ngx_palloc from c->pool and is returned with ngx_pfree.
 *
 * Called from brix_release_pending_buffer() in write_helpers.c.
 */
void
brix_release_read_buffer(brix_ctx_t *ctx, ngx_connection_t *c, u_char *buf)
{
    ngx_uint_t i;

    if (buf == NULL) {
        return;
    }

    if (buf == ctx->rd.read_scratch || buf == ctx->rd.read_hdr_scratch
        || buf == ctx->rd.write_scratch || buf == ctx->rd.cmp_scratch)
    {
        return;
    }

    /*
     * Per-in-flight read-pool buffer (read pipelining): return the slot to the
     * pool rather than freeing it — the buffer is reused for the next read and
     * freed once at disconnect.  Idempotent: a slot already marked free is a
     * no-op, so the queued-then-error double-release path cannot underflow
     * rd_inflight.
     */
    for (i = 0; i < ctx->out.pipeline_depth; i++) {
        if (ctx->rd.pool[i].buf == buf) {
            if (ctx->rd.pool[i].in_use) {
                ctx->rd.pool[i].in_use = 0;
                if (ctx->rd.inflight > 0) {
                    ctx->rd.inflight--;
                }
            }
            return;
        }
    }

    (void) ngx_pfree(c->pool, buf);
}

/*
 * brix_acquire_read_buffer — borrow a per-in-flight data buffer from the
 * connection's read pool (rd_pool), growing the chosen slot to >= need bytes.
 *
 * Unlike the single shared rd.read_scratch, each in-flight read gets its OWN buffer,
 * so a memory-backed (userspace-TLS) read response can stay queued in the out_ring
 * and drain while the recv loop already issues the NEXT read into a different
 * buffer — i.e. memory reads can pipeline.  The slot is returned to the pool by
 * brix_release_read_buffer() when its out_ring response drains; the buffer is
 * freed once at disconnect (raw heap, Phase-31 discipline).
 *
 * The recv loop bounds in-flight reads at pipeline_depth (== rd_pool slot count),
 * so a free slot always exists on the hot path; NULL is returned only on OOM.
 */
u_char *
brix_acquire_read_buffer(brix_ctx_t *ctx, ngx_connection_t *c, size_t need)
{
    ngx_uint_t i;

    if (need == 0) {
        need = 1;
    }

    for (i = 0; i < ctx->out.pipeline_depth; i++) {
        if (ctx->rd.pool[i].in_use) {
            continue;
        }
        if (ctx->rd.pool[i].size < need) {
            u_char *p = ngx_alloc(need, c->log);
            if (p == NULL) {
                return NULL;
            }
            if (ctx->rd.pool[i].buf != NULL) {
                ngx_free(ctx->rd.pool[i].buf);
            }
            ctx->rd.pool[i].buf  = p;
            ctx->rd.pool[i].size = need;
        }
        ctx->rd.pool[i].in_use = 1;
        ctx->rd.inflight++;
        return ctx->rd.pool[i].buf;
    }

    return NULL;   /* pool exhausted — should not happen given the recv bound */
}

/*
 * brix_trim_scratch — shrink the per-session transfer scratch buffers back to
 * BRIX_READ_WINDOW once a large request has fully drained (Phase 31).
 *
 * rd.read_scratch and rd.write_scratch grow to the largest read / pgwrite the session
 * has served and are then kept for reuse.  Without trimming, a single 64 MiB
 * read pins ~64 MiB of resident heap for the entire connection lifetime even
 * while idle — the dominant memory-scaling term for a TLS gateway.  This trims
 * them back to the streaming window so the steady-state per-connection heap is
 * ~window, not ~request-max.
 *
 * MUST be called only when the connection is between requests (state
 * XRD_ST_REQ_HEADER with nothing buffered), so that no in-flight response chain
 * still points into these buffers.  The recv loop calls it at the top of a fresh
 * request.  Buffers at or below BRIX_SCRATCH_TRIM_THRESHOLD are left untouched
 * (hysteresis avoids realloc thrash on sessions that oscillate near the window).
 *
 * rd.read_hdr_scratch (per-chunk wire headers) is tiny and never trimmed.
 * payload_buf has detach semantics owned by the write path and is trimmed there.
 */
static void
brix_trim_one(ngx_pool_t *pool, u_char **slot, size_t *slot_size)
{
    u_char *p;

    if (*slot == NULL || *slot_size <= BRIX_SCRATCH_TRIM_THRESHOLD) {
        return;
    }

    /* Raw heap free/alloc — see brix_get_pool_scratch for why these buffers
     * are not pool-backed.  This is what makes the trim safe to run. */
    ngx_free(*slot);

    p = ngx_alloc(BRIX_READ_WINDOW, pool->log);
    if (p == NULL) {
        /* Could not re-seat a warm buffer; drop it so the next request
         * allocates fresh at exactly the size it needs. */
        *slot = NULL;
        *slot_size = 0;
        return;
    }

    *slot = p;
    *slot_size = BRIX_READ_WINDOW;
}

void
brix_trim_scratch(brix_ctx_t *ctx, ngx_connection_t *c)
{
    brix_trim_one(c->pool, &ctx->rd.read_scratch, &ctx->rd.read_scratch_size);
    brix_trim_one(c->pool, &ctx->rd.write_scratch, &ctx->rd.write_scratch_size);
}
