#ifndef BRIX_WRITEV_INTERNAL_H
#define BRIX_WRITEV_INTERNAL_H

/*
 * writev_internal.h — declarations shared between the two halves of the
 * kXR_writev handler after the phase-79 file-size split.
 *
 * WHAT: Cross-declares the invariant vector context (writev_run_t) and the
 *       single function that crosses the writev.c / writev_aio.c file boundary
 *       (writev_try_aio).
 * WHY:  writev.c (framing + handle admission + synchronous per-segment write +
 *       reply + orchestrator) and writev_aio.c (the thread-pool offload path)
 *       were one 551-line file; splitting keeps each focused and under the
 *       500-line cap. The orchestrator in writev.c calls writev_try_aio (now in
 *       the AIO file), and that function consumes the shared writev_run_t — so
 *       exactly that struct and that one function become non-static/shared.
 * HOW:  Both translation units include this header; neither symbol is exported
 *       beyond the root:// write module.
 *
 * Requires: core/ngx_brix_module.h (brix_ctx_t, ngx_connection_t, write_list) —
 *           included below so this header is self-contained.
 */

#include "core/ngx_brix_module.h"   /* brix_ctx_t, ngx_connection_t, write_list */

/* writev_run_t — the invariant vector context shared by the execute helpers.
 * WHAT: Bundles the per-connection state (ctx, c), the validated descriptor
 * block (wl), its segment count (n_segs), and the start of the contiguous
 * per-segment data blocks (data_ptr) that both the AIO and synchronous execute
 * paths consume identically.
 * WHY: These five values travel together through every write path; carrying
 * them in one struct keeps each helper under the parameter gate without
 * splitting a single logical argument into a loose list. Sharing the struct
 * across the file split lets the AIO path (writev_aio.c) and the synchronous
 * path (writev.c) consume the exact same context the orchestrator populates.
 * HOW: Populated once in brix_handle_writev after framing + handle admission,
 * then passed by const pointer to the execute helpers (which never mutate it —
 * their own mutable outputs are separate out-params). */
typedef struct {
	brix_ctx_t        *ctx;
	ngx_connection_t  *c;
	const write_list  *wl;
	size_t             n_segs;
	const u_char      *data_ptr;
} writev_run_t;

/* writev_try_aio — offload the whole vector to a worker thread if configured.
 * Defined in writev_aio.c; called by brix_handle_writev (writev.c). WHAT: when a
 * thread pool is configured, flattens the wire descriptors into a self-contained
 * decoded array, builds the writev AIO task, and posts it; on a successful post
 * it detaches payload_buf from ctx and reports posted via *posted. Returns
 * NGX_ERROR on allocation failure (caller drops the link); otherwise NGX_OK with
 * *posted 0 when no pool is configured or the post fell back to synchronous. */
ngx_int_t writev_try_aio(const writev_run_t *run, int do_sync,
                         ngx_flag_t *posted);

#endif /* BRIX_WRITEV_INTERNAL_H */
