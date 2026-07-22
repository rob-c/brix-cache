#ifndef BRIX_WRITE_BACKEND_ASYNC_ROOT_H
#define BRIX_WRITE_BACKEND_ASYNC_ROOT_H

#include "core/ngx_brix_module.h"
#include "op_table.h"   /* brix_op_desc_t */

/*
 * brix_root_backend_async_try — root:// adapter for the durable backend-async
 * mutation queue (brix_backend_async).
 *
 * WHAT: If backend-async is enabled for this export AND `d` is a queueable
 *       namespace mutation (kXR_rm / kXR_rmdir), enqueue it durably, park the
 *       connection (ctx->state → XRD_ST_WAITING_BAQ), and return 1. The caller
 *       MUST then return NGX_OK without sending any reply: the queue's waker
 *       (baq_root_done) sends the real kXR_ok/kXR_error on the original streamid
 *       once the batch flushes (on size or on the coalesce timer).
 *
 * WHY:  Trades per-op latency for bulk backend efficiency; the client blocks on
 *       recv until the flush (and may time out — the mutation is journaled and
 *       replays regardless). Kept out of op_table.c's interpreter so the async
 *       park path is one self-contained unit.
 *
 * HOW:  Returns 0 when async is off, the op is not queueable, or the enqueue
 *       fails (queue full / path too long / OOM) — in every such case the caller
 *       runs the op inline, so the feature is strictly fail-safe.
 */
int brix_root_backend_async_try(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const brix_op_desc_t *d,
    const char *resolved);

/*
 * brix_root_backend_async_mv_try — kXR_mv variant of the backend-async park.
 *
 * WHAT: Enqueue a two-path RENAME (src_resolved → dst_resolved) on the durable
 *       queue and park the connection, exactly like brix_root_backend_async_try
 *       but for the mv opcode (which lives outside op_table.c's single-path
 *       interpreter). Returns 1 when parked (caller returns NGX_OK), 0 to run
 *       inline.
 *
 * WHY:  kXR_mv resolves two independent paths and has its own richer dst-exists
 *       error ladder in mv_execute; the caller therefore restricts the async path
 *       to a NON-EXISTENT destination (a pure create) so the queue's overwrite=0
 *       rename can never diverge from the synchronous error mapping.
 *
 * HOW:  Returns 0 when async is off or the enqueue fails, so the caller falls back
 *       to the synchronous mv_execute — strictly fail-safe.
 */
int brix_root_backend_async_mv_try(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *src_resolved,
    const char *dst_resolved);

#endif /* BRIX_WRITE_BACKEND_ASYNC_ROOT_H */
