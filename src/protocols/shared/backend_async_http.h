/*
 * backend_async_http.h — http-plane (S3 / WebDAV) adapter for the durable async
 * backend-op queue (src/fs/xfer/backend_async_queue.{c,h}).
 *
 * WHAT: brix_baq_http_try() enqueues a namespace mutation on the per-worker
 *       coalescing queue and PARKS the http request (r->main->count++, returns
 *       NGX_DONE) until the batch flushes; the supplied render callback then
 *       produces the real response and finalises the request on the event loop.
 *
 * WHY:  The root:// plane parks via its recv state machine; the http plane has
 *       no such state, but nginx already models "hold the request, finish later"
 *       via r->main->count++ + a deferred finalise (see webdav/copy.c collection
 *       offload). This wraps that pattern so S3 and WebDAV share ONE park/resume
 *       path — the queue itself stays protocol-agnostic.
 *
 * HOW:  The queue's flush fires as a posted event / 1s-tick on the event loop, so
 *       the wake (render + ngx_http_finalize_request) runs there too — no thread
 *       safety concern. The park record lives on r->pool, kept alive by the count
 *       reference until the render finalises. root_canon/src_key/dst_key are
 *       copied into the fsync'd durable record, so they need not outlive the call.
 */
#ifndef BRIX_BACKEND_ASYNC_HTTP_H
#define BRIX_BACKEND_ASYNC_HTTP_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "core/config/shared_conf.h"
#include "fs/xfer/backend_async_queue.h"

/*
 * Render callback: emit the HTTP response for `op_errno` (0 = success) and
 * finalise the request. `ctx` is the opaque value passed to brix_baq_http_try
 * (e.g. an S3 method slot). Runs on the event loop after the batch flush.
 */
typedef void (*brix_baq_http_render_pt)(ngx_http_request_t *r, void *ctx,
                                        int op_errno);

/*
 * Try to route an http-plane mutation through the durable async queue.
 *
 * Returns NGX_DONE  — parked; the caller must return NGX_DONE (do NOT touch r).
 *         NGX_DECLINED — run the op inline (async off, path too long to journal,
 *                        or enqueue failure); r is untouched.
 *
 * The auth/write gate MUST already have passed synchronously before this call —
 * a denied mutation must never reach the queue.
 */
ngx_int_t brix_baq_http_try(ngx_http_request_t *r,
    ngx_http_brix_shared_conf_t *common, brix_baq_op_t op,
    const char *root_canon, const char *src_key, const char *dst_key,
    uint32_t mode, brix_baq_http_render_pt render, void *ctx);

#endif /* BRIX_BACKEND_ASYNC_HTTP_H */
