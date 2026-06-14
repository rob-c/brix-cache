#ifndef XROOTD_GSI_KEYPOOL_H
#define XROOTD_GSI_KEYPOOL_H

/*
 * Phase 33 — per-worker pool of pre-generated ephemeral ffdhe2048 DH keys.
 *
 * WHAT: The GSI round-1 (kXGC_certreq) response needs a fresh ephemeral DH key.
 *       This module hands them out from a per-worker warm pool instead of
 *       generating one inline.
 *
 * WHY:  Generating the key inline on the single nginx event thread
 *       head-of-line-blocks EVERY other connection on the worker for the duration
 *       of the keygen.  Under a concurrent GSI-handshake burst (grid pilots, FTS,
 *       xrdcp --sources) that serializes N keygens on one thread and stalls all
 *       other I/O — the exact concurrency wedge this fixes.
 *
 * HOW:  A warm batch is generated synchronously at worker start (no connections
 *       yet).  The pool is refilled by a thread-pool task: the keygen runs on a
 *       worker thread into task-local storage, and only the nginx event thread
 *       mutates the pool (pop on certreq, push from the refill done-callback) —
 *       so no locking is required.  If the pool is momentarily empty the certreq
 *       handler falls back to an inline keygen (correct, just not offloaded).
 *
 * The ffdhe2048 key is standalone (RFC 7919 fixed group; no per-connection
 * inputs), so pre-generating it ahead of time is sound and preserves perfect
 * forward secrecy (each key is handed out to exactly one session, then freed).
 */

#include "gsi_internal.h"   /* ngx + OpenSSL EVP types via ngx_xrootd_module.h */

/* Generate one standalone ephemeral ffdhe2048 EVP_PKEY (caller owns and frees it).
 * Returns NULL on failure.  Shared by warm-init, refill, and the inline fallback. */
EVP_PKEY *xrootd_gsi_dh_keygen(void);

/* Warm the per-worker pool at process start.  Call once from init_process when a
 * GSI/BOTH server is configured (caller gates).  Generates synchronously — safe
 * because no connections are being served yet at worker start. */
void xrootd_gsi_keypool_init(ngx_cycle_t *cycle);

/* Pop one ready ephemeral key (ownership transferred to *out).  Returns 1 on a
 * pool hit, 0 if the pool is empty (caller should inline-generate via
 * xrootd_gsi_dh_keygen()).  When the pool runs low and `pool` is non-NULL, an
 * off-thread refill is scheduled. */
ngx_int_t xrootd_gsi_keypool_pop(ngx_thread_pool_t *pool, ngx_log_t *log,
    EVP_PKEY **out);

#endif /* XROOTD_GSI_KEYPOOL_H */
