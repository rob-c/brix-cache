/*
 * backend_async_queue.h — durable write-behind queue for backend namespace
 * mutations (brix_backend_async).
 *
 * WHAT: A per-worker coalescing queue for backend MUTATIONS (unlink / rmdir /
 *   rename / mkdir). When `brix_backend_async on` is set for a server, a mutation
 *   is (1) fsync'd to a durable journal record, (2) appended to the worker's
 *   pending batch with a protocol-supplied completion callback, and (3) the
 *   client is parked. The batch is drained in bulk — driven against the backend
 *   with the pool-less VFS path primitives — when it reaches `batch` ops OR the
 *   oldest op has waited `wait_ms` (whichever comes first). Each op's real result
 *   is then delivered to its parked client via the callback, and the durable
 *   record is removed. On worker start, brix_baq_reconcile() re-applies any op
 *   left un-drained by a crash (idempotently), so a mutation that the client was
 *   told to wait for is never silently lost across a reboot.
 *
 * WHY: Operators front high-latency / rate-limited origins (tape, object stores,
 *   remote XRootD) where a burst of individual namespace mutations is far more
 *   expensive than one coalesced flush. The queue trades per-op latency (the
 *   client blocks, and may time out — an accepted contract) for bulk backend
 *   efficiency and, crucially, durability: the reply is only sent once the op is
 *   truly on the backend, and a crash mid-batch replays rather than loses it.
 *   Reads / stats / lists are never queued — only mutations, so the namespace a
 *   subsequent request sees is always the post-flush truth for THIS client.
 *
 * HOW: The durable substrate mirrors the stage engine's journal (a fsync'd fixed-
 *   size record per op, scanned + replayed on boot) but keeps its OWN record type
 *   and OWN journal subdirectory (<stage_journal_dir>/backend/) so the two
 *   concerns stay decoupled — a namespace mutation is not a byte transfer and must
 *   not ride the stage mover / deny-cred flush machinery. The pending list and the
 *   park state are per-worker (the worker that parked a client is the only one
 *   that may wake it), so no SHM is needed — unlike the cross-worker stage_waiter.
 *   The core is protocol-agnostic: the root:// and S3/WebDAV adapters each supply
 *   a brix_baq_done_pt that wakes their own client with the delivered errno.
 */
#ifndef BRIX_BACKEND_ASYNC_QUEUE_H
#define BRIX_BACKEND_ASYNC_QUEUE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <stdint.h>

/* The four coalescable namespace mutations. Values are stable on-disk identities
 * (a journal record survives a restart), so they are append-only — never renumber. */
typedef enum {
    BRIX_BAQ_UNLINK = 0,   /* remove a regular file                       */
    BRIX_BAQ_RMDIR  = 1,   /* remove an empty directory                   */
    BRIX_BAQ_RENAME = 2,   /* rename src_key -> dst_key                    */
    BRIX_BAQ_MKDIR  = 3     /* create a directory (mode)                   */
} brix_baq_op_t;

/* The durable on-disk record — one per queued mutation, fixed size (fsync'd whole,
 * decoded size-exactly on replay). root_canon anchors the backend the op is
 * re-driven against on reconcile; src_key/dst_key are export-relative logical
 * paths (dst_key used only by RENAME). APPEND-ONLY layout: never reorder or shrink
 * a field, or old journals become unreadable. */
typedef struct {
    char          reqid[40];        /* minted request id (NUL-terminated)          */
    uint32_t      op;               /* brix_baq_op_t                               */
    char          root_canon[1024]; /* export root (canonical) to resolve backend  */
    char          src_key[1024];    /* target path; RENAME source                  */
    char          dst_key[1024];    /* RENAME destination; "" for single-target ops */
    uint32_t      mode;             /* MKDIR mode; 0 otherwise                      */
    int64_t       enqueued_at;      /* wall-clock enqueue time (seconds)           */
    uint32_t      attempts;         /* re-drive count (durable across restart)      */
} brix_baq_rec_t;

/*
 * Completion callback: the core calls this exactly once per queued op when the op
 * has been driven against the backend, on the SAME worker that enqueued it.
 * `client` is the opaque token the adapter passed to brix_baq_enqueue (an
 * ngx_connection_t* for root://, an ngx_http_request_t* for S3/WebDAV);
 * `op_errno` is 0 on success or the POSIX errno the backend mutation failed with.
 * The adapter delivers the corresponding wire/HTTP status and resumes the client.
 */
typedef void (*brix_baq_done_pt)(void *client, int op_errno);

/*
 * Configure the queue's durable journal subdirectory for this worker.
 *
 * WHAT: Derives <stage_journal_dir>/backend/ from the stage engine's journal dir
 *       (the single source of truth, set by brix_stage_engine_init) and creates it
 *       (0700). A NULL/empty stage journal dir leaves the queue in-memory only (no
 *       crash recovery) — the coalescing still works, only durability is off.
 *
 * WHY:  Keeps the async-queue records physically separate from the stage engine's
 *       *.req records so each subsystem's boot reconcile scans only its own.
 *
 * HOW:  Called from the worker stage-engine init, AFTER brix_stage_engine_init.
 */
void brix_baq_init(void);

/*
 * Enqueue one mutation and park the caller's client.
 *
 * WHAT: Persists a durable record (when a journal dir is configured), appends the
 *       op to the worker's pending batch with its completion callback, and — if
 *       the batch now meets the size trigger — drains immediately (which invokes
 *       `done` for every op including this one, inline). Otherwise the op stays
 *       parked until a later size/time-triggered drain.
 *
 * WHY:  The single entry point every protocol adapter calls after it has resolved
 *       + authorized the mutation and decided (from brix_backend_async) to defer.
 *
 * HOW:  root_canon / src_key / dst_key / mode populate the record; batch and
 *       wait_ms are this server's coalescing thresholds (stored per-op so a worker
 *       shared by servers with different tunables still flushes each correctly).
 *       Returns NGX_OK when the op is queued (or drained inline), NGX_ERROR on a
 *       bad argument or a full queue that could not be drained (the caller then
 *       runs the op inline / errors, never silently drops it).
 */
ngx_int_t brix_baq_enqueue(brix_baq_op_t op, const char *root_canon,
    const char *src_key, const char *dst_key, uint32_t mode,
    ngx_uint_t batch, ngx_msec_t wait_ms,
    brix_baq_done_pt done, void *client);

/*
 * Per-worker timer tick: drain the batch if the time trigger has fired.
 *
 * WHAT: If any parked op has waited >= its wait_ms, drains the whole batch now
 *       (delivering each op's result to its client). A no-op when the batch is
 *       empty or nothing has aged out yet.
 *
 * WHY:  The size trigger fires inline in enqueue; the time trigger needs a clock
 *       source. Called from the same per-worker timer that drives the stage
 *       scheduler tick.
 *
 * HOW:  Compares ngx_current_msec against each pending op's enqueue stamp.
 */
void brix_baq_tick(void);

/*
 * Drop any parked op belonging to `client` without delivering (best-effort).
 *
 * WHAT: Removes pending ops whose opaque client token equals `client` (their
 *       durable records are LEFT on disk, so a still-un-drained mutation is
 *       replayed at next boot rather than lost). Used when a parked client
 *       disconnects before its batch drains.
 *
 * WHY:  A woken callback must never touch a freed connection/request. The adapter
 *       calls this from its disconnect/cleanup handler so the drain skips the dead
 *       client — the mutation itself still lands (inline drain of the rest, or
 *       reconcile).
 */
void brix_baq_drop_client(void *client);

/*
 * Restart replay: re-apply every persisted mutation left un-drained by a crash.
 *
 * WHAT: Scans <stage_journal_dir>/backend/, decodes each record, re-runs the op
 *       against its backend IDEMPOTENTLY (unlink/rmdir of a missing target = done,
 *       mkdir of an existing dir = done, rename of an already-moved source = done),
 *       and removes the record on success. Called on worker 0 at startup.
 *
 * WHY:  The client was told to wait for the op; durability means a crash between
 *       "journalled" and "drained" must not lose it.
 *
 * HOW:  Mirrors brix_stage_reconcile's snapshot-then-drive loop; no client to wake
 *       (the parked connections died with the crash), so it only re-drives the
 *       backend effect.
 */
void brix_baq_reconcile(void);

#endif /* BRIX_BACKEND_ASYNC_QUEUE_H */
