/*
 * WHAT: Async kXR_Qcksum — compute a single-file checksum (adler32/crc32c/md5/sha1/sha256) off the event loop via nginx thread pool.
 *       The thread worker opens a confined fd, computes checksum via brix_checksum_hex_fd, writes "algo hex" result to t->resp.
 *       On failure sets error_code + error_msg. Never touches nginx event-loop state (no ctx, no c, no ngx_pool).
 *
 * WHY:  Qcksum file checksums can be expensive for large files. Running on the event loop blocks all other connections while reading.
 *       The async path uses ngx_thread_pool_run to execute the open+checksum in a background worker thread, keeping nginx responsive.
 *       Results delivered via aio_done callback which restores request streamid, sends response to client, and resumes connection.
 *
 * HOW:  brix_cksum_aio_thread() parses algo from t->algo string, computes checksum via hex_fd on pre-opened fd,
 *       formats result as "algo hex" into resp buffer. On parse failure sets kXR_ArgInvalid; on compute failure sets kXR_IOError.
 *       brix_cksum_aio_done() closes fd if path-based request (t->close_fd), restores streamid via aio_restore_request, sends ok+resp or error, frees resources, resumes client connection event loop via aio_resume().
 */
#include "query_internal.h"
#include "core/compat/checksum.h"
#include "core/compat/integrity_info.h"
#include "protocols/root/response/response.h"
#include "core/aio/aio.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_close — release the path-based read handle */

/* One slot per connection, shared by the serialized checksum query forms.
 * Keeping it behind a pool cleanup avoids a public connection-layout change. */
typedef struct {
    ngx_thread_task_t *task;
    size_t capacity;
} brix_checksum_task_slot_t;

/* WHAT: Release a connection's checksum task after its deferred I/O is done.
 * WHY: The embedded event must not be freed from its own completion callback.
 * HOW: 1. Free its heap block at connection-pool teardown. 2. Retire the slot. */
static void
brix_checksum_task_cleanup(void *data)
{
    brix_checksum_task_slot_t *slot = data;

    if (slot->task != NULL) {
        ngx_free(slot->task);
        slot->task = NULL;
    }
    slot->capacity = 0;
}

/* WHAT: Find or register the one checksum-task owner on a connection pool.
 * WHY: Queue-overflow retries must not allocate a fresh task on every request;
 * ngx_pfree cannot reclaim small pool allocations on large-page hosts.
 * HOW: 1. Match this concern's cleanup handler. 2. Allocate one zeroed slot. */
static brix_checksum_task_slot_t *
brix_checksum_task_slot(ngx_connection_t *c)
{
    ngx_pool_cleanup_t *cleanup;

    for (cleanup = c->pool->cleanup; cleanup != NULL; cleanup = cleanup->next) {
        if (cleanup->handler == brix_checksum_task_cleanup) {
            return cleanup->data;
        }
    }
    cleanup = ngx_pool_cleanup_add(c->pool, sizeof(brix_checksum_task_slot_t));
    if (cleanup == NULL) {
        return NULL;
    }
    ngx_memzero(cleanup->data, sizeof(brix_checksum_task_slot_t));
    cleanup->handler = brix_checksum_task_cleanup;
    return cleanup->data;
}

/* WHAT: Obtain an inactive reusable checksum/scan task, or NULL on failure.
 * WHY: Both accepted queries and busy retries need bounded connection memory;
 * a queued task's event/context must remain untouched until completion.
 * HOW: 1. Find its owner. 2. Reject overlap. 3. Grow before replacing the old
 * block. 4. Reset inactive storage and expose the requested context. */
ngx_thread_task_t *
brix_query_checksum_task(ngx_connection_t *c, size_t size)
{
    brix_checksum_task_slot_t *slot;
    ngx_thread_task_t *task;

    if (size > SIZE_MAX - sizeof(ngx_thread_task_t)) {
        return NULL;
    }
    slot = brix_checksum_task_slot(c);
    if (slot == NULL) {
        return NULL;
    }
    if (slot->task != NULL && slot->task->event.active) {
        return NULL;
    }
    if (slot->task == NULL || slot->capacity < size) {
        task = ngx_alloc(sizeof(ngx_thread_task_t) + size, c->log);
        if (task == NULL) {
            return NULL;
        }
        brix_checksum_task_cleanup(slot);
        slot->task = task;
        slot->capacity = size;
    }
    ngx_memzero(slot->task, sizeof(ngx_thread_task_t) + size);
    slot->task->ctx = slot->task + 1;
    return slot->task;
}


/*
 * brix_cksum_aio_thread — runs on a thread-pool worker.
 *
 * Computes the checksum of t->fd using t->algo and writes the result
 * into t->resp.  On failure sets t->error_code to the appropriate kXR_*
 * code and t->error_msg to a human-readable description.  Never touches
 * nginx event-loop state (no ctx, no c, no ngx_pool).
 */
/* public API: brix_cksum_aio_thread() — async qcksum thread worker
 * WHAT: Thread pool worker that computes single-file checksum.
 *   - Parses algo string via brix_checksum_parse
 *   - Computes checksum via brix_checksum_hex_fd on pre-opened fd
 *   - Writes "algo hex" result to resp buffer
 *   - On parse failure: sets kXR_ArgInvalid
 *   - On compute failure: sets kXR_IOError + error message
 *   - Never touches nginx event-loop state (no ctx, no c, no ngx_pool)
 */

void
brix_cksum_aio_thread(void *data, ngx_log_t *log)
{
    brix_cksum_aio_t      *t = data;
    brix_integrity_info_t  info;
    brix_integrity_opts_t  iopts;
    char                     token[256];

    ngx_memzero(&iopts, sizeof(iopts));
    iopts.allow_xattr_cache  = 1;
    iopts.update_xattr_cache = 1;
    iopts.mutation_policy    = t->mutation_policy;
    iopts.proto              = BRIX_PROTO_ROOT;

    if (brix_integrity_get_fd(log, t->fd, &t->obj, t->resolved, t->algo,
                                &iopts, &info) != NGX_OK)
    {
        t->error_code = kXR_IOError;
        snprintf(t->error_msg, sizeof(t->error_msg),
                 "checksum computation failed");
        return;
    }

    /* kXR_Qcksum wire format: "algo hexvalue" (space-separated) */
    snprintf(token, sizeof(token), "%s %s", info.alg_name, info.hex);
    ngx_cpystrn((u_char *) t->resp, (u_char *) token, sizeof(t->resp));
}

/*
 * brix_cksum_aio_done — main-thread completion callback.
 *
 * Closes t->fd if t->close_fd is set (path-based requests), then sends
 * the response built by the thread worker and re-arms the connection.
 * The fd is closed before the destroy check so it is never leaked even
 * when the client disconnected while the AIO was in flight.
 */
/* public API: brix_cksum_aio_done() — async qcksum completion callback
 * WHAT: Main-thread event handler when thread worker completes.
 *   - Closes t->fd if path-based request (t->close_fd)
 *   - Restores request streamid via aio_restore_request
 *   - Sends error response or ok+checksum data to client
 *   - Resumes client connection event loop via brix_aio_resume()
 */

void
brix_cksum_aio_done(ngx_event_t *ev)
{
    brix_cksum_aio_t *t   = ((ngx_thread_task_t *) ev->data)->ctx;
    brix_ctx_t       *ctx = t->ctx;
    ngx_connection_t   *c   = t->c;

    if (t->close_fd) {
        /* Path-based request: release the VFS handle we opened (it owns the fd).
         * The handle is freed before the destroy check so it is never leaked even
         * when the client disconnected while the AIO was in flight. */
        if (t->fh != NULL) {
            brix_vfs_close(t->fh, c->log);
            t->fh = NULL;
        } else if (t->fd >= 0) {
            close(t->fd);
        }
        t->fd = -1;
    }

    if (!brix_aio_restore_request(ctx, t->streamid)) {
        return;
    }

    if (t->error_code != 0) {
        BRIX_OP_ERR(ctx, BRIX_OP_QUERY_CKSUM);
        brix_send_error(ctx, c, (uint16_t) t->error_code, t->error_msg);
    } else {
        BRIX_OP_OK(ctx, BRIX_OP_QUERY_CKSUM);
        brix_log_access(ctx, c, "QUERY", t->resolved, "cksum", 1, 0, NULL, 0);
        brix_send_ok(ctx, c, t->resp, (uint32_t) (strlen(t->resp) + 1));
    }

    brix_aio_resume(c);
}

