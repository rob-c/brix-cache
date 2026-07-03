#ifndef BRIX_FS_VFS_IO_CORE_H
#define BRIX_FS_VFS_IO_CORE_H

/*
 * vfs_io_core.h — thread-safe VFS I/O execution descriptors.
 *
 * WHAT: Declares the POD job descriptor and small segment descriptor types used
 *       by worker-thread and inline-fallback disk I/O. brix_vfs_io_execute()
 *       consumes one initialized job, performs the requested blocking syscall /
 *       CRC operation, and writes only the job OUT fields plus caller-owned
 *       buffers.
 *
 * WHY: Public VFS entry points are event-loop-only because they allocate from
 *      nginx pools, emit metrics/access logs, and touch cache state. This header
 *      exposes the narrower worker-safe execution core so stream AIO workers and
 *      synchronous fallbacks can share one raw-I/O implementation without
 *      pulling loop-only VFS internals into a thread.
 *
 * HOW: Callers fill immutable IN fields on brix_vfs_job_t, optionally pass
 *      readv/writev segment arrays and an error-message buffer, then call
 *      brix_vfs_io_execute(). The function zeroes OUT fields first, dispatches
 *      by op, captures errno into io_errno, and returns via the job.
 *
 * Requires: ngx_config.h / ngx_core.h types are included here explicitly.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "fs/backend/sd.h"   /* brix_sd_obj_t — the per-handle storage object */

#include <stdint.h>
#include <sys/types.h>

typedef enum {
    BRIX_VFS_IO_READ = 0,
    BRIX_VFS_IO_WRITE,
    BRIX_VFS_IO_PGREAD,
    BRIX_VFS_IO_READV,
    BRIX_VFS_IO_WRITEV,
    BRIX_VFS_IO_SYNC,
    BRIX_VFS_IO_TRUNCATE,
    BRIX_VFS_IO_OPENDIR
} brix_vfs_io_op_e;

typedef struct {
    int             fd;
    int             handle_index;
    off_t           offset;
    uint32_t        read_length;
    u_char         *header_read_length_ptr;
    u_char         *payload_ptr;
    /* The handle's storage object (driver+state) when a non-POSIX backend is
     * bound; obj.driver == NULL ⇒ use `fd` via the POSIX wrap (unchanged). */
    brix_sd_obj_t obj;
} brix_vfs_readv_seg_t;

typedef struct {
    int             fd;
    int             handle_idx;
    off_t           offset;
    const u_char   *data;
    uint32_t        wlen;
    brix_sd_obj_t obj;   /* see brix_vfs_readv_seg_t.obj */
} brix_vfs_writev_seg_t;

typedef struct {
    /* IN: immutable once posted to a worker. */
    brix_vfs_io_op_e  op;
    ngx_fd_t            fd;
    /* The handle's storage object for a non-POSIX backend (driver+state+fd).
     * obj.driver == NULL ⇒ the executor POSIX-wraps `fd` (byte-for-byte the
     * pre-Layer-3 path). Set via brix_vfs_job_set_obj. */
    brix_sd_obj_t     obj;
    off_t               offset;
    size_t              length;
    u_char             *buf;
    size_t              buf_cap;
    void               *segs;
    size_t              nsegs;
    unsigned            want_pgcrc:1;
    unsigned            do_sync:1;
    unsigned            want_stat:1;
    unsigned            want_cksum:1;
    unsigned            csi_mismatch:1;  /* OUT: a page failed CSI verify (W2) */
    void               *csi;             /* IN: brix_csi_t* or NULL (W2)      */
    int                 rootfd;
    u_char              streamid[2];
    const char         *path;
    const char         *cksum_algo;
    ngx_log_t          *log;
    char               *err_msg;
    size_t              err_msg_cap;

    /* OUT: written only by brix_vfs_io_execute(). */
    ssize_t             nio;
    size_t              out_size;
    uint32_t            crc32c;
    int                 io_errno;
    unsigned            short_io:1;
} brix_vfs_job_t;

/* ---- brix_vfs_job_read_init — initialize a thread-safe READ job ----
 *
 * WHAT: Zeroes *job and fills a READ request over fd/offset/length into dst.
 *       dst_cap is retained for defensive validation. Returns nothing.
 *
 * WHY: nginx thread tasks are reused; a dedicated initializer prevents stale
 *      OUT fields from a previous operation from leaking into a new worker run.
 *
 * HOW: ngx_memzero() the descriptor, set op/fd/offset/length/buf/buf_cap, and
 *      leave all OUT fields clear for brix_vfs_io_execute().
 */
static ngx_inline void
brix_vfs_job_read_init(brix_vfs_job_t *job, ngx_fd_t fd, off_t offset,
    size_t length, u_char *dst, size_t dst_cap, unsigned want_pgcrc)
{
    ngx_memzero(job, sizeof(*job));
    job->op = BRIX_VFS_IO_READ;
    job->fd = fd;
    job->offset = offset;
    job->length = length;
    job->buf = dst;
    job->buf_cap = dst_cap;
    job->want_pgcrc = want_pgcrc ? 1 : 0;
}

/* The effective storage object for a data op: the handle's bound driver object
 * when set (a non-POSIX backend), else a POSIX wrap of the bare fd (the unchanged
 * pre-Layer-3 path). `src` is the slot/job/segment obj (may be NULL/zeroed). */
static ngx_inline brix_sd_obj_t *
brix_vfs_effective_obj(brix_sd_obj_t *src, ngx_fd_t fd,
    brix_sd_obj_t *scratch)
{
    if (src != NULL && src->driver != NULL) {
        return src;
    }
    brix_sd_posix_wrap(scratch, fd);
    return scratch;
}

/* Bind the handle's storage object to a job so the executor dispatches data I/O
 * through its driver (block-striped/object backend). A NULL or default-POSIX obj
 * is ignored — the job keeps using its bare fd (the unchanged POSIX path). Call
 * after the op-specific init. */
static ngx_inline void
brix_vfs_job_set_obj(brix_vfs_job_t *job, const brix_sd_obj_t *obj)
{
    if (obj != NULL && obj->driver != NULL) {
        job->obj = *obj;
    }
}

/* ---- brix_vfs_job_write_init — initialize a thread-safe WRITE job ----
 *
 * WHAT: Zeroes *job and fills a WRITE request over fd/offset from src[0..len).
 *
 * WHY: Provides a small, explicit adapter between protocol task structs and the
 *      VFS execution core without letting protocol state cross into the worker.
 *
 * HOW: ngx_memzero() the descriptor, set op/fd/offset/buf/length, and leave OUT
 *      fields clear for execution.
 */
static ngx_inline void
brix_vfs_job_write_init(brix_vfs_job_t *job, ngx_fd_t fd, off_t offset,
    const u_char *src, size_t len)
{
    ngx_memzero(job, sizeof(*job));
    job->op = BRIX_VFS_IO_WRITE;
    job->fd = fd;
    job->offset = offset;
    job->buf = (u_char *) src;
    job->length = len;
    job->buf_cap = len;
}

/* ---- brix_vfs_job_sync_init — initialize a thread-safe SYNC job ----
 *
 * WHAT: Zeroes *job and fills a SYNC request for one open storage fd.
 *
 * WHY: kXR_sync and writev doSync must not bypass the VFS raw-I/O choke point
 *      when flushing main-storage handles.
 *
 * HOW: Store fd with op=SYNC; brix_vfs_io_execute() performs the durable
 *      flush and reports errno in the job OUT fields.
 */
static ngx_inline void
brix_vfs_job_sync_init(brix_vfs_job_t *job, ngx_fd_t fd)
{
    ngx_memzero(job, sizeof(*job));
    job->op = BRIX_VFS_IO_SYNC;
    job->fd = fd;
}

/* ---- brix_vfs_job_truncate_init — initialize a thread-safe TRUNCATE job ----
 *
 * WHAT: Zeroes *job and fills a TRUNCATE request for fd to the given length.
 *
 * WHY: Handle-based and path-based truncation are main-storage mutations and
 *      should share the same worker-safe VFS execution surface as writes.
 *
 * HOW: Store length in offset, because truncate has a single signed position
 *      input and no payload buffer.
 */
static ngx_inline void
brix_vfs_job_truncate_init(brix_vfs_job_t *job, ngx_fd_t fd, off_t length)
{
    ngx_memzero(job, sizeof(*job));
    job->op = BRIX_VFS_IO_TRUNCATE;
    job->fd = fd;
    job->offset = length;
}

/* ---- brix_vfs_job_opendir_init — initialize a thread-safe OPENDIR job ----
 *
 * WHAT: Zeroes *job and fills an OPENDIR request over a confined directory fd.
 *
 * WHY: The dirlist worker must not reopen by path after the loop has performed
 *      confinement. Passing the fd, response buffer, flags, and display strings
 *      keeps the scan/build operation POD-owned by the in-flight task.
 *
 * HOW: Store the prepared fd in rootfd, copy the stream id, and retain pointers
 *      to task-owned response/algo/path/error buffers for brix_vfs_io_execute.
 */
static ngx_inline void
brix_vfs_job_opendir_init(brix_vfs_job_t *job, int rootfd,
    u_char *response, size_t response_cap, const u_char streamid[2],
    ngx_flag_t want_stat, ngx_flag_t want_cksum, const char *path,
    const char *cksum_algo, ngx_log_t *log, char *err_msg, size_t err_msg_cap)
{
    ngx_memzero(job, sizeof(*job));
    job->op = BRIX_VFS_IO_OPENDIR;
    job->rootfd = rootfd;
    job->buf = response;
    job->buf_cap = response_cap;
    job->want_stat = want_stat ? 1 : 0;
    job->want_cksum = want_cksum ? 1 : 0;
    job->streamid[0] = streamid[0];
    job->streamid[1] = streamid[1];
    job->path = path;
    job->cksum_algo = cksum_algo;
    job->log = log;
    job->err_msg = err_msg;
    job->err_msg_cap = err_msg_cap;
}

void brix_vfs_io_execute(brix_vfs_job_t *job);

#endif /* BRIX_FS_VFS_IO_CORE_H */
