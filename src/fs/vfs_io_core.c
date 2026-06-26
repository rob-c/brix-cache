/*
 * vfs_io_core.c — worker-safe VFS disk I/O execution core.
 *
 * WHAT: Implements xrootd_vfs_io_execute(), the POD-only execution surface for
 *       blocking read/write/readv/writev/pgread/sync/truncate work. It mutates
 *       only the job's OUT fields and caller-owned buffers; it never touches
 *       nginx pools, connection state, metrics, access logs, or cache metadata.
 *
 * WHY: Stream AIO workers historically duplicated raw syscalls outside the VFS,
 *      which let confinement, CRC, durability, truncation, short-I/O, and error
 *      behavior drift. This core gives worker and inline fallback paths one
 *      shared syscall/CRC body while preserving the event-loop-only public VFS
 *      contract.
 *
 * HOW: xrootd_vfs_io_execute() clears OUT fields, validates the descriptor, and
 *      dispatches to one small static helper per operation. Helpers use only
 *      thread-safe primitives, raw syscalls, and caller-provided POD buffers.
 */

#include "vfs_internal.h"
#include "vfs_io_core.h"
#include "backend/sd.h"

#include "../aio/aio.h"
#include "../dirlist/dcksm.h"
#include "../path/path.h"
#include "../protocol/dirlist_fmt.h"
#include "../read/read.h"
#include "../response/response.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

/* Maximum wire-response payload per kXR_oksofar / kXR_ok dirlist chunk. */
#define XROOTD_VFS_DIRLIST_CHUNK_CAP  65536UL

/* ---- xrootd_vfs_io_set_error_message — copy an optional worker error string ----
 *
 * WHAT: Writes message into job->err_msg when an error buffer was supplied.
 *
 * WHY: READV/WRITEV/DIRLIST callers already surface task-local error strings.
 *      Keeping message formatting in the core lets rewired workers preserve the
 *      current client-facing diagnostics without touching connection state.
 *
 * HOW: Check err_msg/err_msg_cap, then snprintf the provided message into the
 *      bounded caller-owned buffer.
 */
static void
xrootd_vfs_io_set_error_message(xrootd_vfs_job_t *job, const char *message)
{
    if (job->err_msg == NULL || job->err_msg_cap == 0 || message == NULL) {
        return;
    }

    snprintf(job->err_msg, job->err_msg_cap, "%s", message);
}

/* ---- xrootd_vfs_io_set_errno_message — format errno into the job error string ----
 *
 * WHAT: Formats "<prefix>: <strerror(err)>" into job->err_msg when available.
 *
 * WHY: Vector operations need segment-specific errors in the done callback, but
 *      workers cannot call protocol response helpers. This keeps the formatting
 *      local to the worker-safe core.
 *
 * HOW: If a caller supplied an error buffer, snprintf prefix and strerror(err)
 *      into it; missing buffers are a no-op.
 */
static void
xrootd_vfs_io_set_errno_message(xrootd_vfs_job_t *job, const char *prefix,
    int err)
{
    if (job->err_msg == NULL || job->err_msg_cap == 0 || prefix == NULL) {
        return;
    }

    snprintf(job->err_msg, job->err_msg_cap, "%s: %s", prefix, strerror(err));
}

/* ---- xrootd_vfs_io_write_counted — pwrite all bytes while preserving short-I/O facts ----
 *
 * WHAT: Writes len bytes at offset, retrying EINTR and accumulating progress.
 *       Returns bytes written in *written. A zero-byte write is reported as
 *       short I/O with errno=EIO; a hard pwrite error returns NGX_ERROR.
 *
 * WHY: The public VFS full-write helper deliberately exposes only success/error,
 *      but stream done callbacks distinguish hard errors from short writes. This
 *      counted worker helper preserves that protocol-visible distinction.
 *
 * HOW: Loop until len is written; on EINTR retry; on n==0 set *short_io and EIO;
 *      on n<0 capture errno; otherwise advance cursor and continue.
 */
static ngx_int_t
xrootd_vfs_io_write_counted(ngx_fd_t fd, const u_char *buf, size_t len,
    off_t offset, ssize_t *written, unsigned *short_io)
{
    size_t          done;
    xrootd_sd_obj_t obj;

    if (written == NULL || short_io == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    *written = 0;
    *short_io = 0;
    done = 0;

    /* Route the raw syscall through the Storage Driver seam (phase-55); the
     * short-I/O accounting policy stays here in the VFS. Every data byte op lives
     * in the backend (src/fs/backend/) so a non-POSIX driver slots in unchanged;
     * the sync/truncate executors below are on the same seam. (Reverts the
     * phase-56 A-1 micro-optimization that had inlined a raw pwrite here.) */
    xrootd_sd_posix_wrap(&obj, fd);

    while (done < len) {
        ssize_t nwrite;

        nwrite = xrootd_sd_posix_driver.pwrite(&obj, buf + done, len - done,
                                               offset + (off_t) done);
        if (nwrite < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (done > 0) {
                *written = (ssize_t) done;
                *short_io = 1;
            }
            return NGX_ERROR;
        }

        if (nwrite == 0) {
            *written = (ssize_t) done;
            *short_io = 1;
            errno = EIO;
            return NGX_ERROR;
        }

        done += (size_t) nwrite;
    }

    *written = (ssize_t) done;
    return NGX_OK;
}

/* ---- xrootd_vfs_io_execute_read — execute READ into caller-owned memory ----
 *
 * WHAT: Reads up to job->length bytes into job->buf and records bytes read,
 *       optional CRC32c, and errno on failure.
 *
 * WHY: kXR_read and the public VFS memory-read path both need the same EOF-safe
 *      pread loop without pool allocation or protocol framing in the worker.
 *
 * HOW: Validate fd/buffer/capacity/offset, call xrootd_vfs_pread_full(), then
 *      fill nio/out_size/crc32c or io_errno.
 */
static void
xrootd_vfs_io_execute_read(xrootd_vfs_job_t *job)
{
    size_t nread;

    if (job->fd == NGX_INVALID_FILE || job->offset < 0
        || (job->length > 0 && job->buf == NULL)
        || job->buf_cap < job->length)
    {
        job->nio = -1;
        job->io_errno = EINVAL;
        return;
    }

    nread = 0;
    if (xrootd_vfs_pread_full(job->fd, job->buf, job->length, job->offset,
                              &nread)
        != NGX_OK)
    {
        job->nio = -1;
        job->out_size = nread;
        job->io_errno = errno;
        return;
    }

    job->nio = (ssize_t) nread;
    job->out_size = nread;
    if (job->want_pgcrc && nread > 0) {
        job->crc32c = xrootd_crc32c_value(job->buf, nread);
    }
}

/* ---- xrootd_vfs_io_execute_write — execute WRITE from caller-owned memory ----
 *
 * WHAT: Writes job->length bytes from job->buf at job->offset, reporting hard
 *       errors and short writes in job OUT fields.
 *
 * WHY: Stream write completion already owns protocol accounting and response
 *      framing; the worker needs only a shared counted pwrite body.
 *
 * HOW: Validate fd/buffer/offset, call xrootd_vfs_io_write_counted(), and store
 *      nio/out_size/io_errno/short_io for the completion callback.
 */
static void
xrootd_vfs_io_execute_write(xrootd_vfs_job_t *job)
{
    ssize_t  written;
    unsigned short_io;

    if (job->fd == NGX_INVALID_FILE || job->offset < 0
        || (job->length > 0 && job->buf == NULL))
    {
        job->nio = -1;
        job->io_errno = EINVAL;
        return;
    }

    if (job->length == 0) {
        job->nio = 0;
        return;
    }

    if (xrootd_vfs_io_write_counted(job->fd, job->buf, job->length,
                                    job->offset, &written, &short_io)
        != NGX_OK)
    {
        job->nio = short_io ? written : -1;
        job->out_size = written > 0 ? (size_t) written : 0;
        job->short_io = short_io ? 1 : 0;
        job->io_errno = errno;
        return;
    }

    job->nio = written;
    job->out_size = (size_t) written;
}

/* ---- xrootd_vfs_io_execute_pgread — execute page-mode read encoding ----
 *
 * WHAT: Reads file bytes directly into the final pgread wire buffer and writes
 *       per-page CRC32c words in place.
 *
 * WHY: The existing pgread worker already had a pure, optimized in-place helper.
 *      Routing it through the VFS core gives pgread the same worker contract as
 *      plain reads without reimplementing CRC framing.
 *
 * HOW: Validate inputs, call xrootd_pgread_read_encode_inplace(), and copy its
 *      nread/out_size/io_errno values into the job.
 */
static void
xrootd_vfs_io_execute_pgread(xrootd_vfs_job_t *job)
{
    ssize_t nread;
    int     io_errno;

    if (job->fd == NGX_INVALID_FILE || job->offset < 0
        || (job->length > 0 && job->buf == NULL)
        || job->buf_cap < job->length)
    {
        job->nio = -1;
        job->io_errno = EINVAL;
        return;
    }

    nread = 0;
    io_errno = 0;
    job->out_size = xrootd_pgread_read_encode_inplace(job->fd, job->offset,
                                                      job->length, job->buf,
                                                      &nread, &io_errno,
                                                      0 /* blocking */);
    job->nio = nread;
    if (nread < 0) {
        job->io_errno = io_errno;
    }
}

/* ---- xrootd_vfs_io_execute_readv — execute a pre-built readv response plan ----
 *
 * WHAT: Runs the existing coalesced readv segment helper over job->segs and
 *       records total response bytes or an error string.
 *
 * WHY: The readv handler already validates every segment and lays out the final
 *      response buffer before I/O. The core should reuse that pure helper rather
 *      than duplicating preadv/coalescing logic.
 *
 * HOW: Validate segment count, call xrootd_readv_read_segments(), and compute
 *      out_size as segment headers plus payload bytes on success.
 */
static void
xrootd_vfs_io_execute_readv(xrootd_vfs_job_t *job)
{
    size_t bytes_read_total;

    if (job->segs == NULL || job->nsegs == 0) {
        job->nio = -1;
        job->io_errno = EINVAL;
        xrootd_vfs_io_set_error_message(job, "readv segment count out of range");
        return;
    }

    bytes_read_total = 0;
    if (xrootd_readv_read_segments((xrootd_readv_seg_desc_t *) job->segs,
                                   job->nsegs, &bytes_read_total,
                                   job->err_msg, job->err_msg_cap)
        != NGX_OK)
    {
        job->nio = -1;
        job->io_errno = EIO;
        if (job->err_msg != NULL && job->err_msg_cap > 0
            && job->err_msg[0] == '\0')
        {
            xrootd_vfs_io_set_error_message(job, "readv I/O error");
        }
        return;
    }

    job->nio = (ssize_t) bytes_read_total;
    job->out_size = job->nsegs * XROOTD_READV_SEGSIZE + bytes_read_total;
}

/* ---- xrootd_vfs_io_execute_writev — execute multi-segment pwrite work ----
 *
 * WHAT: Writes each writev segment to its target fd/offset and optionally fsyncs
 *       segment fds after all writes succeed.
 *
 * WHY: kXR_writev's worker duplicated pwrite/fsync handling outside VFS. Moving
 *      that loop here gives writev the same worker-safe counted-write behavior
 *      as single writes while leaving protocol accounting in the done callback.
 *
 * HOW: Iterate segments, skip zero-length entries, call the counted writer, set
 *      first-error message/state, accumulate out_size, then best-effort fsync
 *      non-empty segment fds when requested.
 */
static void
xrootd_vfs_io_execute_writev(xrootd_vfs_job_t *job)
{
    xrootd_vfs_writev_seg_t *segments;
    size_t                  segment_index;

    if (job->segs == NULL || job->nsegs == 0) {
        job->nio = -1;
        job->io_errno = EINVAL;
        xrootd_vfs_io_set_error_message(job, "writev segment count out of range");
        return;
    }

    segments = job->segs;
    for (segment_index = 0; segment_index < job->nsegs; segment_index++) {
        xrootd_vfs_writev_seg_t *segment;
        ssize_t                  written;
        unsigned                 short_io;

        segment = &segments[segment_index];
        if (segment->wlen == 0) {
            continue;
        }

        if (xrootd_vfs_io_write_counted(segment->fd, segment->data,
                                        (size_t) segment->wlen,
                                        segment->offset, &written, &short_io)
            != NGX_OK)
        {
            job->nio = short_io ? written : -1;
            job->io_errno = errno;
            job->short_io = short_io ? 1 : 0;
            if (short_io) {
                if (job->err_msg != NULL && job->err_msg_cap > 0) {
                    snprintf(job->err_msg, job->err_msg_cap,
                             "writev short write at seg %d",
                             (int) segment_index);
                }
            } else {
                char prefix[64];

                snprintf(prefix, sizeof(prefix),
                         "writev I/O error at seg %d", (int) segment_index);
                xrootd_vfs_io_set_errno_message(job, prefix, job->io_errno);
            }
            return;
        }

        job->out_size += (size_t) written;
    }

    if (job->do_sync) {
        for (segment_index = 0; segment_index < job->nsegs; segment_index++) {
            if (segments[segment_index].wlen > 0) {
                (void) fsync(segments[segment_index].fd);
            }
        }
    }

    job->nio = (ssize_t) job->out_size;
}

/* ---- xrootd_vfs_io_execute_sync — execute durable fd flush ----
 *
 * WHAT: Runs fsync() for one open main-storage fd and records errno on failure.
 *
 * WHY: Sync operations are storage I/O, so protocol handlers and writev doSync
 *      should route them through the same VFS raw-I/O chokepoint as writes.
 *
 * HOW: Validate fd, call fsync(), set nio=0 on success, or nio=-1/io_errno on
 *      failure.
 */
static void
xrootd_vfs_io_execute_sync(xrootd_vfs_job_t *job)
{
    xrootd_sd_obj_t obj;

    if (job->fd == NGX_INVALID_FILE) {
        job->nio = -1;
        job->io_errno = EINVAL;
        return;
    }

    /* Dispatch through the Storage Driver seam (phase-55). The POSIX driver's
     * fsync slot is fsync(2) verbatim, so behaviour is byte-identical. */
    xrootd_sd_posix_wrap(&obj, job->fd);
    if (xrootd_sd_posix_driver.fsync(&obj) != NGX_OK) {
        job->nio = -1;
        job->io_errno = errno;
        return;
    }

    job->nio = 0;
}

/* ---- xrootd_vfs_io_execute_truncate — execute fd truncation ----
 *
 * WHAT: Runs ftruncate() for one open main-storage fd to job->offset bytes.
 *
 * WHY: Truncation changes exported file data just like write, so it belongs in
 *      the VFS-owned syscall core instead of protocol handlers.
 *
 * HOW: Validate fd and non-negative length, call ftruncate(), then capture
 *      errno or report a zero-byte successful mutation.
 */
static void
xrootd_vfs_io_execute_truncate(xrootd_vfs_job_t *job)
{
    xrootd_sd_obj_t obj;

    if (job->fd == NGX_INVALID_FILE || job->offset < 0) {
        job->nio = -1;
        job->io_errno = EINVAL;
        return;
    }

    /* Dispatch through the Storage Driver seam (phase-55). The POSIX driver's
     * ftruncate slot is ftruncate(2) verbatim, so behaviour is byte-identical. */
    xrootd_sd_posix_wrap(&obj, job->fd);
    if (xrootd_sd_posix_driver.ftruncate(&obj, job->offset) != NGX_OK) {
        job->nio = -1;
        job->io_errno = errno;
        return;
    }

    job->nio = 0;
}

/* ---- xrootd_vfs_io_dirlist_fail — store an OPENDIR failure in the job ----
 *
 * WHAT: Records errno, marks nio as failed, and writes a bounded error string.
 *
 * WHY: The dirlist done callback already owns protocol error mapping. The core
 *      should return only the syscall fact and a task-local diagnostic string.
 *
 * HOW: Save err into job->io_errno, set nio=-1, and copy either message or
 *      strerror(err) into job->err_msg when the caller supplied one.
 */
static void
xrootd_vfs_io_dirlist_fail(xrootd_vfs_job_t *job, int err,
    const char *message)
{
    job->nio = -1;
    job->io_errno = err;
    xrootd_vfs_io_set_error_message(job,
                                    message != NULL ? message : strerror(err));
}

/* ---- xrootd_vfs_io_dirlist_name_unsafe — reject unframed entry names ----
 *
 * WHAT: Returns 1 when a directory entry name should be skipped.
 *
 * WHY: The kXR_dirlist wire body is newline-delimited; control bytes or the
 *      gateway's hidden control files would corrupt or pollute the listing.
 *
 * HOW: Check dot entries, the ".nginx-xrootd" prefix, and control/DEL bytes.
 */
static ngx_flag_t
xrootd_vfs_io_dirlist_name_unsafe(const char *name)
{
    const u_char *p;

    if (name[0] == '.' && (name[1] == '\0'
                            || (name[1] == '.' && name[2] == '\0')))
    {
        return 1;
    }

    if (ngx_strncmp(name, ".nginx-xrootd",
                    sizeof(".nginx-xrootd") - 1) == 0)
    {
        return 1;
    }

    for (p = (const u_char *) name; *p != '\0'; p++) {
        if (*p < 0x20 || *p == 0x7f) {
            return 1;
        }
    }

    return 0;
}

/* ---- xrootd_vfs_io_dirlist_flush_chunk — finish the current oksofar chunk ----
 *
 * WHAT: Writes a kXR_oksofar header for the current chunk and advances base.
 *
 * WHY: OPENDIR builds the exact pre-existing flat multi-frame wire buffer, but
 *      the caller still owns queueing and response lifetime on the event loop.
 *
 * HOW: Build a response header at out + *base, then advance by header+payload.
 */
static void
xrootd_vfs_io_dirlist_flush_chunk(xrootd_vfs_job_t *job, u_char *out,
    size_t *base, size_t cdpos)
{
    xrootd_build_resp_hdr(job->streamid, kXR_oksofar, (uint32_t) cdpos,
                          (ServerResponseHdr *) (out + *base));
    *base += XRD_RESPONSE_HDR_LEN + cdpos;
}

/* ---- xrootd_vfs_io_dirlist_need_new_chunk — ensure current entry fits ----
 *
 * WHAT: Flushes a full dirlist chunk and prepares a new chunk data pointer.
 *
 * WHY: The worker-safe core must preserve the old fixed-buffer E2BIG behavior:
 *      if one more full chunk would exceed job->buf_cap, completion reports an
 *      I/O error instead of streaming an unbounded allocation.
 *
 * HOW: If cdpos+need fits, return NGX_OK. Otherwise emit kXR_oksofar, check the
 *      remaining response capacity, reset cdata/cdpos, or fail with E2BIG.
 */
static ngx_int_t
xrootd_vfs_io_dirlist_need_new_chunk(xrootd_vfs_job_t *job, u_char *out,
    size_t *base, u_char **cdata, size_t *cdpos, size_t need)
{
    if (*cdpos + need <= XROOTD_VFS_DIRLIST_CHUNK_CAP) {
        return NGX_OK;
    }

    xrootd_vfs_io_dirlist_flush_chunk(job, out, base, *cdpos);
    if (*base + XRD_RESPONSE_HDR_LEN + XROOTD_VFS_DIRLIST_CHUNK_CAP
        > job->buf_cap)
    {
        char message[96];

        snprintf(message, sizeof(message),
                 "listing too large for AIO buffer (%zu bytes)",
                 job->buf_cap);
        xrootd_vfs_io_dirlist_fail(job, E2BIG, message);
        return NGX_ERROR;
    }

    *cdata = out + *base + XRD_RESPONSE_HDR_LEN;
    *cdpos = 0;
    return NGX_OK;
}

/* ---- xrootd_vfs_io_dirlist_stat_entry — format optional stat/checksum text ----
 *
 * WHAT: Fills statbuf and cksum_token for one directory entry and reports the
 *       extra bytes needed in the wire body.
 *
 * WHY: Directory stat and checksum handling is pure fd-relative work and belongs
 *      with the worker-safe scan once the directory fd is confined by PREPARE.
 *
 * HOW: fstatat() the entry without following symlinks, format the stat body, and
 *      optionally compute the checksum token via the fd-relative checksum helper.
 */
static ngx_int_t
xrootd_vfs_io_dirlist_stat_entry(xrootd_vfs_job_t *job, int dfd,
    const char *name, char *statbuf, size_t statbuf_cap,
    char *cksum_token, size_t cksum_token_cap, size_t *need)
{
    struct stat entry_st;

    statbuf[0] = '\0';
    cksum_token[0] = '\0';

    if (!job->want_stat) {
        return NGX_OK;
    }

    if (fstatat(dfd, name, &entry_st, AT_SYMLINK_NOFOLLOW) != 0) {
        return errno == ENOENT ? NGX_DECLINED : NGX_DECLINED;
    }

    if (job->want_cksum) {
        char        entry_path[PATH_MAX];
        const char *algo;
        int         n;

        xrootd_dirlist_make_dcksm_stat_body(&entry_st, statbuf, statbuf_cap);
        algo = job->cksum_algo != NULL ? job->cksum_algo : "unknown";
        n = snprintf(entry_path, sizeof(entry_path), "%s/%s",
                     job->path != NULL ? job->path : "", name);
        if (n < 0 || (size_t) n >= sizeof(entry_path)) {
            snprintf(cksum_token, cksum_token_cap, "%s:none", algo);
        } else {
            xrootd_dirlist_checksum_token(job->log, dfd, name, entry_path,
                                          &entry_st, algo, cksum_token,
                                          cksum_token_cap);
        }
        *need += strlen(cksum_token) + sizeof(" [  ]") - 1;

    } else {
        xrootd_make_stat_body(&entry_st, 0, 0, statbuf, statbuf_cap);
    }

    *need += strlen(statbuf) + 1;
    return NGX_OK;
}

/* ---- xrootd_vfs_io_dirlist_emit_entry — append one entry to the wire chunk ----
 *
 * WHAT: Writes name, optional stat body, and optional checksum token.
 *
 * WHY: Keeping the byte appends in one helper makes the OPENDIR executor easier
 *      to audit for buffer-capacity invariants.
 *
 * HOW: Copy the pre-counted strings into cdata and advance cdpos.
 */
static void
xrootd_vfs_io_dirlist_emit_entry(xrootd_vfs_job_t *job, u_char *cdata,
    size_t *cdpos, const char *name, size_t nlen, const char *statbuf,
    const char *cksum_token)
{
    ngx_memcpy(cdata + *cdpos, name, nlen);
    *cdpos += nlen;
    cdata[(*cdpos)++] = '\n';

    if (job->want_stat) {
        size_t slen;

        slen = strlen(statbuf);
        ngx_memcpy(cdata + *cdpos, statbuf, slen);
        *cdpos += slen;

        if (job->want_cksum) {
            int n;

            n = snprintf((char *) (cdata + *cdpos),
                         XROOTD_VFS_DIRLIST_CHUNK_CAP - *cdpos,
                         " [ %s ]", cksum_token);
            if (n > 0) {
                *cdpos += (size_t) n;
            }
        }

        cdata[(*cdpos)++] = '\n';
    }
}

/* ---- xrootd_vfs_io_execute_opendir — execute confined dirlist scan/build ----
 *
 * WHAT: Iterates a loop-opened confined directory fd and builds the complete
 *       kXR_dirlist flat response buffer in job->buf.
 *
 * WHY: The old dirlist worker reopened by path after confinement. Duplicating
 *      the prepared fd and using fdopendir() keeps the scan anchored to the
 *      exact directory approved on the event loop.
 *
 * HOW: Validate the job, dup rootfd, fdopendir the duplicate, emit optional
 *      dstat lead-in, append filtered entries with fd-relative fstat/checksum
 *      work, then write the final kXR_ok header and response length.
 */
static void
xrootd_vfs_io_execute_opendir(xrootd_vfs_job_t *job)
{
    DIR    *dp;
    int     scanfd;
    u_char *out;
    u_char *cdata;
    size_t  base;
    size_t  cdpos;

    if (job->rootfd < 0 || job->buf == NULL) {
        xrootd_vfs_io_dirlist_fail(job, EINVAL, "invalid opendir job");
        return;
    }

    if (job->buf_cap < (size_t) (XRD_RESPONSE_HDR_LEN
                                 + XROOTD_VFS_DIRLIST_CHUNK_CAP))
    {
        xrootd_vfs_io_dirlist_fail(job, ENOMEM, "response buffer too small");
        return;
    }

    scanfd = dup(job->rootfd);
    if (scanfd < 0) {
        xrootd_vfs_io_dirlist_fail(job, errno, NULL);
        return;
    }

    dp = fdopendir(scanfd);
    if (dp == NULL) {
        int err;

        err = errno;
        close(scanfd);
        xrootd_vfs_io_dirlist_fail(job, err, NULL);
        return;
    }

    out = job->buf;
    base = 0;
    cdpos = 0;
    cdata = out + XRD_RESPONSE_HDR_LEN;

    if (job->want_stat) {
        ngx_memcpy(cdata, XROOTD_DSTAT_LEADIN, XROOTD_DSTAT_LEADIN_LEN);
        cdpos = XROOTD_DSTAT_LEADIN_LEN;
    }

    for (;;) {
        struct dirent *de;
        const char    *name;
        size_t         nlen;
        size_t         need;
        char           statbuf[256];
        char           cksum_token[EVP_MAX_MD_SIZE * 2 + 64];

        errno = 0;
        de = readdir(dp);
        if (de == NULL) {
            if (errno != 0) {
                int err = errno;

                closedir(dp);
                xrootd_vfs_io_dirlist_fail(job, err, NULL);
                return;
            }
            break;
        }

        name = de->d_name;
        if (xrootd_vfs_io_dirlist_name_unsafe(name)) {
            continue;
        }

        nlen = strlen(name);
        need = nlen + 1;
        if (xrootd_vfs_io_dirlist_stat_entry(job, dirfd(dp), name,
                                             statbuf, sizeof(statbuf),
                                             cksum_token, sizeof(cksum_token),
                                             &need)
            == NGX_DECLINED)
        {
            continue;
        }

        if (xrootd_vfs_io_dirlist_need_new_chunk(job, out, &base, &cdata,
                                                 &cdpos, need)
            != NGX_OK)
        {
            closedir(dp);
            return;
        }

        xrootd_vfs_io_dirlist_emit_entry(job, cdata, &cdpos, name, nlen,
                                         statbuf, cksum_token);
    }

    closedir(dp);

    if (cdpos > 0) {
        cdata[cdpos - 1] = '\0';
    }
    xrootd_build_resp_hdr(job->streamid, kXR_ok, (uint32_t) cdpos,
                          (ServerResponseHdr *) (out + base));
    job->out_size = base + XRD_RESPONSE_HDR_LEN + cdpos;
    job->nio = 0;
}

/* ---- xrootd_vfs_io_reset_outputs — clear reusable job result fields ----
 *
 * WHAT: Resets OUT fields and optional error text before execution.
 *
 * WHY: Many nginx thread tasks are reused across requests. Clearing the result
 *      area in one place prevents stale errors or byte counts from escaping.
 *
 * HOW: Assign zero/neutral values to every OUT field and NUL the caller's error
 *      buffer when one was supplied.
 */
static void
xrootd_vfs_io_reset_outputs(xrootd_vfs_job_t *job)
{
    job->nio = 0;
    job->out_size = 0;
    job->crc32c = 0;
    job->io_errno = 0;
    job->short_io = 0;
    if (job->err_msg != NULL && job->err_msg_cap > 0) {
        job->err_msg[0] = '\0';
    }
}

/* ---- xrootd_vfs_io_execute — dispatch one thread-safe VFS I/O job ----
 *
 * WHAT: Executes the operation described by *job and stores the outcome in the
 *       job's OUT fields. Unknown or malformed jobs return EINVAL in io_errno.
 *
 * WHY: This is the single VFS-owned raw I/O chokepoint that stream AIO workers
 *      and inline fallbacks can call without touching event-loop-only state.
 *
 * HOW: Return immediately on NULL, clear reusable OUT fields, switch on op, and
 *      delegate to one static executor. Each executor captures its own errno.
 */
void
xrootd_vfs_io_execute(xrootd_vfs_job_t *job)
{
    if (job == NULL) {
        return;
    }

    xrootd_vfs_io_reset_outputs(job);

    switch (job->op) {
    case XROOTD_VFS_IO_READ:
        xrootd_vfs_io_execute_read(job);
        return;
    case XROOTD_VFS_IO_WRITE:
        xrootd_vfs_io_execute_write(job);
        return;
    case XROOTD_VFS_IO_PGREAD:
        xrootd_vfs_io_execute_pgread(job);
        return;
    case XROOTD_VFS_IO_READV:
        xrootd_vfs_io_execute_readv(job);
        return;
    case XROOTD_VFS_IO_WRITEV:
        xrootd_vfs_io_execute_writev(job);
        return;
    case XROOTD_VFS_IO_SYNC:
        xrootd_vfs_io_execute_sync(job);
        return;
    case XROOTD_VFS_IO_TRUNCATE:
        xrootd_vfs_io_execute_truncate(job);
        return;
    case XROOTD_VFS_IO_OPENDIR:
        xrootd_vfs_io_execute_opendir(job);
        return;
    }

    job->nio = -1;
    job->io_errno = EINVAL;
}
