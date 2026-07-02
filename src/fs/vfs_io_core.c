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
#include "fs/backend/sd.h"
#include "fs/core/vfs_core.h"   /* shared ngx-free VFS I/O verbs */
#include "fs/backend/csi_tagstore.h"

#include "core/aio/aio.h"
#include "dirlist/dcksm.h"
#include "path/path.h"
#include "protocol/dirlist_fmt.h"
#include "read/read.h"
#include "response/response.h"

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

/* xrootd_vfs_io_set_error_message — copy `message` into job->err_msg when the
 * caller supplied a bounded error buffer (READV/WRITEV/DIRLIST diagnostics), so
 * the worker can surface client-facing errors without touching connection state. */
static void
xrootd_vfs_io_set_error_message(xrootd_vfs_job_t *job, const char *message)
{
    if (job->err_msg == NULL || job->err_msg_cap == 0 || message == NULL) {
        return;
    }

    snprintf(job->err_msg, job->err_msg_cap, "%s", message);
}

/* xrootd_vfs_io_set_errno_message — format "<prefix>: <strerror(err)>" into
 * job->err_msg when the caller supplied an error buffer; lets vector ops report
 * segment-specific errors without calling protocol response helpers. */
static void
xrootd_vfs_io_set_errno_message(xrootd_vfs_job_t *job, const char *prefix,
    int err)
{
    if (job->err_msg == NULL || job->err_msg_cap == 0 || prefix == NULL) {
        return;
    }

    snprintf(job->err_msg, job->err_msg_cap, "%s: %s", prefix, strerror(err));
}

/* xrootd_vfs_io_write_counted — pwrite all `len` bytes (EINTR-retried) via the
 * Storage Driver seam, preserving the short-I/O fact the public full-write helper
 * hides: a 0-byte write sets *short_io + EIO and a hard error returns NGX_ERROR,
 * both with bytes-so-far in *written. The short-I/O accounting policy stays here
 * in the VFS; the raw syscall lives in the backend. */
static ngx_int_t
xrootd_vfs_io_write_counted(xrootd_sd_obj_t *job_obj, ngx_fd_t fd,
    const u_char *buf, size_t len, off_t offset, ssize_t *written,
    unsigned *short_io)
{
    xrootd_sd_obj_t  scratch;
    xrootd_sd_obj_t *obj;
    size_t           w = 0;
    int              sh = 0;
    int              rc;

    if (written == NULL || short_io == NULL) {
        errno = EINVAL;
        return NGX_ERROR;
    }

    /* The full-write loop + short-I/O accounting live in the shared `vfs` core
     * (xvfs_pwrite_full, src/fs/core/vfs_core.c — one copy shared with the
     * clients); the raw syscall stays in the backend driver. This wrapper bridges
     * the server's ssize_t/unsigned OUT params. */
    obj = xrootd_vfs_effective_obj(job_obj, fd, &scratch);
    rc = xvfs_pwrite_full(obj, buf, len, offset, &w, &sh);
    *written  = (ssize_t) w;
    *short_io = (unsigned) sh;
    return (rc == 0) ? NGX_OK : NGX_ERROR;
}

/* xrootd_vfs_io_execute_read — EOF-safe pread of job->length into job->buf,
 * filling nio/out_size and the optional CRC32c. (phase-59) When a CSI is present
 * the bytes are verified against the stored page CRCs, failing the read with EIO
 * + csi_mismatch on a mismatch rather than serving corrupt data. */
static void
xrootd_vfs_io_execute_read(xrootd_vfs_job_t *job)
{
    size_t nread;

    if ((job->fd == NGX_INVALID_FILE && job->obj.driver == NULL)
        || job->offset < 0
        || (job->length > 0 && job->buf == NULL)
        || job->buf_cap < job->length)
    {
        job->nio = -1;
        job->io_errno = EINVAL;
        return;
    }

    nread = 0;
    {
        xrootd_sd_obj_t  scratch;
        xrootd_sd_obj_t *o = xrootd_vfs_effective_obj(&job->obj, job->fd, &scratch);

        if (xvfs_pread_full(o, job->buf, job->length, job->offset, &nread) != 0)
        {
            job->nio = -1;
            job->out_size = nread;
            job->io_errno = errno;
            return;
        }
    }

    job->nio = (ssize_t) nread;
    job->out_size = nread;
    if (job->want_pgcrc && nread > 0) {
        job->crc32c = xrootd_crc32c_value(job->buf, nread);
    }

    /* phase-59 W2: verify the bytes just read against the stored page CRCs.
     * A mismatch fails the read with EIO + the csi_mismatch flag so the handler
     * maps it to kXR_ChkSumErr instead of serving corrupt data. */
    if (job->csi != NULL && nread > 0) {
        int v = xrootd_csi_verify_read((xrootd_csi_t *) job->csi, job->buf,
                                       job->offset, nread);
        if (v == XROOTD_CSI_MISMATCH) {
            job->nio = -1;
            job->io_errno = EIO;
            job->csi_mismatch = 1;
        }
    }
}

/* xrootd_vfs_io_execute_write — counted pwrite of job->buf at job->offset,
 * recording hard errors vs short writes in the job OUT fields. (phase-59) Retags
 * aligned page CRCs for the written range (fail-open; non-fatal to the write). */
static void
xrootd_vfs_io_execute_write(xrootd_vfs_job_t *job)
{
    ssize_t  written;
    unsigned short_io;

    if ((job->fd == NGX_INVALID_FILE && job->obj.driver == NULL)
        || job->offset < 0
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

    if (xrootd_vfs_io_write_counted(&job->obj, job->fd, job->buf, job->length,
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

    /* phase-59 W2: update the per-page CRC tags for the bytes just written.
     * Full pages are (re)tagged; a trailing partial page is handled by the
     * RMW-aware path in the engine. Tag-update failure is non-fatal to the
     * data write (logged by the engine); fail-open keeps writes flowing. */
    if (job->csi != NULL && written > 0) {
        (void) xrootd_csi_update_aligned((xrootd_csi_t *) job->csi, job->buf,
                                         job->offset, (size_t) written);
    }
}

/* xrootd_vfs_io_execute_pgread — read straight into the final pgread wire buffer
 * with per-page CRC32c words written in place (xrootd_pgread_read_encode_inplace),
 * giving pgread the same worker contract as a plain read. */
static void
xrootd_vfs_io_execute_pgread(xrootd_vfs_job_t *job)
{
    ssize_t nread;
    int     io_errno;

    if ((job->fd == NGX_INVALID_FILE && job->obj.driver == NULL)
        || job->offset < 0
        || (job->length > 0 && job->buf == NULL)
        || job->buf_cap < job->length)
    {
        job->nio = -1;
        job->io_errno = EINVAL;
        return;
    }

    nread = 0;
    io_errno = 0;
    {
        xrootd_sd_obj_t  scratch;
        xrootd_sd_obj_t *obj = xrootd_vfs_effective_obj(&job->obj, job->fd,
                                                        &scratch);
        job->out_size = xrootd_pgread_read_encode_inplace(obj, job->offset,
                                                          job->length, job->buf,
                                                          &nread, &io_errno,
                                                          0 /* blocking */);
    }
    job->nio = nread;
    if (nread < 0) {
        job->io_errno = io_errno;
    }
}

/* xrootd_vfs_io_execute_readv — run the pre-built, pre-validated coalesced readv
 * plan over job->segs (xrootd_readv_read_segments); out_size = per-segment headers
 * + payload bytes on success. */
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

/* xrootd_vfs_io_execute_writev — counted pwrite of each writev segment (first
 * error wins, with a segment-tagged message), accumulating out_size, then a
 * best-effort fsync of the non-empty segment fds when job->do_sync. */
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

        if (xrootd_vfs_io_write_counted(&segment->obj, segment->fd,
                                        segment->data,
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

/* xrootd_vfs_io_execute_sync — fsync one open fd via the Storage Driver seam so
 * durability routes through the same chokepoint as writes; nio=0 on success,
 * -1/io_errno on failure. */
static void
xrootd_vfs_io_execute_sync(xrootd_vfs_job_t *job)
{
    xrootd_sd_obj_t obj;

    if (job->fd == NGX_INVALID_FILE && job->obj.driver == NULL) {
        job->nio = -1;
        job->io_errno = EINVAL;
        return;
    }

    /* Durability via the shared `vfs` core (xvfs_fsync → backend driver). */
    if (xvfs_fsync(xrootd_vfs_effective_obj(&job->obj, job->fd, &obj)) != 0) {
        job->nio = -1;
        job->io_errno = errno;
        return;
    }

    job->nio = 0;
}

/* xrootd_vfs_io_execute_truncate — ftruncate one open fd to job->offset via the
 * Storage Driver seam (truncation mutates file data, so it belongs on the VFS
 * syscall chokepoint); nio=0 on success, -1/io_errno on failure. */
static void
xrootd_vfs_io_execute_truncate(xrootd_vfs_job_t *job)
{
    xrootd_sd_obj_t obj;

    if ((job->fd == NGX_INVALID_FILE && job->obj.driver == NULL)
        || job->offset < 0)
    {
        job->nio = -1;
        job->io_errno = EINVAL;
        return;
    }

    /* Truncate via the shared `vfs` core (xvfs_ftruncate → backend driver). */
    if (xvfs_ftruncate(xrootd_vfs_effective_obj(&job->obj, job->fd, &obj),
                       job->offset) != 0)
    {
        job->nio = -1;
        job->io_errno = errno;
        return;
    }

    job->nio = 0;
}

/* xrootd_vfs_io_dirlist_fail — record an OPENDIR failure (io_errno=err, nio=-1)
 * plus a bounded error string (message, else strerror(err)); the done callback
 * owns the protocol error mapping. */
static void
xrootd_vfs_io_dirlist_fail(xrootd_vfs_job_t *job, int err,
    const char *message)
{
    job->nio = -1;
    job->io_errno = err;
    xrootd_vfs_io_set_error_message(job,
                                    message != NULL ? message : strerror(err));
}

/* xrootd_vfs_io_dirlist_name_unsafe — 1 if a dir entry must be skipped: "."/".."
 * , the ".nginx-xrootd" control-file prefix, or any control/DEL byte (the
 * newline-delimited kXR_dirlist body would otherwise be corrupted/polluted). */
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

/* xrootd_vfs_io_dirlist_flush_chunk — write the kXR_oksofar header for the
 * current chunk at out + *base and advance *base past header + payload. */
static void
xrootd_vfs_io_dirlist_flush_chunk(xrootd_vfs_job_t *job, u_char *out,
    size_t *base, size_t cdpos)
{
    xrootd_build_resp_hdr(job->streamid, kXR_oksofar, (uint32_t) cdpos,
                          (ServerResponseHdr *) (out + *base));
    *base += XRD_RESPONSE_HDR_LEN + cdpos;
}

/* xrootd_vfs_io_dirlist_need_new_chunk — if the next entry won't fit the current
 * chunk, flush a kXR_oksofar chunk and reset the data cursor; fails E2BIG when one
 * more full chunk would exceed job->buf_cap (preserving the old fixed-buffer bound). */
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

/* xrootd_vfs_io_dirlist_stat_entry — for job->want_stat, fstatat the entry
 * (no-follow) and format the stat body plus optional checksum token, adding the
 * extra wire bytes to *need; NGX_DECLINED skips a vanished/unstattable entry. */
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

/* xrootd_vfs_io_dirlist_emit_entry — append the pre-counted name, optional stat
 * body, and optional checksum token into the chunk, advancing *cdpos (the byte
 * appends live in one helper so capacity invariants are easy to audit). */
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

/* xrootd_vfs_io_execute_opendir — build the complete kXR_dirlist flat response in
 * job->buf by fdopendir'ing a dup of the confined rootfd (so the scan stays
 * anchored to the directory approved on the event loop, not reopened by path):
 * optional dstat lead-in, then filtered entries with fd-relative fstat/checksum,
 * then the final kXR_ok header. */
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

/* xrootd_vfs_io_reset_outputs — clear every job OUT field (and NUL the caller's
 * error buffer) before execution, since nginx thread tasks are reused across
 * requests and stale errors or byte counts must not escape. */
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

/* xrootd_vfs_io_execute — the single VFS-owned raw-I/O chokepoint: clear the OUT
 * fields and dispatch *job to one static executor per op (EINVAL on a NULL or
 * unknown job). Callable from stream AIO workers and inline fallbacks without
 * touching event-loop-only state. */
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
