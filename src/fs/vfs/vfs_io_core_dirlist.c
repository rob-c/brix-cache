/*
 * vfs_io_core_dirlist.c — worker-safe kXR_dirlist OPENDIR response builder.
 *
 * WHAT: Implements brix_vfs_io_execute_opendir(), the OPENDIR arm of the
 *       POD-only VFS I/O execution core. It fdopendir's a dup of the confined
 *       rootfd and builds the complete flat kXR_dirlist wire response (optional
 *       dstat lead-in, filtered entries with fd-relative fstat/checksum, chunked
 *       kXR_oksofar headers, final kXR_ok) straight into the job's caller-owned
 *       buffer, mutating only the job OUT fields.
 *
 * WHY: Split out of vfs_io_core.c for the file-size guard. The dirlist scan and
 *      wire-framing helpers form one self-contained concept — the only I/O op
 *      that emits a protocol response body — so they live in their own unit and
 *      share brix_vfs_io_set_error_message / the dispatch prototype with the
 *      core via vfs_io_core_internal.h.
 *
 * HOW: The dispatcher in vfs_io_core.c calls brix_vfs_io_execute_opendir(); all
 *      other helpers here are file-local statics using only thread-safe
 *      primitives, raw syscalls, and the job's POD buffers.
 */

#include "vfs_internal.h"
#include "vfs_io_core.h"
#include "vfs_io_core_internal.h"
#include "fs/backend/sd.h"
#include "fs/core/vfs_core.h"   /* shared ngx-free VFS I/O verbs */
#include "fs/backend/csi_tagstore.h"

#include "core/aio/aio.h"
#include "protocols/root/dirlist/dcksm.h"
#include "fs/path/path.h"
#include "protocols/root/protocol/dirlist_fmt.h"
#include "protocols/root/read/read.h"
#include "protocols/root/response/response.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

/* brix_vfs_io_dirlist_fail — record an OPENDIR failure (io_errno=err, nio=-1)
 * plus a bounded error string (message, else strerror(err)); the done callback
 * owns the protocol error mapping. */
static void
brix_vfs_io_dirlist_fail(brix_vfs_job_t *job, int err,
    const char *message)
{
    job->nio = -1;
    job->io_errno = err;
    brix_vfs_io_set_error_message(job,
                                    message != NULL ? message : strerror(err));
}

/* brix_vfs_io_dirlist_name_unsafe — 1 if a dir entry must be skipped: "."/".."
 * , the ".nginx-xrootd" control-file prefix, or any control/DEL byte (the
 * newline-delimited kXR_dirlist body would otherwise be corrupted/polluted). */
static ngx_flag_t
brix_vfs_io_dirlist_name_unsafe(const char *name)
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

/* brix_vfs_io_dirlist_flush_chunk — write the kXR_oksofar header for the
 * current chunk at out + *base and advance *base past header + payload. */
static void
brix_vfs_io_dirlist_flush_chunk(brix_vfs_job_t *job, u_char *out,
    size_t *base, size_t cdpos)
{
    brix_build_resp_hdr(job->streamid, kXR_oksofar, (uint32_t) cdpos,
                          (ServerResponseHdr *) (out + *base));
    *base += XRD_RESPONSE_HDR_LEN + cdpos;
}

/* brix_vfs_io_dirlist_need_new_chunk — if the next entry won't fit the current
 * chunk, flush a kXR_oksofar chunk and reset the data cursor; fails E2BIG when one
 * more full chunk would exceed job->buf_cap (preserving the old fixed-buffer bound). */
static ngx_int_t
brix_vfs_io_dirlist_need_new_chunk(brix_vfs_job_t *job, u_char *out,
    size_t *base, u_char **cdata, size_t *cdpos, size_t need)
{
    if (*cdpos + need <= BRIX_VFS_DIRLIST_CHUNK_CAP) {
        return NGX_OK;
    }

    brix_vfs_io_dirlist_flush_chunk(job, out, base, *cdpos);
    if (*base + XRD_RESPONSE_HDR_LEN + BRIX_VFS_DIRLIST_CHUNK_CAP
        > job->buf_cap)
    {
        char message[96];

        snprintf(message, sizeof(message),
                 "listing too large for AIO buffer (%zu bytes)",
                 job->buf_cap);
        brix_vfs_io_dirlist_fail(job, E2BIG, message);
        return NGX_ERROR;
    }

    *cdata = out + *base + XRD_RESPONSE_HDR_LEN;
    *cdpos = 0;
    return NGX_OK;
}

/* brix_vfs_io_dirlist_stat_entry — for job->want_stat, fstatat the entry
 * (no-follow) and format the stat body plus optional checksum token, adding the
 * extra wire bytes to *need; NGX_DECLINED skips a vanished/unstattable entry. */
static ngx_int_t
brix_vfs_io_dirlist_stat_entry(brix_vfs_job_t *job, int dfd,
    const char *name, char *statbuf, size_t statbuf_cap,
    char *cksum_token, size_t cksum_token_cap, size_t *need)
{
    struct stat entry_st;

    statbuf[0] = '\0';
    cksum_token[0] = '\0';

    if (!job->want_stat) {
        return NGX_OK;
    }

    /* dfd < 0 (a failed dirfd upstream) and any fstatat failure — vanished
     * entry or otherwise — take the same path: skip the entry. */
    if (dfd < 0 || fstatat(dfd, name, &entry_st, AT_SYMLINK_NOFOLLOW) != 0) {
        return NGX_DECLINED;
    }

    if (job->want_cksum) {
        char        entry_path[PATH_MAX];
        const char *algo;
        int         n;

        brix_dirlist_make_dcksm_stat_body(&entry_st, statbuf, statbuf_cap);
        algo = job->cksum_algo != NULL ? job->cksum_algo : "unknown";
        n = snprintf(entry_path, sizeof(entry_path), "%s/%s",
                     job->path != NULL ? job->path : "", name);
        if (n < 0 || (size_t) n >= sizeof(entry_path)) {
            snprintf(cksum_token, cksum_token_cap, "%s:none", algo);
        } else {
            brix_dirlist_checksum_token(job->log, dfd, name, entry_path,
                                          &entry_st, algo, cksum_token,
                                          cksum_token_cap);
        }
        *need += strlen(cksum_token) + sizeof(" [  ]") - 1;

    } else {
        brix_make_stat_body(&entry_st, 0, 0, statbuf, statbuf_cap);
    }

    *need += strlen(statbuf) + 1;
    return NGX_OK;
}

/* brix_vfs_io_dirlist_emit_entry — append the pre-counted name, optional stat
 * body, and optional checksum token into the chunk, advancing *cdpos (the byte
 * appends live in one helper so capacity invariants are easy to audit). */
static void
brix_vfs_io_dirlist_emit_entry(brix_vfs_job_t *job, u_char *cdata,
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
                         BRIX_VFS_DIRLIST_CHUNK_CAP - *cdpos,
                         " [ %s ]", cksum_token);
            if (n > 0) {
                *cdpos += (size_t) n;
            }
        }

        cdata[(*cdpos)++] = '\n';
    }
}

/* brix_vfs_io_execute_opendir — build the complete kXR_dirlist flat response in
 * job->buf by fdopendir'ing a dup of the confined rootfd (so the scan stays
 * anchored to the directory approved on the event loop, not reopened by path):
 * optional dstat lead-in, then filtered entries with fd-relative fstat/checksum,
 * then the final kXR_ok header. */
void
brix_vfs_io_execute_opendir(brix_vfs_job_t *job)
{
    DIR    *dp;
    int     scanfd;
    u_char *out;
    u_char *cdata;
    size_t  base;
    size_t  cdpos;

    if (job->rootfd < 0 || job->buf == NULL) {
        brix_vfs_io_dirlist_fail(job, EINVAL, "invalid opendir job");
        return;
    }

    if (job->buf_cap < (size_t) (XRD_RESPONSE_HDR_LEN
                                 + BRIX_VFS_DIRLIST_CHUNK_CAP))
    {
        brix_vfs_io_dirlist_fail(job, ENOMEM, "response buffer too small");
        return;
    }

    scanfd = dup(job->rootfd);
    if (scanfd < 0) {
        brix_vfs_io_dirlist_fail(job, errno, NULL);
        return;
    }

    dp = fdopendir(scanfd);
    if (dp == NULL) {
        int err;

        err = errno;
        close(scanfd);
        brix_vfs_io_dirlist_fail(job, err, NULL);
        return;
    }

    out = job->buf;
    base = 0;
    cdpos = 0;
    cdata = out + XRD_RESPONSE_HDR_LEN;

    if (job->want_stat) {
        ngx_memcpy(cdata, BRIX_DSTAT_LEADIN, BRIX_DSTAT_LEADIN_LEN);
        cdpos = BRIX_DSTAT_LEADIN_LEN;
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
                brix_vfs_io_dirlist_fail(job, err, NULL);
                return;
            }
            break;
        }

        name = de->d_name;
        if (brix_vfs_io_dirlist_name_unsafe(name)) {
            continue;
        }

        nlen = strlen(name);
        need = nlen + 1;
        if (brix_vfs_io_dirlist_stat_entry(job, dirfd(dp), name,
                                             statbuf, sizeof(statbuf),
                                             cksum_token, sizeof(cksum_token),
                                             &need)
            == NGX_DECLINED)
        {
            continue;
        }

        if (brix_vfs_io_dirlist_need_new_chunk(job, out, &base, &cdata,
                                                 &cdpos, need)
            != NGX_OK)
        {
            closedir(dp);
            return;
        }

        brix_vfs_io_dirlist_emit_entry(job, cdata, &cdpos, name, nlen,
                                         statbuf, cksum_token);
    }

    closedir(dp);

    if (cdpos > 0) {
        cdata[cdpos - 1] = '\0';
    }
    brix_build_resp_hdr(job->streamid, kXR_ok, (uint32_t) cdpos,
                          (ServerResponseHdr *) (out + base));
    job->out_size = base + XRD_RESPONSE_HDR_LEN + cdpos;
    job->nio = 0;
}
