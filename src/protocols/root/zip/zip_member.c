/*
 * zip_member.c — ZIP member virtual-handle I/O (phase-57 W2). See zip_member.h.
 *
 * Read-only. The handle's fd is the ARCHIVE fd; the zip_* fields (file.h) carry
 * the member's byte range. Stored members are served by offset translation;
 * deflate members are reserved for the streaming-inflate follow-up (currently
 * rejected with kXR_Unsupported). All bookkeeping mirrors the read-only subset
 * of brix_open_resolved_file(); none of the write/POSC/WT machinery applies.
 */
#include "zip_member.h"
#include "fs/vfs/vfs.h"   /* brix_vfs_open_fd_at (handle-table confined open) */
#include "zip_dir.h"
#include "fs/backend/sd.h"   /* route ZIP member byte reads through the SD backend */
#include "fs/core/vfs_core.h"  /* xvfs_stage_fd: materialize the archive to local scratch */

#include <stdlib.h>             /* free (inflate state cleanup) */

#include "protocols/root/connection/fd_table.h"
#include "fs/path/beneath.h"
#include "fs/path/path.h"
#include "protocols/root/session/registry.h"
#include "protocols/root/response/response.h"
#include "protocols/root/protocol/wire_core_requests.h"
#include "protocols/root/protocol/opcodes.h"
#include "core/types/tunables.h"
#include "core/compat/codec_core.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <zlib.h>

/*
 * Deflate inflate state for a method-8 member (stored in fh->zip_inflate).
 *
 * ZIP members carry RAW deflate (RFC 1951, no zlib/gzip wrapper), so the stream
 * is initialised with windowBits = -15 — codec_core's DEFLATE codec is zlib-
 * wrapped (RFC 1950) and would not decode it.  `cin` is a persistent input
 * buffer so zlib's next_in stays valid across read calls (a stack buffer would
 * dangle).  The member's declared comp_size/uncomp_size bound input and output,
 * so they ARE the decompression-bomb guard — we never feed past comp_size nor
 * emit past uncomp_size.
 */
typedef struct {
    z_stream  zs;
    int       inited;
    uint64_t  in_fed;          /* compressed bytes pread from the archive so far */
    u_char    cin[64 * 1024];  /* persistent input buffer (zlib next_in target) */
} zip_infl_t;

#define ZIP_INFL_SCRATCH (64 * 1024)

static void
zip_deflate_free(brix_file_t *fh)
{
    zip_infl_t *st = fh->zip_inflate;
    if (st == NULL) {
        return;
    }
    if (st->inited) {
        inflateEnd(&st->zs);
    }
    free(st);
    fh->zip_inflate = NULL;
}

/* (Re)start the inflate stream at the member's beginning. 0 / -1. */
static int
zip_deflate_reset(brix_file_t *fh)
{
    zip_infl_t *st;

    zip_deflate_free(fh);
    st = calloc(1, sizeof(*st));
    if (st == NULL) {
        return -1;
    }
    if (inflateInit2(&st->zs, -15) != Z_OK) {   /* raw deflate */
        free(st);
        return -1;
    }
    st->inited          = 1;
    st->in_fed          = 0;
    fh->zip_inflate     = st;
    fh->zip_comp_pos    = 0;
    fh->zip_logical_pos = 0;
    return 0;
}

/*
 * Produce up to `want` uncompressed bytes into out (out == NULL → discard, for a
 * forward skip).  Returns bytes produced (may be < want at end-of-stream), or -1
 * on a decode/IO error.  Advances fh->zip_logical_pos and fh->zip_comp_pos.
 */
static ssize_t
zip_deflate_pump(brix_file_t *fh, u_char *out, size_t want)
{
    zip_infl_t *st = fh->zip_inflate;
    u_char      scratch[ZIP_INFL_SCRATCH];
    size_t      produced = 0;

    while (produced < want) {
        size_t  ocap;
        u_char *o;
        uInt    in_before, out_before;
        int     zr;

        /* Refill compressed input only once zlib has drained the buffer. */
        if (st->zs.avail_in == 0 && st->in_fed < fh->zip_comp_size) {
            uint64_t remain = fh->zip_comp_size - st->in_fed;
            size_t   cn = remain < sizeof(st->cin) ? (size_t) remain
                                                   : sizeof(st->cin);
            brix_sd_obj_t obj;
            brix_sd_posix_wrap(&obj, fh->fd);
            ssize_t  r = obj.driver->pread(&obj, st->cin, cn,
                               (off_t) (fh->zip_data_off + st->in_fed));
            if (r <= 0) {
                return -1;
            }
            st->zs.next_in  = st->cin;
            st->zs.avail_in = (uInt) r;
            st->in_fed     += (uint64_t) r;
            fh->zip_comp_pos = st->in_fed;
        }

        o    = out ? out + produced : scratch;
        ocap = want - produced;
        if (out == NULL && ocap > sizeof(scratch)) {
            ocap = sizeof(scratch);
        }

        in_before  = st->zs.avail_in;
        out_before = (uInt) ocap;
        st->zs.next_out  = o;
        st->zs.avail_out = (uInt) ocap;

        zr = inflate(&st->zs, Z_NO_FLUSH);

        produced            += out_before - st->zs.avail_out;
        fh->zip_logical_pos += out_before - st->zs.avail_out;

        if (zr == Z_STREAM_END) {
            break;
        }
        if (zr != Z_OK && zr != Z_BUF_ERROR) {
            return -1;   /* corrupt deflate stream */
        }
        /* No forward progress and no more input → truncated member; stop. */
        if (st->zs.avail_in == in_before
            && (out_before - st->zs.avail_out) == 0
            && st->in_fed >= fh->zip_comp_size)
        {
            break;
        }
    }
    return (ssize_t) produced;
}

/*
 * Serve a deflate member read at `offset` for `want` bytes into out[want].
 * Sequential reads reuse the stream; a backward seek re-inflates from the start;
 * a forward seek inflates-and-discards up to the offset. Returns bytes produced
 * or -1 on error.
 */
static ssize_t
zip_deflate_read(brix_file_t *fh, uint64_t offset, u_char *out, size_t want)
{
    if (fh->zip_inflate == NULL || offset < fh->zip_logical_pos) {
        if (zip_deflate_reset(fh) != 0) {
            return -1;
        }
    }
    while (offset > fh->zip_logical_pos) {
        uint64_t skip = offset - fh->zip_logical_pos;
        size_t   chunk = skip < ZIP_INFL_SCRATCH ? (size_t) skip
                                                 : ZIP_INFL_SCRATCH;
        ssize_t  got = zip_deflate_pump(fh, NULL, chunk);
        if (got <= 0) {
            return -1;   /* cannot reach the requested offset */
        }
    }
    return zip_deflate_pump(fh, out, want);
}

/* Read exactly n bytes at off into buf; total read on success, -1 on error. */
static ssize_t
zip_pread_full(int fd, u_char *buf, size_t n, off_t off)
{
    size_t          done = 0;
    brix_sd_obj_t obj;
    brix_sd_posix_wrap(&obj, fd);
    while (done < n) {
        ssize_t r = obj.driver->pread(&obj, buf + done, n - done,
                                                 off + (off_t) done);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (r == 0) {
            break;   /* short file — return what we got */
        }
        done += (size_t) r;
    }
    return (ssize_t) done;
}

ngx_int_t
brix_zip_open_member(brix_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_brix_srv_conf_t *conf, const char *archive_logical,
    const char *archive_full, const char *member, uint16_t options)
{
    int                  fd, idx, zrc;
    struct stat          ast;
    brix_zip_member_t  m;
    size_t               cd_max;

    /* Open the archive read-only, confined beneath the export root (same
     * RESOLVE_BENEATH path the normal read open uses). */
    fd = brix_vfs_open_fd_at(conf->rootfd, archive_logical,
                             O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        int err = errno;
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", archive_full,
                          "zip",
                          (err == ENOENT || err == ENOTDIR) ? kXR_NotFound
                          : (err == EACCES) ? kXR_NotAuthorized : kXR_IOError,
                          "cannot open zip archive");
    }
    if (fstat(fd, &ast) != 0 || !S_ISREG(ast.st_mode)) {
        close(fd);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", archive_full,
                          "zip", kXR_IOError, "zip archive not a regular file");
    }

    /* CONSUME via the materialize-to-scratch seam: zip is built on random-access
     * pread over the archive fd (+ sendfile for stored members), which a backend
     * with no kernel fd cannot serve.  When staging is in effect, copy the archive
     * into a local POSIX scratch (anonymous fd) and read THAT.  Capability + size
     * gated; POSIX is a no-op (read the confined fd in place).  Config:
     * brix_zip_stage_dir + brix_zip_force_scratch + brix_zip_stage_max_bytes. */
    {
        const char *sdir = (conf->zip_stage_dir.len > 0)
                           ? (const char *) conf->zip_stage_dir.data : NULL;
        off_t       maxb = (off_t) conf->zip_stage_max_bytes;

        /* The default POSIX archive already has a kernel fd — only materialize a
         * local scratch copy when explicitly forced (a backend without CAP_FD is
         * the future case, but this open path only sees POSIX archives today). */
        if (conf->zip_force_scratch
            && sdir != NULL && sdir[0] != '\0'
            && ast.st_size <= maxb)
        {
            ngx_fd_t sfd = xvfs_stage_fd(fd, sdir);
            if (sfd == NGX_INVALID_FILE) {
                close(fd);
                BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", archive_full,
                                  "zip", kXR_IOError, "zip archive staging failed");
            }
            close(fd);
            fd = sfd;                        /* same bytes/size — ast still valid */
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "zip: archive staged to scratch (%O bytes)",
                          (off_t) ast.st_size);
        }
    }

    cd_max = conf->zip_cd_max_bytes ? conf->zip_cd_max_bytes
                                    : (size_t) (16 * 1024 * 1024);
    zrc = brix_zip_find_member(fd, (off_t) ast.st_size, member, cd_max, &m);
    if (zrc != BRIX_ZIP_OK) {
        close(fd);
        if (zrc == BRIX_ZIP_NOMEMBER) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", archive_full,
                              "zip", kXR_NotFound, "zip member not found");
        }
        /* ECORRUPT covers corrupt/oversize/unsupported (encrypted, method,
         * data-descriptor); EIO covers pread/alloc failure. */
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", archive_full,
                          "zip",
                          (zrc == BRIX_ZIP_EIO) ? kXR_IOError : kXR_Unsupported,
                          "zip member unreadable");
    }

    idx = brix_alloc_fhandle(ctx);
    if (idx < 0) {
        close(fd);
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_OPEN_RD, "OPEN", archive_full,
                          "zip", kXR_ServerError, "too many open files");
    }

    ctx->files[idx].fd              = fd;
    ctx->files[idx].readable        = 1;
    ctx->files[idx].writable        = 0;
    ctx->files[idx].from_cache      = 0;
    ctx->files[idx].is_regular      = 1;       /* member reads behave as a file */
    ctx->files[idx].device          = ast.st_dev;
    ctx->files[idx].inode           = ast.st_ino;
    ctx->files[idx].cached_size     = (off_t) m.uncomp_size;
    ctx->files[idx].read_last_end   = -1;
    ctx->files[idx].read_ahead_end  = 0;
    ctx->files[idx].read_codec      = (uint8_t) BRIX_CODEC_IDENTITY;
    ctx->files[idx].write_codec     = (uint8_t) BRIX_CODEC_IDENTITY;
    ctx->files[idx].dashboard_slot  = -1;

    ctx->files[idx].zip_mode        = 1;
    ctx->files[idx].zip_method      = m.method;
    ctx->files[idx].zip_data_off    = m.data_off;
    ctx->files[idx].zip_comp_size   = m.comp_size;
    ctx->files[idx].zip_uncomp_size = m.uncomp_size;
    ctx->files[idx].zip_crc32       = m.crc32;
    ctx->files[idx].zip_inflate     = NULL;
    ctx->files[idx].zip_logical_pos = 0;
    ctx->files[idx].zip_comp_pos    = 0;

    if (brix_set_fhandle_path(ctx, c, idx, archive_full) != NGX_OK) {
        brix_free_fhandle(ctx, idx);
        return NGX_ERROR;
    }

    ctx->files[idx].bytes_read    = 0;
    ctx->files[idx].bytes_written = 0;
    ctx->files[idx].open_time     = ngx_current_msec;

    if (!ctx->is_bound) {
        brix_session_handle_publish(ctx->login.sessid, idx, &ctx->files[idx]);
    }

    /* Build the kXR_open reply: the 4-byte handle by default, the full body +
     * stat (member's UNCOMPRESSED size) when the client set kXR_retstat. */
    {
        ServerOpenBody  body;
        char            statbuf[256];
        u_char         *buf;
        size_t          hbytes, bodylen, total;
        ngx_flag_t      want_stat = (options & kXR_retstat) ? 1 : 0;

        ngx_memzero(&body, sizeof(body));
        body.fhandle[0] = (u_char) idx;

        statbuf[0] = '\0';
        if (want_stat) {
            snprintf(statbuf, sizeof(statbuf), "%llu %lld %d %ld",
                     (unsigned long long) ast.st_ino,
                     (long long) m.uncomp_size,
                     kXR_readable,
                     (long) ast.st_mtime);
        }

        hbytes  = want_stat ? sizeof(ServerOpenBody) : sizeof(body.fhandle);
        bodylen = hbytes + (want_stat ? strlen(statbuf) + 1 : 0);
        total   = XRD_RESPONSE_HDR_LEN + bodylen;

        buf = ngx_palloc(c->pool, total);
        if (buf == NULL) {
            brix_free_fhandle(ctx, idx);
            return NGX_ERROR;
        }
        brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok, (uint32_t) bodylen,
                              (ServerResponseHdr *) buf);
        ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN, &body, hbytes);
        if (want_stat) {
            ngx_memcpy(buf + XRD_RESPONSE_HDR_LEN + sizeof(ServerOpenBody),
                       statbuf, strlen(statbuf) + 1);
        }

        brix_log_access(ctx, c, "OPEN", archive_full, "zip", 1, 0, NULL, 0);
        BRIX_OP_OK(ctx, BRIX_OP_OPEN_RD);
        return brix_queue_response(ctx, c, buf, total);
    }
}

ngx_int_t
brix_zip_read(brix_ctx_t *ctx, ngx_connection_t *c, int idx,
    int64_t offset, size_t rlen)
{
    brix_file_t *fh = &ctx->files[idx];
    u_char        *buf;
    ssize_t        n;

    /* Past EOF → empty (matches a normal read beyond file size). */
    if ((uint64_t) offset >= fh->zip_uncomp_size) {
        BRIX_OP_OK(ctx, BRIX_OP_READ);
        return brix_send_ok(ctx, c, NULL, 0);
    }
    if ((uint64_t) offset + rlen > fh->zip_uncomp_size) {
        rlen = (size_t) (fh->zip_uncomp_size - (uint64_t) offset);
    }

    if (fh->zip_method == BRIX_ZIP_METHOD_STORE) {
        buf = ngx_palloc(c->pool, rlen);
        if (buf == NULL) {
            return brix_send_error(ctx, c, kXR_NoMemory, "zip read OOM");
        }
        n = zip_pread_full(fh->fd, buf, rlen,
                           (off_t) (fh->zip_data_off + (uint64_t) offset));
        if (n < 0) {
            BRIX_RETURN_ERR(ctx, c, BRIX_OP_READ, "READ",
                              fh->path ? fh->path : "-", "zip",
                              kXR_IOError, "zip member read failed");
        }
        fh->bytes_read += (size_t) n;
        BRIX_OP_OK(ctx, BRIX_OP_READ);
        return brix_send_ok(ctx, c, buf, (size_t) n);
    }

    /* Deflate (method 8): streaming raw inflate. */
    buf = ngx_palloc(c->pool, rlen);
    if (buf == NULL) {
        return brix_send_error(ctx, c, kXR_NoMemory, "zip read OOM");
    }
    n = zip_deflate_read(fh, (uint64_t) offset, buf, rlen);
    if (n < 0) {
        BRIX_RETURN_ERR(ctx, c, BRIX_OP_READ, "READ",
                          fh->path ? fh->path : "-", "zip",
                          kXR_IOError, "zip member inflate failed");
    }
    fh->bytes_read += (size_t) n;
    BRIX_OP_OK(ctx, BRIX_OP_READ);
    return brix_send_ok(ctx, c, buf, (size_t) n);
}

void
brix_zip_handle_cleanup(brix_file_t *fh)
{
    if (fh == NULL) {
        return;
    }
    zip_deflate_free(fh);   /* inflateEnd + free the zip_infl_t (NULL-safe) */
}
