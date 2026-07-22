/*
 * Directory listing handler — chunked entry streaming.
 * Enumerates an open VFS directory handle and renders each visible entry into
 * the newline-delimited kXR_dirlist wire format, flushing full 64KB chunks as
 * kXR_oksofar continuation frames and finishing with a single kXR_ok frame.
 * Extracted verbatim from handler.c; shared walk state + the public entry point
 * live in dirlist_handler_internal.h.
 */

#include "core/ngx_brix_module.h"
#include "core/aio/aio.h"
#include "protocols/root/path/op_path.h"
#include "net/manager/registry.h"
#include "protocols/root/protocol/dirlist_fmt.h"   /* shared dstat lead-in sentinel */
#include "fs/vfs/vfs.h"                 /* directory listing via the VFS seam */
#include "fs/path/reserved_names.h"     /* brix_is_internal_name — hide sidecars */
#include "dcksm.h"
#include "dirlist_handler_internal.h"

/*
 * brix_dirlist_entry_fmt_t — formatted per-entry output produced by
 * brix_dirlist_entry_meta and consumed by brix_dirlist_append_entry.
 *
 * Carries the rendered stat line, the optional checksum token, whether stat
 * data is valid for this entry, and the total wire bytes the entry needs so
 * the streaming loop can decide when to flush a kXR_oksofar chunk.
 */
typedef struct {
    char        statbuf[256];                        /* rendered stat line */
    char        cksum_token[EVP_MAX_MD_SIZE * 2 + 64]; /* "algo:hex" token */
    ngx_flag_t  have_stat;                           /* statbuf is valid */
    size_t      need;                                /* wire bytes required */
} brix_dirlist_entry_fmt_t;

/*
 * brix_dirlist_name_is_unsafe — detect control characters in a directory
 * entry name that would corrupt the newline-delimited kXR_dirlist wire format.
 *
 * The XRootD dirlist response separates entries with '\n'.  A filename
 * containing '\n' (or any other byte < 0x20) would be misinterpreted as a
 * record separator by the client.  Such filenames are skipped silently.
 *
 * Returns 1 (unsafe, skip this entry), 0 (safe to include).
 */
static ngx_flag_t
brix_dirlist_name_is_unsafe(const char *name)
{
    const u_char *p;

    for (p = (const u_char *) name; *p != '\0'; p++) {
        if (*p < 0x20 || *p == 0x7f) {
            return 1;
        }
    }

    return 0;
}

/*
 * brix_dirlist_entry_skip — decide whether a directory entry must be
 * excluded from the listing.
 *
 * Skips "." and "..", this gateway's internal control artifacts (e.g. the
 * checkpoint recovery lock — a stock XRootD export shows no such files;
 * mirror that), internal metadata/staging artifacts (cache sidecars, stage
 * markers, in-flight upload temps — never enumerable to a client), and names
 * with control bytes that would corrupt the wire format (logged at WARN).
 *
 * Returns 1 (skip this entry), 0 (include it).
 */
static ngx_flag_t
brix_dirlist_entry_skip(ngx_log_t *log, const char *name)
{
    char safe_name[256];

    if (name[0] == '.' && (name[1] == '\0' ||
        (name[1] == '.' && name[2] == '\0')))
    {
        return 1;
    }

    if (ngx_strncmp(name, ".nginx-xrootd",
                    sizeof(".nginx-xrootd") - 1) == 0)
    {
        return 1;
    }

    if (brix_is_internal_name(name)) {
        return 1;
    }

    if (brix_dirlist_name_is_unsafe(name)) {
        brix_sanitize_log_string(name, safe_name, sizeof(safe_name));
        ngx_log_error(NGX_LOG_WARN, log, 0,
                      "brix: dirlist skipping entry with control bytes \"%s\"",
                      safe_name);
        return 1;
    }

    return 0;
}

/*
 * brix_dirlist_entry_meta — render the optional stat line and checksum
 * token for one entry, accumulating the wire bytes it needs into fmt->need.
 *
 * readdir already did the no-follow lstat (and skipped any entry whose stat
 * failed), so vst is valid whenever want_stat is set.  The dcksm variant
 * uses the dcksm stat-body format; the checksum token falls back to
 * "algo:none" when the entry path would overflow PATH_MAX.
 *
 * fmt->need must be pre-seeded with the bare name length + '\n'.
 */
static void
brix_dirlist_entry_meta(ngx_log_t *log, brix_dirlist_walk_t *walk,
    const char *name, const brix_vfs_stat_t *vst,
    brix_dirlist_entry_fmt_t *fmt)
{
    struct stat entry_st;
    char        entry_path[PATH_MAX];

    fmt->cksum_token[0] = '\0';
    fmt->have_stat = 0;

    if (walk->want_stat) {
        ngx_memzero(&entry_st, sizeof(entry_st));
        entry_st.st_mode   = (mode_t) vst->mode;
        entry_st.st_size   = vst->size;
        entry_st.st_mtime  = vst->mtime;
        entry_st.st_ctime  = vst->ctime;
        entry_st.st_ino    = vst->ino;
        entry_st.st_dev    = vst->dev;
        entry_st.st_uid    = vst->uid;
        entry_st.st_gid    = vst->gid;
        entry_st.st_blocks = vst->blocks;

        fmt->have_stat = 1;
        if (walk->want_cksum) {
            brix_dirlist_make_dcksm_stat_body(&entry_st, fmt->statbuf,
                                                sizeof(fmt->statbuf));
        } else {
            brix_make_stat_body(&entry_st, 0, 0, fmt->statbuf,
                                  sizeof(fmt->statbuf));
        }
        fmt->need += strlen(fmt->statbuf) + 1;
    }

    if (walk->want_cksum && fmt->have_stat) {
        int n;

        n = snprintf(entry_path, sizeof(entry_path), "%s/%s",
                     walk->full_path, name);
        if (n < 0 || (size_t) n >= sizeof(entry_path)) {
            snprintf(fmt->cksum_token, sizeof(fmt->cksum_token),
                     "%s:none", walk->cksum_algo);
        } else {
            brix_dirlist_checksum_token(log,
                                          brix_vfs_dir_fd(walk->dh), name,
                                          entry_path, &entry_st,
                                          walk->cksum_algo, fmt->cksum_token,
                                          sizeof(fmt->cksum_token));
        }
        fmt->need += strlen(fmt->cksum_token) + sizeof(" [  ]") - 1;
    }
}

/*
 * brix_dirlist_flush_chunk — frame the accumulated chunk as a kXR_oksofar
 * continuation and queue it, resetting the accumulator for the next chunk.
 *
 * Returns the brix_queue_response result (NGX_OK on success).
 */
static ngx_int_t
brix_dirlist_flush_chunk(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_dirlist_walk_t *walk)
{
    ngx_int_t rc;

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_oksofar,
                          (uint32_t) walk->chunk_pos,
                          (ServerResponseHdr *) walk->chunk);

    rc = brix_queue_response(ctx, c, walk->chunk,
                               XRD_RESPONSE_HDR_LEN + walk->chunk_pos);
    if (rc != NGX_OK) {
        return rc;
    }

    walk->chunk_pos = 0;
    return NGX_OK;
}

/*
 * brix_dirlist_append_entry — copy one formatted entry into the chunk
 * accumulator: name '\n' [statline [" [ token ]"] '\n'].
 *
 * The caller has already guaranteed fmt->need bytes of headroom by flushing
 * a full chunk beforehand, so the copies cannot overflow chunk_cap.
 */
static void
brix_dirlist_append_entry(brix_dirlist_walk_t *walk, const char *name,
    size_t nlen, const brix_dirlist_entry_fmt_t *fmt)
{
    u_char *data = walk->chunk + XRD_RESPONSE_HDR_LEN;

    ngx_memcpy(data + walk->chunk_pos, name, nlen);
    walk->chunk_pos += nlen;
    data[walk->chunk_pos++] = '\n';

    if (walk->want_stat && fmt->have_stat) {
        size_t slen;

        slen = strlen(fmt->statbuf);
        ngx_memcpy(data + walk->chunk_pos, fmt->statbuf, slen);
        walk->chunk_pos += slen;

        if (walk->want_cksum) {
            int n;

            n = snprintf((char *) data + walk->chunk_pos,
                         walk->chunk_cap - walk->chunk_pos,
                         " [ %s ]", fmt->cksum_token);
            if (n > 0) {
                walk->chunk_pos += (size_t) n;
            }
        }

        data[walk->chunk_pos++] = '\n';
    }
}

/*
 * brix_dirlist_send_final — frame the last accumulated chunk as kXR_ok to
 * signal end-of-listing, log the access, and bump the success metric.
 *
 * The trailing '\n' of the final entry is replaced by a NUL terminator (an
 * empty listing sends a zero-length body).
 *
 * Returns the brix_queue_response result.
 */
static ngx_int_t
brix_dirlist_send_final(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_dirlist_walk_t *walk)
{
    u_char *data = walk->chunk + XRD_RESPONSE_HDR_LEN;
    size_t  final_len;

    if (walk->chunk_pos == 0) {
        final_len = 0;
    } else {
        data[walk->chunk_pos - 1] = '\0';
        final_len = walk->chunk_pos;
    }

    brix_build_resp_hdr(ctx->recv.cur_streamid, kXR_ok,
                          (uint32_t) final_len,
                          (ServerResponseHdr *) walk->chunk);

    ngx_log_debug1(NGX_LOG_DEBUG_STREAM, c->log, 0,
                   "brix: kXR_dirlist final chunk %uz bytes",
                   walk->chunk_pos);

    brix_log_access(ctx, c, "DIRLIST", walk->reqpath,
                      walk->want_cksum ? "dcksm"
                                       : (walk->want_stat ? "stat" : "-"),
                      1, 0, NULL, 0);
    BRIX_OP_OK(ctx, BRIX_OP_DIRLIST);

    return brix_queue_response(ctx, c, walk->chunk,
                                 XRD_RESPONSE_HDR_LEN + final_len);
}

/*
 * brix_dirlist_stream_entries — the chunked streaming loop: enumerate the
 * open directory, format each visible entry, flush full 64KB chunks as
 * kXR_oksofar frames, and finish with the kXR_ok final frame.
 *
 * Owns walk->dh from here on: the handle is closed on every exit path
 * (queue failure mid-stream or normal end-of-directory).
 *
 * Returns the final queue result (NGX_OK on success).
 */
ngx_int_t
brix_dirlist_stream_entries(brix_ctx_t *ctx, ngx_connection_t *c,
    brix_dirlist_walk_t *walk)
{
    ngx_str_t         entry_name;
    brix_vfs_stat_t entry_vst;
    ngx_int_t         rc;

    while (brix_vfs_readdir(walk->dh, &entry_name,
                              walk->want_stat ? &entry_vst : NULL) == NGX_OK) {
        const char                *name = (char *) entry_name.data;
        size_t                     nlen = entry_name.len;
        brix_dirlist_entry_fmt_t fmt;

        if (brix_dirlist_entry_skip(c->log, name)) {
            continue;
        }

        fmt.need = nlen + 1;
        brix_dirlist_entry_meta(c->log, walk, name, &entry_vst, &fmt);

        if (walk->chunk_pos + fmt.need > walk->chunk_cap) {
            rc = brix_dirlist_flush_chunk(ctx, c, walk);
            if (rc != NGX_OK) {
                brix_vfs_closedir(walk->dh, c->log);
                return rc;
            }
        }

        brix_dirlist_append_entry(walk, name, nlen, &fmt);
    }

    brix_vfs_closedir(walk->dh, c->log);

    return brix_dirlist_send_final(ctx, c, walk);
}
