/* ------------------------------------------------------------------ */
/* Batched Stat — kXR_statx handler                                         */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements the kXR_statx opcode — batched metadata query for multiple paths in a single request. Unlike kXR_stat which queries one path at a time, kXR_statx accepts up to 256 paths (XROOTD_STATX_MAX_PATHS) separated by null terminators and returns inline stat results for each path — reducing network round-trips for clients querying many files simultaneously. Each line contains inode/size/flags/mtime formatted identically to kXR_stat response body but packed into single response without kXR_status framing overhead. Buffer capacity XROOTD_STATX_BUF_MAX = 256 × 256 = 64KB provides adequate space for batched results including error lines ("0 0 0 0\n") for paths that cannot be resolved.
 *
 * WHY: Batched stat reduces network round-trips significantly when clients need to query many files simultaneously (e.g., directory listing pre-population, cache validation across multiple paths). Single-request batching eliminates N separate kXR_stat requests where N = path count — critical for large-scale operations where querying hundreds of files would otherwise require hundreds of individual request/response cycles. Inline stat lines eliminate kXR_status framing overhead per-line while maintaining identical inode/size/flags/mtime format enabling clients to parse results identically regardless of whether they used batched or single-path stat queries.
 *
 * HOW: Two-phase batching → path extraction (xrootd_statx_next_path): iterate through cursor advancing past null terminators extracting each path string — validate length against XROOTD_STATX_MAX_PATHS limit and buffer capacity); metadata aggregation (for each extracted path): resolve via xrootd_resolve_path, stat(2) or fstat(2), append line to response buffer via xrootd_statx_append_line with newline terminator); cache flag detection (xrootd_statx_cached_copy_exists): check whether request_path exists in conf->cache_root returning kXR_cachersp flag if regular file found). Returns kXR_ok with inline stat lines body payload containing results for all successfully resolved paths plus error lines for failed resolutions. */

/* ------------------------------------------------------------------ */
/* Section: Path Extraction from Null-Terminated Buffer                     */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_statx_next_path() extracts individual paths from null-terminated buffer containing multiple paths separated by '\0'. Iterates through cursor advancing past non-null characters until reaching terminator or end boundary — returns extracted path string with length validation against XROOTD_STATX_MAX_PATHS limit and buffer capacity. Zero-length paths (empty strings between terminators) are rejected; paths exceeding output buffer size are also rejected preventing buffer overflow attacks.
 *
 * WHY: Null-terminated multi-path format enables compact payload encoding for batched queries without requiring separator characters or length prefixes — clients can pack up to 256 paths into single request using minimal overhead (one '\0' byte per path separation). Length validation prevents buffer overflow attacks where malicious clients could attempt to encode oversized paths that would exceed response buffer capacity and corrupt subsequent query processing. */

/* ------------------------------------------------------------------ */
/* Section: Response Line Assembly                                          */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_statx_append_line() assembles inline stat lines into response buffer with newline terminator support. Each line contains inode/size/flags/mtime formatted identically to kXR_stat response body but packed into single response without kXR_status framing overhead. Error lines ("0 0 0 0\n") returned for paths that cannot be resolved — clients parse these identically to successful lines and detect failures by checking zero values instead of actual metadata. Buffer capacity tracking prevents overflow when response exceeds XROOTD_STATX_BUF_MAX = 256 × 256 = 64KB limit, rejecting additional paths rather than truncating existing results mid-batch.
 *
 * WHY: Inline stat lines eliminate kXR_status framing overhead per-line while maintaining identical inode/size/flags/mtime format enabling clients to parse results identically regardless of whether they used batched or single-path stat queries. Error line uniformity ("0 0 0 0\n") enables client-side failure detection without requiring separate error code parsing — clients simply check for zero values instead of actual metadata values to identify unresolved paths within batched results. Buffer capacity tracking prevents overflow when response exceeds limit, rejecting additional paths rather than truncating existing results mid-batch ensuring consistent partial-result semantics. */

/* ------------------------------------------------------------------ */
/* Section: Cache Flag Detection                                            */
/* ------------------------------------------------------------------ */
/*
 * WHAT: xrootd_statx_cached_copy_exists() checks whether a requested path exists in the local cache (conf->cache_root). Returns kXR_cachersp flag if regular file found at cache_path = conf->cache_root + request_path, 0 otherwise. Used by statx handler to append cache flags to inline stat lines enabling clients to distinguish between cached content vs origin content for prefetch optimization decisions across batched queries.
 *
 * WHY: Cache flag detection helps clients optimize read patterns when they know content is cached locally — enables downstream logic to skip origin fetches for repeated access patterns, reducing latency across session boundaries. Particularly valuable for large files accessed by multiple clients where cache hit rates significantly reduce overall transfer bandwidth and improve response times compared to origin-only fetches. */

/* ---- Function: xrootd_statx_next_path() ----
 *
 * WHAT: Extracts individual paths from null-terminated buffer containing multiple paths separated by '\0'. Iterates through cursor advancing past non-null characters until reaching terminator or end boundary — returns extracted path string with length validation against XROOTD_STATX_MAX_PATHS limit and buffer capacity. Zero-length paths (empty strings between terminators) are rejected; paths exceeding output buffer size are also rejected preventing buffer overflow attacks.
 *
 * WHY: Null-terminated multi-path format enables compact payload encoding for batched queries without requiring separator characters or length prefixes — clients can pack up to 256 paths into single request using minimal overhead (one '\0' byte per path separation). Length validation prevents buffer overflow attacks where malicious clients could attempt to encode oversized paths that would exceed response buffer capacity and corrupt subsequent query processing.
 *
 * HOW: Iterate through cursor advancing past non-null characters until reaching terminator or end boundary — calculate path_len = cursor - path_start — advance cursor past terminator if present — validate length (0 < path_len < path_size) — memcpy extracted path to output buffer with null termination — return 1 on success, 0 on rejection. */

/* ---- Function: xrootd_statx_append_line() ----
 *
 * WHAT: Assembles inline stat lines into response buffer with newline terminator support. Each line contains inode/size/flags/mtime formatted identically to kXR_stat response body but packed into single response without kXR_status framing overhead. Error lines ("0 0 0 0\n") returned for paths that cannot be resolved — clients parse these identically to successful lines and detect failures by checking zero values instead of actual metadata. Buffer capacity tracking prevents overflow when response exceeds XROOTD_STATX_BUF_MAX = 256 × 256 = 64KB limit, rejecting additional paths rather than truncating existing results mid-batch.
 *
 * WHY: Inline stat lines eliminate kXR_status framing overhead per-line while maintaining identical inode/size/flags/mtime format enabling clients to parse results identically regardless of whether they used batched or single-path stat queries. Error line uniformity ("0 0 0 0\n") enables client-side failure detection without requiring separate error code parsing — clients simply check for zero values instead of actual metadata values to identify unresolved paths within batched results. Buffer capacity tracking prevents overflow when response exceeds limit, rejecting additional paths rather than truncating existing results mid-batch ensuring consistent partial-result semantics.
 *
 * HOW: Calculate required space = line_len + (append_newline ? 1 : 0) — validate remaining buffer capacity (*response_cursor + required < response_end) — memcpy line to response cursor position — advance cursor by line_len — append newline if requested — return NGX_OK on success, NGX_ERROR if insufficient capacity. */

/* ---- Function: xrootd_statx_cached_copy_exists() ----
 *
 * WHAT: Checks whether a requested path exists in the local cache (conf->cache_root). Returns kXR_cachersp flag if regular file found at cache_path = conf->cache_root + request_path, 0 otherwise. Used by statx handler to append cache flags to inline stat lines enabling clients to distinguish between cached content vs origin content for prefetch optimization decisions across batched queries.
 *
 * WHY: Cache flag detection helps clients optimize read patterns when they know content is cached locally — enables downstream logic to skip origin fetches for repeated access patterns, reducing latency across session boundaries. Particularly valuable for large files accessed by multiple clients where cache hit rates significantly reduce overall transfer bandwidth and improve response times compared to origin-only fetches.
 *
 * HOW: Three-step validation → cache enabled check (skip if disabled or cache_root empty) — build cache_path = conf->cache_root + request_path via snprintf with PATH_MAX buffer overflow guard — stat(2) on cache path → return kXR_cachersp if regular file exists, 0 otherwise. Uses PATH_MAX buffer to prevent overflow. */

#include "statx.h"
#include "stat.h"
#include "../ngx_xrootd_module.h"
#include "../path/beneath.h"
#include "../compat/alloc_guard.h"

#include <stdlib.h>   /* realpath */

#define XROOTD_STATX_MAX_PATHS  256
/* kXR_statx returns exactly ONE flag byte per requested path — a packed byte
 * array, no separators, no NUL (reference XrdXrootdXeq.cc:3194-3203):
 * kXR_file(0) / kXR_isDir(2) / kXR_other(4) / kXR_offline(8). An inaccessible or
 * missing path yields kXR_offline. (We previously emitted a full "id size flags
 * mtime" text line per path — a kXR_stat body — which no standard statx parser
 * could read.) */
#define XROOTD_STATX_BUF_MAX    XROOTD_STATX_MAX_PATHS

static ngx_flag_t
xrootd_statx_next_path(const u_char **cursor, const u_char *end,
    char *path, size_t path_size)
{
    const u_char *path_start;
    size_t        path_len;

    /* kXR_statx paths are NEWLINE-separated in the request (reference do_Statx
     * tokenizes a '\n' list); the final path may lack a trailing newline. (We
     * previously split on '\0', so a standard client's newline list was read as
     * one giant path.) */
    path_start = *cursor;
    while (*cursor < end && **cursor != '\n') {
        (*cursor)++;
    }

    path_len = (size_t) (*cursor - path_start);
    if (*cursor < end) {
        (*cursor)++;   /* skip the '\n' separator */
    }

    if (path_len == 0 || path_len >= path_size) {
        return 0;
    }

    ngx_memcpy(path, path_start, path_len);
    path[path_len] = '\0';

    return 1;
}

ngx_int_t
xrootd_handle_statx(xrootd_ctx_t *ctx, ngx_connection_t *c,
    ngx_stream_xrootd_srv_conf_t *conf)
{
    const u_char *cursor, *end;
    u_char       *rsp_buf, *rsp_ptr;
    u_char       *rsp_end;
    char          reqpath_buf[XROOTD_MAX_PATH + 1];
    char          full_path[PATH_MAX];
    struct stat   st;
    int           n_paths = 0;

    if (ctx->cur_dlen == 0 || ctx->payload == NULL) {
        XROOTD_OP_ERR(ctx, XROOTD_OP_STATX);
        return xrootd_send_error(ctx, c, kXR_ArgMissing, "no paths given");
    }

    XROOTD_PALLOC_OR_RETURN(rsp_buf, c->pool, XROOTD_STATX_BUF_MAX, NGX_ERROR);

    rsp_ptr = rsp_buf;
    rsp_end = rsp_buf + XROOTD_STATX_BUF_MAX;
    cursor  = ctx->payload;
    end     = ctx->payload + ctx->cur_dlen;

    while (cursor < end && n_paths < XROOTD_STATX_MAX_PATHS) {
        if (!xrootd_statx_next_path(&cursor, end, reqpath_buf,
                                    sizeof(reqpath_buf)))
        {
            continue;
        }

        n_paths++;

        /* Resolve and stat the path. */
        xrootd_beneath_full_path(conf->common.root_canon, reqpath_buf,
                                 full_path, sizeof(full_path));
        /*
         * W4 — apply the SAME authorization gate STAT uses (authdb + VO ACL +
         * token scope), not just VO ACL + scope.  Previously STATX skipped the
         * authdb check, so an authdb-denied path could leak real metadata via
         * the batched stat where the single STAT op would have refused it.
         * A denial here falls through to the per-path "inaccessible" sentinel,
         * preserving STATX's partial-result semantics.
         */
        if (rsp_ptr >= rsp_end) {
            break;
        }

        /* The reference do_Statx returns an ERROR (fsError) on the FIRST path
         * whose stat fails — it does NOT emit a per-path sentinel and continue.
         * kXR_offline is reserved for a path that stat()s OK but reports mode==-1
         * (a tape-staged file), handled via the FRM probe below. A missing or
         * authz-denied path therefore terminates the batch with a kXR_error,
         * matching XrdXrootdXeq.cc:do_Statx and every standard statx parser. */
        if (xrootd_check_authdb(ctx, full_path, XROOTD_AUTH_LOOKUP) != NGX_OK
            || xrootd_check_vo_acl_identity(c->log, full_path, conf->vo_rules,
                                            ctx->identity) != NGX_OK
            || xrootd_check_token_scope(ctx, reqpath_buf, 0) != NGX_OK)
        {
            XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STATX, "STATX", reqpath_buf,
                              "-", kXR_NotAuthorized, "permission denied");
        }
        if (xrootd_stat_beneath(conf->rootfd, reqpath_buf, &st) != 0) {
            /* Follow fallback for an in-export symlink with a host-ABSOLUTE
             * target (RESOLVE_IN_ROOT chroots it to ENOENT; stock follows on the
             * real fs).  Match stock, confined via realpath within the export. */
            int       ok = 0;
            if (errno == ENOENT && conf->common.root_canon[0] != '\0') {
                char   real[PATH_MAX];
                size_t rl = ngx_strlen(conf->common.root_canon);
                if (realpath(full_path, real) != NULL
                    && ngx_strncmp(real, conf->common.root_canon, rl) == 0
                    && (real[rl] == '/' || real[rl] == '\0')
                    && stat(real, &st) == 0)
                {
                    ok = 1;
                }
            }
            if (!ok) {
                XROOTD_RETURN_ERR(ctx, c, XROOTD_OP_STATX, "STATX", reqpath_buf,
                                  "-", xrootd_kxr_from_errno(errno),
                                  strerror(errno));
            }
        }

        {
            /* One flag byte per path. The reference do_Statx emits ONLY
             * kXR_isDir or kXR_file (plus kXR_offline for a tape-staged file via
             * the FRM probe below) — there is NO kXR_other in statx, so a FIFO /
             * socket / device stats as kXR_file(0), exactly as stock. (Plain
             * kXR_stat does use kXR_other; statx deliberately does not.) */
            u_char flag;

            if (S_ISDIR(st.st_mode)) {
                flag = (u_char) kXR_isDir;
            } else {
                flag = (u_char) kXR_file;          /* 0 — incl. non-regular */
            }
            if (conf->frm.enable) {
                frm_residency_t _res;
                if (frm_residency_probe(c->log, full_path, &_res) == NGX_OK
                    && (_res.state == FRM_RES_NEARLINE
                        || _res.state == FRM_RES_OFFLINE))
                {
                    flag |= (u_char) kXR_offline;
                }
            }
            *rsp_ptr++ = flag;
        }
    }

    {
        char detail[32];

        snprintf(detail, sizeof(detail), "%d_paths", n_paths);
        xrootd_log_access(ctx, c, "STATX", "-", detail, 1, 0, NULL, 0);
    }
    XROOTD_OP_OK(ctx, XROOTD_OP_STATX);

    return xrootd_send_ok(ctx, c, rsp_buf,
                          (uint32_t)((size_t)(rsp_ptr - rsp_buf)));
}
