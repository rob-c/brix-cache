#include "open.h"
#include <string.h>
#include <unistd.h>
#include "manager/registry.h"
#include "manager/pending.h"
#include "cms/cms_internal.h"
#include "session/registry.h"
#include "fs/cache/writethrough_decision.h"

/*
 * open_overview.c — kXR_open architecture map + the opaque-string helper.
 *
 * kXR_open is the protocol's densest request; its handling spans several files:
 *   - xrootd_handle_open()        (open_request.c)     — parse, auth (authdb /
 *       VO ACL / token scope), path resolve, manager-mode redirect, TPC
 *       detection, then dispatch to the cached-read or resolved-file opener.
 *   - xrootd_open_cached_read()   (open_cache.c)       — XCache-style cached serve.
 *   - xrootd_open_resolved_file() (open_resolved_file.c) — confined open(2),
 *       fhandle allocation (fd_table.c), per-handle bookkeeping, write-through
 *       policy, and kXR_ok response assembly (+ optional retstat, session publish).
 * This file itself holds only open_extract_opaque(), used during that parse.
 */

/*
 * Extract the opaque query string (everything after '?') from the raw open
 * payload into out[].  Returns 1 if a '?' was found, 0 otherwise.
 */
int
open_extract_opaque(const u_char *payload, size_t payload_len, char *out,
    size_t out_size)
{
    const u_char *question_mark;
    const u_char *opaque_start;
    size_t        opaque_len;

    out[0] = '\0';
    question_mark = memchr(payload, '?', payload_len);
    if (question_mark == NULL) {
        return 0;
    }

    opaque_start = question_mark + 1;
    opaque_len = payload_len - (size_t) (opaque_start - payload);

    /* Trim trailing NUL byte that kXR_open payloads may carry. */
    if (opaque_len > 0 && opaque_start[opaque_len - 1] == '\0') {
        opaque_len--;
    }
    if (opaque_len == 0 || opaque_len >= out_size) {
        return 0;
    }

    memcpy(out, opaque_start, opaque_len);
    out[opaque_len] = '\0';
    return 1;
}

