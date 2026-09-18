/*
 * xrootdfs_argsplit.h — the command-line split rule shared by both FUSE
 * transports (xrootdfs.c's aio parser and xrootdfs_legacy_ext.c's legacy
 * parser).
 *
 * WHAT: xfs_arg_passthrough() places one token the transport's own option
 *       matcher did NOT consume — the first bare word is the endpoint, later
 *       bare words and any unrecognised dash-arg fall through to libfuse.
 * WHY:  the two parsers honour different option sets but must split the
 *       endpoint / mountpoint / fuse-passthrough the same way; one helper
 *       keeps that rule from drifting between transports.
 * HOW:  header-only, static inline — no build registration, no shared TU.
 */
#ifndef XROOTDFS_ARGSPLIT_H
#define XROOTDFS_ARGSPLIT_H

/* Max libfuse passthrough args either transport's splitter accumulates. */
#define XFS_FUSE_ARGV_MAX 61

#include <stdlib.h>
#include <string.h>
#include "platform/platform.h"   /* brix_plat_fuse_opt_supported */

/* Dispatch one command-line token the caller's option matcher did not consume:
 * a bare word (is_opt == 0) becomes *endpoint when none is set yet, otherwise it
 * and every unrecognised dash-arg pass through to fuse_argv (bounded at
 * XFS_FUSE_ARGV_MAX). */
static inline void
xfs_arg_passthrough(char *arg, int is_opt, char **fuse_argv, int *fuse_argc,
                    const char **endpoint)
{
    if (!is_opt && *endpoint == NULL) {
        *endpoint = arg;
    } else if (*fuse_argc < XFS_FUSE_ARGV_MAX) {
        fuse_argv[(*fuse_argc)++] = arg;
    }
}

/* Append the host's own mount options (brix_plat_fuse_host_opts: none on
 * Linux, "noappledouble" for macFUSE) as one "-o" pair, ahead of the user's
 * arguments so an explicit later "-o" can still override them. */
static inline void
xfs_add_host_opts(char **fuse_argv, int *fuse_argc)
{
    const char *opts = brix_plat_fuse_host_opts();

    if (opts != NULL && *fuse_argc + 2 <= XFS_FUSE_ARGV_MAX) {
        fuse_argv[(*fuse_argc)++] = (char *) "-o";
        fuse_argv[(*fuse_argc)++] = (char *) opts;
    }
}

/* Rewrite a libfuse "-o" comma list in place, dropping every element this
 * host's libfuse would reject (brix_plat_fuse_opt_supported): one option
 * string then mounts on Linux libfuse3 and macFUSE alike.  Returns the new
 * length; 0 means nothing survived (the caller drops the "-o" pair). */
static inline size_t
xfs_filter_fuse_opts(char *list)
{
    char  *out = list;
    char  *save = NULL;
    char  *copy = strdup(list);
    char  *tok;

    if (copy == NULL) {
        return strlen(list);            /* ENOMEM: pass the list unchanged */
    }
    *out = '\0';
    for (tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (!brix_plat_fuse_opt_supported(tok)) {
            continue;
        }
        if (out != list) {
            *out++ = ',';
        }
        memcpy(out, tok, strlen(tok) + 1);
        out += strlen(tok);
    }
    free(copy);
    return (size_t) (out - list);
}

#endif /* XROOTDFS_ARGSPLIT_H */
