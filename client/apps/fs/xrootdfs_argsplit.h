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

#endif /* XROOTDFS_ARGSPLIT_H */
