/*
 * xrootdfs_main.c — unified `xrootdfs` FUSE front-end (multi-call, like `xrd`).
 *
 * WHAT: A single `xrootdfs` binary that runs EITHER driver: the default
 *       async/resilient one (root:// + http(s)/WebDAV), or — with `--legacy` —
 *       the simple synchronous one. One tool, one man page, a mode flag.
 * WHY:  The two drivers were separate binaries; a single binary with `--legacy`
 *       is simpler to ship and matches how the `xrd` front-end selects behavior.
 * HOW:  Scan argv for a leading `--legacy` token, strip it, and dispatch to the
 *       matching driver entry point (xrootdfs_drivers.h). The legacy driver tags
 *       its own FUSE subtype (fuse.xrootdfs_legacy) so mount listings still tell
 *       the two modes apart.
 *
 * Clean-room: only the two in-tree driver entry points + libc.
 */
#include "xrootdfs_drivers.h"

#include <string.h>

int
main(int argc, char **argv)
{
    /* A leading `--legacy` (before the positional endpoint) selects the simple
     * synchronous driver. We accept it anywhere among the leading options and
     * strip it so the chosen driver sees its own native argv. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--legacy") == 0) {
            for (int j = i; j < argc - 1; j++) {
                argv[j] = argv[j + 1];
            }
            argv[--argc] = NULL;
            return xrootdfs_legacy_main(argc, argv);
        }
        /* Stop scanning once we hit the positional endpoint (first non-option):
         * anything after it belongs to the driver / fuse, including a literal
         * "--legacy" passed through as a fuse option value. */
        if (argv[i][0] != '-') {
            break;
        }
    }
    return xrootdfs_aio_main(argc, argv);
}
