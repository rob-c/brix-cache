/*
 * xrootdfs_drivers.h — entry points of the two FUSE driver implementations that
 * the unified `xrootdfs` binary multiplexes (apps/xrootdfs_main.c).
 *
 * WHAT: One `xrootdfs` binary contains BOTH drivers; the front-end picks one at
 *       runtime. `--legacy` selects the simple synchronous driver
 *       (xrootdfs_legacy.c); otherwise the default async/resilient driver
 *       (xrootdfs.c) runs.
 * WHY:  A single tool with a mode flag — like the `xrd` multi-call front-end —
 *       instead of two separate binaries.
 * HOW:  Each driver's former main() is exposed here as a plain entry function; the
 *       two translation units share no other symbols (all else is file-static).
 */
#ifndef XROOTDFS_DRIVERS_H
#define XROOTDFS_DRIVERS_H

/* The default async/resilient driver (root:// + http(s)/WebDAV). */
int xrootdfs_aio_main(int argc, char **argv);

/* The simple synchronous fallback driver (root:// only). */
int xrootdfs_legacy_main(int argc, char **argv);

#endif /* XROOTDFS_DRIVERS_H */
