/*
 * brixmount.c — brixMount: one hardened front-end that mounts any supported
 * backend by type.
 *
 * WHAT: `brixMount <type> <endpoint> <mountdir> [fuse-opts]` dispatches to the
 *       right FUSE driver:
 *         brixMount cvmfs atlas.cern.ch          ~/myAtlasMountDir/   → CVMFS-brix
 *         brixMount eos   root://eoslhcb.cern.ch ~/myEOSMountDir/     → XRootDFS-brix
 * WHY:  a single tool + one brand ("a hardened, iron-clad FUSE driver, battle-
 *       tested against bad/evil networks") over pluggable drivers that all share
 *       the same resilience core.
 * HOW:  a tiny table maps a type keyword to a driver entry function; dispatch
 *       rewrites argv into the driver's own `[<driver> <endpoint> <mount> …]`
 *       form and calls it. The dispatch core is pure and unit-tested with mock
 *       drivers; main() wires the real ones (xrootdfs is weak-linked so a
 *       cvmfs-only build still links).
 */
#include "cvmfs/client/client.h"   /* not required, keeps include-path uniform */

#include <stdio.h>
#include <string.h>

typedef int (*brix_driver_fn)(int argc, char **argv);

typedef struct {
    const char     *type;    /* keyword the user types */
    const char     *brand;   /* argv[0] handed to the driver (branding) */
    brix_driver_fn  fn;      /* driver entry, or NULL if unavailable */
} brix_driver_t;

#define BRIXMOUNT_MAX_ARGS 64

static void brixmount_usage(FILE *out, const brix_driver_t *drv, size_t n) {
    fprintf(out,
        "brixMount — a hardened, iron-clad FUSE mount, battle-tested against bad/evil networks\n"
        "usage: brixMount <type> <endpoint> <mountdir> [fuse-opts]\n"
        "       brixMount --overlay-list  <mountdir>   (cvmfs-rw: show local changes)\n"
        "       brixMount --overlay-reset <mountdir>   (cvmfs-rw: discard local changes)\n"
        "  e.g. brixMount cvmfs    atlas.cern.ch           ~/myAtlasMountDir/\n"
        "       brixMount cvmfs-rw atlas.cern.ch           ~/myAtlasMountDir/\n"
        "       brixMount eos      root://eoslhcb.cern.ch  ~/myEOSMountDir/\n"
        "types:\n");
    for (size_t i = 0; i < n; i++)
        fprintf(out, "  %-8s %s%s\n", drv[i].type, drv[i].brand,
                drv[i].fn ? "" : "  (unavailable in this build)");
}

/* Route the overlay maintenance subcommands to the injected cores (injection
 * keeps this dispatch TU link-free of the overlay library, and mock-testable).
 * Returns -1 when argv[1] is not an overlay subcommand (fall through to mount
 * dispatch), else the subcommand's exit code (2 = missing mountdir). */
int brixmount_overlay_route(int argc, char **argv,
                            int (*list_fn)(const char *, FILE *),
                            int (*reset_fn)(const char *)) {
    if (argc < 2) return -1;
    int is_list  = strcmp(argv[1], "--overlay-list") == 0;
    int is_reset = strcmp(argv[1], "--overlay-reset") == 0;
    if (!is_list && !is_reset) return -1;
    if (argc < 3) {
        fprintf(stderr, "usage: brixMount %s <mountdir>\n", argv[1]);
        return 2;
    }
    return is_list ? list_fn(argv[2], stdout) : reset_fn(argv[2]);
}

/* Pure dispatch: select a driver by `argv[1]` type and invoke it with
 * `[<brand> <endpoint> <mountdir> <fuse-opts…>]`. Returns the driver's exit code,
 * or 2 on usage error. Exposed (non-static) for unit testing. */
int brixmount_dispatch(int argc, char **argv, const brix_driver_t *drv, size_t ndrv) {
    if (argc < 4) {
        brixmount_usage(stderr, drv, ndrv);
        return 2;
    }
    const char *type     = argv[1];
    const char *endpoint = argv[2];
    const char *mountdir = argv[3];

    const brix_driver_t *sel = NULL;
    for (size_t i = 0; i < ndrv; i++)
        if (strcmp(drv[i].type, type) == 0) { sel = &drv[i]; break; }

    if (sel == NULL) {
        fprintf(stderr, "brixMount: unknown type '%s'\n", type);
        brixmount_usage(stderr, drv, ndrv);
        return 2;
    }
    if (sel->fn == NULL) {
        fprintf(stderr, "brixMount: type '%s' (%s) is not available in this build\n",
                type, sel->brand);
        return 2;
    }

    char *sub[BRIXMOUNT_MAX_ARGS];
    int   sc = 0;
    sub[sc++] = (char *) sel->brand;
    sub[sc++] = (char *) endpoint;
    sub[sc++] = (char *) mountdir;
    for (int i = 4; i < argc && sc < BRIXMOUNT_MAX_ARGS - 1; i++)
        sub[sc++] = argv[i];
    sub[sc] = NULL;

    return sel->fn(sc, sub);
}

#ifndef BRIXMOUNT_NO_MAIN
/* real driver entries */
int brixcvmfs_main(int argc, char **argv);
int brixcvmfs_rw_main(int argc, char **argv);
extern int xrootdfs_aio_main(int argc, char **argv) __attribute__((weak));

/* overlay subcommand cores (client/lib/fs/overlay.h — decls kept local so the
 * dispatch TU stays header-light for the mock-driver unit build) */
int brix_overlay_cli_list(const char *mountdir, FILE *out);
int brix_overlay_cli_reset(const char *mountdir);

int main(int argc, char **argv) {
    int orc = brixmount_overlay_route(argc, argv,
                                      brix_overlay_cli_list, brix_overlay_cli_reset);
    if (orc >= 0) return orc;

    static const brix_driver_t drivers[] = {
        { "cvmfs",    "CVMFS-brix",    brixcvmfs_main },
        { "cvmfs-rw", "CVMFS-brix-rw", brixcvmfs_rw_main },
        { "eos",   "XRootDFS-brix", NULL },   /* filled below if weak-linked */
        { "root",  "XRootDFS-brix", NULL },
        { "roots", "XRootDFS-brix", NULL },
    };
    /* copy so we can fill the weak xrootdfs entry at runtime */
    brix_driver_t tbl[sizeof(drivers)/sizeof(drivers[0])];
    memcpy(tbl, drivers, sizeof(drivers));
    for (size_t i = 0; i < sizeof(tbl)/sizeof(tbl[0]); i++)
        if (tbl[i].fn == NULL && xrootdfs_aio_main)
            tbl[i].fn = xrootdfs_aio_main;

    return brixmount_dispatch(argc, argv, tbl, sizeof(tbl)/sizeof(tbl[0]));
}
#endif
