/*
 * brixautofs_ext_internal.h — private Phase-38 split contract for the CVMFS
 * automount umbrella daemon, shared ONLY between brixautofs.c (core: the pure
 * validator/table state machine plus the libfuse per-request handlers and the
 * ops table) and brixautofs_ext.c (lifecycle: signals, child reaper, idle
 * expiry, option parsing, mount-farm/config bring-up and the entry point).
 *
 * WHAT: the umbrella's process-global daemon state and the handful of core
 *       helpers/objects the lifecycle TU calls.
 * WHY:  not a public API — the pure core (compiled standalone with
 *       -DBRIXAUTOFS_UNIT) still lives in brixautofs.h. This header is guarded
 *       by the same BRIXAUTOFS_UNIT switch's absence: it pulls in libfuse and
 *       is included ONLY inside each TU's `#ifndef BRIXAUTOFS_UNIT` block, so a
 *       unit build never sees it. Behaviour is unchanged from the pre-split
 *       single file. See docs/refactor/phase-38-file-size-unix-modularity.md.
 * HOW:  every extern/prototype is DEFINED in brixautofs.c. The daemon is
 *       single-threaded per FUSE request with its own control/idle threads;
 *       g_af's concurrency is governed by tab's mutex as before.
 */
#ifndef BRIXAUTOFS_EXT_INTERNAL_H
#define BRIXAUTOFS_EXT_INTERNAL_H

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 31
#endif
#include <fuse3/fuse.h>

#include "brixautofs.h"   /* brixautofs_table_t, BRIXAUTOFS_MAX_REPOS/_FQRN_MAX */

/* Parsed umbrella options (`-o` keys the umbrella owns; unknown tokens are
 * forwarded to the umbrella's own libfuse instance, brixcvmfs-style). */
typedef struct {
    int  idle_s;                    /* -o idle=<s>: child expiry (0 = off)   */
    int  spawn_timeout_s;           /* -o timeout=<s>: child bring-up cap    */
    int  allow_other;               /* -o allow_other: umbrella AND children */
    int  foreground;                /* -f / -d                               */
    int  debug;                     /* -d                                    */
    char cache_base[256];           /* -o cachebase=<dir>: child caches here */
    char mnt_base[256];             /* -o mntbase=<dir>: child mount farm    */
    char repos[512];                /* -o repos=a:b (overrides CVMFS_REPOSITORIES) */
    char fuse_extra[512];           /* passthrough -o tokens for the umbrella */
} autofs_opts_t;

typedef struct {
    char               mnt[512];    /* umbrella mountpoint (/cvmfs)          */
    char               farm[512];   /* child mount farm (never under mnt!)   */
    char               etc[256];    /* config root ("" = /etc/cvmfs default) */
    autofs_opts_t      o;
    int                strict;      /* CVMFS_STRICT_MOUNT                    */
    char               repos[512];  /* effective repository list (may be "") */
    char               ghost[BRIXAUTOFS_MAX_REPOS][BRIXAUTOFS_FQRN_MAX];
    int                nghost;      /* config.d repos (.conf), for readdir   */
    brixautofs_table_t tab;
    struct fuse       *fuse;
    int                sigpipe[2];  /* self-pipe: 'T'=terminate 'C'=SIGCHLD  */
    int                shutting_down;
} autofs_state_t;

/* Process-global umbrella state + the ops table (DEFINED in brixautofs.c). */
extern autofs_state_t g_af;
extern const struct fuse_operations af_ops;

/* Core helpers the lifecycle TU reuses (DEFINED in brixautofs.c). */
void af_log(const char *fmt, ...);
int  af_is_mounted(const char *path);
void af_child_path(const char *fqrn, char *out, size_t cap);
int  af_mkdir_p(const char *path);
int  af_umount_path(const char *path);

#endif /* BRIXAUTOFS_EXT_INTERNAL_H */
