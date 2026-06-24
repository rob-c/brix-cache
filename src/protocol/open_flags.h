/*
 * open_flags.h — kXR_open option-bit semantics (single source of truth).
 *
 * WHAT: the create/exclusive/truncate/append/rdwr meaning of the kXR_open
 *       `options` field, expressed once and shared by every encoder and the one
 *       decoder:
 *         - xrootd_open_options_build:    intent  -> kXR_open options (the request)
 *         - xrootd_open_options_to_posix: options -> POSIX open(2) flags (the server)
 *         - xrootd_open_options_is_write: options -> is this a write-mode open?
 *         - xrootd_open_force_for_open/create: POSIX flags -> the `force` tri-state
 * WHY:  this flag contract was hand-coded in FOUR places — the server's
 *       options->O_* decoder (src/read/open_resolved_file.c), the xrdcp/xrdfs
 *       options builder (client/lib/ops_file.c), and BOTH FUSE drivers' POSIX->force
 *       mapping (client/apps/xrootdfs.c, xrootdfs_legacy.c). The two halves are
 *       inverse operations on the SAME spec: if "kXR_new without kXR_delete" drifts
 *       between the client's intent and the server's O_EXCL derivation, the result
 *       is a spurious EEXIST or a SILENT OVERWRITE — a data-integrity bug no test
 *       catches, because the halves never referenced a shared definition.
 * HOW:  header-only static inlines — pure flag math, no ngx/alloc/OpenSSL — so the
 *       same code compiles into the nginx module and the ngx-free client. Server
 *       policy that is NOT part of the flag spec (POSC staging, directory checks,
 *       access-control) stays at the call sites.
 *
 * The `force` tri-state (shared by xrdcp and both FUSE drivers):
 *   1 = truncate/overwrite (kXR_delete)   0 = create-new, fail if exists (kXR_new)
 *   2 = update in place (kXR_open_updt only, neither create nor truncate)
 *
 * Clean-room: bit meanings from src/protocol/flags.h (vs XProtocol kXR_open*).
 */
#ifndef XROOTD_PROTOCOL_OPEN_FLAGS_H
#define XROOTD_PROTOCOL_OPEN_FLAGS_H

#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>

#include "flags.h"   /* kXR_open_read/updt/apnd/new/delete/wrto/mkpath/posc */

/* The option bits that make an open a write (any one present => write mode). */
#define XROOTD_OPEN_WRITE_BITS \
    (kXR_new | kXR_delete | kXR_open_updt | kXR_open_wrto | kXR_open_apnd)

/* Is this kXR_open options word a write-mode open? */
static inline int
xrootd_open_options_is_write(uint16_t options)
{
    return (options & XROOTD_OPEN_WRITE_BITS) ? 1 : 0;
}

/*
 * Build the kXR_open `options` field from a caller's write intent.
 *   write : 0 = read-only (kXR_open_read), nonzero = write
 *   force : the create disposition tri-state described in the file header
 *   posc  : add kXR_posc (persist-on-successful-close) when nonzero
 *   mkpath: add kXR_mkpath (create parent dirs) when nonzero
 * A write open always uses kXR_open_updt (read+write) so the server opens O_RDWR
 * and partial writes can read-modify-write existing content.
 */
static inline uint16_t
xrootd_open_options_build(int write, int force, int posc, int mkpath)
{
    uint16_t options;

    if (!write) {
        return (uint16_t) kXR_open_read;
    }

    options = (uint16_t) kXR_open_updt;
    if (mkpath) {
        options |= (uint16_t) kXR_mkpath;
    }
    if (force == 1) {
        options |= (uint16_t) kXR_delete;        /* truncate/overwrite */
    } else if (force == 0) {
        options |= (uint16_t) kXR_new;           /* create-new, fail if exists */
    }
    /* force == 2: update in place — neither kXR_delete nor kXR_new. */
    if (posc) {
        options |= (uint16_t) kXR_posc;
    }
    return options;
}

/*
 * Derive POSIX open(2) flags (and whether the fd is readable) from a kXR_open
 * `options` word — the exact inverse of xrootd_open_options_build and the single
 * definition of each open bit's POSIX meaning:
 *   read            -> O_RDONLY                    (readable)
 *   kXR_open_updt   -> O_RDWR                      (readable)
 *   kXR_open_apnd   -> O_WRONLY | O_APPEND         (write-only)
 *   else (wrto/...) -> O_WRONLY                    (write-only)
 *   kXR_new         -> O_CREAT (+ O_EXCL unless kXR_delete is also set)
 *   kXR_delete      -> O_CREAT | O_TRUNC
 * O_NOCTTY is always added. `is_write` is the caller's already-computed write-mode
 * flag (see xrootd_open_options_is_write). Either out-pointer may be NULL.
 */
static inline void
xrootd_open_options_to_posix(uint16_t options, int is_write,
                             int *oflags, int *is_readable)
{
    int f, rd;

    if (!is_write) {
        f  = O_RDONLY;
        rd = 1;
    } else {
        if (options & kXR_open_updt) {
            f  = O_RDWR;
            rd = 1;
        } else if (options & kXR_open_apnd) {
            f  = O_WRONLY | O_APPEND;
            rd = 0;
        } else {
            f  = O_WRONLY;
            rd = 0;
        }

        if (options & kXR_new) {
            f |= O_CREAT;
            if (!(options & kXR_delete)) {
                f |= O_EXCL;
            }
        }
        if (options & kXR_delete) {
            f |= O_CREAT | O_TRUNC;
        }
    }

    f |= O_NOCTTY;

    if (oflags != NULL) {
        *oflags = f;
    }
    if (is_readable != NULL) {
        *is_readable = rd;
    }
}

/*
 * Map the POSIX open(2) flags a FUSE open()/create() receives onto the `force`
 * tri-state, so both xrootdfs drivers derive it identically. For a writable
 * open(): O_TRUNC means overwrite (1), otherwise update in place (2). For
 * create(): O_EXCL means create-new (0), otherwise truncate-create (1).
 */
static inline int
xrootd_open_force_for_open(int o_flags)
{
    return (o_flags & O_TRUNC) ? 1 : 2;
}

static inline int
xrootd_open_force_for_create(int o_flags)
{
    return (o_flags & O_EXCL) ? 0 : 1;
}

#endif /* XROOTD_PROTOCOL_OPEN_FLAGS_H */
