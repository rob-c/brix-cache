/*
 * brixcvmfs_errline.h — the one-line stderr error emitter the brixcvmfs CLI
 * tools (repo/admin/ingest/publish) share.
 *
 * WHAT: brixcvmfs_emit_err() prints "brixcvmfs <ctx>: <what>[: <detail>]\n" and
 *       returns the caller's exit code, so each TU's own ad_err/tx_err/rp_err/
 *       bci_fail is a one-line wrapper binding its context string and code.
 * WHY:  the four tools formatted the identical diagnostic four different times;
 *       one emitter keeps the wire format ("brixcvmfs …: …") from drifting.
 * HOW:  header-only, static inline — no build registration, no shared TU.
 */
#ifndef BRIXCVMFS_ERRLINE_H
#define BRIXCVMFS_ERRLINE_H

#include <stdio.h>

/* Emit "brixcvmfs <ctx>: <what>[: <detail>]\n" to stderr; return `code`. */
static inline int brixcvmfs_emit_err(const char *ctx, const char *what,
                                     const char *detail, int code) {
    fprintf(stderr, "brixcvmfs %s: %s%s%s\n", ctx, what,
            detail != NULL ? ": " : "", detail != NULL ? detail : "");
    return code;
}

#endif /* BRIXCVMFS_ERRLINE_H */
