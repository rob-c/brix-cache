#ifndef XROOTD_CACHE_ADMIT_H
#define XROOTD_CACHE_ADMIT_H

/*
 * cache_admit.h — the shared admission filter for the cache subsystem.
 *
 * WHAT: One prefix/size/regex matcher that BOTH the read-through cache (what to
 *       fill from origin) and the write-through cache (what to mirror back) call,
 *       so the two halves are configured with the same shape. Returns ADMIT or
 *       DECLINE for a (path, size) pair.
 *
 * WHY:  The write-through decision engine (writethrough_decision.c) historically
 *       owned the deny/allow-prefix + size + include-regex logic; the read side
 *       had a thinner ad-hoc copy. Lifting the matcher into one unit gives
 *       config/decision parity and a single place to test the precedence rules.
 *
 * HOW:  deny prefixes win over allow prefixes; a non-empty allow list makes it a
 *       whitelist; a size over the limit DECLINEs unless an include regex matches;
 *       is_new=1 (a not-yet-existing file, size unknown) skips the size cap. NULL
 *       cfg/path → DECLINE (fail-closed). The prefix arrays hold
 *       xrootd_wt_prefix_entry_t, the element type the config already parses.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include <regex.h>
#include <sys/types.h>

#include "writethrough_decision.h"   /* xrootd_wt_prefix_entry_t */

typedef enum {
    XROOTD_CACHE_ADMIT   = 0,
    XROOTD_CACHE_DECLINE = 1
} xrootd_cache_admit_e;

typedef struct {
    ngx_array_t *deny_prefixes;   /* xrootd_wt_prefix_entry_t[] — precedence */
    ngx_array_t *allow_prefixes;  /* xrootd_wt_prefix_entry_t[] — whitelist if non-empty */
    off_t        size_limit;      /* 0 = no limit */
    regex_t     *include_regex;   /* NULL = none; a match bypasses the size cap */
} xrootd_cache_admit_cfg_t;

/* Shared admission filter (read-caching AND write-through). is_new=1 ⇒ the file
 * does not exist yet (size unknown) so the size cap is skipped. Deny beats allow;
 * a non-empty allow list is a whitelist. NULL cfg/path → DECLINE. */
xrootd_cache_admit_e xrootd_cache_admit(const xrootd_cache_admit_cfg_t *cfg,
    const char *path, off_t size, int is_new);

#endif /* XROOTD_CACHE_ADMIT_H */
