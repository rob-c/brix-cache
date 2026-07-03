#ifndef BRIX_WRITETHROUGH_DECISION_H
#define BRIX_WRITETHROUGH_DECISION_H

/* ---- Write-through decision interface — policy evaluation at kXR_open ----
 *
 * WHAT: Interface for evaluating write-through policy when a file is opened.
 *       Decision cached on handle determines close-time flush behavior (sync/async/deny).
 *
 * WHY: Mirrors XrdPfcDecision::Decide() from official XRootD PFC module but implemented as C callbacks.
 *      Function-pointer pattern allows external plugins to provide custom policy engines without recompiling.
 *
 * HOW: Decision flow mirrors XrdPfc::Cache::Decide():
 *   1. Client opens file with kXR_open options indicating write intent
 *   2. At open time, evaluate brix_wt_decision_fn(path, options, user_data) — default is brix_wt_default_decide()
 *   3. Cache result on handle (brix_file_t): wt_policy, wt_enabled, wt_dirty_offset = -1
 *   4. Close-time: a real write-back implementation can use the cached policy
 *      and dirty-range metadata to decide whether and how to flush.
 *
 * INVARIANT: Decision is evaluated ONCE at open time — never re-evaluated for each write. */

/*
 * Write-through decision interface for nginx-xrootd cache.
 *
 * Mirrors the XrdPfcDecision pattern from the official XRootD PFC module:
 *   src/XrdPfc/XrdPfcDecision.hh — base class with Decide() virtual method
 *   src/XrdPfc/XrdPfcAllowDecision.cc  — always-cache decision (default)
 *   src/XrdPfc/XrdPfcBlacklistDecision.cc — blacklist-based decision
 */

/* Decision outcomes (mirrors XrdPfcDecision::Decide return) */

#include <ngx_config.h>
#include <ngx_core.h>
#include <regex.h>
#include "core/types/file.h"          /* brix_file_t forward decl context */
#include "protocols/root/protocol/flags.h"      /* kXR_open option constants */

/* ---- Decision outcomes (mirrors XrdPfcDecision::Decide return) ---- */

typedef enum {
    BRIX_WT_DECISION_DENY = 0,      /* never write-through; local-only writes */
    BRIX_WT_DECISION_ALLOW_SYNC,    /* write-back synchronously on close() */
    BRIX_WT_DECISION_ALLOW_ASYNC,   /* schedule async write-back flush */
} brix_wt_decision_t;

/* ---- Decision callback signature (mirrors XrdPfcDecision::Decide) ----
 *
 * @param path      Resolved filesystem path (same as ctx->files[idx].path).
 *                  This is the absolute canonical path after resolve_path().
 * @param options   kXR_open options from the client (kXR_open_updt,
 *                  kXR_open_apnd, kXR_new, etc.). Used to distinguish
 *                  update vs append opens.
 * @param user_data Opaque pointer to the decision configuration block
 *                  (brix_wt_decision_cfg_t) passed at parse time.
 *
 * Returns one of BRIX_WT_DECISION_* values.
 */

typedef brix_wt_decision_t (*brix_wt_decision_fn)(
    const char      *path,
    uint16_t         options,
    void            *user_data
);

/* ---- Prefix entry for allow/deny lists ----
 * Mirrors XrdPfcBlacklistDecision's path-database concept but as a C struct. */

typedef struct {
    ngx_str_t prefix;   /* NUL-terminated string comparison (not regex) */
} brix_wt_prefix_entry_t;

/* ---- Decision configuration — loaded from nginx.conf at parse time ----
 *
 * Mirrors XrdPfcDecision's policy database concept but as a C struct.
 * The fn pointer is set by the policy engine implementation at config load. */

typedef struct {
    brix_wt_decision_fn   fn;           /* function pointer, set by policy engine */
    void                   *user_data;    /* opaque config passed to callback */

    /* Per-prefix allow/deny lists (loaded at startup from directives).
     * Order matters: deny_prefixes checked first, then allow_prefixes.
     * A path matching a deny prefix is always DENY regardless of allow list. */
    ngx_array_t            *deny_prefixes;   /* brix_wt_prefix_entry[] paths excluded from WT */
    ngx_array_t            *allow_prefixes;  /* brix_wt_prefix_entry[] paths always write-through */

    /* Size-based admission filter — mirrors cache_max_file_size but for
     * write-back budget. Files larger than this limit are DENY unless they
     * also match the include regex (if configured). 0 = no limit. */
    off_t                   max_write_through_bytes;
    regex_t                 include_regex;
    ngx_flag_t              include_regex_set;

} brix_wt_decision_cfg_t;

/* ---- Default policy engine functions (prefix-based) ----
 * These are implemented in writethrough_decision.c as the built-in
 * policy engine. External plugins could provide their own fn pointer. */

brix_wt_decision_t brix_wt_default_decide(const char *path, uint16_t options,
                                               void *user_data);

/* ---- Decision configuration helpers ---- */

ngx_int_t brix_wt_config_init_prefixes(ngx_conf_t *cf,
    ngx_array_t *prefix_list, ngx_array_t **out_array,
    const char *directive_name);

/* ---- Default decision function pointer (used when no custom plugin loaded) ---- */

#define BRIX_WT_DEFAULT_DECISION_FN  brix_wt_default_decide

#endif /* BRIX_WRITETHROUGH_DECISION_H */
