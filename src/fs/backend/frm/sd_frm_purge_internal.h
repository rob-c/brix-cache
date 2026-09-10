/*
 * sd_frm_purge_internal.h — the purge engine's private candidate model,
 * shared by the LRU pass (sd_frm_purge.c) and the 2.0 F4 per-group policy
 * layer (sd_frm_purge_policy.c). Nothing outside src/fs/backend/frm/
 * includes this.
 */
#ifndef BRIX_FS_BACKEND_FRM_SD_FRM_PURGE_INTERNAL_H
#define BRIX_FS_BACKEND_FRM_SD_FRM_PURGE_INTERNAL_H

#include "sd_frm.h"

/* Every name under the online root starting with ".brix-purge." belongs to
 * the engine (the pass lock, the policy program's candidate list and its
 * decision file); the scan never treats one as a copy. */
#define FRM_PURGE_LOCK_NAME        ".brix-purge.lock"
#define FRM_PURGE_PRIVATE_PREFIX   "/.brix-purge."
#define FRM_PURGE_CANDIDATES_NAME  ".brix-purge.candidates"
#define FRM_PURGE_DECISION_NAME    ".brix-purge.decision"

typedef struct {
    char      *rel;       /* key relative to the online root, leading '/' */
    uint64_t   size;
    time_t     touched;   /* max(atime, mtime) */
    int        rule;      /* 2.0 F4: index into pol->rules, -1 = no rule */
    unsigned   approved:1;/* 2.0 F4: the policy program approved a release */
} frm_purge_cand_t;

typedef struct {
    frm_purge_cand_t  *v;
    size_t             n;
    size_t             cap;
    size_t             root_len;
    uint64_t           owned;
    ngx_uint_t         symlinks;
    int                oom;
} frm_purge_scan_t;

/* 2.0 F4 — one pass's state of the brix_frm_purge_policy rules. */
typedef struct {
    uint64_t     owned;     /* bytes the rule's group holds in the buffer */
    uint64_t     need;      /* bytes the rule still wants released       */
    uint64_t     released;
    ngx_uint_t   evicted;
} frm_purge_rule_state_t;

#define FRM_POLPROG_IDLE    0   /* no pressure on a polprog group: not run  */
#define FRM_POLPROG_OK      1
#define FRM_POLPROG_FAILED  2   /* spawn / deadline / exit / decision error */

typedef struct {
    frm_purge_rule_state_t  *rules;    /* one per pol->rules[i]; NULL = none */
    size_t                   n;
    int                      polprog;  /* FRM_POLPROG_*                      */
    ngx_uint_t               approved; /* decisions matched to a candidate   */
    ngx_uint_t               ignored;  /* decisions naming no candidate      */
} frm_purge_policy_t;

/* sd_frm_purge_policy.c — the walk's per-pass questions, in call order. */
int    frm_purge_policy_init(frm_purge_policy_t *pp,
    const brix_sd_frm_purge_policy_t *pol, frm_purge_scan_t *s);
int    frm_purge_policy_pending(const frm_purge_policy_t *pp);
int    frm_purge_policy_wants(const frm_purge_policy_t *pp,
    const frm_purge_cand_t *c);
time_t frm_purge_policy_hold(const brix_sd_frm_purge_policy_t *pol,
    const frm_purge_cand_t *c);
void   frm_purge_policy_consult(frm_purge_policy_t *pp,
    const brix_sd_frm_purge_policy_t *pol, frm_purge_scan_t *s,
    const char *online, uint64_t need, ngx_log_t *log);
int    frm_purge_policy_allows(const frm_purge_policy_t *pp,
    const brix_sd_frm_purge_policy_t *pol, const frm_purge_cand_t *c);
void   frm_purge_policy_account(frm_purge_policy_t *pp,
    const frm_purge_cand_t *c);
void   frm_purge_policy_log(const frm_purge_policy_t *pp,
    const brix_sd_frm_purge_policy_t *pol, const char *online,
    const brix_sd_frm_purge_report_t *rep, ngx_log_t *log);
void   frm_purge_policy_free(frm_purge_policy_t *pp);

#endif /* BRIX_FS_BACKEND_FRM_SD_FRM_PURGE_INTERNAL_H */
