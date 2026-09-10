/*
 * sd_frm_purge_policy.c — 2.0 F4: per-group purge rules + the external
 * policy program of the tape-buffer purge engine.
 *
 * WHAT: The layer between sd_frm_purge.c's LRU walk and the
 *       brix_frm_purge_policy / brix_frm_purge_polprog directives: tags every
 *       candidate with the rule its brix_oss_space group falls under, gives
 *       each rule its own owned-bytes arm (hi/lo) and hold, and, for rules
 *       marked `polprog`, lets an operator program choose which of the
 *       group's eligible copies may go.
 *
 * WHY:  frm_purged has `purge.policy {*|space} min max [hold] [polprog]` and
 *       `frm.purge.polprog`; sites use them to keep one VO's hot set while
 *       draining another's. Until this phase the engine had one export-wide
 *       LRU with a watermark pair and a cap (release-2.0 register F4).
 *
 * HOW:  1. init: rule_of(key) -> rule index per candidate; sum the owned
 *          bytes per rule; need = owned - lo once owned > hi.
 *       2. consult: when any polprog rule is under pressure (its own arm or
 *          the export-wide one), write "<group> <touched> <size> <key>" for
 *          every candidate of a polprog rule to <online>/.brix-purge.candidates,
 *          run "<program> <candidates-file> <decision-file>" under the exec
 *          shared reparented runner's deadline, read the decision file back
 *          (one key per line) and mark the matching candidates approved.
 *          Any failure is fail-closed: the polprog rules release nothing this
 *          pass. A key the program names that is not one of ITS candidates is
 *          counted and ignored — the program chooses among eligible copies, it
 *          can never add one. Both files are unlinked afterwards.
 *       3. The walk asks hold(), wants(), allows() and calls account() per
 *          release; log() writes one line per rule + one for the pass.
 *
 * Raw filesystem calls are legitimate here: this TU is under src/fs/backend/
 * (invariant 12), working on the backend's private buffer directory.
 */

#include "sd_frm_purge_internal.h"
#include "core/compat/subprocess.h"    /* shared SIGCHLD-safe reparented runner */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

#define FRM_POLPROG_LINE_MAX  (PATH_MAX + 64)

static int
policy_rule_index(const brix_sd_frm_purge_policy_t *pol, const char *key)
{
    int r;

    if (pol->rule_of == NULL) {
        return -1;
    }
    r = pol->rule_of(pol->ud, key);
    return (r >= 0 && (size_t) r < pol->nrules) ? r : -1;
}

static int
policy_rule_is_polprog(const brix_sd_frm_purge_policy_t *pol,
    const frm_purge_cand_t *c)
{
    return c->rule >= 0 && (size_t) c->rule < pol->nrules
           && pol->rules[c->rule].polprog;
}

int
frm_purge_policy_init(frm_purge_policy_t *pp,
    const brix_sd_frm_purge_policy_t *pol, frm_purge_scan_t *s)
{
    size_t i;

    memset(pp, 0, sizeof(*pp));
    if (pol->rules == NULL || pol->nrules == 0) {
        return 0;
    }
    pp->rules = calloc(pol->nrules, sizeof(*pp->rules));
    if (pp->rules == NULL) {
        return -1;
    }
    pp->n = pol->nrules;
    for (i = 0; i < s->n; i++) {
        frm_purge_cand_t *c = &s->v[i];

        c->rule = policy_rule_index(pol, c->rel);
        if (c->rule >= 0) {
            pp->rules[c->rule].owned += c->size;
        }
    }
    for (i = 0; i < pp->n; i++) {
        const brix_sd_frm_purge_rule_t *r = &pol->rules[i];
        uint64_t                        owned = pp->rules[i].owned;

        if (owned > r->hi_bytes && owned > r->lo_bytes) {
            pp->rules[i].need = owned - r->lo_bytes;
        }
    }
    return 0;
}

int
frm_purge_policy_pending(const frm_purge_policy_t *pp)
{
    size_t i;

    for (i = 0; i < pp->n; i++) {
        if (pp->rules[i].need > 0) {
            return 1;
        }
    }
    return 0;
}

int
frm_purge_policy_wants(const frm_purge_policy_t *pp, const frm_purge_cand_t *c)
{
    return c->rule >= 0 && (size_t) c->rule < pp->n
           && pp->rules[c->rule].need > 0;
}

time_t
frm_purge_policy_hold(const brix_sd_frm_purge_policy_t *pol,
    const frm_purge_cand_t *c)
{
    time_t hold = pol->min_age_s;

    if (c->rule >= 0 && (size_t) c->rule < pol->nrules
        && pol->rules[c->rule].hold_s > hold)
    {
        hold = pol->rules[c->rule].hold_s;
    }
    return hold;
}

/* The program runs only when a polprog rule is under pressure: its own arm,
 * or the export-wide arms that may reach into its group. */
static int
policy_needs_program(const frm_purge_policy_t *pp,
    const brix_sd_frm_purge_policy_t *pol, uint64_t need)
{
    size_t i;

    if (pol->polprog == NULL || pol->polprog[0] == '\0' || pp->n == 0) {
        return 0;
    }
    for (i = 0; i < pp->n; i++) {
        if (pol->rules[i].polprog && (need > 0 || pp->rules[i].need > 0)) {
            return 1;
        }
    }
    return 0;
}

static int
policy_private_path(const char *online, const char *name, char *buf,
    size_t cap)
{
    if (snprintf(buf, cap, "%s/%s", online, name) >= (int) cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

/* The candidate list: every copy of a polprog rule's group, one line
 * "<group> <touched> <size> <key>" (the key is the buffer-relative path). */
static int
policy_write_candidates(const brix_sd_frm_purge_policy_t *pol,
    const frm_purge_scan_t *s, const char *path)
{
    FILE   *fp;
    int     fd;
    size_t  i;

    (void) unlink(path);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        return -1;
    }
    fp = fdopen(fd, "w");
    if (fp == NULL) {
        close(fd);
        return -1;
    }
    for (i = 0; i < s->n; i++) {
        const frm_purge_cand_t *c = &s->v[i];

        if (!policy_rule_is_polprog(pol, c)) {
            continue;
        }
        fprintf(fp, "%s %" PRId64 " %" PRIu64 " %s\n",
                pol->rules[c->rule].name, (int64_t) c->touched, c->size,
                c->rel);
    }
    return (fclose(fp) == 0) ? 0 : -1;
}

/* "<program> <candidates-file> <decision-file>", no shell, under the shared
 * reparented runner's deadline. 0 = exited 0, else -1 with *why.
 *
 * brix_subprocess_run, not a direct child (2.0, 2026-09-09): nginx's SIGCHLD
 * handler reaps a worker's children itself, so the policy program's status was
 * stolen before this code could wait for it and EVERY pass ended "wait failed"
 * — the groups released nothing, which is the safe direction but made the
 * feature inert. The runner's agent is the program's only parent; it also
 * enforces polprog_timeout_ms and SIGKILLs the whole process group on expiry. */
static int
policy_run_program(const brix_sd_frm_purge_policy_t *pol, const char *cands,
    const char *decision, const char **why)
{
    char                  *argv[4];
    brix_subprocess_req_t  req;
    int                    exit_code = -1;

    argv[0] = (char *) pol->polprog;
    argv[1] = (char *) cands;
    argv[2] = (char *) decision;
    argv[3] = NULL;

    req.argv       = argv;
    req.out        = NULL;                 /* the verdict is the decision file */
    req.outsz      = 0;
    req.timeout_ms = (unsigned) pol->polprog_timeout_ms;

    if (brix_subprocess_run(&req, NULL, &exit_code) != 0) {
        *why = (errno == ETIMEDOUT) ? "deadline exceeded, killed"
                                    : "cannot run";
        return -1;
    }
    if (exit_code != 0) {
        *why = "non-zero exit";
        return -1;
    }
    return 0;
}

static int
policy_cmp_rel(const void *a, const void *b)
{
    frm_purge_cand_t *const *x = a, *const *y = b;

    return strcmp((*x)->rel, (*y)->rel);
}

/* The candidates the program may choose among, sorted by key for bsearch. */
static frm_purge_cand_t **
policy_index(const brix_sd_frm_purge_policy_t *pol, frm_purge_scan_t *s,
    size_t *n_out)
{
    frm_purge_cand_t **idx = malloc((s->n ? s->n : 1) * sizeof(*idx));
    size_t             i, n = 0;

    if (idx == NULL) {
        return NULL;
    }
    for (i = 0; i < s->n; i++) {
        if (policy_rule_is_polprog(pol, &s->v[i])) {
            idx[n++] = &s->v[i];
        }
    }
    qsort(idx, n, sizeof(*idx), policy_cmp_rel);
    *n_out = n;
    return idx;
}

static void
policy_mark_line(frm_purge_policy_t *pp, frm_purge_cand_t **idx, size_t n,
    char *line)
{
    frm_purge_cand_t   key, *kp = &key, **hit;

    line[strcspn(line, "\r\n")] = '\0';
    if (line[0] == '\0') {
        return;
    }
    key.rel = line;
    hit = bsearch(&kp, idx, n, sizeof(*idx), policy_cmp_rel);
    if (hit == NULL) {
        pp->ignored++;
        return;
    }
    (*hit)->approved = 1;
    pp->approved++;
}

/* Mark the candidates the decision file names. -1 when the file cannot be
 * read (the program must create it, even empty), else 0. */
static int
policy_read_decision(frm_purge_policy_t *pp,
    const brix_sd_frm_purge_policy_t *pol, frm_purge_scan_t *s,
    const char *path)
{
    frm_purge_cand_t **idx;
    char               line[FRM_POLPROG_LINE_MAX];
    FILE              *fp;
    size_t             n;
    int                fd;

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }
    fp = fdopen(fd, "r");
    if (fp == NULL) {
        close(fd);
        return -1;
    }
    idx = policy_index(pol, s, &n);
    if (idx == NULL) {
        fclose(fp);
        return -1;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        policy_mark_line(pp, idx, n, line);
    }
    free(idx);
    fclose(fp);
    return 0;
}

static int
policy_exchange(frm_purge_policy_t *pp, const brix_sd_frm_purge_policy_t *pol,
    frm_purge_scan_t *s, const char *cands, const char *decision,
    const char **why)
{
    (void) unlink(decision);
    if (policy_write_candidates(pol, s, cands) != 0) {
        *why = "cannot write the candidate list";
        return -1;
    }
    if (policy_run_program(pol, cands, decision, why) != 0) {
        return -1;
    }
    if (policy_read_decision(pp, pol, s, decision) != 0) {
        *why = "decision file unreadable";
        return -1;
    }
    return 0;
}

void
frm_purge_policy_consult(frm_purge_policy_t *pp,
    const brix_sd_frm_purge_policy_t *pol, frm_purge_scan_t *s,
    const char *online, uint64_t need, ngx_log_t *log)
{
    char        cands[PATH_MAX], decision[PATH_MAX];
    const char *why = "";
    int         rc;

    if (!policy_needs_program(pp, pol, need)) {
        pp->polprog = FRM_POLPROG_IDLE;
        return;
    }
    if (policy_private_path(online, FRM_PURGE_CANDIDATES_NAME, cands,
                            sizeof(cands)) != 0
        || policy_private_path(online, FRM_PURGE_DECISION_NAME, decision,
                               sizeof(decision)) != 0)
    {
        pp->polprog = FRM_POLPROG_FAILED;
        ngx_log_error(NGX_LOG_ERR, log, errno,
            "brix: tape purge \"%s\": policy program paths do not fit", online);
        return;
    }
    rc = policy_exchange(pp, pol, s, cands, decision, &why);
    (void) unlink(cands);
    (void) unlink(decision);
    if (rc != 0) {
        pp->polprog = FRM_POLPROG_FAILED;
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "brix: tape purge \"%s\": policy program \"%s\" failed (%s); its "
            "groups release nothing this pass", online, pol->polprog, why);
        return;
    }
    pp->polprog = FRM_POLPROG_OK;
}

int
frm_purge_policy_allows(const frm_purge_policy_t *pp,
    const brix_sd_frm_purge_policy_t *pol, const frm_purge_cand_t *c)
{
    if (!policy_rule_is_polprog(pol, c)) {
        return 1;
    }
    return pp->polprog == FRM_POLPROG_OK && c->approved;
}

void
frm_purge_policy_account(frm_purge_policy_t *pp, const frm_purge_cand_t *c)
{
    frm_purge_rule_state_t *r;

    if (c->rule < 0 || (size_t) c->rule >= pp->n) {
        return;
    }
    r = &pp->rules[c->rule];
    r->released += c->size;
    r->evicted++;
    r->need = (r->need > c->size) ? r->need - c->size : 0;
}

void
frm_purge_policy_log(const frm_purge_policy_t *pp,
    const brix_sd_frm_purge_policy_t *pol, const char *online,
    const brix_sd_frm_purge_report_t *rep, ngx_log_t *log)
{
    static const char *const  state[] = { "idle", "ok", "failed" };
    ngx_uint_t                level;
    size_t                    i;

    if (pp->n == 0) {
        return;
    }
    for (i = 0; i < pp->n; i++) {
        const brix_sd_frm_purge_rule_t *r  = &pol->rules[i];
        const frm_purge_rule_state_t   *st = &pp->rules[i];
        time_t hold = (r->hold_s > pol->min_age_s) ? r->hold_s : pol->min_age_s;

        level = st->evicted ? NGX_LOG_NOTICE : NGX_LOG_INFO;
        ngx_log_error(level, log, 0,
            "brix: tape purge \"%s\" policy \"%s\": owned %uL -> %uL bytes "
            "(hi=%uL lo=%uL hold=%T s%s), released %ui file(s), %uL bytes",
            online, r->name, st->owned, st->owned - st->released, r->hi_bytes,
            r->lo_bytes, hold, r->polprog ? ", polprog" : "", st->evicted,
            st->released);
    }
    level = (pp->polprog == FRM_POLPROG_FAILED) ? NGX_LOG_ERR : NGX_LOG_INFO;
    ngx_log_error(level, log, 0,
        "brix: tape purge \"%s\" policy pass: rules=%uz held=%ui "
        "unapproved=%ui polprog=%s approved=%ui ignored=%ui",
        online, pp->n, rep->held, rep->unapproved, state[pp->polprog],
        pp->approved, pp->ignored);
}

void
frm_purge_policy_free(frm_purge_policy_t *pp)
{
    free(pp->rules);
    pp->rules = NULL;
    pp->n = 0;
}
