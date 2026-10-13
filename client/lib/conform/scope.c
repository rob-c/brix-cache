/*
 * Phase-118 scope, profile and safety selection.
 *
 * WHAT: Decides whether a clause may run and records an explicit skip reason.
 * WHY: Absent capability or authority must never be converted into a pass.
 * HOW: Apply id/family filters, role profile, then probe-class authorization.
 */
#include "conform/run.h"

#include <stdio.h>
#include <string.h>

/* ---- Test an exact token inside a comma-separated selector ----
 *
 * WHAT: Returns one when list contains value as a whole token.
 * WHY: Family selection must not confuse RD with RDV or a substring.
 * HOW: Walk comma boundaries and compare equal-length spans.
 */
static int
selector_has(const char *list, const char *value)
{
    const char *cursor;
    size_t value_len;

    if (list == NULL || list[0] == '\0') return 0;
    value_len = strlen(value);
    cursor = list;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, ',');
        size_t token_len = end == NULL ? strlen(cursor) : (size_t) (end - cursor);

        if (token_len == value_len && strncmp(cursor, value, value_len) == 0) {
            return 1;
        }
        if (end == NULL) return 0;
        cursor = end + 1;
    }
    return 0;
}

/* ---- Determine whether a role profile includes a family ----
 *
 * WHAT: Returns one for families belonging to profile, zero otherwise.
 * WHY: An operator's declared endpoint role is an independent scope boundary.
 * HOW: Use explicit comma-separated family sets mirroring Phase 118 section 31.
 */
static int
profile_has_family(const char *profile, const char *family)
{
    static const char data[] =
        "FRM,HSK,PROT,LOG,SIG,OPN,RD,PGR,RDV,WRT,PGW,WVC,SYN,TRN,CKP,STA,DIR,"
        "MKD,MV,RM,CHM,LOC,FAT,PRP,QRY,ERR,TLS,CLM,CHU,ENV";
    static const char manager[] =
        "FRM,HSK,PROT,LOG,SIG,LOC,QRY,RDR,WAI,ERR,TLS,CLM,CMS";
    static const char http[] = "HTR,HTC,HTE,DAV,XPR,ERR,TLS";
    static const char s3[] = "HTR,HTC,HTE,S3,XPR,ERR,TLS";
    static const char tls[] = "TLS,HSK,PROT,SIG";
    static const char tpc[] = "TPC,LOC,ERR,TLS";

    struct role_set { const char *name; const char *families; };
    const struct role_set roles[] = {
        { "data", data }, { "tape", data },
        { "manager", manager }, { "http", http }, { "s3", s3 },
        { "tls", tls }, { "tpc", tpc }
    };
    size_t index;

    if (profile == NULL || selector_has(profile, "full")) return 1;
    for (index = 0; index < sizeof(roles) / sizeof(roles[0]); index++) {
        if (selector_has(profile, roles[index].name)
            && selector_has(roles[index].families, family)) return 1;
    }
    if (selector_has(profile, "cache")
        && (selector_has(data, family) || strcmp(family, "CAC") == 0
            || strcmp(family, "RDR") == 0)) return 1;
    if (selector_has(profile, "proxy")
        && (selector_has(manager, family) || strcmp(family, "RD") == 0
            || strcmp(family, "PGR") == 0)) return 1;
    return 0;
}

static int scope_skip(char *reason, size_t reason_size, const char *format,
    const char *value);

/* ---- Enforce mutation authority for direct and adversarial probes ----
 *
 * WHAT: Returns one when no mutation gate applies or all mutation gates pass.
 * WHY: ADV is disruption-classed but its corpus can also mutate remote state.
 * HOW: Treat the ADV family like a mutate-class row and emit the common reason.
 */
static int
mutation_authorized(const brix_conform_clause *clause,
    const brix_conform_run_config *config, char *reason, size_t reason_size)
{
    int required = clause->probe_class == BRIX_CONFORM_PROBE_MUTATE
        || strcmp(clause->family, "ADV") == 0;

    if (!required || (config->allow_mutate && config->scratch != NULL)) return 1;
    return scope_skip(reason, reason_size, "%s",
        config->scratch == NULL ? "no-scratch-prefix"
                                : "probe-class-disabled:mutate");
}

/* ---- Apply selectors and role profile ----
 *
 * WHAT: Returns one when a row survives all non-authority filters.
 * WHY: Separating filters keeps the public selection gate below CCN limits.
 * HOW: Apply exact id, family include/exclude and profile in frozen order.
 */
static int
scope_filters(const brix_conform_clause *clause,
    const brix_conform_run_config *config, char *reason, size_t reason_size)
{
    if (config->only != NULL && strcmp(config->only, clause->id) != 0)
        return scope_skip(reason, reason_size, "filtered:not-%s", config->only);
    if (config->families != NULL
        && !selector_has(config->families, clause->family))
        return scope_skip(reason, reason_size, "family-excluded:%s",
            clause->family);
    if (config->exclude != NULL
        && (selector_has(config->exclude, clause->family)
            || selector_has(config->exclude, clause->id)))
        return scope_skip(reason, reason_size, "explicitly-excluded:%s",
            clause->id);
    if (!profile_has_family(config->profile, clause->family))
        return scope_skip(reason, reason_size, "profile-excluded:%s",
            config->profile);
    return 1;
}

/* ---- Record one bounded skip reason ----
 *
 * WHAT: Writes reason when storage is available and returns zero.
 * WHY: Selection callers need one linear fail-closed idiom.
 * HOW: Format the supplied stable machine-readable reason into the buffer.
 */
static int
scope_skip(char *reason, size_t reason_size, const char *format,
    const char *value)
{
    if (reason != NULL && reason_size > 0) {
        snprintf(reason, reason_size, format, value == NULL ? "" : value);
    }
    return 0;
}

/* ---- Decide whether a clause is in scope and authorized ----
 *
 * WHAT: Returns one to run or zero with an explicit skip reason.
 * WHY: Profiles and safety flags may narrow a run but must never silently omit.
 * HOW: Apply exact-id, include/exclude family, profile and probe-class gates.
 */
int
brix_conform_clause_selected(const brix_conform_clause *clause,
    const brix_conform_run_config *config, char *reason, size_t reason_size)
{
    if (clause == NULL || config == NULL) {
        return scope_skip(reason, reason_size, "%s", "invalid-clause");
    }
    if (!scope_filters(clause, config, reason, reason_size)) return 0;
    if (!mutation_authorized(clause, config, reason, reason_size)) return 0;
    if (clause->probe_class == BRIX_CONFORM_PROBE_DISRUPT
        && (!config->allow_disrupt || config->confirm_target == NULL
            || strcmp(config->confirm_target, config->target) != 0)) {
        return scope_skip(reason, reason_size, "%s",
            "probe-class-disabled:disrupt");
    }
    if (reason != NULL && reason_size > 0) reason[0] = '\0';
    return 1;
}
