/* Macaroon caveat parsing and scope narrowing — first-party caveat classification, activity→scope mapping, before: expiry, and path: intersection.
 *
 * WHAT: Turns the caveat bytes recovered from the HMAC packet chain into structured claims. Classifies each
 * first-party caveat (activity:/before:/path:), maps WLCG activities to storage.* scopes, records the earliest
 * before: expiry, collects path: caveats, and — after parsing — narrows scope paths by intersecting every path:
 * caveat (and, via the same helper, discharge-supplied paths) against the granted scopes.
 *
 * WHY: Split out of macaroon.c (phase-79 file-size split). Caveat interpretation is the authorization core of a
 * macaroon: activity mapping decides which permissions a token conveys, before: enforces expiry, and path:
 * intersection guarantees the effective path is the most restrictive of all caveats and scopes (never widening).
 * Isolating this logic keeps the security-critical narrowing rules in one auditable file, separate from the HMAC
 * chain machinery (macaroon_parse.c).
 *
 * HOW: parse_iso8601() converts a restricted ISO8601 before: value to time_t. macaroon_parse_first_party_caveat()
 * dispatches on the caveat prefix. macaroon_parse_activity_caveat() splits comma-separated activities and appends
 * mapped scopes. macaroon_apply_path_caveats() walks each caveat × scope pair via macaroon_apply_path_to_scope()
 * (narrow / keep / revoke), then rebuilds scope_raw via macaroon_rebuild_scope_raw() if anything narrowed. */

#include "token_internal.h"
#include "macaroon.h"
#include "macaroon_internal.h"
#include "b64url.h"
#include "scopes.h"
#include "core/compat/hex.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <string.h>
#include <time.h>

/* WHAT: Parse ISO8601 timestamp "YYYY-MM-DDTHH:MM:SSZ" into time_t for before: caveat expiry checking.
 * WHY: Macaroon "before:" caveats specify absolute expiry times in a restricted ISO8601 format (no timezone offsets, no fractional seconds). This helper converts the string to epoch seconds for comparison with current time.
 * HOW: Validate len≥20 and len<32; copy into buf[32] null-terminated; memset tm struct; sscanf(buf,"%d-%d-%dT%d:%d:%dZ") extracting year/month/day/hour/min/sec (expect 6 matches); adjust tm_year-=1900, tm_mon-=1, tm_isdst=-1; return timegm(&tm) or -1 on parse failure. */
static time_t
parse_iso8601(const char *s, size_t len)
{
    struct tm tm;
    char      buf[32];

    if (len < 20 || len >= sizeof(buf)) return (time_t) -1;
    memcpy(buf, s, len);
    buf[len] = '\0';

    memset(&tm, 0, sizeof(tm));
    /* %Y-%m-%dT%H:%M:%SZ */
    if (sscanf(buf, "%d-%d-%dT%d:%d:%dZ",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
    {
        return (time_t) -1;
    }

    tm.tm_year -= 1900;
    tm.tm_mon  -= 1;
    tm.tm_isdst = -1;

    return timegm(&tm);
}

/* WHAT: Reconstruct scope_raw from individual scope entries and re-parse to refresh claims->scopes[].
 * WHY: After path narrowing (macaroon_apply_path_caveats) modifies individual scope paths, the raw scope string becomes stale — it still contains old paths. This function rebuilds the canonical scope_raw string from the updated scopes[] array so downstream access checks use the correct narrowed paths.
 * HOW: Iterate each scope entry's permission bits (read/write/create/modify); for each enabled bit append "perm_name:path" to scope_raw with space separator between entries; check bounds against sizeof(claims->scope_raw) — break if overflow; re-parse the rebuilt string via brix_token_parse_scopes() to refresh claims->scopes[]. */
/* HOW: Clear scope_raw buffer. Iterate each scope entry's permission bits (read/write/create/modify).
 *       For each enabled bit, append "perm_name:path" to scope_raw with space separator between entries.
 *       Check bounds against sizeof(claims->scope_raw) — break if overflow.
 *       Re-parse the rebuilt string via brix_token_parse_scopes() to refresh claims->scopes[]. */
static void
macaroon_rebuild_scope_raw(brix_token_claims_t *claims)
{
    static const char *perm_names[] = {
        "storage.read", "storage.write",
        "storage.create", "storage.modify"
    };
    size_t off = 0;
    int    si;

    claims->scope_raw[0] = '\0';
    for (si = 0; si < claims->scope_count; si++) {
        brix_token_scope_t *sc = &claims->scopes[si];
        unsigned int bits[4] = {
            sc->read, sc->write, sc->create, sc->modify
        };
        int bi;
        for (bi = 0; bi < 4; bi++) {
            size_t plen, pathlen;
            if (!bits[bi]) {
                continue;
            }
            plen    = strlen(perm_names[bi]);
            pathlen = strlen(sc->path);
            if (off + plen + 1 + pathlen + 2 > sizeof(claims->scope_raw)) {
                break;
            }
            if (off > 0) {
                claims->scope_raw[off++] = ' ';
            }
            memcpy(claims->scope_raw + off, perm_names[bi], plen);
            off += plen;
            claims->scope_raw[off++] = ':';
            memcpy(claims->scope_raw + off, sc->path, pathlen);
            off += pathlen;
            claims->scope_raw[off] = '\0';
        }
    }

    claims->scope_count = brix_token_parse_scopes(
        claims->scope_raw, claims->scopes, BRIX_MAX_TOKEN_SCOPES);
}
/*
 * HOW: Clear scope_raw buffer. Iterate each scope entry's permission bits (read/write/create/modify).
 *       For each enabled bit, append "perm_name:path" to scope_raw with space separator between entries.
 *       Check bounds against sizeof(claims->scope_raw) — break if overflow.
 *       Re-parse the rebuilt string via brix_token_parse_scopes() to refresh claims->scopes[].
 */

/* WHAT: Apply path: caveats to restrict scope paths via intersection logic — each caveat narrows allowed paths further.
 * WHY: WLCG macaroon "path:" caveats enforce hierarchical path restrictions on top of already-granted scope permissions. The intersection ensures the final effective path is the most restrictive among all caveats and scopes, preventing over-authorization.
 * HOW: For each caveat path cp: strip trailing slash from scope paths for comparison; case 1 (cp equal/deeper than sc->path): narrow scope to cp if different; case 2 (sc->path deeper than cp): keep sc->path already more restrictive; case 3 (disjoint paths): revoke all permissions (read/write/create/modify=0) on this scope entry; track narrowed flag; after processing all caveats, call macaroon_rebuild_scope_raw() if any narrowing occurred. */
static int
macaroon_apply_path_to_scope(ngx_log_t *log, brix_token_scope_t *scope,
                             const char *caveat_path, size_t caveat_path_len)
{
    size_t scope_len = strlen(scope->path);
    size_t scope_cmp_len = scope_len;

    if (scope_cmp_len > 1 && scope->path[scope_cmp_len - 1] == '/') {
        scope_cmp_len--;
    }

    if (strncmp(caveat_path, scope->path, scope_cmp_len) == 0
        && (caveat_path[scope_cmp_len] == '/'
            || caveat_path[scope_cmp_len] == '\0')) {
        if (strcmp(scope->path, caveat_path) == 0) {
            return 0;
        }
        ngx_log_error(NGX_LOG_INFO, log, 0,
            "brix_macaroon: path: caveat \"%s\" narrows "
            "scope path \"%s\" → \"%s\"", caveat_path, scope->path,
            caveat_path);
        memcpy(scope->path, caveat_path, caveat_path_len + 1);
        return 1;
    }

    if (strncmp(scope->path, caveat_path, caveat_path_len) == 0
        && (scope->path[caveat_path_len] == '/'
            || scope->path[caveat_path_len] == '\0')) {
        return 0;
    }

    if (scope->read || scope->write || scope->create || scope->modify) {
        ngx_log_error(NGX_LOG_INFO, log, 0,
            "brix_macaroon: path: caveat \"%s\" revokes "
            "scope path \"%s\" (disjoint)", caveat_path, scope->path);
    }
    scope->read = scope->write = scope->create = scope->modify = 0;
    return 1;
}

void
macaroon_apply_path_caveats(ngx_log_t *log,
    brix_token_claims_t *claims,
    char path_caveats[][BRIX_SCOPE_PATH_MAX], int n_path_caveats)
{
    int ci, si;
    int narrowed = 0;

    for (ci = 0; ci < n_path_caveats; ci++) {
        const char *cp    = path_caveats[ci];
        size_t      cplen = strlen(cp);

        for (si = 0; si < claims->scope_count; si++) {
            narrowed |= macaroon_apply_path_to_scope(log, &claims->scopes[si],
                                                     cp, cplen);
        }
    }

    if (narrowed) {
        macaroon_rebuild_scope_raw(claims);
    }
}

static const char *
macaroon_scope_for_activity(const char *activity, size_t activity_len)
{
    if (activity_len == 8 && memcmp(activity, "DOWNLOAD", 8) == 0) {
        return "storage.read";
    }
    if (activity_len == 4 && memcmp(activity, "LIST", 4) == 0) {
        return "storage.read";
    }
    if (activity_len == 5 && memcmp(activity, "STAGE", 5) == 0) {
        return "storage.stage";
    }
    if (activity_len == 6 && memcmp(activity, "UPLOAD", 6) == 0) {
        return "storage.write";
    }
    if (activity_len == 6 && memcmp(activity, "DELETE", 6) == 0) {
        return "storage.write";
    }
    if (activity_len == 6 && memcmp(activity, "MANAGE", 6) == 0) {
        return "storage.modify";
    }
    return NULL;
}

static void
macaroon_append_activity_scope(brix_macaroon_parse_state_t *state,
                               const char *scope)
{
    size_t scope_len = strlen(scope);

    /*
     * Overflow-proof capacity check: reject first if scope_off is already
     * at/past the buffer end, then compare against the REMAINING space by
     * subtraction. The additive form (scope_off + scope_len + 4 >= sizeof)
     * can wrap size_t for a corrupt/hostile scope_off and admit an
     * out-of-bounds append; this form cannot. Semantics for all in-range
     * offsets are identical: proceed iff scope_off + scope_len + 4 < sizeof.
     */
    if (state->scope_off >= sizeof(state->scope_buf)
        || scope_len + 4 >= sizeof(state->scope_buf) - state->scope_off) {
        return;
    }
    if (state->scope_off > 0) {
        state->scope_buf[state->scope_off++] = ' ';
    }
    memcpy(state->scope_buf + state->scope_off, scope, scope_len);
    state->scope_off += scope_len;
    state->scope_buf[state->scope_off++] = ':';
    state->scope_buf[state->scope_off++] = '/';
    state->scope_buf[state->scope_off] = '\0';
}

static void
macaroon_parse_activity_caveat(brix_macaroon_parse_state_t *state,
                               const u_char *caveat, size_t caveat_len)
{
    const char *activity = (const char *)(caveat + 9);
    size_t remaining = caveat_len - 9;

    while (remaining > 0) {
        const char *comma = memchr(activity, ',', remaining);
        size_t activity_len = (comma != NULL)
                              ? (size_t)(comma - activity) : remaining;
        const char *scope = macaroon_scope_for_activity(activity,
                                                        activity_len);

        if (scope != NULL) {
            macaroon_append_activity_scope(state, scope);
        }

        activity += activity_len + (comma != NULL ? 1 : 0);
        remaining -= activity_len + (comma != NULL ? 1 : 0);
    }
}

static void
macaroon_parse_before_caveat(brix_macaroon_parse_state_t *state,
                             const u_char *caveat, size_t caveat_len)
{
    time_t exp = parse_iso8601((const char *)(caveat + 7), caveat_len - 7);

    if (exp != (time_t)-1
        && (state->claims->exp == 0 || exp < state->claims->exp)) {
        state->claims->exp = exp;
    }
}

static void
macaroon_parse_path_caveat(brix_macaroon_parse_state_t *state,
                           const u_char *caveat, size_t caveat_len)
{
    const char *path = (const char *)(caveat + 5);
    size_t path_len = caveat_len - 5;

    if (state->n_path_caveats >= 8 || path_len == 0
        || path_len >= BRIX_SCOPE_PATH_MAX) {
        return;
    }

    memcpy(state->path_caveats[state->n_path_caveats], path, path_len);
    state->path_caveats[state->n_path_caveats][path_len] = '\0';
    state->n_path_caveats++;
}

void
macaroon_parse_first_party_caveat(brix_macaroon_parse_state_t *state,
                                  const u_char *caveat, size_t caveat_len)
{
    if (caveat_len >= 9 && memcmp(caveat, "activity:", 9) == 0) {
        macaroon_parse_activity_caveat(state, caveat, caveat_len);
        return;
    }
    if (caveat_len >= 7 && memcmp(caveat, "before:", 7) == 0) {
        macaroon_parse_before_caveat(state, caveat, caveat_len);
        return;
    }
    if (caveat_len >= 5 && memcmp(caveat, "path:", 5) == 0) {
        macaroon_parse_path_caveat(state, caveat, caveat_len);
    }
}
