/* Macaroon caveat parsing and scope narrowing.
 *
 * WHAT: Parse activity, expiry, and path restrictions and intersect discharge
 *       permissions/paths into structured token claims.
 * WHY: Signed caveats are authorization conditions; ignoring, truncating, or
 *      unioning one can widen a credential beyond its issuer's intent.
 * HOW: Strict parsers produce bounded claims, path helpers narrow hierarchy,
 *      and discharge helpers compute permission-and-path intersections.
 */

#include "core/compat/log_event.h"
#include "core/types/tunables.h"
#include "token_internal.h"
#include "macaroon.h"
#include "macaroon_internal.h"
#include "b64url.h"
#include "scopes.h"
#include "core/compat/hex.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <limits.h>
#include <string.h>
#include <time.h>

/* WHAT: Decode one fixed-width decimal field without permissive libc syntax.
 * WHY: Expiry text is authorization input. HOW: Validate and accumulate digits. */
static ngx_int_t
macaroon_parse_decimal(const char *text, size_t length, int *out)
{
    size_t index;
    int value = 0;

    if (length == 0) {
        return NGX_ERROR;
    }
    for (index = 0; index < length; index++) {
        int digit;

        if (text[index] < '0' || text[index] > '9') {
            return NGX_ERROR;
        }
        digit = text[index] - '0';
        if (value > (INT_MAX - digit) / 10) {
            return NGX_ERROR;
        }
        value = value * 10 + digit;
    }
    *out = value;
    return NGX_OK;
}

/* WHAT: Verify the literal positions in YYYY-MM-DDTHH:MM:SSZ.
 * WHY: Numeric parsing alone could accept alternate separators.
 * HOW: Compare every non-digit format position using a local shape template. */
static ngx_int_t
macaroon_timestamp_shape_valid(const char *text, size_t length)
{
    const char shape[] = "0000-00-00T00:00:00Z";
    size_t index;

    if (length != sizeof(shape) - 1) {
        return NGX_ERROR;
    }
    for (index = 0; index < sizeof(shape) - 1; index++) {
        if (shape[index] != '0' && text[index] != shape[index]) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

/* WHAT: Decode all six timestamp fields into one UTC broken-down time.
 * WHY: Table-driven fixed widths keep strict parsing auditable and bounded.
 * HOW: Parse local offset/width tables, then map values into struct tm. */
static ngx_int_t
macaroon_parse_timestamp_fields(const char *text, struct tm *parsed)
{
    const size_t offsets[] = {0, 5, 8, 11, 14, 17};
    const size_t widths[] = {4, 2, 2, 2, 2, 2};
    int values[6];
    size_t index;

    for (index = 0; index < 6; index++) {
        if (macaroon_parse_decimal(text + offsets[index], widths[index],
                                   &values[index]) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    memset(parsed, 0, sizeof(*parsed));
    parsed->tm_year = values[0] - BRIX_UNIX_EPOCH_YEAR;
    parsed->tm_mon = values[1] - 1;
    parsed->tm_mday = values[2];
    parsed->tm_hour = values[3];
    parsed->tm_min = values[4];
    parsed->tm_sec = values[5];
    parsed->tm_isdst = -1;
    return NGX_OK;
}

/* WHAT: Check that UTC conversion preserved every caller-supplied field.
 * WHY: timegm normalizes impossible dates such as February 31.
 * HOW: Compare the six security-relevant calendar fields after round-trip. */
static ngx_int_t
macaroon_timestamp_matches(const struct tm *expected,
                           const struct tm *actual)
{
    if (actual->tm_year != expected->tm_year
        || actual->tm_mon != expected->tm_mon
        || actual->tm_mday != expected->tm_mday
        || actual->tm_hour != expected->tm_hour
        || actual->tm_min != expected->tm_min
        || actual->tm_sec != expected->tm_sec) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* WHAT: Convert exactly YYYY-MM-DDTHH:MM:SSZ to UTC or return -1.
 * WHY: Malformed expiry restrictions must not become unbounded credentials.
 * HOW: Validate shape/fields and reject any normalization on a UTC round-trip. */
static time_t
parse_iso8601(const char *text, size_t length)
{
    struct tm parsed;
    struct tm expected;
    struct tm checked;
    time_t expiry;

    if (macaroon_timestamp_shape_valid(text, length) != NGX_OK
        || macaroon_parse_timestamp_fields(text, &parsed) != NGX_OK) {
        return (time_t)-1;
    }
    expected = parsed;
    expiry = timegm(&parsed);
    if (expiry == (time_t)-1 || gmtime_r(&expiry, &checked) == NULL
        || macaroon_timestamp_matches(&expected, &checked) != NGX_OK) {
        return (time_t)-1;
    }
    return expiry;
}

/* WHAT: Clear structured and textual scopes. WHY: Unrepresentable narrowing
 * must fail closed. HOW: Zero both views and publish a zero count. */
static void
macaroon_revoke_claim_scopes(brix_token_claims_t *claims)
{
    ngx_memzero(claims->scopes, sizeof(claims->scopes));
    claims->scope_raw[0] = '\0';
    claims->scope_count = 0;
}

/* WHAT: Serialize all structured permission:path entries to scope_raw.
 * WHY: Partial output would make authorization views disagree.
 * HOW: Append with checked bounds; revoke and error on overflow. */
static ngx_int_t
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
            size_t plen, pathlen, needed;
            if (!bits[bi]) {
                continue;
            }
            plen    = strlen(perm_names[bi]);
            pathlen = strlen(sc->path);
            needed = plen + pathlen + 2 + (off > 0 ? 1 : 0);
            if (off >= sizeof(claims->scope_raw)
                || needed > sizeof(claims->scope_raw) - off) {
                macaroon_revoke_claim_scopes(claims);
                return NGX_ERROR;
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
    return NGX_OK;
}

/* WHAT: Narrow, retain, or revoke one scope by path. WHY: Caveats are AND
 * restrictions. HOW: Use the shared boundary matcher and choose the deeper
 * containing path, clearing permissions for disjoint paths. */
static int
macaroon_apply_path_to_scope(ngx_log_t *log, brix_token_scope_t *scope,
                             const char *caveat_path, size_t caveat_path_len)
{
    if (brix_token_scope_path_matches(scope->path, caveat_path)) {
        if (strcmp(scope->path, caveat_path) == 0) {
            return 0;
        }
        BRIX_LOG(NGX_LOG_INFO, log, 0,
            "brix_macaroon: path: caveat \"%s\" narrows "
            "scope path \"%s\" → \"%s\"", caveat_path, scope->path,
            caveat_path);
        memcpy(scope->path, caveat_path, caveat_path_len + 1);
        return 1;
    }

    if (brix_token_scope_path_matches(caveat_path, scope->path)) {
        return 0;
    }

    if (scope->read || scope->write || scope->create || scope->modify) {
        BRIX_LOG(NGX_LOG_INFO, log, 0,
            "brix_macaroon: path: caveat \"%s\" revokes "
            "scope path \"%s\" (disjoint)", caveat_path, scope->path);
    }
    scope->read = scope->write = scope->create = scope->modify = 0;
    return 1;
}

/* WHAT: Narrow claims by every path. WHY: Repeated paths are cumulative AND
 * restrictions. HOW: Cross caveats with scopes and rebuild changed output. */
ngx_int_t
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
        return macaroon_rebuild_scope_raw(claims);
    }
    return NGX_OK;
}

/* WHAT: Compute one permission-and-path overlap. WHY: Discharges may only
 * attenuate parent authority. HOW: AND permissions, choose the deeper
 * containing path, and reject disjoint paths. */
static int
macaroon_scope_intersection(const brix_token_scope_t *parent,
    const brix_token_scope_t *restriction, brix_token_scope_t *result)
{
    const char *path;
    size_t path_length;

    ngx_memzero(result, sizeof(*result));
    result->read = parent->read && restriction->read;
    result->write = parent->write && restriction->write;
    result->create = parent->create && restriction->create;
    result->modify = parent->modify && restriction->modify;
    if (!result->read && !result->write && !result->create
        && !result->modify) {
        return 0;
    }

    if (brix_token_scope_path_matches(parent->path, restriction->path)) {
        path = restriction->path;
    } else if (brix_token_scope_path_matches(restriction->path,
                                             parent->path)) {
        path = parent->path;
    } else {
        return 0;
    }
    path_length = strlen(path);
    if (path_length == 0 || path_length >= sizeof(result->path)) {
        return 0;
    }
    ngx_memcpy(result->path, path, path_length + 1);
    return 1;
}

/* WHAT: Merge or append one bounded intersection. WHY: Several pairs may
 * yield the same path. HOW: OR same-path permissions or append with a cap. */
static ngx_int_t
macaroon_merge_intersection(brix_token_scope_t *scopes, int *scope_count,
    const brix_token_scope_t *candidate)
{
    int scope_index;

    for (scope_index = 0; scope_index < *scope_count; scope_index++) {
        if (strcmp(scopes[scope_index].path, candidate->path) != 0) {
            continue;
        }
        scopes[scope_index].read |= candidate->read;
        scopes[scope_index].write |= candidate->write;
        scopes[scope_index].create |= candidate->create;
        scopes[scope_index].modify |= candidate->modify;
        return NGX_OK;
    }
    if (*scope_count >= BRIX_MAX_TOKEN_SCOPES) {
        return NGX_ERROR;
    }
    scopes[*scope_count] = *candidate;
    (*scope_count)++;
    return NGX_OK;
}

/* WHAT: Replace root scopes with the exact discharge intersection.
 * WHY: Permissions and paths must attenuate together.
 * HOW: Cross, merge bounded overlaps, then atomically rebuild text. */
ngx_int_t
macaroon_intersect_claim_scopes(ngx_log_t *log,
    brix_token_claims_t *claims, const brix_token_claims_t *restriction)
{
    brix_token_scope_t narrowed[BRIX_MAX_TOKEN_SCOPES];
    int narrowed_count = 0;
    int parent_index, restriction_index;

    ngx_memzero(narrowed, sizeof(narrowed));
    for (parent_index = 0; parent_index < claims->scope_count; parent_index++) {
        for (restriction_index = 0;
             restriction_index < restriction->scope_count;
             restriction_index++) {
            brix_token_scope_t candidate;

            if (!macaroon_scope_intersection(&claims->scopes[parent_index],
                    &restriction->scopes[restriction_index], &candidate)) {
                continue;
            }
            if (macaroon_merge_intersection(narrowed, &narrowed_count,
                                            &candidate) != NGX_OK) {
                BRIX_LOG(NGX_LOG_WARN, log, 0,
                    "brix_macaroon: discharge scope intersection exceeds limit");
                macaroon_revoke_claim_scopes(claims);
                return NGX_ERROR;
            }
        }
    }

    ngx_memzero(claims->scopes, sizeof(claims->scopes));
    if (narrowed_count > 0) {
        ngx_memcpy(claims->scopes, narrowed,
                   (size_t)narrowed_count * sizeof(narrowed[0]));
    }
    claims->scope_count = narrowed_count;
    return macaroon_rebuild_scope_raw(claims);
}

enum {
    MACAROON_ACTIVITY_READ = 1U,
    MACAROON_ACTIVITY_WRITE = 2U,
    MACAROON_ACTIVITY_MODIFY = 4U
};

/* ---- Map one exact WLCG activity to effective permission bits ----
 *
 * WHAT: Return the permission bit for one known activity, or zero if unknown.
 * WHY: Unknown activity text must not be ignored inside a signed caveat.
 * HOW: Compare exact lengths and bytes; group equivalent read/write activities.
 */
static unsigned int
macaroon_permission_for_activity(const char *activity, size_t activity_len)
{
    if ((activity_len == 8 && memcmp(activity, "DOWNLOAD", 8) == 0)
        || (activity_len == 4 && memcmp(activity, "LIST", 4) == 0)
        || (activity_len == 5 && memcmp(activity, "STAGE", 5) == 0)) {
        return MACAROON_ACTIVITY_READ;
    }
    if ((activity_len == 6 && memcmp(activity, "UPLOAD", 6) == 0)
        || (activity_len == 6 && memcmp(activity, "DELETE", 6) == 0)) {
        return MACAROON_ACTIVITY_WRITE;
    }
    if (activity_len == 6 && memcmp(activity, "MANAGE", 6) == 0) {
        return MACAROON_ACTIVITY_MODIFY;
    }
    return 0;
}

/* ---- Append one effective activity scope to the bounded parser buffer ----
 *
 * WHAT: Append scope:/ and return NGX_OK, or NGX_ERROR without truncation.
 * WHY: Silently dropping a caveat-derived scope can change intersection
 *      semantics between signed input and enforced authority.
 * HOW: Compute required bytes by subtraction, add a separator when needed,
 *      then copy the fixed scope and root path.
 */
static ngx_int_t
macaroon_append_activity_scope(brix_macaroon_parse_state_t *state,
    const char *scope)
{
    size_t scope_len = strlen(scope);
    size_t needed = scope_len + 2 + (state->scope_off > 0 ? 1 : 0);

    if (state->scope_off >= sizeof(state->scope_buf)
        || needed >= sizeof(state->scope_buf) - state->scope_off) {
        return NGX_ERROR;
    }
    if (state->scope_off > 0) {
        state->scope_buf[state->scope_off++] = ' ';
    }
    memcpy(state->scope_buf + state->scope_off, scope, scope_len);
    state->scope_off += scope_len;
    state->scope_buf[state->scope_off++] = ':';
    state->scope_buf[state->scope_off++] = '/';
    state->scope_buf[state->scope_off] = '\0';
    return NGX_OK;
}

/* ---- Serialize the current intersection of activity caveats ----
 *
 * WHAT: Rebuild state->scope_buf from activity_mask; return NGX_OK or error.
 * WHY: Each activity caveat is an AND restriction while comma-separated
 *      activities inside one caveat are alternatives.  Rebuilding prevents a
 *      later caveat from unioning new authority into the earlier one.
 * HOW: Clear the buffer and append the read, write, and modify scopes selected
 *      by the already-intersected mask.
 */
static ngx_int_t
macaroon_rebuild_activity_scopes(brix_macaroon_parse_state_t *state)
{
    state->scope_off = 0;
    state->scope_buf[0] = '\0';
    if ((state->activity_mask & MACAROON_ACTIVITY_READ)
        && macaroon_append_activity_scope(state, "storage.read") != NGX_OK) {
        return NGX_ERROR;
    }
    if ((state->activity_mask & MACAROON_ACTIVITY_WRITE)
        && macaroon_append_activity_scope(state, "storage.write") != NGX_OK) {
        return NGX_ERROR;
    }
    if ((state->activity_mask & MACAROON_ACTIVITY_MODIFY)
        && macaroon_append_activity_scope(state, "storage.modify") != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ---- Parse and intersect one activity: caveat ----
 *
 * WHAT: Parse comma-separated known activities and intersect their union with
 *       prior activity caveats; return NGX_ERROR for malformed/unknown input.
 * WHY: Repeated caveats attenuate authority.  Unioning them allowed a holder
 *      to append activity:UPLOAD to a read-only token and gain write access.
 * HOW: Build one caveat mask, rejecting empty/unknown elements, AND it after
 *      the first caveat, then rebuild the effective scope buffer.
 */
static ngx_int_t
macaroon_parse_activity_caveat(brix_macaroon_parse_state_t *state,
    const u_char *caveat, size_t caveat_len)
{
    const char *activity = (const char *)(caveat + 9);
    size_t remaining = caveat_len - 9;
    unsigned int caveat_mask = 0;

    if (remaining == 0) {
        return NGX_ERROR;
    }
    while (remaining > 0) {
        const char *comma = memchr(activity, ',', remaining);
        size_t activity_len = comma != NULL
                              ? (size_t)(comma - activity) : remaining;
        unsigned int permission;

        if (activity_len == 0) {
            return NGX_ERROR;
        }
        permission = macaroon_permission_for_activity(activity, activity_len);
        if (permission == 0) {
            return NGX_ERROR;
        }
        caveat_mask |= permission;
        if (comma == NULL) {
            remaining = 0;
        } else {
            activity += activity_len + 1;
            remaining -= activity_len + 1;
            if (remaining == 0) {
                return NGX_ERROR;
            }
        }
    }

    state->activity_mask = state->activity_seen
                           ? state->activity_mask & caveat_mask : caveat_mask;
    state->activity_seen = 1;
    return macaroon_rebuild_activity_scopes(state);
}

/* ---- Parse one before: caveat ----
 *
 * WHAT: Record the earliest valid expiry and return NGX_OK, or NGX_ERROR for
 *       malformed timestamp text.
 * WHY: Ignoring a malformed signed expiry turns attenuation into no limit.
 * HOW: Parse the fixed UTC form and retain the minimum epoch value.
 */
static ngx_int_t
macaroon_parse_before_caveat(brix_macaroon_parse_state_t *state,
                             const u_char *caveat, size_t caveat_len)
{
    time_t exp = parse_iso8601((const char *)(caveat + 7), caveat_len - 7);

    if (exp == (time_t)-1) {
        return NGX_ERROR;
    }
    if (state->claims->exp == 0 || exp < state->claims->exp) {
        state->claims->exp = exp;
    }
    return NGX_OK;
}

/* ---- Parse one path: caveat into the bounded restriction set ----
 *
 * WHAT: Record one absolute, control-free path and return NGX_OK; reject empty,
 *       oversized, malformed, or excess caveats with NGX_ERROR.
 * WHY: Truncation and embedded NUL/control bytes let signed and enforced paths
 *      differ, while dropped caveats widen authority.
 * HOW: Enforce count/length/leading slash, scan every byte, then copy exactly.
 */
static ngx_int_t
macaroon_parse_path_caveat(brix_macaroon_parse_state_t *state,
                           const u_char *caveat, size_t caveat_len)
{
    const char *path = (const char *)(caveat + 5);
    size_t path_len = caveat_len - 5;
    size_t index;

    if (state->n_path_caveats >= 8 || path_len == 0
        || path_len >= BRIX_SCOPE_PATH_MAX || path[0] != '/') {
        return NGX_ERROR;
    }
    for (index = 0; index < path_len; index++) {
        u_char ch = (u_char)path[index];

        if (ch == '\0' || ch < 0x20 || ch == 0x7f || ch == '\\') {
            return NGX_ERROR;
        }
    }

    memcpy(state->path_caveats[state->n_path_caveats], path, path_len);
    state->path_caveats[state->n_path_caveats][path_len] = '\0';
    state->n_path_caveats++;
    return NGX_OK;
}

/* ---- Classify one first-party caveat with fail-closed semantics ----
 *
 * WHAT: Apply one supported caveat and return NGX_OK; reject unsupported or
 *       malformed signed caveats with NGX_ERROR.
 * WHY: Silently ignoring a condition makes the server authorize more than the
 *      macaroon expresses.
 * HOW: Dispatch exact activity:/before:/path: prefixes and reject everything
 *      else without interpreting it as a third-party caveat.
 */
ngx_int_t
macaroon_parse_first_party_caveat(brix_macaroon_parse_state_t *state,
    const u_char *caveat, size_t caveat_len)
{
    if (caveat_len >= 9 && memcmp(caveat, "activity:", 9) == 0) {
        return macaroon_parse_activity_caveat(state, caveat, caveat_len);
    }
    if (caveat_len >= 7 && memcmp(caveat, "before:", 7) == 0) {
        return macaroon_parse_before_caveat(state, caveat, caveat_len);
    }
    if (caveat_len >= 5 && memcmp(caveat, "path:", 5) == 0) {
        return macaroon_parse_path_caveat(state, caveat, caveat_len);
    }
    BRIX_LOG(NGX_LOG_WARN, state->log, 0,
        "brix_macaroon: unsupported first-party caveat");
    return NGX_ERROR;
}
