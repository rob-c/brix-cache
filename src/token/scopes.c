/*
 * scopes.c — WLCG scope parsing and path authorization.
 *
 * WHAT: Parses space-separated WLCG "permission:path" scope claims into structured
 *       xrootd_token_scope_t entries, then checks read/write access against parsed
 *       scopes for a given request path. Recognizes storage.read/write/create/modify/stage
 *       permissions with exact-length matching to prevent substring attacks.
 * WHY: WLCG tokens encode authorization as space-separated scope claims (e.g.,
 *      "storage.read:/atlas/reco"). This module extracts permission and path components,
 *      applies prefix-based path matching with boundary checks ("/data" must not match "/database"),
 *      and provides read/write access decision functions for use by validate.c and s3/auth.c.
 * HOW: parse_scopes() tokenizes space-separated input → splits on ":" separator → copies path
 *      component (default "/" if empty) → sets permission flags via exact-length memcmp → returns
 *      count of parsed scopes. check_read()/check_write() iterate over parsed scopes, checking
 *      read/write/create flags against scope_path_matches() prefix comparison with boundary enforcement.
 */

#include "scopes.h"

#include <string.h>

static const char *
token_scope_skip_spaces(const char *cursor)
{
    while (*cursor == ' ') {
        cursor++;
    }

    return cursor;
}

static const char *
token_scope_end(const char *scope_start)
{
    const char *scope_end;

    scope_end = scope_start;
    while (*scope_end != '\0' && *scope_end != ' ') {
        scope_end++;
    }

    return scope_end;
}

/* ---- Function: token_scope_copy_path() — WLCG scope path copy with "/" default ---- */
/* WHAT: Copies a permission:path path component into the xrootd_token_scope_t structure, enforcing XROOTD_SCOPE_PATH_MAX boundary. When path_len == 0 (no path specified in "permission:" token), defaults to "/" which matches all paths per WLCG token profile convention. Enforces buffer overflow prevention via truncation at XROOTD_SCOPE_PATH_MAX - 1 when input exceeds capacity.
 * WHY: WLCG scope tokens use "storage.read:/atlas/reco" format where the path component grants access only to specific directories. Defaulting empty paths to "/" follows WLCG convention (unscoped permission = full access). Buffer overflow guard prevents malicious tokens with oversized path components from corrupting downstream scope validation logic.
 * HOW: Three-step → if path_len == 0, set scope->path = "/" default; else truncate at XROOTD_SCOPE_PATH_MAX - 1 for boundary safety; memcpy(path) into scope->path with null termination at truncated length. */

static void
token_scope_copy_path(xrootd_token_scope_t *scope, const char *path,
    size_t path_len)
{
    if (path_len == 0) {
        scope->path[0] = '/';
        scope->path[1] = '\0';
        return;
    }

    if (path_len >= XROOTD_SCOPE_PATH_MAX) {
        path_len = XROOTD_SCOPE_PATH_MAX - 1;
    }

    memcpy(scope->path, path, path_len);
    scope->path[path_len] = '\0';
}

/* ---- Function: token_scope_set_permission() — WLCG storage permission string matcher ---- */
/* WHAT: Parses a WLCG "storage.*" permission string into boolean flags on xrootd_token_scope_t using exact-length memcmp comparison. Recognizes five permissions: storage.read (12 chars), storage.write (13 chars), storage.create (14 chars), storage.modify (14 chars), and storage.stage (13 chars — treated as read-only). Length-based matching prevents substring attacks where "storage.re" could incorrectly match "storage.read".
 * WHY: WLCG token scope claims use standardized permission strings; exact-length memcmp ensures precise matching without partial-string ambiguity. Storage.stage is mapped to read-only (not write) per WLCG staging semantics — staged files are read-accessible but not writable until committed. Length-based validation prevents malformed tokens from granting unintended permissions through substring overlap.
 * HOW: Sequential memcmp comparison against five known permission strings with exact length checks (12/13/14 chars), setting scope->read/write/create/modify/stage flags accordingly on match. Returns immediately after first positive match; storage.stage falls-through sets read=1 as final case. */

static void
token_scope_set_permission(xrootd_token_scope_t *scope,
    const char *permission, size_t permission_len)
{
    if (permission_len == 12
        && memcmp(permission, "storage.read", 12) == 0)
    {
        scope->read = 1;
        return;
    }

    if (permission_len == 13
        && memcmp(permission, "storage.write", 13) == 0)
    {
        scope->write = 1;
        return;
    }

    if (permission_len == 14
        && memcmp(permission, "storage.create", 14) == 0)
    {
        scope->create = 1;
        return;
    }

    if (permission_len == 14
        && memcmp(permission, "storage.modify", 14) == 0)
    {
        scope->modify = 1;
        return;
    }

    if (permission_len == 13
        && memcmp(permission, "storage.stage", 13) == 0)
    {
        scope->read = 1;
    }
}

/*
 * xrootd_token_parse_scopes — parse the WLCG "scope" claim into a structured
 * list.
 *
 * The scope claim is a space-separated list of "permission:path" tokens
 * as defined by the WLCG token profile.  Examples:
 *   "storage.read:/atlas/reco  storage.write:/atlas/output"
 *
 * Each token is parsed into an xrootd_token_scope_t; at most max_scopes
 * entries are written to scopes[].
 *
 * Preconditions: scopes[] must have room for max_scopes elements.
 * Postconditions: scopes[0..return_value-1] are initialised.
 * Returns: number of scope entries written (may be 0 on empty input).
 */
int
xrootd_token_parse_scopes(const char *scope_str,
    xrootd_token_scope_t *scopes, int max_scopes)
{
    const char *cursor;
    int         count;

    if (scope_str == NULL || scope_str[0] == '\0' || max_scopes <= 0) {
        return 0;
    }

    cursor = scope_str;
    count = 0;

    while (*cursor != '\0' && count < max_scopes) {
        const char *entry_start;
        const char *entry_end;
        const char *colon;
        const char *path;
        size_t      entry_len;
        size_t      permission_len;
        size_t      path_len;

        cursor = token_scope_skip_spaces(cursor);
        if (*cursor == '\0') {
            break;
        }

        entry_start = cursor;
        entry_end = token_scope_end(entry_start);
        entry_len = (size_t) (entry_end - entry_start);

        colon = memchr(entry_start, ':', entry_len);
        if (colon == NULL) {
            cursor = entry_end;
            continue;
        }

        permission_len = (size_t) (colon - entry_start);
        path = colon + 1;
        path_len = (size_t) (entry_end - path);

        memset(&scopes[count], 0, sizeof(scopes[count]));
        token_scope_copy_path(&scopes[count], path, path_len);
        token_scope_set_permission(&scopes[count], entry_start,
                                   permission_len);

        /*
         * Preserve the previous behavior: an unknown storage.* permission
         * still consumes a parsed slot, but grants no read/write capability.
         */
        count++;
        cursor = entry_end;
    }

    return count;
}

/*
 * scope_path_matches — decide whether scope_path covers request_path.
 *
 * Rules:
 *   - scope "/" matches every path.
 *   - A trailing "/" in scope_path is ignored for comparison purposes.
 *   - scope_path matches request_path only if scope_path is a prefix of
 *     request_path AND the next character in request_path is either '/'
 *     or NUL.
 *
 * Path-prefix attack prevention: "/data" must not match "/database".
 * The boundary check (next == '/' || next == '\0') enforces this.
 *
 * Preconditions: both scope_path and request_path are NUL-terminated,
 *   absolute paths (start with '/').
 * Returns: 1 if scope covers the request path, 0 otherwise.
 */
static int
scope_path_matches(const char *scope_path, const char *request_path)
{
    size_t scope_len;
    char   next;

    scope_len = strlen(scope_path);
    if (scope_len == 1 && scope_path[0] == '/') {
        return 1;
    }

    if (scope_len > 1 && scope_path[scope_len - 1] == '/') {
        scope_len--;
    }

    if (strncmp(scope_path, request_path, scope_len) != 0) {
        return 0;
    }

    /* path-prefix attack: "/data" must not match "/database" */
    next = request_path[scope_len];
    return (next == '\0' || next == '/');
}

/*
 * xrootd_token_check_read — test whether any scope grants storage.read
 * access to path.
 *
 * Preconditions: scopes[0..scope_count-1] produced by xrootd_token_parse_scopes().
 * Returns: 1 if access is granted, 0 if denied.
 */
int
xrootd_token_check_read(const xrootd_token_scope_t *scopes, int scope_count,
    const char *path)
{
    int scope_index;

    for (scope_index = 0; scope_index < scope_count; scope_index++) {
        if (scopes[scope_index].read
            && scope_path_matches(scopes[scope_index].path, path))
        {
            return 1;
        }
    }

    return 0;
}

/*
 * xrootd_token_check_write — test whether any scope grants storage.write or
 * storage.create access to path.
 *
 * Both write and create permission are treated as sufficient for write ops;
 * this matches the WLCG token profile intent where "create" is a write-like
 * capability restricted to new objects.
 *
 * Returns: 1 if access is granted, 0 if denied.
 */
int
xrootd_token_check_write(const xrootd_token_scope_t *scopes, int scope_count,
    const char *path)
{
    int scope_index;

    for (scope_index = 0; scope_index < scope_count; scope_index++) {
        if ((scopes[scope_index].write || scopes[scope_index].create)
            && scope_path_matches(scopes[scope_index].path, path))
        {
            return 1;
        }
    }

    return 0;
}
