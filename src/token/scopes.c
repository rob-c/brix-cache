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
