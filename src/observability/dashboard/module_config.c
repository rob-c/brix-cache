#include "dashboard_http.h"
#include "module_internal.h"

#include <stdio.h>
#include <string.h>

/*
 * dashboard/module_config.c - htpasswd-style users-file directive setter.
 *
 * WHAT: Implements the `brix_dashboard_users <file>` directive, splitting the
 *       per-line parse of the "username:hash" file out of module.c so every
 *       dashboard module translation unit stays under the file-size cap.
 * WHY:  Cohesive, self-contained config-time parsing with no runtime coupling
 *       to the module glue; moved out VERBATIM (zero behavior change).
 */

/*
 * WHAT: Directive setter for `brix_dashboard_users <file>` — load an
 *       htpasswd-style "username:hash" file into the loc-conf users array.
 * HOW:  Parse line by line at config time: strip trailing CR/LF in place, skip
 *       blank and '#'-comment lines, split on the first ':' (username before,
 *       crypt/plaintext hash after), and copy both halves into pool memory.
 *       A malformed entry (no ':', empty name, empty hash) aborts config load.
 * NOTE: Every early return after fopen() closes fp to avoid leaking the FILE*.
 */
/* Outcome of parsing one line of a brix_dashboard_users file. */
typedef enum {
    DASH_USER_LINE_SKIP = 0,   /* blank or '#'-comment: ignore, keep going */
    DASH_USER_LINE_OK,         /* one user pushed into the array           */
    DASH_USER_LINE_MALFORMED,  /* no ':', empty name, or empty hash        */
    DASH_USER_LINE_OOM         /* pool allocation / array push failed      */
} dashboard_user_line_t;

/*
 * WHAT: Parse ONE htpasswd-style "username:hash" line into a new user entry in
 *       `users`.  Blank and '#'-comment lines are skipped.
 * WHY:  Isolating the per-line logic keeps the file loop flat (open/read/close
 *       only) and removes its nested branch count, with no behavior change.
 * HOW:  Trim trailing CR/LF in place; skip blank/comment; split on the first
 *       ':' (reject absent / leading / empty-hash as MALFORMED); copy both
 *       halves into pool memory (OOM on any allocation failure). The '\0' NUL
 *       written over ':' makes `line` the username and colon+1 the hash.
 */
static dashboard_user_line_t
dashboard_parse_user_line(ngx_conf_t *cf, char *line, ngx_array_t *users)
{
    char                           *colon, *end;
    ngx_http_brix_dashboard_user_t *user;
    size_t                          name_len, hash_len;

    /* Trim trailing CR/LF in place. */
    end = line + strlen(line);
    while (end > line && (end[-1] == '\n' || end[-1] == '\r')) {
        *--end = '\0';
    }
    if (line[0] == '\0' || line[0] == '#') {
        return DASH_USER_LINE_SKIP;
    }

    /* Split on the first ':'. Reject if absent, leading (empty username),
     * or with nothing after it (empty hash). */
    colon = strchr(line, ':');
    if (colon == NULL || colon == line || colon[1] == '\0') {
        return DASH_USER_LINE_MALFORMED;
    }

    /* NUL the ':' so `line` is the username; colon+1 is the hash. */
    *colon = '\0';
    name_len = strlen(line);
    hash_len = strlen(colon + 1);

    user = ngx_array_push(users);
    if (user == NULL) {
        return DASH_USER_LINE_OOM;
    }

    user->username.data = ngx_pnalloc(cf->pool, name_len);
    user->password_hash.data = ngx_pnalloc(cf->pool, hash_len);
    if (user->username.data == NULL || user->password_hash.data == NULL) {
        return DASH_USER_LINE_OOM;
    }
    ngx_memcpy(user->username.data, line, name_len);
    ngx_memcpy(user->password_hash.data, colon + 1, hash_len);
    user->username.len = name_len;
    user->password_hash.len = hash_len;
    return DASH_USER_LINE_OK;
}

char *
ngx_http_brix_dashboard_set_users(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_dashboard_loc_conf_t *lcf = conf;
    ngx_str_t                            *value;
    FILE                                 *fp;
    char                                  line[2048];
    char                                 *err = NULL;

    /* Mutually exclusive with single-user password mode (see auth.c). */
    if (lcf->password.len != 0) {
        return "cannot be used with brix_dashboard_password";
    }
    if (lcf->users != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;
    fp = fopen((const char *) value[1].data, "r");
    if (fp == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "brix_dashboard_users \"%V\" is not readable",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    lcf->users = ngx_array_create(cf->pool, 4,
        sizeof(ngx_http_brix_dashboard_user_t));
    if (lcf->users == NULL) {
        (void) fclose(fp);  /* read-only stream; nothing to recover on close */
        return NGX_CONF_ERROR;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        switch (dashboard_parse_user_line(cf, line, lcf->users)) {
        case DASH_USER_LINE_MALFORMED:
            err = "contains a malformed user entry";
            break;
        case DASH_USER_LINE_OOM:
            err = NGX_CONF_ERROR;
            break;
        default:            /* SKIP or OK: continue reading */
            continue;
        }
        (void) fclose(fp);  /* read-only stream; close failure irrelevant */
        return err;
    }

    (void) fclose(fp);  /* read-only stream; nothing to recover on close */
    return NGX_CONF_OK;
}
