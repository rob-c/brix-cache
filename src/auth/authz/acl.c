#include "core/ngx_xrootd_module.h"

#include <stddef.h>
#include <string.h>

#include "path/path_internal.h"

/* Postconfig finalization of the VO-rule array: resolve each rule's path against
 * the export root. */
ngx_int_t
xrootd_finalize_vo_rules(ngx_log_t *log, const ngx_str_t *root,
                         ngx_array_t *rules)
{
    return xrootd_finalize_path_rules(log, root, rules,
                                      sizeof(xrootd_vo_rule_t),
                                      offsetof(xrootd_vo_rule_t, path),
                                      offsetof(xrootd_vo_rule_t, resolved),
                                      sizeof(((xrootd_vo_rule_t *) 0)->resolved));
}
/* Return 1 if the client's colon/space-separated vo_list contains required_vo. */
ngx_flag_t
xrootd_vo_list_contains(const char *vo_list, const char *required_vo)
{
    const char *start;
    const char *end;
    size_t required_len;

    if (required_vo == NULL || required_vo[0] == '\0') {
        return 1;
    }

    if (vo_list == NULL || vo_list[0] == '\0') {
        return 0;
    }

    required_len = strlen(required_vo);
    start = vo_list;

    while (*start != '\0') {
        end = strchr(start, ',');

        if (end == NULL) {
            end = start + strlen(start);
        }

        if ((size_t) (end - start) == required_len
            && ngx_strncmp(start, required_vo, required_len) == 0)
        {
            return 1;
        }

        start = (*end == '\0') ? end : end + 1;
    }

    return 0;
}
/* Authorize `vo_list` against the VO rules covering resolved_path.  NGX_OK if
 * granted (or no rule applies), NGX_ERROR if denied. */
ngx_int_t
xrootd_check_vo_acl(ngx_log_t *log, const char *resolved_path,
                    ngx_array_t *vo_rules, const char *vo_list)
{
    const xrootd_vo_rule_t *rule;
    char                    safe_path[512];
    char                    safe_vo[128];

    if (vo_rules == NULL || vo_rules->nelts == 0) {
        return NGX_OK;
    }

    rule = xrootd_find_vo_rule(resolved_path, vo_rules);
    if (rule == NULL) {
        return NGX_OK;
    }

    if (xrootd_vo_list_contains(vo_list, (const char *) rule->vo.data)) {
        return NGX_OK;
    }

    xrootd_sanitize_log_string(resolved_path, safe_path, sizeof(safe_path));
    xrootd_sanitize_log_string((const char *) rule->vo.data, safe_vo,
                               sizeof(safe_vo));

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "xrootd: VO ACL denied path=\"%s\" required_vo=\"%s\" "
                  "client_vos=\"%s\"",
                  safe_path, safe_vo, (vo_list && vo_list[0]) ? vo_list : "-");

    return NGX_ERROR;
}

/* VO ACL check using the identity's VO list (wraps xrootd_check_vo_acl). */
ngx_int_t
xrootd_check_vo_acl_identity(ngx_log_t *log, const char *resolved_path,
                             ngx_array_t *vo_rules,
                             const xrootd_identity_t *identity)
{
    return xrootd_check_vo_acl(log, resolved_path, vo_rules,
                               xrootd_identity_vo_csv_cstr(identity));
}
