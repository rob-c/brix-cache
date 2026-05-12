#include "../ngx_xrootd_module.h"

#include <stddef.h>
#include <string.h>
#include <ctype.h>

#include "path_internal.h"

ngx_int_t
xrootd_finalize_authdb_rules(ngx_log_t *log, const ngx_str_t *root,
                             ngx_array_t *rules)
{
    return xrootd_finalize_path_rules(log, root, rules,
                                      sizeof(xrootd_authdb_rule_t),
                                      offsetof(xrootd_authdb_rule_t, path),
                                      offsetof(xrootd_authdb_rule_t, resolved),
                                      sizeof(((xrootd_authdb_rule_t *) 0)->resolved));
}


static uint32_t
xrootd_parse_privs(const char *p, size_t len)
{
    uint32_t privs = 0;
    size_t   i;

    for (i = 0; i < len; i++) {
        switch (p[i]) {
        case 'r': privs |= XROOTD_AUTH_READ | XROOTD_AUTH_LOOKUP;   break;
        case 'l': privs |= XROOTD_AUTH_LOOKUP; break;
        case 'w': privs |= XROOTD_AUTH_UPDATE; break;
        case 'a': privs |= XROOTD_AUTH_UPDATE; break; /* append is update */
        case 'd': privs |= XROOTD_AUTH_DELETE; break;
        case 'm': privs |= XROOTD_AUTH_MKDIR;  break;
        case 'k': privs |= XROOTD_AUTH_ADMIN;  break;
        default: break;
        }
    }

    return privs;
}


ngx_int_t
xrootd_parse_authdb(ngx_conf_t *cf, ngx_str_t *filename, ngx_array_t *rules)
{
    ngx_fd_t              fd;
    ngx_file_t            file;
    ngx_file_info_t       fi;
    ngx_uint_t            line_no = 0;
    u_char               *buf, *p, *end, *line_start, *line_end;
    ssize_t               n;
    size_t                buf_size;
    (void) ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_xrootd_module);

    fd = ngx_open_file(filename->data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           ngx_open_file_n " \"%s\" failed", filename->data);
        return NGX_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name = *filename;
    file.log = cf->log;

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, ngx_errno,
                           "fstat \"%s\" failed", filename->data);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    buf_size = (size_t) ngx_file_size(&fi);
    if (buf_size == 0) {
        ngx_close_file(fd);
        return NGX_OK;
    }
    if (buf_size > 1024 * 1024) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "xrootd_authdb \"%s\" exceeds 1 MiB limit",
                           filename->data);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    buf = ngx_alloc(buf_size + 1, cf->log);
    if (buf == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_file(&file, buf, buf_size, 0);
    if (n == NGX_ERROR) {
        ngx_free(buf);
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    p = buf;
    end = buf + n;

    while (p < end) {
        line_start = p;
        while (p < end && *p != '\n' && *p != '\r') {
            p++;
        }
        line_end = p;
        line_no++;

        /* Skip line terminators */
        if (p < end && *p == '\r') p++;
        if (p < end && *p == '\n') p++;

        /* Skip leading whitespace */
        while (line_start < line_end && isspace(*line_start)) {
            line_start++;
        }

        /* Skip comments and empty lines */
        if (line_start == line_end || *line_start == '#') {
            continue;
        }

        /* Format: [u|g|p|a] <id> <path> <privs> */
        u_char *type_p, *id_p, *path_p, *privs_p;
        u_char *id_end, *path_end, *privs_end;

        type_p = line_start;
        p = type_p;
        while (p < line_end && !isspace(*p)) p++;
        if (p == line_end) continue;
        
        id_p = p;
        while (id_p < line_end && isspace(*id_p)) id_p++;
        p = id_p;
        while (p < line_end && !isspace(*p)) p++;
        if (p == line_end) continue;
        id_end = p;

        path_p = id_end;
        while (path_p < line_end && isspace(*path_p)) path_p++;
        p = path_p;
        while (p < line_end && !isspace(*p)) p++;
        if (p == line_end) continue;
        path_end = p;

        privs_p = path_end;
        while (privs_p < line_end && isspace(*privs_p)) privs_p++;
        p = privs_p;
        while (p < line_end && !isspace(*p)) p++;
        privs_end = p;

        xrootd_authdb_rule_t *rule = ngx_array_push(rules);
        if (rule == NULL) {
            ngx_free(buf);
            ngx_close_file(fd);
            return NGX_ERROR;
        }

        rule->type = (xrootd_auth_type_t) type_p[0];
        
        rule->id.len = id_end - id_p;
        rule->id.data = ngx_palloc(cf->pool, rule->id.len + 1);
        ngx_memcpy(rule->id.data, id_p, rule->id.len);
        rule->id.data[rule->id.len] = '\0';

        rule->path.len = path_end - path_p;
        rule->path.data = ngx_palloc(cf->pool, rule->path.len + 1);
        ngx_memcpy(rule->path.data, path_p, rule->path.len);
        rule->path.data[rule->path.len] = '\0';

        rule->privs = xrootd_parse_privs((const char *) privs_p,
                                        privs_end - privs_p);
        
        ngx_memzero(rule->resolved, sizeof(rule->resolved));
    }

    ngx_free(buf);
    ngx_close_file(fd);
    return NGX_OK;
}


static ngx_flag_t
xrootd_path_prefix_match(const char *prefix, const char *path)
{
    size_t prefix_len;

    if (prefix == NULL || path == NULL) {
        return 0;
    }

    prefix_len = strlen(prefix);
    if (strncmp(prefix, path, prefix_len) != 0) {
        return 0;
    }

    return path[prefix_len] == '\0' || path[prefix_len] == '/';
}


const xrootd_authdb_rule_t *
xrootd_find_authdb_rule(const char *resolved_path, ngx_array_t *rules,
                        xrootd_ctx_t *ctx, uint32_t needed_privs)
{
    const xrootd_authdb_rule_t *best = NULL;
    xrootd_authdb_rule_t       *rule;
    size_t                      best_len = 0;
    ngx_uint_t                  i;

    if (resolved_path == NULL || rules == NULL) {
        return NULL;
    }

    rule = rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        size_t rule_len = strlen(rule[i].resolved);

        if (!xrootd_path_prefix_match(rule[i].resolved, resolved_path)) {
            continue;
        }

        /* Check identity */
        ngx_flag_t match = 0;
        switch (rule[i].type) {
        case XROOTD_AUTH_ALL:
            match = 1;
            break;
        case XROOTD_AUTH_USER:
            if (rule[i].id.len == 1 && rule[i].id.data[0] == '*') {
                match = 1;
            } else if (ngx_strcmp(rule[i].id.data, ctx->dn) == 0) {
                match = 1;
            }
            break;
        case XROOTD_AUTH_GROUP:
            if (rule[i].id.len == 1 && rule[i].id.data[0] == '*') {
                match = 1;
            } else if (xrootd_vo_list_contains(ctx->vo_list,
                                               (const char *) rule[i].id.data))
            {
                match = 1;
            }
            break;
        default:
            break;
        }

        if (!match) {
            continue;
        }

        /* If identity matches, but doesn't have enough privs, we keep looking
         * for a more specific rule? Or does XRootD stop at the first match?
         * XRootD usually uses longest prefix. If multiple rules have same
         * length, it depends on order. Here we take the longest prefix that
         * matches identity AND has the required privs. */
        
        if ((rule[i].privs & needed_privs) == needed_privs) {
            if (rule_len >= best_len) {
                best = &rule[i];
                best_len = rule_len;
            }
        }
    }

    return best;
}


ngx_int_t
xrootd_check_authdb(xrootd_ctx_t *ctx, const char *resolved_path,
                    uint32_t needed_privs)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    const xrootd_authdb_rule_t   *rule;
    char                          safe_path[512];

    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_xrootd_module);

    if (conf->authdb_rules == NULL || conf->authdb_rules->nelts == 0) {
        return NGX_OK;
    }

    rule = xrootd_find_authdb_rule(resolved_path, conf->authdb_rules, ctx,
                                   needed_privs);
    if (rule != NULL) {
        return NGX_OK;
    }

    xrootd_sanitize_log_string(resolved_path, safe_path, sizeof(safe_path));

    ngx_log_error(NGX_LOG_WARN, ctx->session->connection->log, 0,
                  "xrootd: authdb denied path=\"%s\" privs=0x%02xd "
                  "dn=\"%s\" vos=\"%s\"",
                  safe_path, needed_privs, ctx->dn,
                  (ctx->vo_list && ctx->vo_list[0]) ? ctx->vo_list : "-");

    return NGX_ERROR;
}
