/* ------------------------------------------------------------------ */
/* AuthDB — User/Group/Host Permission Database                          */
/* ------------------------------------------------------------------ */
/*
 * WHAT: This file implements an XRootD authorization database loader and checker. xrootd_finalize_authdb_rules() canonicalizes all authdb rule paths using xrootd_finalize_path_rules with sizeof(xrootd_authdb_rule_t) parameters; xrootd_parse_authdb() reads a config-file-format authdb ("[u|g|p|a] <id> <path> <privs>") into an ngx_array_t of rules, parsing privilege chars ('r','l','w','a','d','m','k') into XROOTD_AUTH_* bitflags; xrootd_find_authdb_rule() performs longest-prefix path matching across all loaded rules with identity filtering (XROOTD_AUTH_ALL/user DN/group VO/host CIDR) and privilege bitmask checks; xrootd_check_authdb() invokes find rule + logs deny on failure. Static helpers: xrootd_parse_privs(), xrootd_path_prefix_match(), xrootd_authdb_addr_prefix_match(), xrootd_authdb_host_cidr_match(), xrootd_authdb_host_match().
 *
 * WHY: AuthDB provides fine-grained per-path access control for XRootD native protocol — unlike VO ACL which controls by organization, authDB controls by individual user DN, group membership, or host CIDR with granular privilege sets (read/lookup/update/delete/mkdir/admin). Longest-prefix matching ensures more specific rules override broader ones; identity filtering supports wildcard '*' for all-users/groups and precise DN/CIDR matching. File-based config allows site administrators to maintain permission tables without nginx recompilation.
 */

/* ------------------------------------------------------------------ */
/* Section: Rule Finalization                                            */
/* ------------------------------------------------------------------ */
#include "../ngx_xrootd_module.h"

#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

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
/* ---- HOW: Calls xrootd_finalize_path_rules(log, root, rules, sizeof(xrootd_authdb_rule_t), offsetof(xrootd_authdb_rule_t, path), offsetof(xrootd_authdb_rule_t, resolved), sizeof(resolved)) — passes authDB rule struct size and field offsets so the generic finalizer canonicalizes each rule's path via realpath(2) into resolved. Returns xrootd_finalize_path_rules() result directly (NGX_OK or NGX_ERROR). */

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
/* ---- HOW: Initializes privs=0. Iterates chars p[0..len-1]: 'r' → XROOTD_AUTH_READ | XROOTD_AUTH_LOOKUP, 'l' → XROOTD_AUTH_LOOKUP, 'w' or 'a' → XROOTD_AUTH_UPDATE (append treated as update), 'd' → XROOTD_AUTH_DELETE, 'm' → XROOTD_AUTH_MKDIR, 'k' → XROOTD_AUTH_ADMIN. Default case: no-op. Returns accumulated privs bitmask via bitwise OR accumulation across all input chars. */

ngx_int_t
xrootd_parse_authdb(ngx_conf_t *cf, ngx_str_t *filename, ngx_array_t *rules)
{
    ngx_fd_t              fd;
    ngx_file_t            file;
    ngx_file_info_t       fi;
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
/* ---- HOW: Opens filename via ngx_open_file(NGX_FILE_RDONLY). If fd invalid → log emerg + NGX_ERROR. Initializes ngx_file_t with fd/name/log. fstat via ngx_fd_info — if error → close+NGX_ERROR. Reads file size into buf_size; 0→close+NGX_OK (empty file); >1 MiB→log emerg+NGX_ERROR. Allocates buf=ngx_alloc(buf_size+1). Reads file via ngx_read_file into buf. If read error → free+close+NGX_ERROR. Parses buf line-by-line: finds newline/carriage-return delimiters, skips leading whitespace, skips comments (starting with '#') and empty lines. For each valid line extracts 4 space-delimited fields: type_char (u/g/p/a), id string, path string, privs string. Allocates rule via ngx_array_push(rules). Sets rule->type=type_p[0]. Copies id into rule->id.data via ngx_palloc+ngx_memcpy+null-terminate. Copies path similarly. Computes privilege bitmask via xrootd_parse_privs(privs_p, privs_end-pivs_p). Zeroes rule->resolved (deferred finalization). After all lines: free buf, close fd, return NGX_OK. */

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
/* ---- HOW: Checks prefix==NULL || path==NULL → returns 0. Computes strlen(prefix) into prefix_len. strncmp(prefix, path, prefix_len) — if !=0 returns 0 (prefix not found at start of path). Returns 1 only when path[prefix_len]=='\0' (exact match) OR path[prefix_len]=='/' (path starts with prefix as a directory component boundary). This prevents partial-prefix false matches: "foo" matches "foo/bar" but NOT "foobar". */

static ngx_flag_t
xrootd_authdb_addr_prefix_match(const u_char *a, const u_char *b,
                                ngx_uint_t bits)
{
    ngx_uint_t full;
    ngx_uint_t rem;

    full = bits / 8;
    rem = bits % 8;

    if (full > 0 && ngx_memcmp(a, b, full) != 0) {
        return 0;
    }

    if (rem != 0) {
        u_char mask = (u_char) (0xffu << (8 - rem));
        if ((a[full] & mask) != (b[full] & mask)) {
            return 0;
        }
    }

    return 1;
}
/* ---- HOW: Computes full=bits/8 (complete bytes to compare), rem=bits%8 (remaining bits). If full>0 && ngx_memcmp(a,b,full)!=0 → returns 0 (first N bytes differ). If rem!=0: mask=(u_char)(0xff << (8-rem)); compares a[full]&mask vs b[full]&mask — if !=0 returns 0. Returns 1 when all full bytes match AND remaining bits match under CIDR mask. */

static ngx_flag_t
xrootd_authdb_host_cidr_match(const char *rule_id, const char *peer_ip)
{
    char        cidr[128];
    char       *slash;
    char       *end;
    long        bits;
    u_char      rule_addr[16];
    u_char      peer_addr[16];
    int         family;
    ngx_uint_t  max_bits;

    if (rule_id == NULL || peer_ip == NULL || peer_ip[0] == '\0') {
        return 0;
    }

    if (strlen(rule_id) >= sizeof(cidr)) {
        return 0;
    }

    ngx_cpystrn((u_char *) cidr, (u_char *) rule_id, sizeof(cidr));
    slash = strchr(cidr, '/');
    if (slash == NULL) {
        return strcmp(rule_id, peer_ip) == 0;
    }

    *slash++ = '\0';
    if (strchr(cidr, ':') != NULL) {
        family = AF_INET6;
        max_bits = 128;
    } else {
        family = AF_INET;
        max_bits = 32;
    }

    bits = strtol(slash, &end, 10);
    if (end == slash || *end != '\0' || bits < 0
        || (ngx_uint_t) bits > max_bits)
    {
        return 0;
    }

    if (inet_pton(family, cidr, rule_addr) != 1
        || inet_pton(family, peer_ip, peer_addr) != 1)
    {
        return 0;
    }

    return xrootd_authdb_addr_prefix_match(rule_addr, peer_addr,
                                           (ngx_uint_t) bits);
}
/* ---- HOW: Checks rule_id==NULL || peer_ip==NULL || peer_ip[0]=='\0' → returns 0. If strlen(rule_id)>=sizeof(cidr) → returns 0 (buffer overflow protection). Copies rule_id into cidr via ngx_cpystrn. strchr(cidr,'/') — if NULL strcmp(rule_id,peer_ip)==0 exact match check. If slash found: *slash++='\0' splits CIDR into addr/bits. strchr(cidr,':') → AF_INET6 (max_bits=128) else AF_INET (max_bits=32). strtol(slash,&end,10): validates end==slash || *end!='\0' || bits<0 || bits>max_bits → returns 0 on invalid. inet_pton(family,cidr,rule_addr) && inet_pton(family,peer_ip,peer_addr) — if either fails → returns 0. Returns xrootd_authdb_addr_prefix_match(rule_addr, peer_addr, (ngx_uint_t)bits). */

static ngx_flag_t
xrootd_authdb_host_match(const ngx_str_t *rule_id, const char *peer_ip)
{
    if (rule_id == NULL || peer_ip == NULL || peer_ip[0] == '\0') {
        return 0;
    }

    if (rule_id->len == 1 && rule_id->data[0] == '*') {
        return 1;
    }

    return xrootd_authdb_host_cidr_match((const char *) rule_id->data,
                                         peer_ip);
}
/* ---- HOW: Checks rule_id==NULL || peer_ip==NULL || peer_ip[0]=='\0' → returns 0. If rule_id->len==1 && rule_id->data[0]=='*' → returns 1 (wildcard matches all hosts). Otherwise delegates to xrootd_authdb_host_cidr_match((const char*)rule_id->data, peer_ip) for CIDR or exact IP matching. */

const xrootd_authdb_rule_t *
xrootd_find_authdb_rule_identity(const char *resolved_path, ngx_array_t *rules,
                        const xrootd_identity_t *identity,
                        const char *peer_ip, uint32_t needed_privs)
{
    const xrootd_authdb_rule_t *best = NULL;
    xrootd_authdb_rule_t       *rule;
    size_t                      best_len = 0;
    ngx_uint_t                  i;
    const char                 *dn;
    const char                 *vo_list;

    if (resolved_path == NULL || rules == NULL) {
        return NULL;
    }

    dn = xrootd_identity_dn_cstr(identity);
    vo_list = xrootd_identity_vo_csv_cstr(identity);

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
            } else if (ngx_strcmp(rule[i].id.data, dn) == 0) {
                match = 1;
            }
            break;
        case XROOTD_AUTH_GROUP:
            if (rule[i].id.len == 1 && rule[i].id.data[0] == '*') {
                match = 1;
            } else if (xrootd_vo_list_contains(vo_list,
                                               (const char *) rule[i].id.data))
            {
                match = 1;
            }
            break;
        case XROOTD_AUTH_HOST:
            match = xrootd_authdb_host_match(&rule[i].id, peer_ip);
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

const xrootd_authdb_rule_t *
xrootd_find_authdb_rule(const char *resolved_path, ngx_array_t *rules,
                        xrootd_ctx_t *ctx, uint32_t needed_privs)
{
    xrootd_identity_t fallback;

    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->identity != NULL) {
        return xrootd_find_authdb_rule_identity(resolved_path, rules,
                                                ctx->identity, ctx->peer_ip,
                                                needed_privs);
    }

    ngx_memzero(&fallback, sizeof(fallback));
    fallback.dn.data = (u_char *) ctx->dn;
    fallback.dn.len = strlen(ctx->dn);
    fallback.vo_csv.data = (u_char *) ctx->vo_list;
    fallback.vo_csv.len = strlen(ctx->vo_list);

    return xrootd_find_authdb_rule_identity(resolved_path, rules,
                                            &fallback, ctx->peer_ip,
                                            needed_privs);
}
/* ---- HOW: Checks resolved_path==NULL || rules==NULL → returns NULL. Iterates all rules via rule=rules->elts, for i=0..nelts-1: computes rule_len=strlen(rule[i].resolved). xrootd_path_prefix_match(rule[i].resolved, resolved_path) — if 0 (no path prefix match) continues. Identity check switch on rule[i].type: XROOTD_AUTH_ALL→match=1; XROOTD_AUTH_USER→rule_id=='*' or ngx_strcmp(id.data,ctx->dn)==0; XROOTD_AUTH_GROUP→rule_id=='*' or xrootd_vo_list_contains(ctx->vo_list,id.data); XROOTD_AUTH_HOST→xrootd_authdb_host_match(&id, ctx). If !match continues. If rule[i].privs & needed_privs == needed_privs (privs satisfied) AND rule_len >= best_len → updates best=&rule[i], best_len=rule_len (longest prefix wins). Returns best (NULL if no matching rule found). */

ngx_int_t
xrootd_check_authdb_identity(ngx_log_t *log, ngx_array_t *rules,
                    const xrootd_identity_t *identity, const char *peer_ip,
                    const char *resolved_path, uint32_t needed_privs)
{
    const xrootd_authdb_rule_t   *rule;
    char                          safe_path[512];
    const char                   *dn;
    const char                   *vo_list;

    if (rules == NULL || rules->nelts == 0) {
        return NGX_OK;
    }

    rule = xrootd_find_authdb_rule_identity(resolved_path, rules, identity,
                                            peer_ip, needed_privs);
    if (rule != NULL) {
        return NGX_OK;
    }

    dn = xrootd_identity_dn_cstr(identity);
    vo_list = xrootd_identity_vo_csv_cstr(identity);
    xrootd_sanitize_log_string(resolved_path, safe_path, sizeof(safe_path));

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "xrootd: authdb denied path=\"%s\" privs=0x%02xd "
                  "dn=\"%s\" vos=\"%s\" peer=\"%s\"",
                  safe_path, needed_privs, dn,
                  vo_list[0] ? vo_list : "-",
                  (peer_ip != NULL && peer_ip[0]) ? peer_ip : "-");

    return NGX_ERROR;
}

ngx_int_t
xrootd_check_authdb(xrootd_ctx_t *ctx, const char *resolved_path,
                    uint32_t needed_privs)
{
    ngx_stream_xrootd_srv_conf_t *conf;
    xrootd_identity_t            fallback;

    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_xrootd_module);

    if (ctx->identity != NULL) {
        return xrootd_check_authdb_identity(ctx->session->connection->log,
                                            conf->authdb_rules, ctx->identity,
                                            ctx->peer_ip, resolved_path,
                                            needed_privs);
    }

    ngx_memzero(&fallback, sizeof(fallback));
    fallback.dn.data = (u_char *) ctx->dn;
    fallback.dn.len = strlen(ctx->dn);
    fallback.vo_csv.data = (u_char *) ctx->vo_list;
    fallback.vo_csv.len = strlen(ctx->vo_list);

    return xrootd_check_authdb_identity(ctx->session->connection->log,
                                        conf->authdb_rules, &fallback,
                                        ctx->peer_ip, resolved_path,
                                        needed_privs);
}
/* ---- HOW: Gets srv conf via ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_xrootd_module). Checks conf->authdb_rules==NULL || nelts==0 → returns NGX_OK (no rules = unrestricted). Calls xrootd_find_authdb_rule(resolved_path, conf->authdb_rules, ctx, needed_privs) — if rule!=NULL returns NGX_OK. Otherwise: sanitizes resolved_path into safe_path[512] via xrootd_sanitize_log_string(); logs warn-level error with "authdb denied path=... privs=0x.. dn=... vos=... peer=..." format; returns NGX_ERROR. */
