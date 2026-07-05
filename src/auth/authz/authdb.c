#include "core/ngx_brix_module.h"

#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "fs/path/path_internal.h"

/* Postconfig finalization of the authdb rule array: resolve/validate each rule's
 * path against the export root. */
ngx_int_t
brix_finalize_authdb_rules(ngx_log_t *log, const ngx_str_t *root,
                             ngx_array_t *rules)
{
    return brix_finalize_path_rules(log, root, rules,
                                      sizeof(brix_authdb_rule_t),
                                      offsetof(brix_authdb_rule_t, path),
                                      offsetof(brix_authdb_rule_t, resolved),
                                      sizeof(((brix_authdb_rule_t *) 0)->resolved));
}
/* Parse an XrdAcc privilege string (e.g. "rwld") into an BRIX_PRIV_* bitmask. */
static uint32_t
brix_parse_privs(const char *p, size_t len)
{
    uint32_t privs = 0;
    size_t   i;

    /* Each privilege char maps to one or more BRIX_AUTH_* bits; OR-accumulate
     * across the whole string. 'r' implies 'l' (you cannot read what you cannot
     * look up), and 'a' (append) is folded into UPDATE since the FS-level write
     * permission is identical. Unknown chars are silently ignored. */
    for (i = 0; i < len; i++) {
        switch (p[i]) {
        case 'r': privs |= BRIX_AUTH_READ | BRIX_AUTH_LOOKUP;   break;
        case 'l': privs |= BRIX_AUTH_LOOKUP; break;
        case 'w': privs |= BRIX_AUTH_UPDATE; break;
        case 'a': privs |= BRIX_AUTH_UPDATE; break; /* append is update */
        case 'd': privs |= BRIX_AUTH_DELETE; break;
        case 'm': privs |= BRIX_AUTH_MKDIR;  break;
        case 'k': privs |= BRIX_AUTH_ADMIN;  break;
        default: break;
        }
    }

    return privs;
}
/* Parse the authdb file into `rules`: one rule per line (path + identity matcher
 * + privileges).  Returns NGX_CONF_OK / NGX_CONF_ERROR. */
ngx_int_t
brix_parse_authdb(ngx_conf_t *cf, ngx_str_t *filename, ngx_array_t *rules)
{
    ngx_fd_t              fd;
    ngx_file_t            file;
    ngx_file_info_t       fi;
    u_char               *buf, *p, *end, *line_start, *line_end;
    ssize_t               n;
    size_t                buf_size;
    (void) ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_brix_module);

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
                           "brix_authdb \"%s\" exceeds 1 MiB limit",
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

    /* Line loop: p is the running cursor over the whole buffer. Each iteration
     * carves out one line [line_start, line_end), advances p past the EOL
     * terminator, then re-tokenizes within that line. line_start/line_end are
     * mutated below for trimming, so p (not line_end) is what carries the loop
     * forward to the next line. */
    while (p < end) {
        line_start = p;
        while (p < end && *p != '\n' && *p != '\r') {
            p++;
        }
        line_end = p;

        /* Consume the EOL so the next iteration starts on the following line.
         * Handles LF, CR, and CRLF (CR then LF) without double-counting. */
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

        /* Format: [u|g|p|a] <id> <path> <privs>
         *
         * Four space-delimited fields, tokenized left-to-right with the same
         * two-step pattern per field: (1) skip leading whitespace to the field
         * start, (2) scan to the next whitespace for the field end. Each
         * "if (p == line_end) continue" guards against a truncated line that
         * lacks the field still to come — a missing trailing field aborts the
         * whole line (the rule is never pushed). NOTE: privs is the last field,
         * so it has no "p == line_end" guard: an empty privs string is allowed
         * and parses to a zero (no-permission) bitmask. */
        u_char *type_p, *id_p, *path_p, *privs_p;
        u_char *id_end, *path_end, *privs_end;

        /* Field 1: type char. Only type_p[0] is read later; the rest of the
         * token (if any) is scanned over but ignored. */
        type_p = line_start;
        p = type_p;
        while (p < line_end && !isspace(*p)) p++;
        if (p == line_end) continue;   /* no id/path/privs follow -> reject */

        /* Field 2: identity id (DN, VO, host/CIDR, or '*'). */
        id_p = p;
        while (id_p < line_end && isspace(*id_p)) id_p++;
        p = id_p;
        while (p < line_end && !isspace(*p)) p++;
        if (p == line_end) continue;   /* no path/privs follow -> reject */
        id_end = p;

        /* Field 3: path prefix this rule applies to. */
        path_p = id_end;
        while (path_p < line_end && isspace(*path_p)) path_p++;
        p = path_p;
        while (p < line_end && !isspace(*p)) p++;
        if (p == line_end) continue;   /* no privs follow -> reject */
        path_end = p;

        /* Field 4: privilege chars. Last field, so reaching line_end here is
         * fine — privs_p..privs_end may be empty. */
        privs_p = path_end;
        while (privs_p < line_end && isspace(*privs_p)) privs_p++;
        p = privs_p;
        while (p < line_end && !isspace(*p)) p++;
        privs_end = p;

        brix_authdb_rule_t *rule = ngx_array_push(rules);
        if (rule == NULL) {
            ngx_free(buf);
            ngx_close_file(fd);
            return NGX_ERROR;
        }

        /* Rule type is the first byte of field 1 only (e.g. 'u','g','p','a');
         * a multi-char first token is effectively truncated to its lead char. */
        rule->type = (brix_auth_type_t) type_p[0];

        /* id and path are copied into the config pool (NUL-terminated) because
         * the source buf is freed at function exit — rules must own their
         * strings for the lifetime of the config. resolved[] is zeroed now and
         * filled later by brix_finalize_authdb_rules() (deferred realpath). */

        rule->id.len = id_end - id_p;
        rule->id.data = ngx_palloc(cf->pool, rule->id.len + 1);
        ngx_memcpy(rule->id.data, id_p, rule->id.len);
        rule->id.data[rule->id.len] = '\0';

        rule->path.len = path_end - path_p;
        rule->path.data = ngx_palloc(cf->pool, rule->path.len + 1);
        ngx_memcpy(rule->path.data, path_p, rule->path.len);
        rule->path.data[rule->path.len] = '\0';

        rule->privs = brix_parse_privs((const char *) privs_p,
                                        privs_end - privs_p);
        
        ngx_memzero(rule->resolved, sizeof(rule->resolved));
    }

    ngx_free(buf);
    ngx_close_file(fd);
    return NGX_OK;
}
/* Return 1 if `path` is at or beneath `prefix` (component-aligned prefix match). */
static ngx_flag_t
brix_path_prefix_match(const char *prefix, const char *path)
{
    size_t prefix_len;

    if (prefix == NULL || path == NULL) {
        return 0;
    }

    prefix_len = strlen(prefix);
    if (strncmp(prefix, path, prefix_len) != 0) {
        return 0;
    }

    /* Require the match to fall on a path-component boundary so that prefix
     * "/foo" matches "/foo" (exact) and "/foo/bar" (child) but NOT "/foobar".
     * The char immediately after the prefix in path must therefore be either
     * end-of-string or a '/' separator. */
    return path[prefix_len] == '\0' || path[prefix_len] == '/';
}
/* Compare the first `bits` of two packed addresses — the CIDR prefix-match core. */
static ngx_flag_t
brix_authdb_addr_prefix_match(const u_char *a, const u_char *b,
                                ngx_uint_t bits)
{
    ngx_uint_t full;
    ngx_uint_t rem;

    /* Compare two raw addresses (4 bytes IPv4 / 16 bytes IPv6) under a /bits
     * CIDR mask. Split the prefix length into whole bytes plus leftover bits:
     * the first `full` bytes must match exactly, and the next byte must match
     * only on its top `rem` bits. */
    full = bits / 8;
    rem = bits % 8;

    if (full > 0 && ngx_memcmp(a, b, full) != 0) {
        return 0;
    }

    if (rem != 0) {
        /* Top `rem` bits set: e.g. rem=3 -> 0xff << 5 -> 0b11100000. Mask both
         * addresses' partial byte and compare only the significant high bits. */
        u_char mask = (u_char) (0xffu << (8 - rem));
        if ((a[full] & mask) != (b[full] & mask)) {
            return 0;
        }
    }

    return 1;
}
/* Match a peer IP against a rule's host CIDR (rule_id is host/addr[/bits]). */
static ngx_flag_t
brix_authdb_host_cidr_match(const char *rule_id, const char *peer_ip)
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

    /* Reject anything that would not fit (with NUL) in the local cidr buffer;
     * this bounds the copy below and prevents reading a truncated CIDR. */
    if (strlen(rule_id) >= sizeof(cidr)) {
        return 0;
    }

    /* Work on a private mutable copy so we can split "addr/bits" in place. */
    ngx_cpystrn((u_char *) cidr, (u_char *) rule_id, sizeof(cidr));
    slash = strchr(cidr, '/');
    if (slash == NULL) {
        /* No '/': rule_id is a bare address -> require an exact string match
         * against the peer IP (no masking). */
        return strcmp(rule_id, peer_ip) == 0;
    }

    /* Split at '/': cidr now holds the address, slash holds the bit count. */
    *slash++ = '\0';
    /* Infer family from the address half; a ':' can only appear in IPv6. */
    if (strchr(cidr, ':') != NULL) {
        family = AF_INET6;
        max_bits = 128;
    } else {
        family = AF_INET;
        max_bits = 32;
    }

    /* Parse and validate the prefix length: must be a complete integer
     * (end consumed entirely, slash actually had digits) within [0, max_bits].
     * Any junk or out-of-range value rejects the rule rather than matching. */
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

    return brix_authdb_addr_prefix_match(rule_addr, peer_addr,
                                           (ngx_uint_t) bits);
}
/* Match a peer IP against an authdb rule's host id (exact, hostname, or CIDR). */
static ngx_flag_t
brix_authdb_host_match(const ngx_str_t *rule_id, const char *peer_ip)
{
    if (rule_id == NULL || peer_ip == NULL || peer_ip[0] == '\0') {
        return 0;
    }

    if (rule_id->len == 1 && rule_id->data[0] == '*') {
        return 1;
    }

    return brix_authdb_host_cidr_match((const char *) rule_id->data,
                                         peer_ip);
}
/* Find the authdb rule granting `needed_privs` on resolved_path for `identity`;
 * returns the matching rule or NULL. */
const brix_authdb_rule_t *
brix_find_authdb_rule_identity(const char *resolved_path, ngx_array_t *rules,
                        const brix_identity_t *identity,
                        const char *peer_ip, uint32_t needed_privs)
{
    const brix_authdb_rule_t *best = NULL;
    brix_authdb_rule_t       *rule;
    size_t                      best_len = 0;
    ngx_uint_t                  i;
    const char                 *dn;
    const char                 *vo_list;

    if (resolved_path == NULL || rules == NULL) {
        return NULL;
    }

    dn = brix_identity_dn_cstr(identity);
    vo_list = brix_identity_vo_csv_cstr(identity);

    rule = rules->elts;
    for (i = 0; i < rules->nelts; i++) {
        size_t rule_len = strlen(rule[i].resolved);

        if (!brix_path_prefix_match(rule[i].resolved, resolved_path)) {
            continue;
        }

        /* Check identity */
        ngx_flag_t match = 0;
        switch (rule[i].type) {
        case BRIX_AUTH_ALL:
            match = 1;
            break;
        case BRIX_AUTH_USER:
            if (rule[i].id.len == 1 && rule[i].id.data[0] == '*') {
                match = 1;
            } else if (ngx_strcmp(rule[i].id.data, dn) == 0) {
                match = 1;
            }
            break;
        case BRIX_AUTH_GROUP:
            if (rule[i].id.len == 1 && rule[i].id.data[0] == '*') {
                match = 1;
            } else if (brix_vo_list_contains(vo_list,
                                               (const char *) rule[i].id.data))
            {
                match = 1;
            }
            break;
        case BRIX_AUTHDB_HOST:
            match = brix_authdb_host_match(&rule[i].id, peer_ip);
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
        
        /* Path + identity match: now require the rule to grant ALL needed bits
         * ((privs & needed) == needed). Only sufficient rules compete; among
         * them the longest prefix wins, with >= letting a later equal-length
         * rule override an earlier one (config last-wins on ties). */
        if ((rule[i].privs & needed_privs) == needed_privs) {
            if (rule_len >= best_len) {
                best = &rule[i];
                best_len = rule_len;
            }
        }
    }

    return best;
}

/* Find the authdb rule granting needed_privs on resolved_path for ctx's identity
 * (wraps the _identity form). */
const brix_authdb_rule_t *
brix_find_authdb_rule(const char *resolved_path, ngx_array_t *rules,
                        brix_ctx_t *ctx, uint32_t needed_privs)
{
    brix_identity_t fallback;

    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->identity != NULL) {
        return brix_find_authdb_rule_identity(resolved_path, rules,
                                                ctx->identity, ctx->login.peer_ip,
                                                needed_privs);
    }

    /* Legacy path: wrap the raw dn/vo_list strings in a transient identity.
     * Fields alias ctx storage (no ownership); safe for this synchronous call. */
    ngx_memzero(&fallback, sizeof(fallback));
    fallback.dn.data = (u_char *) ctx->login.dn;
    fallback.dn.len = strlen(ctx->login.dn);
    fallback.vo_csv.data = (u_char *) ctx->login.vo_list;
    fallback.vo_csv.len = strlen(ctx->login.vo_list);

    return brix_find_authdb_rule_identity(resolved_path, rules,
                                            &fallback, ctx->login.peer_ip,
                                            needed_privs);
}
/* Authorize `identity` for needed_privs on resolved_path against the rules.
 * Returns NGX_OK (granted) or NGX_ERROR (denied). */
ngx_int_t
brix_check_authdb_identity(ngx_log_t *log, ngx_array_t *rules,
                    const brix_identity_t *identity, const char *peer_ip,
                    const char *resolved_path, uint32_t needed_privs)
{
    const brix_authdb_rule_t   *rule;
    char                          safe_path[512];
    const char                   *dn;
    const char                   *vo_list;

    /* No rules loaded == no authdb policy == unrestricted (allow-all). */
    if (rules == NULL || rules->nelts == 0) {
        return NGX_OK;
    }

    rule = brix_find_authdb_rule_identity(resolved_path, rules, identity,
                                            peer_ip, needed_privs);
    if (rule != NULL) {
        return NGX_OK;
    }

    dn = brix_identity_dn_cstr(identity);
    vo_list = brix_identity_vo_csv_cstr(identity);
    brix_sanitize_log_string(resolved_path, safe_path, sizeof(safe_path));

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix: authdb denied path=\"%s\" privs=0x%02xd "
                  "dn=\"%s\" vos=\"%s\" peer=\"%s\"",
                  safe_path, needed_privs, dn,
                  vo_list[0] ? vo_list : "-",
                  (peer_ip != NULL && peer_ip[0]) ? peer_ip : "-");

    return NGX_ERROR;
}

/* Authorize ctx for needed_privs on resolved_path via the authdb (wraps the
 * _identity form). */
ngx_int_t
brix_check_authdb(brix_ctx_t *ctx, const char *resolved_path,
                    uint32_t needed_privs)
{
    ngx_stream_brix_srv_conf_t *conf;
    brix_identity_t            fallback;

    conf = ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_brix_module);

    if (ctx->identity != NULL) {
        return brix_check_authdb_identity(ctx->session->connection->log,
                                            conf->authdb_rules, ctx->identity,
                                            ctx->login.peer_ip, resolved_path,
                                            needed_privs);
    }

    ngx_memzero(&fallback, sizeof(fallback));
    fallback.dn.data = (u_char *) ctx->login.dn;
    fallback.dn.len = strlen(ctx->login.dn);
    fallback.vo_csv.data = (u_char *) ctx->login.vo_list;
    fallback.vo_csv.len = strlen(ctx->login.vo_list);

    return brix_check_authdb_identity(ctx->session->connection->log,
                                        conf->authdb_rules, &fallback,
                                        ctx->login.peer_ip, resolved_path,
                                        needed_privs);
}
