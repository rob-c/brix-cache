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
/* One tokenized authdb line: the four field slices [start,end) carved out of the
 * source buffer. `valid` is 0 for a blank/comment/truncated line the caller must
 * skip (no rule to push). Slices point into the caller's buffer — no ownership. */
typedef struct {
    ngx_flag_t  valid;
    u_char     *type_p;
    u_char     *id_p,    *id_end;
    u_char     *path_p,  *path_end;
    u_char     *privs_p, *privs_end;
} adb_line_t;

/* WHAT: read a full authdb file into a heap buffer, enforcing the size policy.
 * WHY:  isolates the file/stat/read/limit I/O so the parser proper is pure over
 *       an in-memory buffer. On the empty-file fast path returns NGX_OK with
 *       *out_buf==NULL and *out_len==0 (caller has nothing to parse).
 * HOW:  open → fstat → size-guard (0 = ok/empty, >1 MiB = reject) → alloc+read.
 *       On any error logs via cf and closes the fd; the fd is always closed here.
 *       On success *out_buf is a heap block the caller must ngx_free(). */
static ngx_int_t
adb_read_file(ngx_conf_t *cf, ngx_str_t *filename, u_char **out_buf,
              size_t *out_len)
{
    ngx_fd_t         fd;
    ngx_file_t       file;
    ngx_file_info_t  fi;
    u_char          *buf;
    ssize_t          n;
    size_t           buf_size;

    *out_buf = NULL;
    *out_len = 0;

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
        return NGX_OK;                 /* empty file: nothing to parse */
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

    ngx_close_file(fd);
    *out_buf = buf;
    *out_len = (size_t) n;
    return NGX_OK;
}

/* WHAT: carve [line_start,line_end) for the next line from *cursor and advance
 *       *cursor past its EOL; return the leading-whitespace-trimmed start.
 * WHY:  isolates line-splitting + EOL handling from field tokenization.
 * HOW:  scan from *cursor to the first CR/LF for the line end, then consume the
 *       EOL (LF, CR, or CRLF — no double-count) so the next call resumes on the
 *       following line. *line_start_out is the first non-whitespace byte (may
 *       equal *line_end_out for a blank line). */
static void
adb_next_line(u_char **cursor, u_char *end, u_char **line_start_out,
              u_char **line_end_out)
{
    u_char *p = *cursor;
    u_char *line_start = p;

    while (p < end && *p != '\n' && *p != '\r') {
        p++;
    }
    *line_end_out = p;

    if (p < end && *p == '\r') p++;
    if (p < end && *p == '\n') p++;
    *cursor = p;                        /* carries the loop forward */

    while (line_start < *line_end_out && isspace(*line_start)) {
        line_start++;
    }
    *line_start_out = line_start;
}

/* WHAT: scan one whitespace-delimited field from *p within [.,line_end); on
 *       return *field_p is the field start and *p is the field end (first
 *       trailing whitespace or line_end). Returns 1 if a following field can
 *       still exist (*p < line_end), 0 if the field ran to line_end.
 * WHY:  the four authdb fields share one (skip-ws, scan-to-ws, truncation-guard)
 *       pattern; expressing it once keeps the tokenizer flat and uniform.
 * HOW:  advance *p over leading whitespace to *field_p, then scan to the next
 *       whitespace. The boolean return lets the caller reject a line truncated
 *       before a still-required field (return 0) while allowing the final field
 *       to legitimately end at line_end. */
static ngx_flag_t
adb_scan_field(u_char **p, u_char *line_end, u_char **field_p)
{
    while (*p < line_end && isspace(**p)) (*p)++;
    *field_p = *p;
    while (*p < line_end && !isspace(**p)) (*p)++;
    return *p < line_end;
}

/* WHAT: tokenize one authdb line into its four fields, advancing *cursor past
 *       the line (including its EOL) for the next call.
 * WHY:  splits the line-carving + field-scanning grammar out of the parse loop
 *       so the loop body reads as tokenize → append. Pure over the buffer.
 * HOW:  adb_next_line carves the trimmed line; a blank line or one starting '#'
 *       yields out->valid=0. Otherwise scan four space-delimited fields with
 *       adb_scan_field: a line truncated before path/privs (scan returns 0 on a
 *       non-final field) yields out->valid=0 (rejected). The last field (privs)
 *       may be empty. Field slices point into the caller's buffer. */
static void
adb_tokenize_line(u_char **cursor, u_char *end, adb_line_t *out)
{
    u_char *line_start;
    u_char *line_end;
    u_char *p;

    ngx_memzero(out, sizeof(*out));
    adb_next_line(cursor, end, &line_start, &line_end);

    /* Skip comments and empty lines. */
    if (line_start == line_end || *line_start == '#') {
        return;                         /* out->valid stays 0 */
    }

    /* Format: [u|g|p|a] <id> <path> <privs>. Field 1 (type): only type_p[0] is
     * read later; the rest of the token (if any) is scanned over but ignored.
     * Fields 1-3 must be followed by another field, so a 0 return rejects the
     * line. Field 4 (privs) is last, so its scan return is not required. */
    p = line_start;
    if (!adb_scan_field(&p, line_end, &out->type_p)) return;

    if (!adb_scan_field(&p, line_end, &out->id_p)) return;
    out->id_end = p;

    if (!adb_scan_field(&p, line_end, &out->path_p)) return;
    out->path_end = p;

    (void) adb_scan_field(&p, line_end, &out->privs_p);
    out->privs_end = p;

    out->valid = 1;
}

/* WHAT: push one parsed line as a rule into `rules`, copying id/path into the
 *       config pool. Returns NGX_OK, or NGX_ERROR on allocation failure.
 * WHY:  isolates the array-push + pool ownership from the tokenizer so both are
 *       independently testable and the loop body stays flat.
 * HOW:  ngx_array_push, then set type from field-1's lead byte only, copy id and
 *       path into cf->pool (NUL-terminated — the source buffer is freed at
 *       function exit so rules must own their strings), parse privs, and zero
 *       resolved[] (filled later by brix_finalize_authdb_rules — deferred
 *       realpath). */
static ngx_int_t
adb_append(ngx_conf_t *cf, ngx_array_t *rules, const adb_line_t *line)
{
    brix_authdb_rule_t *rule = ngx_array_push(rules);

    if (rule == NULL) {
        return NGX_ERROR;
    }

    /* Rule type is the first byte of field 1 only (e.g. 'u','g','p','a'); a
     * multi-char first token is effectively truncated to its lead char. */
    rule->type = (brix_auth_type_t) line->type_p[0];

    rule->id.len = line->id_end - line->id_p;
    rule->id.data = ngx_palloc(cf->pool, rule->id.len + 1);
    ngx_memcpy(rule->id.data, line->id_p, rule->id.len);
    rule->id.data[rule->id.len] = '\0';

    rule->path.len = line->path_end - line->path_p;
    rule->path.data = ngx_palloc(cf->pool, rule->path.len + 1);
    ngx_memcpy(rule->path.data, line->path_p, rule->path.len);
    rule->path.data[rule->path.len] = '\0';

    rule->privs = brix_parse_privs((const char *) line->privs_p,
                                    line->privs_end - line->privs_p);

    ngx_memzero(rule->resolved, sizeof(rule->resolved));
    return NGX_OK;
}

/* Parse the authdb file into `rules`: one rule per line (path + identity matcher
 * + privileges).  Returns NGX_CONF_OK / NGX_CONF_ERROR. */
ngx_int_t
brix_parse_authdb(ngx_conf_t *cf, ngx_str_t *filename, ngx_array_t *rules)
{
    u_char      *buf = NULL;
    u_char      *p;
    u_char      *end;
    size_t       buf_len = 0;
    adb_line_t   line;

    (void) ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_brix_module);

    if (adb_read_file(cf, filename, &buf, &buf_len) != NGX_OK) {
        return NGX_ERROR;
    }
    if (buf == NULL) {
        return NGX_OK;                 /* empty file: no rules */
    }

    /* Line loop: p is the running cursor over the whole buffer. adb_tokenize_line
     * carves one line and advances p past its EOL; a valid line is appended. */
    p = buf;
    end = buf + buf_len;
    while (p < end) {
        adb_tokenize_line(&p, end, &line);
        if (!line.valid) {
            continue;
        }
        if (adb_append(cf, rules, &line) != NGX_OK) {
            ngx_free(buf);
            return NGX_ERROR;
        }
    }

    ngx_free(buf);
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
/* WHAT: 1 if a user-type rule's id matches this identity's DN (wildcard or exact).
 * WHY:  isolates the USER matcher (exact/'*' split) from the dispatch switch.
 * HOW:  a bare '*' id matches any DN; otherwise require an exact string compare
 *       of the rule id against dn. dn may be an empty string (no match). */
static ngx_flag_t
adb_user_matches(const ngx_str_t *rule_id, const char *dn)
{
    if (rule_id->len == 1 && rule_id->data[0] == '*') {
        return 1;
    }
    return ngx_strcmp(rule_id->data, dn) == 0;
}

/* WHAT: 1 if a group-type rule's id matches this identity's VO list (wildcard or
 *       membership).
 * WHY:  isolates the GROUP matcher ('*'/VO-membership split) from the switch.
 * HOW:  a bare '*' id matches any VO list; otherwise the rule id (a VO name) must
 *       appear in the comma-separated vo_list. */
static ngx_flag_t
adb_group_matches(const ngx_str_t *rule_id, const char *vo_list)
{
    if (rule_id->len == 1 && rule_id->data[0] == '*') {
        return 1;
    }
    return brix_vo_list_contains(vo_list, (const char *) rule_id->data);
}

/* WHAT: 1 if `rule` applies to this identity by its matcher type; else 0.
 * WHY:  table-flat dispatch over the four rule kinds (all/user/group/host),
 *       keeping the caller's loop body linear. Pure — no I/O, no mutation.
 * HOW:  branch on rule->type: ALL matches unconditionally; USER splits to
 *       adb_user_matches(dn); GROUP to adb_group_matches(vo_list); HOST to
 *       brix_authdb_host_match(peer_ip). Any unknown type does not match
 *       (default-deny). Semantics are frozen against the multi-user conformance
 *       suite; do not alter the per-type rules. */
static ngx_flag_t
adb_identity_matches(const brix_authdb_rule_t *rule, const char *dn,
                     const char *vo_list, const char *peer_ip)
{
    switch (rule->type) {
    case BRIX_AUTH_ALL:
        return 1;
    case BRIX_AUTH_USER:
        return adb_user_matches(&rule->id, dn);
    case BRIX_AUTH_GROUP:
        return adb_group_matches(&rule->id, vo_list);
    case BRIX_AUTHDB_HOST:
        return brix_authdb_host_match(&rule->id, peer_ip);
    default:
        return 0;
    }
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

        if (!adb_identity_matches(&rule[i], dn, vo_list, peer_ip)) {
            continue;
        }

        /* Path + identity match: now require the rule to grant ALL needed bits
         * ((privs & needed) == needed). Only sufficient rules compete; among
         * them the longest prefix wins, with >= letting a later equal-length
         * rule override an earlier one (config last-wins on ties). This is the
         * XRootD longest-prefix semantics — frozen against the conformance suite. */
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
/* Authorize `query->identity` for query->needed_privs on query->resolved_path
 * against query->rules. Returns NGX_OK (granted) or NGX_ERROR (denied). */
ngx_int_t
brix_check_authdb_identity(ngx_log_t *log, const brix_authdb_query_t *query)
{
    const brix_authdb_rule_t   *rule;
    char                          safe_path[512];
    const char                   *dn;
    const char                   *vo_list;

    /* No rules loaded == no authdb policy == unrestricted (allow-all). */
    if (query->rules == NULL || query->rules->nelts == 0) {
        return NGX_OK;
    }

    rule = brix_find_authdb_rule_identity(query->resolved_path, query->rules,
                                            query->identity, query->peer_ip,
                                            query->needed_privs);
    if (rule != NULL) {
        return NGX_OK;
    }

    dn = brix_identity_dn_cstr(query->identity);
    vo_list = brix_identity_vo_csv_cstr(query->identity);
    brix_sanitize_log_string(query->resolved_path, safe_path, sizeof(safe_path));

    ngx_log_error(NGX_LOG_WARN, log, 0,
                  "brix: authdb denied path=\"%s\" privs=0x%02xd "
                  "dn=\"%s\" vos=\"%s\" peer=\"%s\"",
                  safe_path, query->needed_privs, dn,
                  vo_list[0] ? vo_list : "-",
                  (query->peer_ip != NULL && query->peer_ip[0])
                      ? query->peer_ip : "-");

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
        brix_authdb_query_t query = {
            .rules         = conf->authdb_rules,
            .identity      = ctx->identity,
            .peer_ip       = ctx->login.peer_ip,
            .resolved_path = resolved_path,
            .needed_privs  = needed_privs,
        };
        return brix_check_authdb_identity(ctx->session->connection->log,
                                            &query);
    }

    ngx_memzero(&fallback, sizeof(fallback));
    fallback.dn.data = (u_char *) ctx->login.dn;
    fallback.dn.len = strlen(ctx->login.dn);
    fallback.vo_csv.data = (u_char *) ctx->login.vo_list;
    fallback.vo_csv.len = strlen(ctx->login.vo_list);

    brix_authdb_query_t query = {
        .rules         = conf->authdb_rules,
        .identity      = &fallback,
        .peer_ip       = ctx->login.peer_ip,
        .resolved_path = resolved_path,
        .needed_privs  = needed_privs,
    };
    return brix_check_authdb_identity(ctx->session->connection->log, &query);
}
