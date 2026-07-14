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
