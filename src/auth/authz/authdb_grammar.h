#ifndef BRIX_AUTHDB_GRAMMAR_H
#define BRIX_AUTHDB_GRAMMAR_H
/*
 * authdb_grammar.h — the native authdb LINE grammar, split out of
 * authdb_parse.c (which owns file I/O and line carving) so both stay under the
 * 600-line file cap.  Internal to src/auth/authz/; not a public surface.
 */
#include "core/ngx_brix_module.h"

/* One tokenized authdb line: the four field slices [start,end) carved out of the
 * source buffer. `valid` is 0 for a blank/comment/truncated line the caller must
 * skip (no rule to push). Slices point into the caller's buffer — no ownership. */
typedef struct {
    ngx_flag_t  valid;
    ngx_flag_t  malformed;   /* a non-comment line that did not tokenize */
    u_char     *type_p,  *type_end;
    u_char     *id_p,    *id_end;
    u_char     *path_p,  *path_end;
    u_char     *privs_p, *privs_end;
} adb_line_t;

/*
 * adb_parse_ctx_t — everything the grammar helpers need to refuse a line.
 *
 * `defect` is the deferral seam.  `brix_authdb` is a directive, but the ENGINE
 * that consumes the file (`brix_authdb_engine native|xrdacc`) may not have been
 * stated yet when the directive runs, and the same file is parsed by BOTH
 * engines' parsers.  Refusing an xrdacc-shaped file here would break every
 * `brix_authdb_engine xrdacc` server, so a grammar defect is RECORDED (first
 * one wins) and the merge — where the engine is final — turns it into an
 * `nginx -t` failure for the native engine only.  A NULL `defect` means the
 * caller wants the defect raised immediately.
 */
typedef struct {
    ngx_conf_t  *cf;
    ngx_str_t   *filename;
    ngx_str_t   *defect;
    ngx_uint_t   lineno;
} adb_parse_ctx_t;


/* Record (or immediately raise) a grammar defect on pc->lineno.  Always
 * returns NGX_DECLINED. */
ngx_int_t brix_adb_reject(adb_parse_ctx_t *pc, const char *reason);

/* Build one rule from a tokenized line and push it.  NGX_OK pushed;
 * NGX_DECLINED refused (nothing pushed); NGX_ERROR allocation failure. */
ngx_int_t brix_adb_append(adb_parse_ctx_t *pc, ngx_array_t *rules,
    const adb_line_t *line);

#endif /* BRIX_AUTHDB_GRAMMAR_H */
