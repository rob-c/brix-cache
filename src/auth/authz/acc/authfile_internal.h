/*
 * authfile_internal.h — internal contract shared across the XrdAcc authdb
 * parser translation units (authfile.c orchestrator + authfile_tokenize.c lexer
 * + authfile_record.c record builders).
 *
 * WHAT: declares the tokenizer scanner state (acc_tok_t) and its word/record/EOF
 *   token codes, the parse-wide dispatch context (acc_parse_ctx_t), and the four
 *   cross-file entry points — the lexer's acc_tok_next() consumed by the
 *   orchestrator, and the three per-record handlers (iddef/rule/named) invoked
 *   from the orchestrator's record dispatch.
 *
 * WHY: authfile.c was split into three focused units (file-size + single-concern
 *   standard) — the lexer, the record parser/matcher, and the load/dispatch
 *   orchestrator.  A symbol defined in one unit and referenced from another must
 *   be non-static and declared once, in a single include-guarded header, so the
 *   split stays link-clean with zero behaviour change from the former monolith.
 *
 * HOW: every authfile*.c includes this after acc.h.  Structs are plain PODs
 *   carried on the parse stack; the extern functions keep the exact signatures
 *   they had as file-local statics.  Requires: acc.h (brix_acc_* types, ngx core)
 *   before inclusion.
 */

#ifndef NGX_BRIX_ACC_AUTHFILE_INTERNAL_H
#define NGX_BRIX_ACC_AUTHFILE_INTERNAL_H

#include "acc.h"

/* ------------------------------------------------------------------ */
/* Tokenizer (authfile_tokenize.c)                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    u_char      *p;
    u_char      *end;
    ngx_pool_t  *pool;
} acc_tok_t;

enum { ACC_TOK_EOF = -1, ACC_TOK_EOR = 0, ACC_TOK_WORD = 1 };

/*
 * acc_tok_next — return the next word (ACC_TOK_WORD, *word set), an end-of-record
 * marker (ACC_TOK_EOR, at a non-continued newline), or ACC_TOK_EOF.  Whitespace
 * separates words; `\` immediately before a newline continues the record; `#`
 * starts a comment to end of line.
 */
int acc_tok_next(acc_tok_t *t, char **word);

/* ------------------------------------------------------------------ */
/* Record dispatch context + handlers (authfile_record.c)              */
/* ------------------------------------------------------------------ */

/*
 * acc_parse_ctx_t — the parse-wide state threaded through the record dispatch
 * chain.
 *
 * WHAT: bundles the destination tables, the running id-definition tail, the
 *   exclusive-rule sequence counter and the log so that the record helpers take
 *   one context pointer instead of five loose scalars.
 * WHY: the XrdAcc record handlers all read `tabs`/`log` and mutate the same
 *   `id_tail`/`excl_seq` cursors; passing them as a unit keeps signatures small
 *   (≤5 params) and makes the shared mutable cursors explicit at every call.
 * HOW: created once on the parse stack in brix_acc_authfile_parse() and passed
 *   by address down through acc_dispatch_record() and the per-type helpers; the
 *   pool/spacechar/uridecode inputs live on `tabs` and are read via it.
 */
typedef struct {
    brix_acc_tables_t   *tabs;
    brix_acc_idrule_t   *id_tail;    /* tail of id_defs, appended in file order */
    int                  excl_seq;   /* next exclusive-rule order number */
    ngx_log_t           *log;
} acc_parse_ctx_t;

/* `=` record: define a compound identity (selectors only, caps filled by x/s). */
ngx_int_t acc_record_iddef(acc_parse_ctx_t *pc, char **w, ngx_uint_t n);

/* `x`/`s` record: attach capabilities (and exclusive/inclusive flag) to a def. */
ngx_int_t acc_record_rule(acc_parse_ctx_t *pc, char **w, ngx_uint_t n,
                          int exclusive);

/* g/h/n/o/r/t/u record: bind a name to a capability list. */
ngx_int_t acc_record_named(acc_parse_ctx_t *pc, char rtype, char **w,
                           ngx_uint_t n);

#endif /* NGX_BRIX_ACC_AUTHFILE_INTERNAL_H */
