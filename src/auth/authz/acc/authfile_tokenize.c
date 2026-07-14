/*
 * authfile_tokenize.c — the XrdAccAuthFile lexer for the `authdb` parser.
 *
 * WHAT: acc_tok_next() splits the slurped authdb buffer into logical records —
 *   whitespace-separated words, one record per line, with `\`-at-end-of-line
 *   continuation and `#` comments — returning ACC_TOK_WORD / ACC_TOK_EOR /
 *   ACC_TOK_EOF.  Words are pool-copied and NUL-terminated for the record layer.
 *
 * WHY: the byte-level scanner is a self-contained concern with no knowledge of
 *   record types or the tables it feeds; splitting it out of authfile.c keeps the
 *   orchestrator focused on load→dispatch→finalize and each unit under the
 *   file-size standard.  Its tokenization is byte-for-byte the stock
 *   XrdAccAuthFile behaviour so an existing authdb parses identically.
 *
 * HOW: acc_tok_skip_gap() advances over separators, `\`-newline continuations
 *   and comments to classify the next byte; acc_tok_next() then scans a word (or
 *   emits the record/EOF marker).  All allocation comes from the caller's pool.
 */

#include "authfile_internal.h"

/*
 * acc_pstrdup — pool-copy `len` bytes of `s` into a fresh NUL-terminated buffer.
 *
 * WHAT: returns a pool-owned NUL-terminated copy of the word, or NULL on alloc
 *   failure.
 * WHY: wire words are not NUL-terminated slices of the mmap'd buffer; the record
 *   layer wants C strings it can strcmp/strlen without carrying lengths around.
 * HOW: 1) allocate len+1 from the pool; 2) memcpy the bytes; 3) append '\0'.
 */
static char *
acc_pstrdup(ngx_pool_t *pool, const u_char *s, size_t len)
{
    char *d = ngx_pnalloc(pool, len + 1);
    if (d == NULL) {
        return NULL;
    }
    ngx_memcpy(d, s, len);
    d[len] = '\0';
    return d;
}

/* Outcome of skipping inter-token gap: what the scanner is now positioned on. */
enum { ACC_GAP_EOF = 0, ACC_GAP_EOR, ACC_GAP_WORD };

/*
 * acc_tok_bslash_is_cont — is the '\' at t->p an end-of-line continuation
 * (`\<newline>` or `\<cr><newline>`) rather than the start of an escaped path
 * word?  Advances t->p past the continuation and returns 1 when it is; leaves
 * t->p untouched and returns 0 otherwise.
 */
static int
acc_tok_bslash_is_cont(acc_tok_t *t)
{
    if (t->p + 1 < t->end && t->p[1] == '\n') {
        t->p += 2;
        return 1;
    }
    if (t->p + 2 < t->end && t->p[1] == '\r' && t->p[2] == '\n') {
        t->p += 3;
        return 1;
    }
    return 0;
}

/*
 * acc_tok_skip_gap — advance t->p over separators (space/tab/cr), `\`-newline
 * continuations and `#` comments, stopping at the first byte that starts a word,
 * a record-terminating newline, or end of input.  Returns ACC_GAP_WORD /
 * ACC_GAP_EOR (having consumed the newline) / ACC_GAP_EOF accordingly.  Split
 * out of acc_tok_next so the classify step is separate from word scanning.
 */
static int
acc_tok_skip_gap(acc_tok_t *t)
{
    for (;;) {
        if (t->p >= t->end) {
            return ACC_GAP_EOF;
        }
        switch (*t->p) {
        case ' ': case '\t': case '\r':
            t->p++;
            continue;
        case '\\':
            if (acc_tok_bslash_is_cont(t)) {
                continue;
            }
            return ACC_GAP_WORD;   /* literal '\' begins a word (path escape) */
        case '#':
            while (t->p < t->end && *t->p != '\n') {
                t->p++;
            }
            continue;
        case '\n':
            t->p++;
            return ACC_GAP_EOR;
        default:
            return ACC_GAP_WORD;
        }
    }
}

/*
 * acc_tok_next — return the next word (ACC_TOK_WORD, *word set), an end-of-record
 * marker (ACC_TOK_EOR, at a non-continued newline), or ACC_TOK_EOF.  Whitespace
 * separates words; `\` immediately before a newline continues the record; `#`
 * starts a comment to end of line.
 */
int
acc_tok_next(acc_tok_t *t, char **word)
{
    u_char *start;

    switch (acc_tok_skip_gap(t)) {
    case ACC_GAP_EOF: return ACC_TOK_EOF;
    case ACC_GAP_EOR: return ACC_TOK_EOR;
    default:          break;   /* ACC_GAP_WORD: a word starts at t->p */
    }

    start = t->p;
    while (t->p < t->end
           && *t->p != ' ' && *t->p != '\t'
           && *t->p != '\n' && *t->p != '\r')
    {
        t->p++;
    }

    *word = acc_pstrdup(t->pool, start, (size_t) (t->p - start));
    return (*word == NULL) ? ACC_TOK_EOF : ACC_TOK_WORD;
}
