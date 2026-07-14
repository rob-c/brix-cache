/*
 * authfile.c — XrdAcc authorization database parser (XrdAccAuthFile/ConfigDB).
 *
 * WHAT: brix_acc_authfile_parse() reads a stock XRootD `authdb` file and
 *   builds a complete brix_acc_tables_t generation: the per-category name
 *   lists (users/groups/hosts/netgroups/orgs/roles/templates), the default
 *   (`u *`) and fungible (`u =`) lists, the domain (`h .suffix`) list, and the
 *   compound-identity (`=`) definitions wired to their exclusive (`x`) or
 *   inclusive (`s`) rule capabilities.
 *
 * WHY: faithful port of XrdAccConfig::ConfigDBrec()/idDef() plus the
 *   XrdAccAuthFile tokenizer, so a site can point `brix_authdb_format xrdacc`
 *   at an existing XRootD authdb and get identical structure.
 *
 * HOW: this unit is the orchestrator — it loads the file (<= 1 MiB), drives the
 *   tokenizer (authfile_tokenize.c) to accumulate each logical record, dispatches
 *   each record by its type letter to the per-type handlers (authfile_record.c),
 *   then finalizes the exclusive/inclusive rule ordering.  All storage comes from
 *   the generation's own pool for a one-shot atomic free.
 */

#include "authfile_internal.h"

#include "core/compat/log_diag.h"

#define BRIX_ACC_AUTHDB_MAX  (1024 * 1024)


/*
 * acc_finalize_rules — split the parsed `=` definitions into the exclusive
 * (sx_list, file order) and inclusive (sy_list) chains, dropping any definition
 * that never received an x/s rule (caps == NULL).  Runs once after the whole
 * file parses so the access engine sees the two ordered rule lists.
 */
static void
acc_finalize_rules(brix_acc_tables_t *tabs, ngx_log_t *log)
{
    brix_acc_idrule_t *id, *next;
    brix_acc_idrule_t *sx_tail = NULL, *sy_tail = NULL;

    for (id = tabs->id_defs; id != NULL; id = next) {
        next = id->next;
        id->next = NULL;

        if (id->caps == NULL) {
            ngx_log_error(NGX_LOG_WARN, log, 0,
                          "xrootd authdb: id \"%s\" defined but never used "
                          "(no x/s rule) — ignored", id->name);
            continue;
        }
        if (id->rule >= 0) {                 /* exclusive, file order */
            if (sx_tail == NULL) {
                tabs->sx_list = id;
            } else {
                sx_tail->next = id;
            }
            sx_tail = id;
        } else {                             /* inclusive */
            if (sy_tail == NULL) {
                tabs->sy_list = id;
            } else {
                sy_tail->next = id;
            }
            sy_tail = id;
        }
    }
}

/*
 * acc_dispatch_record — validate the one-letter record type and name of an
 * accumulated record and route it to its type handler (=, x, s, or a named
 * g/h/n/o/r/t/u).  Returns NGX_OK or NGX_ERROR (logged).  Bumps rule_count for
 * diagnostics on every well-formed record.
 */
static ngx_int_t
acc_dispatch_record(acc_parse_ctx_t *pc, char **w, ngx_uint_t n)
{
    char rtype;

    if (w[0][0] == '\0' || w[0][1] != '\0') {
        BRIX_DIAG_EMERG(pc->log, 0,
            "xrootd authdb: invalid record type \"%s\"",
            "each record must begin with a single-letter type in column 1",
            "valid record types are = x s g h n o r t u; fix this line in "
            "the authdb file",
            w[0]);
        return NGX_ERROR;
    }
    rtype = w[0][0];

    if (n < 2) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "xrootd authdb: record name missing after '%c'", rtype);
        return NGX_ERROR;
    }

    pc->tabs->rule_count++;

    switch (rtype) {
    case '=': return acc_record_iddef(pc, w, n);
    case 'x': return acc_record_rule(pc, w, n, 1);
    case 's': return acc_record_rule(pc, w, n, 0);
    case 'g': case 'h': case 'n': case 'o':
    case 'r': case 't': case 'u':
        return acc_record_named(pc, rtype, w, n);
    default:
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "xrootd authdb: invalid id type \"%c\"", rtype);
        return NGX_ERROR;
    }
}

/* Outcome of loading the authdb file into memory. */
enum { ACC_LOAD_OK = 0, ACC_LOAD_EMPTY, ACC_LOAD_ERROR };

/* The slurped authdb file: buffer, byte count and mtime (load out-params). */
typedef struct {
    u_char  *buf;
    size_t   fsize;
    time_t   mtime;
} acc_loaded_t;

/*
 * acc_load_authfile — open, size-check (max 1 MiB) and slurp the authdb `file`
 * into a fresh pool buffer.  On success fills `ld` (buf/fsize/mtime) and returns
 * ACC_LOAD_OK; an empty file returns ACC_LOAD_EMPTY (a valid deny-all db, mtime
 * still set); any error returns ACC_LOAD_ERROR (logged).  Split out of the
 * parser so the main function is just load then tokenize then finalize.
 */
static int
acc_load_authfile(ngx_log_t *log, const char *file, ngx_pool_t *pool,
                  acc_loaded_t *ld)
{
    ngx_fd_t         fd;
    ngx_file_info_t  fi;
    ssize_t          nread;
    size_t           n;

    fd = ngx_open_file((u_char *) file, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        BRIX_DIAG_EMERG(log, ngx_errno,
            "xrootd authdb: cannot open \"%s\"",
            "the path in brix_acc_authdb is wrong or unreadable by the "
            "nginx user",
            "check the path exists and the nginx master/worker user can read "
            "it (the OS reason is appended below)",
            file);
        return ACC_LOAD_ERROR;
    }
    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_close_file(fd);
        return ACC_LOAD_ERROR;
    }
    n = (size_t) ngx_file_size(&fi);
    if (n > BRIX_ACC_AUTHDB_MAX) {
        BRIX_DIAG_EMERG(log, 0,
            "xrootd authdb \"%s\" exceeds the 1 MiB limit",
            "the file is larger than the parser accepts — usually a wrong "
            "path (pointing at a data file) or a runaway generated authdb",
            "confirm brix_acc_authdb points at the authorization file, not "
            "something else; split or trim it below 1 MiB",
            file);
        ngx_close_file(fd);
        return ACC_LOAD_ERROR;
    }

    ld->mtime = ngx_file_mtime(&fi);
    ld->fsize = n;

    if (n == 0) {
        ngx_close_file(fd);
        return ACC_LOAD_EMPTY;   /* empty authdb = deny-all, valid */
    }

    ld->buf = ngx_pnalloc(pool, n);
    if (ld->buf == NULL) {
        ngx_close_file(fd);
        return ACC_LOAD_ERROR;
    }
    nread = ngx_read_fd(fd, ld->buf, n);
    ngx_close_file(fd);
    if (nread < 0 || (size_t) nread != n) {
        BRIX_DIAG_EMERG(log, 0,
            "xrootd authdb: short read of \"%s\"",
            "the file changed size or an I/O error occurred while reading it",
            "make sure the authdb is written atomically (write-then-rename), "
            "then re-run nginx -t",
            file);
        return ACC_LOAD_ERROR;
    }
    return ACC_LOAD_OK;
}

/*
 * acc_tokenize_and_dispatch — run the tokenizer over `buf`/`fsize`, accumulating
 * each logical record's words and dispatching them through the parse context.
 * Returns NGX_OK when the whole buffer parsed, or NGX_ERROR on the first
 * tokenizer alloc failure or record error (which is already logged).
 */
static ngx_int_t
acc_tokenize_and_dispatch(acc_parse_ctx_t *pc, u_char *buf, size_t fsize)
{
    acc_tok_t     tok;
    ngx_array_t  *words;       /* of char* for the current record */
    int           tok_rc;

    words = ngx_array_create(pc->tabs->pool, 16, sizeof(char *));
    if (words == NULL) {
        return NGX_ERROR;
    }

    tok.p = buf;
    tok.end = buf + fsize;
    tok.pool = pc->tabs->pool;

    do {
        char  *w;
        tok_rc = acc_tok_next(&tok, &w);

        if (tok_rc == ACC_TOK_WORD) {
            char **slot = ngx_array_push(words);
            if (slot == NULL) { return NGX_ERROR; }
            *slot = w;
            continue;
        }

        /* End of record or EOF: dispatch any accumulated words. */
        if (words->nelts > 0) {
            if (acc_dispatch_record(pc, (char **) words->elts, words->nelts)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            words->nelts = 0;
        }
    } while (tok_rc != ACC_TOK_EOF);

    return NGX_OK;
}

brix_acc_tables_t *
brix_acc_authfile_parse(ngx_log_t *log, const char *file,
                          char spacechar, ngx_int_t uri_decode)
{
    brix_acc_tables_t  *tabs;
    ngx_pool_t          *pool;
    acc_parse_ctx_t      pc;
    acc_loaded_t         ld = { NULL, 0, 0 };
    int                  load;

    pool = ngx_create_pool(16 * 1024, log);
    if (pool == NULL) {
        return NULL;
    }
    tabs = ngx_pcalloc(pool, sizeof(*tabs));
    if (tabs == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    load = acc_load_authfile(log, file, pool, &ld);
    if (load == ACC_LOAD_ERROR) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    tabs->pool = pool;
    tabs->mtime = ld.mtime;
    tabs->parse_spacechar = spacechar;
    tabs->parse_uridecode = uri_decode;

    if (load == ACC_LOAD_EMPTY) {
        return tabs;   /* empty authdb = deny-all, valid */
    }

    pc.tabs = tabs;
    pc.id_tail = NULL;
    pc.excl_seq = 0;
    pc.log = log;

    if (acc_tokenize_and_dispatch(&pc, ld.buf, ld.fsize) != NGX_OK) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    acc_finalize_rules(tabs, log);
    return tabs;
}
