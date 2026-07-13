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
 * HOW: the whole file (<= 1 MiB) is tokenized into records — one logical line
 *   each, with `\`-at-end-of-line continuation and `#` comments — then each
 *   record (`<type> <name> <pairs...>`) is dispatched by its type letter.  All
 *   storage comes from the generation's own pool for a one-shot atomic free.
 */

#include "acc.h"

#include <limits.h>
#include "core/compat/alloc_guard.h"
#include "core/compat/log_diag.h"

#define BRIX_ACC_AUTHDB_MAX  (1024 * 1024)


typedef struct {
    u_char      *p;
    u_char      *end;
    ngx_pool_t  *pool;
} acc_tok_t;

enum { ACC_TOK_EOF = -1, ACC_TOK_EOR = 0, ACC_TOK_WORD = 1 };

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
static int
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


/*
 * acc_subspace — in-place replace every `sc` with a real space in an identity
 * name, so a name containing spaces can be written without quoting (ports
 * XrdAccConfig::subSpace).  No-op when sc is 0.  Applied to g/o/r/u names only.
 */
static void
acc_subspace(char *id, char sc)
{
    if (sc == '\0' || id == NULL) {
        return;
    }
    for (; *id != '\0'; id++) {
        if (*id == sc) {
            *id = ' ';
        }
    }
}

/*
 * acc_uri_decode — return a pool copy of `s` with %XX escapes decoded (ports
 * the XrdOucUri::Decode applied to path tokens under `encoding pct path`).  A
 * malformed escape is left literal.  Returns `s` unchanged on alloc failure.
 */
static const char *
acc_uri_decode(ngx_pool_t *pool, const char *s)
{
    size_t  n = ngx_strlen(s);
    char   *out = ngx_pnalloc(pool, n + 1);
    char   *w;
    size_t  i;

    if (out == NULL) {
        return s;
    }
    for (w = out, i = 0; i < n; i++) {
        if (s[i] == '%' && i + 2 < n) {
            ngx_int_t hi = ngx_hextoi((u_char *) &s[i + 1], 2);
            if (hi >= 0) {                 /* both nibbles were hex digits */
                *w++ = (char) hi;
                i += 2;
                continue;
            }
        }
        *w++ = s[i];
    }
    *w = '\0';
    return out;
}


static brix_acc_named_t *
acc_named_prepend(ngx_pool_t *pool, brix_acc_named_t **head,
                  const char *name, brix_acc_cap_t *caps)
{
    brix_acc_named_t *n = ngx_pcalloc(pool, sizeof(*n));
    if (n == NULL) {
        return NULL;
    }
    n->name = (char *) name;
    n->nlen = (int) ngx_strlen(name);
    n->caps = caps;
    n->next = *head;
    *head = n;
    return n;
}

/* Build a capability node for a concrete path + privilege string. */
static brix_acc_cap_t *
acc_cap_path(ngx_pool_t *pool, const char *path, const char *privs,
             ngx_log_t *log)
{
    brix_acc_cap_t       *cap;
    brix_acc_priv_caps_t  pc;
    int                     i;

    if (brix_acc_parse_privs(privs, ngx_strlen(privs), &pc) != 0) {
        BRIX_DIAG_EMERG(log, 0,
            "xrootd authdb: invalid privileges \"%s\"",
            "a privilege token contains an unknown letter",
            "valid privilege letters are a(ll) d(elete) i(nsert) k(lock) "
            "l(ookup) n(rename) r(ead) w(rite), optionally prefixed '-' to "
            "deny; fix this record in the authdb file",
            privs);
        return NULL;
    }

    BRIX_PCALLOC_OR_RETURN(cap, pool, sizeof(*cap), NULL);
    cap->path = (char *) path;
    cap->plen = (int) ngx_strlen(path);
    cap->caps = pc;

    /* Locate a "@=" template-substitution point. */
    for (i = 0; i < cap->plen; i++) {
        if (cap->path[i] == '@' && cap->path[i + 1] == '=') {
            cap->pins = i;
            cap->prem = cap->plen - i - 2;
            break;
        }
    }
    return cap;
}

/*
 * acc_build_caps — parse the trailing `<path|template> <priv>` pairs of a record
 * (words[start..n]) into a capability list.  Returns NGX_OK and sets *out, or
 * NGX_ERROR (logged).  Mirrors the getPP loop in ConfigDBrec.  Pool/tables/log
 * travel on the parse context so the signature stays ≤5 params.
 */
static ngx_int_t
acc_build_caps(acc_parse_ctx_t *pc, char **words, ngx_uint_t start,
               ngx_uint_t n, brix_acc_cap_t **out)
{
    brix_acc_tables_t *tabs = pc->tabs;
    ngx_pool_t        *pool = tabs->pool;
    ngx_log_t         *log  = pc->log;
    brix_acc_cap_t    *head = NULL, *tail = NULL, *cap;
    ngx_uint_t          i = start;

    while (i < n) {
        char *path = words[i++];
        int   istmplt;

        if (path[0] == '\\') {
            if (path[1] == '\0') {
                ngx_log_error(NGX_LOG_EMERG, log, 0,
                              "xrootd authdb: object id missing after '\\'");
                return NGX_ERROR;
            }
            path++;           /* escaped: a real path, '\' stripped */
            istmplt = 0;
        } else {
            istmplt = (path[0] != '/');
        }

        if (istmplt) {
            /* Template indirection: reference a previously-defined `t` list. */
            brix_acc_cap_t *tcaps = brix_acc_named_find(tabs->t_list, path);
            if (tcaps == NULL) {
                ngx_log_error(NGX_LOG_EMERG, log, 0,
                              "xrootd authdb: missing template \"%s\"", path);
                return NGX_ERROR;
            }
            BRIX_PCALLOC_OR_RETURN(cap, pool, sizeof(*cap), NGX_ERROR);
            cap->tmpl = tcaps;
        } else {
            if (i >= n) {
                ngx_log_error(NGX_LOG_EMERG, log, 0,
                              "xrootd authdb: missing privs for path \"%s\"",
                              path);
                return NGX_ERROR;
            }
            /* encoding pct path: URI-decode the path token before storing. */
            if (tabs->parse_uridecode) {
                path = (char *) acc_uri_decode(pool, path);
            }
            cap = acc_cap_path(pool, path, words[i++], log);
            if (cap == NULL) {
                return NGX_ERROR;
            }
        }

        if (tail == NULL) {
            head = tail = cap;
        } else {
            tail->next = cap;
            tail = cap;
        }
    }

    if (head == NULL) {
        return NGX_ERROR;   /* no capabilities specified */
    }
    *out = head;
    return NGX_OK;
}


static int
acc_selector_ok(char c)
{
    return c == 'g' || c == 'h' || c == 'o' || c == 'r' || c == 'u';
}

/*
 * acc_iddef_set — bind one `=` selector value into its slot, rejecting a
 * duplicate selector and applying spacechar to identity values (all but host).
 * Returns NGX_OK or NGX_ERROR (logged) — replaces the former `goto dup`.  The
 * log and spacechar travel on the parse context; only the per-selector slot/
 * value/letter and the def name are passed loose.
 */
static ngx_int_t
acc_iddef_set(acc_parse_ctx_t *pc, char **slot, char *val, char sel,
              const char *defname)
{
    if (*slot != NULL) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "xrootd authdb: id selector '%c' twice for %s",
                      sel, defname);
        return NGX_ERROR;
    }
    if (sel != 'h') {               /* spacechar: identity names only, not host */
        acc_subspace(val, pc->tabs->parse_spacechar);
    }
    *slot = val;
    return NGX_OK;
}

/*
 * acc_iddef_bind_selector — bind one `<selector> <value>` pair of a `=` record
 * into the matching slot of `id`, validating the one-letter selector and setting
 * host length for `h`.  Returns NGX_OK or NGX_ERROR (logged).  Split out of the
 * iddef loop so the record handler stays a flat scan.
 */
static ngx_int_t
acc_iddef_bind_selector(acc_parse_ctx_t *pc, brix_acc_idrule_t *id,
                        char **w, const char *defname)
{
    char sel = w[0][0];
    char *val = w[1];

    if (w[0][1] != '\0' || !acc_selector_ok(sel)) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "xrootd authdb: invalid id selector \"%s\" for %s",
                      w[0], defname);
        return NGX_ERROR;
    }
    switch (sel) {
    case 'g': return acc_iddef_set(pc, &id->grp,  val, sel, defname);
    case 'h': {
        ngx_int_t rc = acc_iddef_set(pc, &id->host, val, sel, defname);
        if (rc == NGX_OK) { id->hlen = (int) ngx_strlen(val); }
        return rc;
    }
    case 'o': return acc_iddef_set(pc, &id->org,  val, sel, defname);
    case 'r': return acc_iddef_set(pc, &id->role, val, sel, defname);
    default:  return acc_iddef_set(pc, &id->user, val, sel, defname);
    }
}

/* `=` record: define a compound identity (selectors only, caps filled by x/s). */
static ngx_int_t
acc_record_iddef(acc_parse_ctx_t *pc, char **w, ngx_uint_t n)
{
    brix_acc_tables_t *tabs = pc->tabs;
    brix_acc_idrule_t *id;
    ngx_uint_t           i;

    if ((n - 2) % 2 != 0 || n < 4) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "xrootd authdb: `= %s` needs <selector value> pairs",
                      w[1]);
        return NGX_ERROR;
    }
    for (id = tabs->id_defs; id != NULL; id = id->next) {
        if (ngx_strcmp(id->name, w[1]) == 0) {
            ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                          "xrootd authdb: duplicate id definition \"%s\"", w[1]);
            return NGX_ERROR;
        }
    }

    BRIX_PCALLOC_OR_RETURN(id, tabs->pool, sizeof(*id), NGX_ERROR);
    id->name = w[1];
    id->rule = INT_MIN;   /* "no x/s rule attached yet" */

    for (i = 2; i + 1 < n; i += 2) {
        if (acc_iddef_bind_selector(pc, id, &w[i], w[1]) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* Append in file order. */
    if (pc->id_tail == NULL) {
        tabs->id_defs = id;
    } else {
        pc->id_tail->next = id;
    }
    pc->id_tail = id;
    return NGX_OK;
}

/* `x`/`s` record: attach capabilities (and exclusive/inclusive flag) to a def. */
static ngx_int_t
acc_record_rule(acc_parse_ctx_t *pc, char **w, ngx_uint_t n, int exclusive)
{
    brix_acc_idrule_t *id;

    for (id = pc->tabs->id_defs; id != NULL; id = id->next) {
        if (ngx_strcmp(id->name, w[1]) == 0) {
            break;
        }
    }
    if (id == NULL) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "xrootd authdb: missing id definition \"%s\"", w[1]);
        return NGX_ERROR;
    }
    if (id->caps != NULL) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "xrootd authdb: duplicate rule for id \"%s\"", w[1]);
        return NGX_ERROR;
    }
    if (acc_build_caps(pc, w, 2, n, &id->caps) != NGX_OK) {
        return NGX_ERROR;
    }
    id->rule = exclusive ? (pc->excl_seq)++ : -1;
    return NGX_OK;
}

/*
 * acc_named_t — the resolved placement of one g/h/n/o/r/t/u record: which name
 * list it prepends to, and whether it is one of the two `u` wildcards (`u *` →
 * default z_list, `u =` → fungible x_list) which store a bare cap list instead.
 */
typedef struct {
    brix_acc_named_t **head;     /* target name list, or NULL for a wildcard */
    int                alluser;  /* the `u *` default record */
    int                anyuser;  /* the `u =` fungible record */
} acc_named_t;

/*
 * acc_named_resolve — classify a g/h/n/o/r/t/u record by its type letter and
 * name into an acc_named_t placement.  Ports the head-selection switch of
 * ConfigDBrec: `h .suffix` → domain list, `u *`/`u =` → the wildcard slots.
 * Returns NGX_OK (out filled) or NGX_ERROR for an unknown type.
 */
static ngx_int_t
acc_named_resolve(brix_acc_tables_t *tabs, char rtype, const char *name,
                  acc_named_t *out)
{
    out->head = NULL;
    out->alluser = 0;
    out->anyuser = 0;

    switch (rtype) {
    case 'g': out->head = &tabs->g_list; return NGX_OK;
    case 'n': out->head = &tabs->n_list; return NGX_OK;
    case 'o': out->head = &tabs->o_list; return NGX_OK;
    case 'r': out->head = &tabs->r_list; return NGX_OK;
    case 't': out->head = &tabs->t_list; return NGX_OK;
    case 'h':
        out->head = (name[0] == '.') ? &tabs->d_list : &tabs->h_list;
        return NGX_OK;
    case 'u':
        out->alluser = (name[0] == '*' && name[1] == '\0');
        out->anyuser = (name[0] == '=' && name[1] == '\0');
        out->head = &tabs->u_list;
        return NGX_OK;
    default:
        return NGX_ERROR;
    }
}

/*
 * acc_named_is_dup — has this named record already been defined?  A `u *`/`u =`
 * wildcard is duplicate when its dedicated slot is set; any other name is a
 * duplicate when already present in its list.  Read-only classification helper.
 */
static int
acc_named_is_dup(brix_acc_tables_t *tabs, const acc_named_t *nc,
                 const char *name)
{
    if (nc->alluser) {
        return tabs->z_list != NULL;
    }
    if (nc->anyuser) {
        return tabs->x_list != NULL;
    }
    return brix_acc_named_find(*nc->head, name) != NULL;
}

/*
 * acc_named_store — install the built capability list at its resolved slot: the
 * default (z), fungible (x), or the prepended name list.  Returns NGX_OK or
 * NGX_ERROR on alloc failure of the name node.
 */
static ngx_int_t
acc_named_store(brix_acc_tables_t *tabs, const acc_named_t *nc,
                const char *name, brix_acc_cap_t *caps)
{
    if (nc->alluser) {
        tabs->z_list = caps;
        return NGX_OK;
    }
    if (nc->anyuser) {
        tabs->x_list = caps;
        return NGX_OK;
    }
    return acc_named_prepend(tabs->pool, nc->head, name, caps) == NULL
           ? NGX_ERROR : NGX_OK;
}

/* g/h/n/o/r/t/u record: bind a name to a capability list. */
static ngx_int_t
acc_record_named(acc_parse_ctx_t *pc, char rtype, char **w, ngx_uint_t n)
{
    brix_acc_tables_t *tabs = pc->tabs;
    brix_acc_cap_t    *caps;
    char                *name = w[1];
    acc_named_t          nc;

    if (acc_named_resolve(tabs, rtype, name, &nc) != NGX_OK) {
        return NGX_ERROR;
    }

    /* spacechar: substitute in identity names only (g/o/r/u), never the `u *`/
     * `u =` wildcards, host, netgroup or template names (XrdAcc ConfigDBrec). */
    if (rtype == 'g' || rtype == 'o' || rtype == 'r'
        || (rtype == 'u' && !nc.alluser && !nc.anyuser))
    {
        acc_subspace(name, tabs->parse_spacechar);
    }

    if (acc_named_is_dup(tabs, &nc, name)) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "xrootd authdb: duplicate rule for id \"%s\"", name);
        return NGX_ERROR;
    }

    if (acc_build_caps(pc, w, 2, n, &caps) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, pc->log, 0,
                      "xrootd authdb: no capabilities for \"%s\"", name);
        return NGX_ERROR;
    }

    return acc_named_store(tabs, &nc, name, caps);
}


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
