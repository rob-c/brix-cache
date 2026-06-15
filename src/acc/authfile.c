/*
 * authfile.c — XrdAcc authorization database parser (XrdAccAuthFile/ConfigDB).
 *
 * WHAT: xrootd_acc_authfile_parse() reads a stock XRootD `authdb` file and
 *   builds a complete xrootd_acc_tables_t generation: the per-category name
 *   lists (users/groups/hosts/netgroups/orgs/roles/templates), the default
 *   (`u *`) and fungible (`u =`) lists, the domain (`h .suffix`) list, and the
 *   compound-identity (`=`) definitions wired to their exclusive (`x`) or
 *   inclusive (`s`) rule capabilities.
 *
 * WHY: faithful port of XrdAccConfig::ConfigDBrec()/idDef() plus the
 *   XrdAccAuthFile tokenizer, so a site can point `xrootd_authdb_format xrdacc`
 *   at an existing XRootD authdb and get identical structure.
 *
 * HOW: the whole file (<= 1 MiB) is tokenized into records — one logical line
 *   each, with `\`-at-end-of-line continuation and `#` comments — then each
 *   record (`<type> <name> <pairs...>`) is dispatched by its type letter.  All
 *   storage comes from the generation's own pool for a one-shot atomic free.
 */

#include "acc.h"

#include <limits.h>

#define XROOTD_ACC_AUTHDB_MAX  (1024 * 1024)

/* ------------------------------------------------------------------ */
/* Tokenizer — words + logical-record boundaries                       */
/* ------------------------------------------------------------------ */

typedef struct {
    u_char      *p;
    u_char      *end;
    ngx_pool_t  *pool;
} acc_tok_t;

enum { ACC_TOK_EOF = -1, ACC_TOK_EOR = 0, ACC_TOK_WORD = 1 };

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

    for (;;) {
        if (t->p >= t->end) {
            return ACC_TOK_EOF;
        }
        switch (*t->p) {
        case ' ': case '\t': case '\r':
            t->p++;
            continue;
        case '\\':
            /* Backslash at end of line continues the record (join lines). */
            if (t->p + 1 < t->end && t->p[1] == '\n') {
                t->p += 2;
                continue;
            }
            if (t->p + 2 < t->end && t->p[1] == '\r' && t->p[2] == '\n') {
                t->p += 3;
                continue;
            }
            break;  /* otherwise a literal '\' begins a word (path escape) */
        case '#':
            while (t->p < t->end && *t->p != '\n') {
                t->p++;
            }
            continue;
        case '\n':
            t->p++;
            return ACC_TOK_EOR;
        default:
            break;
        }
        break;  /* a word starts here */
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

/* ------------------------------------------------------------------ */
/* Legacy encoding tunables (spacechar / encoding pct path)            */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/* Small builders                                                      */
/* ------------------------------------------------------------------ */

static xrootd_acc_named_t *
acc_named_prepend(ngx_pool_t *pool, xrootd_acc_named_t **head,
                  const char *name, xrootd_acc_cap_t *caps)
{
    xrootd_acc_named_t *n = ngx_pcalloc(pool, sizeof(*n));
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
static xrootd_acc_cap_t *
acc_cap_path(ngx_pool_t *pool, const char *path, const char *privs,
             ngx_log_t *log)
{
    xrootd_acc_cap_t       *cap;
    xrootd_acc_priv_caps_t  pc;
    int                     i;

    if (xrootd_acc_parse_privs(privs, ngx_strlen(privs), &pc) != 0) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb: invalid privileges \"%s\"", privs);
        return NULL;
    }

    cap = ngx_pcalloc(pool, sizeof(*cap));
    if (cap == NULL) {
        return NULL;
    }
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
 * NGX_ERROR (logged).  Mirrors the getPP loop in ConfigDBrec.
 */
static ngx_int_t
acc_build_caps(ngx_pool_t *pool, xrootd_acc_tables_t *tabs,
               char **words, ngx_uint_t start, ngx_uint_t n,
               xrootd_acc_cap_t **out, ngx_log_t *log)
{
    xrootd_acc_cap_t  *head = NULL, *tail = NULL, *cap;
    ngx_uint_t         i = start;

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
            xrootd_acc_cap_t *tcaps = xrootd_acc_named_find(tabs->t_list, path);
            if (tcaps == NULL) {
                ngx_log_error(NGX_LOG_EMERG, log, 0,
                              "xrootd authdb: missing template \"%s\"", path);
                return NGX_ERROR;
            }
            cap = ngx_pcalloc(pool, sizeof(*cap));
            if (cap == NULL) {
                return NGX_ERROR;
            }
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

/* ------------------------------------------------------------------ */
/* Record dispatch                                                     */
/* ------------------------------------------------------------------ */

static int
acc_selector_ok(char c)
{
    return c == 'g' || c == 'h' || c == 'o' || c == 'r' || c == 'u';
}

/*
 * acc_iddef_set — bind one `=` selector value into its slot, rejecting a
 * duplicate selector and applying spacechar to identity values (all but host).
 * Returns NGX_OK or NGX_ERROR (logged) — replaces the former `goto dup`.
 */
static ngx_int_t
acc_iddef_set(char **slot, char *val, char sel, const char *defname,
              char spacechar, ngx_log_t *log)
{
    if (*slot != NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb: id selector '%c' twice for %s",
                      sel, defname);
        return NGX_ERROR;
    }
    if (sel != 'h') {               /* spacechar: identity names only, not host */
        acc_subspace(val, spacechar);
    }
    *slot = val;
    return NGX_OK;
}

/* `=` record: define a compound identity (selectors only, caps filled by x/s). */
static ngx_int_t
acc_record_iddef(xrootd_acc_tables_t *tabs, char **w, ngx_uint_t n,
                 xrootd_acc_idrule_t **id_tail, ngx_log_t *log)
{
    xrootd_acc_idrule_t *id;
    ngx_uint_t           i;

    if ((n - 2) % 2 != 0 || n < 4) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb: `= %s` needs <selector value> pairs",
                      w[1]);
        return NGX_ERROR;
    }
    for (id = tabs->id_defs; id != NULL; id = id->next) {
        if (ngx_strcmp(id->name, w[1]) == 0) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "xrootd authdb: duplicate id definition \"%s\"", w[1]);
            return NGX_ERROR;
        }
    }

    id = ngx_pcalloc(tabs->pool, sizeof(*id));
    if (id == NULL) {
        return NGX_ERROR;
    }
    id->name = w[1];
    id->rule = INT_MIN;   /* "no x/s rule attached yet" */

    for (i = 2; i + 1 < n; i += 2) {
        char       sel = w[i][0];
        char      *val = w[i + 1];
        char       sc  = tabs->parse_spacechar;
        ngx_int_t  rc;

        if (w[i][1] != '\0' || !acc_selector_ok(sel)) {
            ngx_log_error(NGX_LOG_EMERG, log, 0,
                          "xrootd authdb: invalid id selector \"%s\" for %s",
                          w[i], w[1]);
            return NGX_ERROR;
        }
        switch (sel) {
        case 'g': rc = acc_iddef_set(&id->grp,  val, sel, w[1], sc, log); break;
        case 'h': rc = acc_iddef_set(&id->host, val, sel, w[1], sc, log);
                  if (rc == NGX_OK) { id->hlen = (int) ngx_strlen(val); }
                  break;
        case 'o': rc = acc_iddef_set(&id->org,  val, sel, w[1], sc, log); break;
        case 'r': rc = acc_iddef_set(&id->role, val, sel, w[1], sc, log); break;
        default:  rc = acc_iddef_set(&id->user, val, sel, w[1], sc, log); break;
        }
        if (rc != NGX_OK) {
            return NGX_ERROR;
        }
    }

    /* Append in file order. */
    if (*id_tail == NULL) {
        tabs->id_defs = id;
    } else {
        (*id_tail)->next = id;
    }
    *id_tail = id;
    return NGX_OK;
}

/* `x`/`s` record: attach capabilities (and exclusive/inclusive flag) to a def. */
static ngx_int_t
acc_record_rule(xrootd_acc_tables_t *tabs, char **w, ngx_uint_t n,
                int exclusive, int *excl_seq, ngx_log_t *log)
{
    xrootd_acc_idrule_t *id;

    for (id = tabs->id_defs; id != NULL; id = id->next) {
        if (ngx_strcmp(id->name, w[1]) == 0) {
            break;
        }
    }
    if (id == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb: missing id definition \"%s\"", w[1]);
        return NGX_ERROR;
    }
    if (id->caps != NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb: duplicate rule for id \"%s\"", w[1]);
        return NGX_ERROR;
    }
    if (acc_build_caps(tabs->pool, tabs, w, 2, n, &id->caps, log) != NGX_OK) {
        return NGX_ERROR;
    }
    id->rule = exclusive ? (*excl_seq)++ : -1;
    return NGX_OK;
}

/* g/h/n/o/r/t/u record: bind a name to a capability list. */
static ngx_int_t
acc_record_named(xrootd_acc_tables_t *tabs, char rtype, char **w, ngx_uint_t n,
                 ngx_log_t *log)
{
    xrootd_acc_named_t **head = NULL;
    xrootd_acc_cap_t    *caps;
    char                *name = w[1];
    int                  alluser = 0, anyuser = 0, domain = 0;

    switch (rtype) {
    case 'g': head = &tabs->g_list; break;
    case 'n': head = &tabs->n_list; break;
    case 'o': head = &tabs->o_list; break;
    case 'r': head = &tabs->r_list; break;
    case 't': head = &tabs->t_list; break;
    case 'h':
        domain = (name[0] == '.');
        head = domain ? &tabs->d_list : &tabs->h_list;
        break;
    case 'u':
        alluser = (name[0] == '*' && name[1] == '\0');
        anyuser = (name[0] == '=' && name[1] == '\0');
        head = &tabs->u_list;
        break;
    default:
        return NGX_ERROR;
    }

    /* spacechar: substitute in identity names only (g/o/r/u), never the `u *`/
     * `u =` wildcards, host, netgroup or template names (XrdAcc ConfigDBrec). */
    if (rtype == 'g' || rtype == 'o' || rtype == 'r'
        || (rtype == 'u' && !alluser && !anyuser))
    {
        acc_subspace(name, tabs->parse_spacechar);
    }

    /* Duplicate detection. */
    if ((alluser && tabs->z_list != NULL)
        || (anyuser && tabs->x_list != NULL)
        || (!alluser && !anyuser
            && xrootd_acc_named_find(*head, name) != NULL))
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb: duplicate rule for id \"%s\"", name);
        return NGX_ERROR;
    }

    if (acc_build_caps(tabs->pool, tabs, w, 2, n, &caps, log) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb: no capabilities for \"%s\"", name);
        return NGX_ERROR;
    }

    if (alluser) {
        tabs->z_list = caps;
    } else if (anyuser) {
        tabs->x_list = caps;
    } else if (acc_named_prepend(tabs->pool, head, name, caps) == NULL) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

/* ------------------------------------------------------------------ */
/* Post-parse: split id defs into exclusive (ordered) + inclusive      */
/* ------------------------------------------------------------------ */

static void
acc_finalize_rules(xrootd_acc_tables_t *tabs, ngx_log_t *log)
{
    xrootd_acc_idrule_t *id, *next;
    xrootd_acc_idrule_t *sx_tail = NULL, *sy_tail = NULL;

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

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

static ngx_int_t
acc_dispatch_record(xrootd_acc_tables_t *tabs, char **w, ngx_uint_t n,
                    xrootd_acc_idrule_t **id_tail, int *excl_seq, ngx_log_t *log)
{
    char rtype;

    if (w[0][0] == '\0' || w[0][1] != '\0') {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb: invalid id type \"%s\"", w[0]);
        return NGX_ERROR;
    }
    rtype = w[0][0];

    if (n < 2) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb: record name missing after '%c'", rtype);
        return NGX_ERROR;
    }

    tabs->rule_count++;

    switch (rtype) {
    case '=': return acc_record_iddef(tabs, w, n, id_tail, log);
    case 'x': return acc_record_rule(tabs, w, n, 1, excl_seq, log);
    case 's': return acc_record_rule(tabs, w, n, 0, excl_seq, log);
    case 'g': case 'h': case 'n': case 'o':
    case 'r': case 't': case 'u':
        return acc_record_named(tabs, rtype, w, n, log);
    default:
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb: invalid id type \"%c\"", rtype);
        return NGX_ERROR;
    }
}

xrootd_acc_tables_t *
xrootd_acc_authfile_parse(ngx_log_t *log, const char *file,
                          char spacechar, ngx_int_t uri_decode)
{
    xrootd_acc_tables_t  *tabs;
    xrootd_acc_idrule_t  *id_tail = NULL;
    ngx_pool_t           *pool;
    ngx_fd_t              fd;
    ngx_file_info_t       fi;
    u_char               *buf;
    ssize_t               nread;
    size_t                fsize;
    acc_tok_t             tok;
    ngx_array_t          *words;       /* of char* for the current record */
    int                   excl_seq = 0, rc, tok_rc;
    ngx_int_t             status = NGX_OK;

    fd = ngx_open_file((u_char *) file, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      "xrootd authdb: open \"%s\" failed", file);
        return NULL;
    }
    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_close_file(fd);
        return NULL;
    }
    fsize = (size_t) ngx_file_size(&fi);
    if (fsize > XROOTD_ACC_AUTHDB_MAX) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb \"%s\" exceeds 1 MiB", file);
        ngx_close_file(fd);
        return NULL;
    }

    pool = ngx_create_pool(16 * 1024, log);
    if (pool == NULL) {
        ngx_close_file(fd);
        return NULL;
    }
    tabs = ngx_pcalloc(pool, sizeof(*tabs));
    if (tabs == NULL) {
        ngx_destroy_pool(pool);
        ngx_close_file(fd);
        return NULL;
    }
    tabs->pool = pool;
    tabs->mtime = ngx_file_mtime(&fi);
    tabs->parse_spacechar = spacechar;
    tabs->parse_uridecode = uri_decode;

    if (fsize == 0) {
        ngx_close_file(fd);
        return tabs;   /* empty authdb = deny-all, valid */
    }

    buf = ngx_pnalloc(pool, fsize);
    if (buf == NULL) {
        ngx_destroy_pool(pool);
        ngx_close_file(fd);
        return NULL;
    }
    nread = ngx_read_fd(fd, buf, fsize);
    ngx_close_file(fd);
    if (nread < 0 || (size_t) nread != fsize) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "xrootd authdb: read \"%s\" failed", file);
        ngx_destroy_pool(pool);
        return NULL;
    }

    words = ngx_array_create(pool, 16, sizeof(char *));
    if (words == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    tok.p = buf;
    tok.end = buf + fsize;
    tok.pool = pool;

    do {
        char  *w;
        tok_rc = acc_tok_next(&tok, &w);

        if (tok_rc == ACC_TOK_WORD) {
            char **slot = ngx_array_push(words);
            if (slot == NULL) { status = NGX_ERROR; break; }
            *slot = w;
            continue;
        }

        /* End of record or EOF: dispatch any accumulated words. */
        if (words->nelts > 0) {
            rc = acc_dispatch_record(tabs, (char **) words->elts, words->nelts,
                                     &id_tail, &excl_seq, log);
            if (rc != NGX_OK) { status = NGX_ERROR; break; }
            words->nelts = 0;
        }
    } while (tok_rc != ACC_TOK_EOF);

    if (status != NGX_OK) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    acc_finalize_rules(tabs, log);
    return tabs;
}
