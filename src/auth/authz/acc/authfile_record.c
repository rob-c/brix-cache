/*
 * authfile_record.c — XrdAcc authdb per-record parsing and capability building.
 *
 * WHAT: turns one tokenized record (`<type> <name> <pairs...>`) into table
 *   state.  acc_record_iddef()/acc_record_rule()/acc_record_named() are the three
 *   type handlers the orchestrator dispatches to; the file-local helpers build
 *   the trailing `<path|template> <priv>` capability lists, apply the spacechar/
 *   URI-decode legacy tunables, and classify a g/h/n/o/r/t/u name to its list.
 *
 * WHY: this is the security-load-bearing heart of the parser — the exact rule
 *   parse, privilege bits, template indirection, and grant/deny slot placement
 *   that XrdAccConfig::ConfigDBrec()/idDef() define.  Isolating it from the lexer
 *   and the load/dispatch orchestrator keeps each unit single-concern and under
 *   the file-size standard, with the record semantics preserved byte-for-byte.
 *
 * HOW: acc_build_caps() mirrors the getPP loop; acc_record_iddef() builds the `=`
 *   compound-identity, acc_record_rule() attaches x/s capabilities, and
 *   acc_record_named() resolves+stores a named record via the acc_named_* helpers.
 *   All storage comes from the generation's own pool.
 */

#include "authfile_internal.h"

#include <limits.h>
#include "core/compat/alloc_guard.h"
#include "core/compat/log_diag.h"

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
ngx_int_t
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
ngx_int_t
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
ngx_int_t
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
