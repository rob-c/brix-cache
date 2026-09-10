/*
 * cms_fsxeq_conf.c — 2.0 F17: brix_cms_fsxeq / brix_cms_fsxeq_timeout.
 *
 * WHAT: Parse `brix_cms_fsxeq <op> [<op>...] <program> [<arg>...]` into the
 *       seven-slot brix_cms_conf_t.fsxeq[] table — the operator program that
 *       REPLACES this data node's built-in execution of a manager-forwarded
 *       namespace op (chmod, mkdir, mkpath, mv, rm, rmdir, trunc) — and hold
 *       that program to the same file-mode rule brix_frm_stagecmd and
 *       brix_frm_purge_polprog already apply.
 *
 * WHY:  stock cmsd's `cms.fsxeq <types> <prog>` (XrdCmsConfig::xfsxq) lets a
 *       site put its own namespace semantics — a catalogue update, a quota
 *       hook, a tape-aware unlink — behind the ops a manager forwards down.
 *       BriX refused the feature until 2.0 on performance and blast-radius
 *       grounds; the refusal was withdrawn by the 2026-09-09 scope decision and
 *       the constraints it was made for became this item's requirements (see
 *       node_fsxeq.c, which never forks on the worker's own thread).
 *
 * HOW:  The grammar is stock's: leading tokens are op names, consumed while
 *       they match; the first token that is not an op name begins the command
 *       line, and everything after it is a literal argument the runner keeps in
 *       front of the op's own arguments.  One directive line allocates one
 *       brix_cms_fsxeq_prog_t and points every op it names at it, so a program
 *       shared between ops is stored once.  Re-registering an op that already
 *       has a program is a config error rather than a silent last-wins, because
 *       "which program runs my rm" must have exactly one answer.
 */

#include "config.h"
#include "tape_stage_conf.h"      /* brix_frm_check_program */

/* The directive's op keywords, in slot order (BRIX_CMS_FSXEQ_*). */
static const char *const  brix_cms_fsxeq_names[BRIX_CMS_FSXEQ_OPS] = {
    "chmod", "mkdir", "mkpath", "mv", "rm", "rmdir", "trunc"
};

/* Slot index for an op keyword, or -1 when the token is not one (which is how
 * the parser learns the command line has started). */
static ngx_int_t
fsxeq_op_index(const ngx_str_t *tok)
{
    ngx_uint_t  i;

    for (i = 0; i < BRIX_CMS_FSXEQ_OPS; i++) {
        if (ngx_strlen(brix_cms_fsxeq_names[i]) == tok->len
            && ngx_strncmp(tok->data, brix_cms_fsxeq_names[i], tok->len) == 0)
        {
            return (ngx_int_t) i;
        }
    }
    return -1;
}

/* The whole command line as one displayable string (log + error text). */
static ngx_int_t
fsxeq_render_display(ngx_conf_t *cf, ngx_str_t *value, ngx_uint_t first,
    ngx_uint_t n, ngx_str_t *out)
{
    ngx_uint_t  i, len = 0;
    u_char     *p;

    for (i = 0; i < n; i++) {
        len += value[first + i].len + 1;
    }
    p = ngx_pnalloc(cf->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }
    out->data = p;
    for (i = 0; i < n; i++) {
        if (i > 0) {
            *p++ = ' ';
        }
        p = ngx_cpymem(p, value[first + i].data, value[first + i].len);
    }
    *p = '\0';
    out->len = (size_t) (p - out->data);
    return NGX_OK;
}

/* Build the program record from value[first..first+n-1].  The conf parser
 * NUL-terminates every token, so the argv entries borrow the token bytes
 * directly — no copy, and nothing here outlives cf->pool's cycle. */
static brix_cms_fsxeq_prog_t *
fsxeq_build_prog(ngx_conf_t *cf, ngx_str_t *value, ngx_uint_t first,
    ngx_uint_t n)
{
    brix_cms_fsxeq_prog_t  *prog;
    ngx_uint_t              i;

    prog = ngx_pcalloc(cf->pool, sizeof(*prog));
    if (prog == NULL) {
        return NULL;
    }
    prog->argv = ngx_pcalloc(cf->pool, (n + 1) * sizeof(char *));
    if (prog->argv == NULL) {
        return NULL;
    }
    for (i = 0; i < n; i++) {
        prog->argv[i] = (char *) value[first + i].data;
    }
    prog->argc = n;
    if (fsxeq_render_display(cf, value, first, n, &prog->display) != NGX_OK) {
        return NULL;
    }
    return prog;
}

/* Consume the leading op keywords into *mask.  Returns the index of the first
 * token that is not an op keyword (== cf->args->nelts when the line named only
 * ops, which the caller reports as a missing program). */
static ngx_uint_t
fsxeq_take_ops(ngx_str_t *value, ngx_uint_t nelts, ngx_uint_t *mask)
{
    ngx_uint_t  i;
    ngx_int_t   slot;

    for (i = 1; i < nelts; i++) {
        slot = fsxeq_op_index(&value[i]);
        if (slot < 0) {
            break;
        }
        *mask |= (ngx_uint_t) 1 << slot;
    }
    return i;
}

/*
 * brix_conf_set_cms_fsxeq — the directive setter.  Bounded by
 * BRIX_CMS_FSXEQ_ARGV_MAX because the runner builds one stack argv of that size
 * from the fixed prefix plus the op's own arguments.
 */
char *
brix_conf_set_cms_fsxeq(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_brix_srv_conf_t  *scf = conf;
    ngx_str_t                   *value = cf->args->elts;
    brix_cms_fsxeq_prog_t       *prog;
    ngx_uint_t                   mask = 0;
    ngx_uint_t                   first, n, i;

    (void) cmd;

    first = fsxeq_take_ops(value, cf->args->nelts, &mask);

    if (mask == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cms_fsxeq: the line must begin with one or more of "
            "chmod mkdir mkpath mv rm rmdir trunc");
        return NGX_CONF_ERROR;
    }
    if (first >= cf->args->nelts) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cms_fsxeq: no program named after the op list");
        return NGX_CONF_ERROR;
    }

    n = cf->args->nelts - first;
    if (n + 2 >= BRIX_CMS_FSXEQ_ARGV_MAX) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cms_fsxeq: command line has %ui tokens, at most %ui fit "
            "beside the op's own arguments",
            n, (ngx_uint_t) BRIX_CMS_FSXEQ_ARGV_MAX - 3);
        return NGX_CONF_ERROR;
    }
    if (brix_frm_check_program(cf, "brix_cms_fsxeq", &value[first],
            "the node runs it in place of the forwarded namespace op")
        != NGX_CONF_OK)
    {
        return NGX_CONF_ERROR;
    }

    prog = fsxeq_build_prog(cf, value, first, n);
    if (prog == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; i < BRIX_CMS_FSXEQ_OPS; i++) {
        if (!(mask & ((ngx_uint_t) 1 << i))) {
            continue;
        }
        if (scf->cms.fsxeq[i] != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_cms_fsxeq: \"%s\" already has a program (\"%V\"); one op "
                "may name exactly one program",
                brix_cms_fsxeq_names[i], &scf->cms.fsxeq[i]->display);
            return NGX_CONF_ERROR;
        }
        scf->cms.fsxeq[i] = prog;
    }
    return NGX_CONF_OK;
}
