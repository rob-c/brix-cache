/* virtual.c — virtual / composed repos (phase-87 G16).
 *
 * WHAT: brix_cvmfs_virtual_repo <virtual-fqrn> <member-fqrn>... presents a
 *       read-only UNION of member repos under a repo name that need not exist
 *       anywhere upstream. A request naming the virtual fqrn is rewritten in
 *       place to member[0]; a definitive 404 advances to the next member
 *       (declaration order = precedence); the first non-404 answer is final.
 * WHY:  compose curated views (a site-wide umbrella over per-experiment
 *       repos, a staged repo shadowing production) purely at the HTTP plane —
 *       no catalog surgery, no origin changes, no second cache copy.
 * HOW:  the gate calls brix_cvmfs_virtual_enter() right after classification,
 *       BEFORE per-repo accounting, F3 repo authz, and class routing — so
 *       every member attempt is policed exactly as a direct request for that
 *       member would be (composition never elevates access), and the cache
 *       key IS the member path (an object cached via the virtual name and via
 *       direct member access is one entry). The handler's member loop and the
 *       off-loop fill-failure interceptor call brix_cvmfs_virtual_advance()
 *       on 404. A 401/403/5xx from a member is terminal: only "the object is
 *       not there" consults the next member — access denial must never be
 *       papered over by a more permissive sibling.
 *
 * HONEST LIMIT: this is HTTP-plane composition only. Signed metadata
 * (.cvmfspublished et al.) comes from the first member that has it; no merged
 * catalog is synthesized, so a FUSE client mounting the virtual name sees
 * member[0]'s namespace plus whatever CAS objects the others contribute.
 */
#include "cvmfs.h"
#include "cvmfs_module_internal.h"

/* Rewrite r->uri to the current member: the fqrn span of the ORIGINAL
 * (virtual-name) uri is replaced by members[virt_idx], then the result is
 * re-classified so every downstream consumer of ctx->url sees the member.
 * Only the repo span changes, so the traffic class is preserved — the
 * classifier stays the sole truth all the same. */
static ngx_int_t
cvmfs_virt_apply(ngx_http_request_t *r, ngx_http_brix_cvmfs_ctx_t *ctx)
{
    const brix_cvmfs_virtual_t *v = ctx->virt;
    const ngx_str_t             *members = v->members->elts;
    const ngx_str_t             *member = &members[ctx->virt_idx];
    size_t                        pre = ctx->virt_off;
    size_t                        suf = pre + v->fqrn.len;
    size_t                        len;
    u_char                       *p;

    len = ctx->virt_uri.len - v->fqrn.len + member->len;
    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(p, ctx->virt_uri.data, pre);
    ngx_memcpy(p + pre, member->data, member->len);
    ngx_memcpy(p + pre + member->len, ctx->virt_uri.data + suf,
               ctx->virt_uri.len - suf);
    r->uri.data = p;
    r->uri.len = len;

    if (cvmfs_classify_url((const char *) p, len, &ctx->url) != 0
        || ctx->url.repo == NULL)
    {
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t
brix_cvmfs_virtual_enter(ngx_http_request_t *r,
    ngx_http_brix_cvmfs_loc_conf_t *lcf)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);
    brix_cvmfs_virtual_t        *e;
    ngx_uint_t                    i;

    /* ctx->virt set = a member pass of the advance loop (the uri already
     * names a member — never rewrite twice, so composition cannot chain);
     * repo == NULL = a REJECT shape the gate is about to refuse anyway. */
    if (ctx == NULL || ctx->virt != NULL || ctx->url.repo == NULL) {
        return NGX_DECLINED;
    }

    e = lcf->virtual_repos->elts;
    for (i = 0; i < lcf->virtual_repos->nelts; i++) {
        if (e[i].fqrn.len == ctx->url.repo_len
            && ngx_strncmp(e[i].fqrn.data, ctx->url.repo,
                           ctx->url.repo_len) == 0)
        {
            break;
        }
    }
    if (i == lcf->virtual_repos->nelts) {
        return NGX_DECLINED;                    /* a direct (real) repo */
    }

    ctx->virt = &e[i];
    ctx->virt_idx = 0;
    ctx->virt_uri = r->uri;
    ctx->virt_off = (size_t) ((u_char *) ctx->url.repo - r->uri.data);

    if (cvmfs_virt_apply(r, ctx) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    return NGX_DECLINED;
}

ngx_int_t
brix_cvmfs_virtual_advance(ngx_http_request_t *r)
{
    ngx_http_brix_cvmfs_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_brix_cvmfs_module);

    if (ctx == NULL || ctx->virt == NULL
        || ctx->virt_idx + 1 >= ctx->virt->members->nelts)
    {
        return NGX_DECLINED;            /* not composed / members exhausted */
    }

    ctx->virt_idx++;
    if (cvmfs_virt_apply(r, ctx) != NGX_OK) {
        return NGX_DECLINED;                 /* fail closed: the 404 stands */
    }

    /* each member attempt starts with a clean disposition — a failed
     * member[0] fill must not label a member[1] cache hit as FILL */
    ctx->cache_status = BRIX_CVMFS_CACHE_NONE;
    ngx_str_null(&ctx->origin_used);
    ctx->repo = NULL;                        /* re-mapped by the gate pass */

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
        "cvmfs-virt: virtual=%V event=member-miss-advance member=%ui/%ui",
        &ctx->virt->fqrn, ctx->virt_idx + 1,
        (ngx_uint_t) ctx->virt->members->nelts);
    return NGX_OK;
}

/* brix_cvmfs_virtual_repo <virtual-fqrn> <member-fqrn>... — one union entry
 * per occurrence. Rejected at config time: a duplicate virtual name (would
 * make precedence ambiguous), a duplicate member, and any nesting — a
 * virtual name listed as a member of any entry, either direction. */

static int
cvmfs_virt_str_eq(const ngx_str_t *a, const ngx_str_t *b)
{
    return a->len == b->len
           && ngx_strncmp(a->data, b->data, b->len) == 0;
}

/* Reject a new virtual name that is already a virtual (duplicate) or already
 * a member of an earlier entry (nesting, member->virtual direction). */
static char *
cvmfs_virt_conf_check_name(ngx_conf_t *cf,
    ngx_http_brix_cvmfs_loc_conf_t *c, const ngx_str_t *name)
{
    brix_cvmfs_virtual_t *e = c->virtual_repos->elts;
    ngx_str_t            *pm;
    ngx_uint_t            i, j;

    for (i = 0; i < c->virtual_repos->nelts; i++) {
        if (cvmfs_virt_str_eq(&e[i].fqrn, name)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "duplicate brix_cvmfs_virtual_repo \"%V\"", name);
            return NGX_CONF_ERROR;
        }
        pm = e[i].members->elts;
        for (j = 0; j < e[i].members->nelts; j++) {
            if (cvmfs_virt_str_eq(&pm[j], name)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                    "brix_cvmfs_virtual_repo \"%V\" is already a member of "
                    "\"%V\" — virtual repos cannot nest", name,
                    &e[i].fqrn);
                return NGX_CONF_ERROR;
            }
        }
    }
    return NGX_CONF_OK;
}

/* Validate one member name against the entry being built (self-reference,
 * virtual->member nesting against every EARLIER entry, duplicate member)
 * and append it. */
static char *
cvmfs_virt_conf_add_member(ngx_conf_t *cf,
    ngx_http_brix_cvmfs_loc_conf_t *c, brix_cvmfs_virtual_t *entry,
    const ngx_str_t *name)
{
    brix_cvmfs_virtual_t *e = c->virtual_repos->elts;
    ngx_str_t            *m;
    ngx_uint_t            j;

    if (cvmfs_virt_str_eq(&entry->fqrn, name)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "brix_cvmfs_virtual_repo \"%V\" cannot be its own member",
            &entry->fqrn);
        return NGX_CONF_ERROR;
    }
    for (j = 0; j + 1 < c->virtual_repos->nelts; j++) {
        if (cvmfs_virt_str_eq(&e[j].fqrn, name)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "brix_cvmfs_virtual_repo member \"%V\" is itself a "
                "virtual repo — virtual repos cannot nest", name);
            return NGX_CONF_ERROR;
        }
    }
    m = entry->members->elts;
    for (j = 0; j < entry->members->nelts; j++) {
        if (cvmfs_virt_str_eq(&m[j], name)) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "duplicate brix_cvmfs_virtual_repo member \"%V\"", name);
            return NGX_CONF_ERROR;
        }
    }
    m = ngx_array_push(entry->members);
    if (m == NULL) {
        return NGX_CONF_ERROR;
    }
    *m = *name;
    return NGX_CONF_OK;
}

char *
cvmfs_conf_virtual_repo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_brix_cvmfs_loc_conf_t *c = conf;
    ngx_str_t                        *value = cf->args->elts;
    brix_cvmfs_virtual_t            *entry;
    ngx_uint_t                        i;

    (void) cmd;

    if (c->virtual_repos == NGX_CONF_UNSET_PTR) {
        c->virtual_repos = ngx_array_create(cf->pool, 2,
                                            sizeof(brix_cvmfs_virtual_t));
        if (c->virtual_repos == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    if (cvmfs_virt_conf_check_name(cf, c, &value[1]) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    entry = ngx_array_push(c->virtual_repos);
    if (entry == NULL) {
        return NGX_CONF_ERROR;
    }
    entry->fqrn = value[1];
    entry->members = ngx_array_create(cf->pool, cf->args->nelts - 2,
                                      sizeof(ngx_str_t));
    if (entry->members == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {
        if (cvmfs_virt_conf_add_member(cf, c, entry, &value[i])
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
