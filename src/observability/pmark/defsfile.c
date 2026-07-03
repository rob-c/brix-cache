/*
 * defsfile.c — load the SciTags experiment/activity registry (JSON).
 *
 * WHAT: Parse the scitags "defsfile" — the JSON registry that maps experiment
 *   and activity NAMES to their numeric ids — into an in-memory table the
 *   mapping layer (mapping.c) resolves config rules against.  Mirrors XRootD's
 *   XrdNetPMarkCfg LoadJson (XrdNetPMarkCfg.cc:891-966).
 *
 * WHY: SciTags config is written in terms of names (experiment "atlas",
 *   activity "write"), but the wire/firefly carries numeric ids; the registry is
 *   the authoritative name→id source (published at scitags.org / by the WLCG).
 *
 * HOW: jansson (already linked, see config:70-77 and src/dashboard/api.c) parses
 *   the document {"experiments":[{"expName","expId","activities":[{"activityName",
 *   "activityId"}]}]}.  Everything is copied into pool-allocated, NUL-terminated
 *   ngx_str_t so the jansson tree can be freed immediately.  A missing file is
 *   NGX_DECLINED (not an error — only a problem if mappings reference names).
 */

#include "pmark.h"

#include <jansson.h>
#include <unistd.h>


/* Copy a jansson string into a pool-allocated, NUL-terminated ngx_str_t. */
static ngx_int_t
pmark_dup_json_str(ngx_pool_t *pool, json_t *js, ngx_str_t *out)
{
    const char *s;
    size_t      len;

    if (!json_is_string(js)) {
        return NGX_ERROR;
    }
    s = json_string_value(js);
    len = ngx_strlen(s);

    out->data = ngx_pnalloc(pool, len + 1);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(out->data, s, len);
    out->data[len] = '\0';
    out->len = len;
    return NGX_OK;
}


ngx_int_t
brix_pmark_defsfile_load(const char *path, ngx_pool_t *pool,
    ngx_array_t **out, ngx_log_t *log)
{
    json_t        *root, *exps, *e;
    json_error_t   jerr;
    ngx_array_t   *defs;
    size_t         i;

    *out = NULL;

    if (path == NULL || *path == '\0') {
        return NGX_DECLINED;
    }
    if (access(path, R_OK) != 0) {
        return NGX_DECLINED;          /* absent/unreadable → "no registry" */
    }

    root = json_load_file(path, 0, &jerr);
    if (root == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "pmark: cannot parse defsfile \"%s\": %s (line %d)",
            path, jerr.text, jerr.line);
        return NGX_ERROR;
    }

    exps = json_object_get(root, "experiments");
    if (!json_is_array(exps)) {
        json_decref(root);
        ngx_log_error(NGX_LOG_ERR, log, 0,
            "pmark: defsfile \"%s\" has no \"experiments\" array", path);
        return NGX_ERROR;
    }

    defs = ngx_array_create(pool, json_array_size(exps),
                            sizeof(brix_pmark_exp_def_t));
    if (defs == NULL) {
        json_decref(root);
        return NGX_ERROR;
    }

    json_array_foreach(exps, i, e) {
        brix_pmark_exp_def_t *def;
        json_t                 *acts, *a;
        size_t                  j;

        if (!json_is_object(e)) {
            continue;
        }

        def = ngx_array_push(defs);
        if (def == NULL) {
            json_decref(root);
            return NGX_ERROR;
        }
        ngx_memzero(def, sizeof(*def));

        if (pmark_dup_json_str(pool, json_object_get(e, "expName"),
                               &def->exp_name) != NGX_OK)
        {
            def->exp_name.len = 0;
        }
        def->exp_id = (ngx_uint_t) json_integer_value(json_object_get(e, "expId"));

        acts = json_object_get(e, "activities");
        if (!json_is_array(acts)) {
            continue;
        }
        def->activities = ngx_array_create(pool, json_array_size(acts),
                                           sizeof(brix_pmark_named_t));
        if (def->activities == NULL) {
            json_decref(root);
            return NGX_ERROR;
        }

        json_array_foreach(acts, j, a) {
            brix_pmark_named_t *act;

            if (!json_is_object(a)) {
                continue;
            }
            act = ngx_array_push(def->activities);
            if (act == NULL) {
                json_decref(root);
                return NGX_ERROR;
            }
            ngx_memzero(act, sizeof(*act));
            if (pmark_dup_json_str(pool, json_object_get(a, "activityName"),
                                   &act->name) != NGX_OK)
            {
                act->name.len = 0;
            }
            act->id = (ngx_uint_t)
                json_integer_value(json_object_get(a, "activityId"));
        }
    }

    json_decref(root);
    *out = defs;
    return NGX_OK;
}


ngx_uint_t
brix_pmark_defs_exp_id(ngx_array_t *defs, ngx_str_t *name)
{
    brix_pmark_exp_def_t *d;
    ngx_uint_t              i;

    if (defs == NULL || name == NULL) {
        return 0;
    }
    d = defs->elts;
    for (i = 0; i < defs->nelts; i++) {
        if (d[i].exp_name.len == name->len
            && ngx_strncmp(d[i].exp_name.data, name->data, name->len) == 0)
        {
            return d[i].exp_id;
        }
    }
    return 0;
}


ngx_uint_t
brix_pmark_defs_act_id(ngx_array_t *defs, ngx_uint_t exp_id, ngx_str_t *name)
{
    brix_pmark_exp_def_t *d;
    ngx_uint_t              i, j;

    if (defs == NULL || name == NULL) {
        return 0;
    }
    d = defs->elts;
    for (i = 0; i < defs->nelts; i++) {
        if (d[i].exp_id != exp_id || d[i].activities == NULL) {
            continue;
        }
        {
            brix_pmark_named_t *a = d[i].activities->elts;
            for (j = 0; j < d[i].activities->nelts; j++) {
                if (a[j].name.len == name->len
                    && ngx_strncmp(a[j].name.data, name->data, name->len) == 0)
                {
                    return a[j].id;
                }
            }
        }
    }
    return 0;
}
