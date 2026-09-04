/*
 * auth_gate_identity.c — cache-free identity form of the shared authorization
 * evaluator. Used by the VFS backstop; the protocol edge remains in
 * auth_gate.c and owns wire responses plus the verdict cache.
 */
#include "core/ngx_brix_module.h"
#include "auth_gate.h"
#include "core/compat/cstr.h"
#include "auth/authz/acc/acc.h"
#include "auth/impersonate/impersonate.h"

static void
authz_resolve_fqan_name(brix_identity_t *id)
{
    ngx_uint_t k;
    ngx_str_t *fqans;
    char       fqan[512];

    fqans = id->vo_list != NULL ? id->vo_list->elts : NULL;
    for (k = 0; fqans != NULL && k < id->vo_list->nelts; k++) {
        if (brix_str_cbuf(fqan, sizeof(fqan), &fqans[k]) != NULL
            && brix_idmap_gate_username(fqan, id->mapped_user,
                                        sizeof(id->mapped_user)))
        {
            return;
        }
        id->mapped_user[0] = '\0';
    }
}

static void
authz_resolve_mapped_name(brix_identity_t *id, const char *dn)
{
    id->mapped_resolved = 1;
    id->mapped_user[0] = '\0';
    authz_resolve_fqan_name(id);
    if (id->mapped_user[0] == '\0' && dn != NULL && dn[0] != '\0') {
        if (!brix_idmap_gate_username(dn, id->mapped_user,
                                      sizeof(id->mapped_user)))
        {
            id->mapped_user[0] = '\0';
        }
    }
}

const char *
brix_authz_mapped_name(brix_identity_t *id, const char *dn)
{
    if (id == NULL || !brix_idmap_gate_enabled()) {
        return (dn != NULL) ? dn : "";
    }
    if (!id->mapped_resolved) {
        authz_resolve_mapped_name(id, dn);
    }
    return id->mapped_user[0] != '\0' ? id->mapped_user
                                      : (dn != NULL ? dn : "");
}

void *
brix_authz_acc_entity(ngx_pool_t *pool, brix_identity_t *id, const char *peer)
{
    const char      *name;
    brix_acc_entity_t *entity;

    if (pool == NULL) {
        return NULL;
    }
    if (id == NULL) {
        return brix_acc_entity_build(pool, "", peer, 0, "", "", "");
    }
    if (!id->acc_entity_resolved) {
        id->acc_entity_resolved = 1;
        name = brix_authz_mapped_name(id, brix_identity_dn_cstr(id));
        entity = brix_acc_entity_build(pool, name,
            peer != NULL ? peer : "?", name[0] != '\0',
            brix_identity_acc_vorg_cstr(id),
            brix_identity_acc_role_cstr(id),
            brix_identity_acc_group_cstr(id));
        id->acc_entity = entity;
    }
    return id->acc_entity;
}

static ngx_int_t
authz_identity_primary(const brix_authz_identity_query_t *q)
{
    if (q->acc_format == BRIX_AUTHDB_FORMAT_XRDACC) {
        brix_acc_entity_t *ent = q->acc_entity;

        if (ent == NULL) {
            ent = brix_authz_acc_entity(q->pool, q->identity, q->peer_ip);
        }

        if (q->acc_tables == NULL || ent == NULL) {
            return NGX_ERROR;
        }
        return brix_acc_access((brix_acc_tables_t *) q->acc_tables, ent,
            q->logical_path, q->acc_op) != BRIX_ACC_PRIV_NONE
            ? NGX_OK : NGX_ERROR;
    }

    {
        brix_authdb_query_t native = {
            .rules = q->authdb_rules,
            .identity = q->identity,
            .peer_ip = q->peer_ip,
            .resolved_path = q->resolved_path,
            .needed_privs = q->needed_privs,
        };
        return brix_check_authdb_identity(q->log, &native);
    }
}

ngx_int_t
brix_authz_check_identity(const brix_authz_identity_query_t *q)
{
    if (q == NULL || q->resolved_path == NULL || q->logical_path == NULL) {
        return NGX_ERROR;
    }
    if (authz_identity_primary(q) != NGX_OK
        || brix_check_vo_acl_identity(q->log, q->resolved_path, q->vo_rules,
                                      q->identity) != NGX_OK)
    {
        return NGX_ERROR;
    }
    return brix_identity_check_token_scope(q->identity, q->logical_path,
                                           q->need_write);
}
