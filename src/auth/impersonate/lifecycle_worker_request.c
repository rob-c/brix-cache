/*
 * lifecycle_worker_request.c — worker broker connection and request context.
 *
 * Kept separate from lifecycle_worker.c so the security-sensitive identity and
 * capability transition remains reviewable within the native size limit.
 */

#include "core/compat/log_event.h"
#include "lifecycle.h"
#include "impersonate.h"
#include "lifecycle_internal.h"

#include <limits.h>

ngx_int_t
brix_imp_init_worker(ngx_cycle_t *cycle)
{
    char sockbuf[256];

    /* Load the grid-mapfile before the map-mode early return: the worker-side
     * authorization gate applies in off, single and map modes. */
    if (imp_settings.gridmap.len > 0) {
        char mapbuf[PATH_MAX];

        ngx_snprintf((u_char *) mapbuf, sizeof(mapbuf), "%V%Z",
                     &imp_settings.gridmap);
        if (brix_idmap_gate_init(mapbuf, cycle->log) != NGX_OK) {
            BRIX_LOG(NGX_LOG_EMERG, cycle->log, 0,
                "impersonate: authz-gate grid-mapfile load failed (\"%s\")",
                mapbuf);
            return NGX_ERROR;
        }
    }

    if (imp_settings.mode != BRIX_IMP_MAP) {
        return NGX_OK;
    }

    ngx_snprintf((u_char *) sockbuf, sizeof(sockbuf), "%V%Z",
                 &imp_settings.socket);
    if (brix_imp_client_connect(sockbuf, cycle->log) != NGX_OK) {
        /* Broker may still be starting; the client retries lazily per op. */
        BRIX_LOG(NGX_LOG_WARN, cycle->log, 0,
            "impersonate: broker not reachable yet at \"%s\" "
            "(will reconnect on first op)", sockbuf);
    }
    return NGX_OK;
}

/* Best principal string for impersonation: DN first, then token subject. */
static const char *
imp_principal_of(const brix_identity_t *id)
{
    const char *p = brix_identity_dn_cstr(id);

    if (p != NULL && p[0] != '\0') {
        return p;
    }
    p = brix_identity_subject_cstr(id);
    return (p != NULL && p[0] != '\0') ? p : NULL;
}

void
brix_imp_request_begin(const brix_identity_t *id)
{
    if (imp_settings.mode != BRIX_IMP_MAP) {
        return;
    }
    /* Mark the request active before setting the principal: an empty identity
     * must route to the broker and deny, never fall back to the worker. */
    brix_imp_mark_in_request(1);
    brix_imp_set_principal(id != NULL ? imp_principal_of(id) : NULL);
}

void
brix_imp_request_end(void)
{
    if (imp_settings.mode != BRIX_IMP_MAP) {
        return;
    }
    brix_imp_clear_principal();
    brix_imp_mark_in_request(0);
}
