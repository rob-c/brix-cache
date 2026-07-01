/*
 * provider.c — SSI provider registry. See provider.h.
 *
 * Phase 1 ships only the built-in services reachable through
 * xrootd_ssi_service_lookup (the reference "echo"). New native services (e.g.
 * the CTA tape service) register here as the framework grows.
 */

#include "provider.h"
#include "svc_cta/cta_service.h"
#include <stddef.h>
#include <string.h>

int
xrootd_ssi_provider_lookup(const char *name, xrootd_ssi_provider_t *out)
{
    xrootd_ssi_process_fn fn;

    if (name == NULL || out == NULL) {
        return 0;
    }
    /* The flagship CTA tape service is a native provider (its own protobuf
     * protocol), separate from the built-in test/reference services. */
    if (strcmp(name, "cta") == 0) {
        out->name    = "cta";
        out->process = xrootd_ssi_cta_process;
        return 1;
    }
    fn = xrootd_ssi_service_lookup(name);
    if (fn == NULL) {
        return 0;
    }
    /* Use the registry's static-lifetime name so the descriptor (copied by value
     * into a session) never points at a caller's transient buffer. */
    out->name    = xrootd_ssi_service_canon_name(name);
    out->process = fn;
    return 1;
}
