#ifndef BRIX_SSI_PROVIDER_H
#define BRIX_SSI_PROVIDER_H

/*
 * provider.h — SSI service-name → implementation registry.
 *
 * WHAT: resolves the service name parsed from "/.ssi/<service>" to a handler.
 * WHY:  the no-plugin-ABI stand-in for XrdSsiProvider/XrdSsiService; lets the
 *       open path bind a session to a service without a C++ plugin.
 * HOW:  a compiled-in table delegating to the built-in service handlers; the
 *       descriptor is returned by value so callers copy it into their session
 *       (reentrant — no shared static state).
 */

#include "ssi_service.h"

typedef struct {
    const char            *name;
    brix_ssi_process_fn  process;
} brix_ssi_provider_t;

/* Fill *out for a known service name; returns 1 if found, 0 otherwise. */
int brix_ssi_provider_lookup(const char *name, brix_ssi_provider_t *out);

#endif /* BRIX_SSI_PROVIDER_H */
