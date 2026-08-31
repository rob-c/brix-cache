/*
 * stream_variables.h — the $brix_session_* stream variable surface (phase 106 W2).
 *
 * WHAT: Declares brix_stream_add_variables(), the registration entry point for
 *       every variable the root:// stream plane exposes to nginx.
 *
 * WHY:  The stream plane registered NO variables before phase 106, so root://
 *       traffic could not be logged with nginx's own `stream {}` access_log.
 *       See stream_variables.c for the session-vs-op scope reasoning.
 *
 * HOW:  Called once from the stream module's preconfiguration hook
 *       (module_definition.c), which is the only point at which nginx accepts
 *       variable registrations.
 */
#ifndef BRIX_STREAM_VARIABLES_H
#define BRIX_STREAM_VARIABLES_H

#include <ngx_config.h>
#include <ngx_core.h>

ngx_int_t brix_stream_add_variables(ngx_conf_t *cf);

#endif /* BRIX_STREAM_VARIABLES_H */
