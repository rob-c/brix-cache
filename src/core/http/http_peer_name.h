/*
 * http_peer_name.h — PREACCESS-phase wait for the peer's reverse-DNS name
 * (phase-116).
 */
#ifndef BRIX_CORE_HTTP_PEER_NAME_H
#define BRIX_CORE_HTTP_PEER_NAME_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/* Registers the PREACCESS handler; the common module's postconfiguration. */
ngx_int_t brix_http_peer_name_postconfiguration(ngx_conf_t *cf);

#endif /* BRIX_CORE_HTTP_PEER_NAME_H */
