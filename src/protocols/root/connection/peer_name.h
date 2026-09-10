/*
 * peer_name.h — accept-time wait for the peer's reverse-DNS name (phase-116).
 */
#ifndef BRIX_CONN_PEER_NAME_H
#define BRIX_CONN_PEER_NAME_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

typedef void (*brix_conn_pump_pt)(ngx_connection_t *c);

/* NGX_OK: pump now (the name is cached, not consulted by this listener, or the
 * lookup could not start); NGX_AGAIN: the lookup is in flight and `pump` runs
 * from its completion. */
ngx_int_t brix_conn_peer_name_wait(ngx_stream_session_t *s,
    ngx_connection_t *c, brix_conn_pump_pt pump);

#endif /* BRIX_CONN_PEER_NAME_H */
