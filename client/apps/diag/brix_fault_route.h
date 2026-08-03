/*
 * brix_fault_route.h — named routes: independent listener→upstream mappings (C2).
 *
 * The base proxy is one listener forwarding to one target pool.  A route adds
 * further named (listener-port → own target pool) mappings that run alongside it,
 * each with its own connection/byte counters, while the global fault levers and
 * toxics apply uniformly to every route.  This lets one running proxy stand in
 * for a small fabric of endpoints (`route add cache 6000 host:1094`) without a
 * second process, and lets a test attribute traffic per endpoint.
 *
 * Split of concerns: this module owns the route TABLE (identity, target pool,
 * counters) and the add/del/list control verb.  The core owns the MECHANISM —
 * binding a listener on the one vetted (loopback-gated) bind address and running
 * the accept+relay engine — exposed through fp_route_ops so a dynamic route can
 * never widen the control-plane bind gate: it reuses the same address, only the
 * port differs.
 */
#ifndef BRIX_FAULT_ROUTE_H
#define BRIX_FAULT_ROUTE_H

#include <stddef.h>

typedef struct fp_route fp_route;

/* Core mechanism the route control-plane drives (registered once at startup). */
typedef struct {
    /* Bind+listen on the vetted control-bind address at `port`; -1 on failure. */
    int  (*bind_listen)(int port);
    /* Run the accept+relay loop for `route` on `lfd`, returning when the route is
     * stopped (fp_route_alive(route) == 0).  Invoked on a dedicated thread for a
     * dynamic route; the core calls it directly on the main thread for default. */
    void (*accept_loop)(fp_route *route, int lfd);
} fp_route_ops;

/* Register the core mechanism callbacks (once, before any route is added). */
void fp_route_init(const fp_route_ops *ops);

/* Register the always-on default route (the startup listener).  Targets are
 * added with fp_route_add_target().  Returns its handle (never NULL). */
fp_route *fp_route_register_default(int listen_port);
fp_route *fp_route_default(void);

/* Append one upstream to a route's pool (used to seed the default route). */
int fp_route_add_target(fp_route *route, const char *host, int port);

/* `route <add|del|list> ...` control verb.  Always writes a reply; returns 1. */
int fp_route_cmd(char *args, char *reply, size_t rsz);

/* --- relay-engine hooks (called per accepted connection on that route) --- */

/* 0 once the route has been stopped, so its accept loop should return. */
int         fp_route_alive(fp_route *route);
const char *fp_route_name(fp_route *route);

/* Round-robin target selection: fp_route_rr_next() returns a monotonically
 * advancing cursor; index it modulo fp_route_target_count() with failover. */
int         fp_route_target_count(fp_route *route);
unsigned    fp_route_rr_next(fp_route *route);
void        fp_route_get_target(fp_route *route, unsigned idx,
                                char *host, size_t hostsz, int *port);

/* Per-route counters (atomic; safe from concurrent relay threads). */
void        fp_route_inc_conns(fp_route *route);
void        fp_route_add_bytes(fp_route *route, unsigned long up,
                               unsigned long down);

#endif /* BRIX_FAULT_ROUTE_H */
