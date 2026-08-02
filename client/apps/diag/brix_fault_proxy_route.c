/*
 * brix_fault_proxy_route.c — dynamic multi-route table (C2) for brix-fault-proxy.
 *
 * WHAT: lets ONE daemon host many named L4 proxies created and destroyed at
 *       runtime — `route add <name> <listen_port> <host:port[,host:port…]>`,
 *       `route del <name>`, `route list [json]`.  Each route owns its own listen
 *       socket, target pool and traffic counters; the legacy --listen/--target
 *       pair is registered as route "default" (g_routes[0]) so the accept plane
 *       treats every route uniformly.
 *
 * WHY:  a single fault proxy could only shape one hop.  Real test topologies fan
 *       a client across several upstreams (data server + redirector + backend);
 *       binding them into one daemon keeps the control plane — and the shared
 *       fault levers — in one place instead of N processes to marshal.
 *
 * HOW:  a fixed FP_MAX_ROUTES table under one mutex.  New ports are bound via
 *       fp_route_bind() so a route inherits the startup loopback/insecure gate
 *       and can NEVER widen it (invariant I4).  Each dynamic route runs its own
 *       accept thread (fp_accept_serve, which polls route->stop); `route del`
 *       sets stop, joins the thread, then closes the fd — close AFTER join so we
 *       never race a live accept().  Slots are never reused (no compaction): a
 *       relay thread may hold its fp_route* for its whole lifetime, so a retired
 *       slot stays valid memory forever.  Fault levers and the toxic table stay
 *       process-global (shared by all routes) in this revision — only targets,
 *       counters and lifecycle are per-route.
 */
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "brix_fault_proxy_internal.h"

/* Accept clients on `lfd` forever, spawning a detached relay thread per
 * connection (subject to the outage/connection-cap levers), attributing each to
 * `route` (targets + counters).  Returns when the accept loop terminates on a
 * non-EINTR error (or, for a dynamic route, on `route del`).  This is the accept
 * plane for every route — the default route drives it on the main thread, each
 * dynamic route on its own accept thread. */
int
fp_accept_serve(int lfd, fp_route *route)
{
    for (;;) {
        /* Dynamic routes poll so `route del` (stop + close) unwinds promptly;
         * the default route runs the main thread and blocks in accept(). */
        if (route != NULL && !route->is_default) {
            if (route->stop) {
                break;
            }
            struct pollfd p = { .fd = lfd, .events = POLLIN };
            int pr = poll(&p, 1, 200);
            if (pr <= 0) {
                continue;   /* timeout -> re-check stop; error -> retry */
            }
        }
        int client = accept(lfd, NULL, NULL);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (g_blocked) {
            brix_fp_event(CBUMP(refused, 1), NULL, "refuse", "block", NULL, 0);
            close(client);        /* outage: refuse */
            continue;
        }
        if (g_refuse_ppm > 0) {
            /* Probabilistic refusal of NEW connections (a flaky listener) —
             * distinct from the all-or-nothing block and the exact fail-nth.
             * Seed the roll from --seed so a scripted run is reproducible. */
            static unsigned rseed = 0;
            if (rseed == 0) {
                rseed = g_seed ? g_seed : 0xC0FFEEu;
            }
            if ((int) (rand_r(&rseed) % 1000000u) < g_refuse_ppm) {
                brix_fp_event(CBUMP(refused, 1), NULL, "refuse", "refuse",
                              NULL, 0);
                close(client);
                continue;
            }
        }
        if (g_max_conns > 0
            && __atomic_load_n(&C.active, __ATOMIC_RELAXED) >= (unsigned long) g_max_conns) {
            brix_fp_event(CBUMP(refused, 1), NULL, "refuse", "max-conns", NULL, 0);
            close(client);        /* connection cap reached */
            continue;
        }
        int one = 1;
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        relay_arg *ra = malloc(sizeof(*ra));
        ra->client_fd = client;
        ra->epoch = __atomic_load_n(&g_drop_epoch, __ATOMIC_SEQ_CST);
        ra->conn_id = CBUMP(conns, 1);
        ra->route = route;
        if (route != NULL) {
            __atomic_add_fetch(&route->counters.conns, 1, __ATOMIC_RELAXED);
        }
        CBUMP(active, 1);
        pthread_t t;
        if (pthread_create(&t, NULL, relay_thread, ra) != 0) {
            close(client);
            CDEC(active);
            free(ra);
            continue;
        }
        pthread_detach(t);
    }
    return 0;
}

fp_route g_routes[FP_MAX_ROUTES];
int      g_nroutes = 0;

static pthread_mutex_t g_route_mtx = PTHREAD_MUTEX_INITIALIZER;

/* Bounded appender shared by the two list renderers (text + json). */
static void
rt_appendf(char *out, size_t osz, size_t *off, const char *fmt, ...)
{
    if (*off >= osz) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + *off, osz - *off, fmt, ap);
    va_end(ap);
    if (n > 0) {
        *off += (size_t) n;
        if (*off >= osz) {
            *off = osz - 1;   /* clamp: vsnprintf truncated */
        }
    }
}

/* Parse "host:port[,host:port…]" into rt's target pool.  0 = ok, -1 = malformed
 * or over capacity.  Mirrors add_target() but writes a route, not the globals. */
static int
rt_parse_targets(fp_route *rt, const char *spec)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", spec);
    rt->ntargets = 0;
    for (char *tok = strtok(tmp, ","); tok != NULL; tok = strtok(NULL, ",")) {
        if (rt->ntargets >= FP_MAX_TARGETS) {
            return -1;
        }
        const char *colon = strrchr(tok, ':');
        if (colon == NULL || colon == tok || colon[1] == '\0') {
            return -1;
        }
        size_t hlen = (size_t) (colon - tok);
        if (hlen >= sizeof(rt->targets[0].host)) {
            return -1;
        }
        int p = atoi(colon + 1);
        if (p <= 0 || p > 65535) {
            return -1;
        }
        memcpy(rt->targets[rt->ntargets].host, tok, hlen);
        rt->targets[rt->ntargets].host[hlen] = '\0';
        rt->targets[rt->ntargets].port = p;
        rt->ntargets++;
    }
    return (rt->ntargets > 0) ? 0 : -1;
}

/* Accept thread for a dynamic route (the default route runs on the main thread). */
static void *
route_accept_thread(void *arg)
{
    fp_route *rt = (fp_route *) arg;
    fp_accept_serve(rt->listen_fd, rt);
    return NULL;
}

/* Seed g_routes[0] as the legacy "default" route from the global target pool.
 * Called once at startup after the main listen fd is bound. */
int
fp_route_register_default(int lfd, int port)
{
    pthread_mutex_lock(&g_route_mtx);
    fp_route *rt = &g_routes[0];
    memset(rt, 0, sizeof(*rt));
    snprintf(rt->name, sizeof(rt->name), "default");
    rt->listen_fd   = lfd;
    rt->listen_port = port;
    rt->ntargets    = g_ntargets;
    for (int i = 0; i < g_ntargets && i < FP_MAX_TARGETS; i++) {
        rt->targets[i] = g_targets[i];
    }
    rt->is_default = 1;
    rt->active     = 1;
    if (g_nroutes < 1) {
        g_nroutes = 1;
    }
    pthread_mutex_unlock(&g_route_mtx);
    return 0;
}

static void
route_add(char *args, char *reply, size_t rsz)
{
    char     name[32];
    int      port = 0;
    char     tspec[512];
    if (sscanf(args, "%31s %d %511s", name, &port, tspec) != 3) {
        snprintf(reply, rsz, "err: usage: route add <name> <port> <host:port,...>");
        return;
    }
    if (port <= 0 || port > 65535) {
        snprintf(reply, rsz, "err: invalid port");
        return;
    }

    pthread_mutex_lock(&g_route_mtx);

    int slot = -1;
    for (int i = 0; i < g_nroutes; i++) {
        if (g_routes[i].active && strcmp(g_routes[i].name, name) == 0) {
            pthread_mutex_unlock(&g_route_mtx);
            snprintf(reply, rsz, "err: exists");
            return;
        }
        if (slot < 0 && !g_routes[i].active) {
            slot = i;   /* reuse a retired-but-quiesced high-water slot */
        }
    }
    if (slot < 0) {
        if (g_nroutes >= FP_MAX_ROUTES) {
            pthread_mutex_unlock(&g_route_mtx);
            snprintf(reply, rsz, "err: too many routes");
            return;
        }
        slot = g_nroutes++;
    }

    fp_route *rt = &g_routes[slot];
    memset(rt, 0, sizeof(*rt));
    snprintf(rt->name, sizeof(rt->name), "%s", name);
    rt->listen_port = port;
    if (rt_parse_targets(rt, tspec) != 0) {
        pthread_mutex_unlock(&g_route_mtx);
        snprintf(reply, rsz, "err: invalid target");
        return;
    }

    int lfd = fp_route_bind(port);   /* inherits the vetted loopback/insecure gate */
    if (lfd < 0) {
        pthread_mutex_unlock(&g_route_mtx);
        snprintf(reply, rsz, "err: port in use");
        return;
    }
    rt->listen_fd = lfd;
    rt->active    = 1;

    if (pthread_create(&rt->tid, NULL, route_accept_thread, rt) != 0) {
        close(lfd);
        rt->active = 0;
        pthread_mutex_unlock(&g_route_mtx);
        snprintf(reply, rsz, "err: cannot start route");
        return;
    }
    pthread_mutex_unlock(&g_route_mtx);
    snprintf(reply, rsz, "ok: route %s listen=%d targets=%d", name, port,
             rt->ntargets);
}

static void
route_del(char *args, char *reply, size_t rsz)
{
    char name[32];
    if (sscanf(args, "%31s", name) != 1) {
        snprintf(reply, rsz, "err: usage: route del <name>");
        return;
    }
    if (strcmp(name, "default") == 0) {
        snprintf(reply, rsz, "err: cannot delete default route");
        return;
    }

    pthread_mutex_lock(&g_route_mtx);
    fp_route *rt = NULL;
    for (int i = 0; i < g_nroutes; i++) {
        if (g_routes[i].active && !g_routes[i].is_default
            && strcmp(g_routes[i].name, name) == 0) {
            rt = &g_routes[i];
            break;
        }
    }
    if (rt == NULL) {
        pthread_mutex_unlock(&g_route_mtx);
        snprintf(reply, rsz, "err: no such route");
        return;
    }
    /* Signal the accept thread and capture its handle, then release the lock so
     * `route list` etc. never block behind the join. */
    rt->stop = 1;
    pthread_t tid = rt->tid;
    int       fd  = rt->listen_fd;
    pthread_mutex_unlock(&g_route_mtx);

    pthread_join(tid, NULL);   /* accept loop polls stop @200ms and returns */
    close(fd);                 /* close AFTER join: never race a live accept() */

    pthread_mutex_lock(&g_route_mtx);
    rt->active    = 0;         /* slot stays allocated; relay threads may hold rt* */
    rt->listen_fd = -1;
    pthread_mutex_unlock(&g_route_mtx);
    snprintf(reply, rsz, "ok: route %s deleted", name);
}

static void
route_list(int as_json, char *reply, size_t rsz)
{
    size_t off = 0;
    pthread_mutex_lock(&g_route_mtx);

    int nactive = 0;
    for (int i = 0; i < g_nroutes; i++) {
        if (g_routes[i].active) {
            nactive++;
        }
    }

    if (as_json) {
        rt_appendf(reply, rsz, &off, "{\"routes\":[");
        int first = 1;
        for (int i = 0; i < g_nroutes; i++) {
            fp_route *rt = &g_routes[i];
            if (!rt->active) {
                continue;
            }
            rt_appendf(reply, rsz, &off,
                       "%s{\"name\":\"%s\",\"listen\":%d,\"conns\":%lu,"
                       "\"up_bytes\":%lu,\"down_bytes\":%lu}",
                       first ? "" : ",", rt->name, rt->listen_port,
                       rt->counters.conns, rt->counters.up_bytes,
                       rt->counters.down_bytes);
            first = 0;
        }
        rt_appendf(reply, rsz, &off, "]}");
    } else {
        rt_appendf(reply, rsz, &off, "routes=%d", nactive);
        for (int i = 0; i < g_nroutes; i++) {
            fp_route *rt = &g_routes[i];
            if (!rt->active) {
                continue;
            }
            rt_appendf(reply, rsz, &off,
                       "\n  %s listen=%d targets=%d conns=%lu up=%lu down=%lu",
                       rt->name, rt->listen_port, rt->ntargets,
                       rt->counters.conns, rt->counters.up_bytes,
                       rt->counters.down_bytes);
        }
    }
    pthread_mutex_unlock(&g_route_mtx);
}

void
fp_route_cmd(char *args, char *reply, size_t rsz)
{
    char sub[16];
    int  off = 0;
    if (sscanf(args, "%15s %n", sub, &off) < 1) {
        snprintf(reply, rsz, "err: usage: route add|del|list");
        return;
    }
    char *rest = args + off;
    if (strcmp(sub, "add") == 0) {
        route_add(rest, reply, rsz);
    } else if (strcmp(sub, "del") == 0 || strcmp(sub, "remove") == 0) {
        route_del(rest, reply, rsz);
    } else if (strcmp(sub, "list") == 0) {
        route_list(strstr(rest, "json") != NULL, reply, rsz);
    } else {
        snprintf(reply, rsz, "err: unknown route subcommand");
    }
}
