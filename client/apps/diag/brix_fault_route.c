/*
 * brix_fault_route.c — named routes: independent listener→upstream mappings (C2).
 *
 * WHAT: a table of named routes, each a (listener port → own target pool) with
 *       its own connection/byte counters.  `route add <name> <port> <host:port
 *       [,host:port...]>` starts a new listener; `route del <name>` stops it;
 *       `route list [json]` reports every route and its counters.  The default
 *       route is the startup listener, always present, never deletable.
 *
 * WHY:  one process can then stand in for a handful of endpoints during a test,
 *       and traffic is attributable per endpoint — neither of which the single
 *       global listener can do.  The global fault levers and toxics still apply
 *       uniformly, so a scenario is configured once and every route feels it.
 *
 * HOW:  a fixed-size table under one mutex.  A route slot, once bound to a name,
 *       keeps that identity for the process lifetime: `del` stops the listener
 *       (closing it and joining the accept thread) but leaves the struct — and
 *       thus its counters — valid, so in-flight relay threads that still hold the
 *       route pointer can finish writing counters with no use-after-free, and a
 *       later `add` of the same name simply restarts the same slot.  Binding and
 *       the accept/relay engine live in the core, reached only through the
 *       registered fp_route_ops, so a dynamic route reuses the one vetted
 *       loopback-gated bind address (only the port differs) and cannot widen the
 *       unauthenticated control plane's exposure.
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "brix_fault_route.h"

#define FP_ROUTE_MAX          16
#define FP_ROUTE_NAME         32
#define FP_ROUTE_MAX_TARGETS  8

struct fp_route {
    char     name[FP_ROUTE_NAME];
    int      listen_port;
    struct { char host[256]; int port; } targets[FP_ROUTE_MAX_TARGETS];
    int      ntargets;
    unsigned rr;

    int          is_default;
    volatile int alive;         /* 1 while the listener should keep accepting */
    volatile int listening;     /* 1 while a listener/accept-thread is active */
    int          listen_fd;     /* dynamic routes only (-1 when not listening) */
    pthread_t    accept_tid;

    int      in_use;            /* slot has been assigned an identity */

    /* Counters (atomic). */
    unsigned long conns;
    unsigned long up_bytes, down_bytes;
};

static struct fp_route g_routes[FP_ROUTE_MAX];
static pthread_mutex_t  g_route_lock = PTHREAD_MUTEX_INITIALIZER;
static fp_route_ops     g_ops;

void
fp_route_init(const fp_route_ops *ops)
{
    g_ops = *ops;
}

/* Find a slot by name (any in_use slot, listening or stopped), or NULL. */
static fp_route *
find_by_name(const char *name)
{
    for (int i = 0; i < FP_ROUTE_MAX; i++) {
        if (g_routes[i].in_use && strcmp(g_routes[i].name, name) == 0) {
            return &g_routes[i];
        }
    }
    return NULL;
}

static fp_route *
alloc_slot(void)
{
    for (int i = 0; i < FP_ROUTE_MAX; i++) {
        if (!g_routes[i].in_use) {
            return &g_routes[i];
        }
    }
    return NULL;
}

fp_route *
fp_route_register_default(int listen_port)
{
    pthread_mutex_lock(&g_route_lock);
    fp_route *r = &g_routes[0];
    memset(r, 0, sizeof *r);
    snprintf(r->name, sizeof r->name, "default");
    r->listen_port = listen_port;
    r->is_default  = 1;
    r->alive       = 1;
    r->listening   = 1;         /* the main thread owns the default accept loop */
    r->listen_fd   = -1;
    r->in_use      = 1;
    pthread_mutex_unlock(&g_route_lock);
    return r;
}

fp_route *
fp_route_default(void)
{
    return &g_routes[0];
}

int
fp_route_add_target(fp_route *route, const char *host, int port)
{
    if (route->ntargets >= FP_ROUTE_MAX_TARGETS) {
        return -1;
    }
    snprintf(route->targets[route->ntargets].host,
             sizeof route->targets[0].host, "%s", host);
    route->targets[route->ntargets].port = port;
    route->ntargets++;
    return 0;
}

/* Parse a comma-separated host:port list into `route` (replacing its pool).
 * Returns 0 on success, -1 on any malformed entry or overflow. */
static int
parse_targets(fp_route *route, const char *spec)
{
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s", spec);
    route->ntargets = 0;
    for (char *tok = strtok(tmp, ","); tok != NULL; tok = strtok(NULL, ",")) {
        const char *colon = strrchr(tok, ':');
        if (colon == NULL || colon == tok || colon[1] == '\0') {
            return -1;
        }
        size_t hlen = (size_t) (colon - tok);
        if (hlen >= sizeof route->targets[0].host) {
            return -1;
        }
        int p = atoi(colon + 1);
        if (p <= 0 || p > 65535) {
            return -1;
        }
        char host[256];
        memcpy(host, tok, hlen);
        host[hlen] = '\0';
        if (fp_route_add_target(route, host, p) != 0) {
            return -1;
        }
    }
    return route->ntargets > 0 ? 0 : -1;
}

/* Accept-thread trampoline: run the core accept loop, then mark not listening. */
struct accept_arg { fp_route *route; int lfd; };

static void *
route_accept_trampoline(void *arg)
{
    struct accept_arg *a = arg;
    fp_route *route = a->route;
    int       lfd   = a->lfd;
    free(a);
    g_ops.accept_loop(route, lfd);      /* returns once route->alive == 0 */
    close(lfd);
    __atomic_store_n(&route->listening, 0, __ATOMIC_RELEASE);
    return NULL;
}

/* Bind a listener and spawn its accept thread for `route`.  Caller holds the
 * lock.  Returns 0 on success, -1 on bind/thread failure. */
static int
start_listener(fp_route *route, char *reply, size_t rsz)
{
    int lfd = g_ops.bind_listen(route->listen_port);
    if (lfd < 0) {
        /* The bind address is the one vetted loopback template — only the port
         * varies — so a bind failure is a port collision in all realistic cases. */
        if (reply && rsz) {
            snprintf(reply, rsz, "err: port in use: cannot bind %d\n",
                     route->listen_port);
        }
        return -1;
    }
    struct accept_arg *a = malloc(sizeof *a);
    if (a == NULL) {
        close(lfd);
        if (reply && rsz) {
            snprintf(reply, rsz, "err: out of memory\n");
        }
        return -1;
    }
    route->alive     = 1;
    route->listen_fd = lfd;
    a->route = route;
    a->lfd   = lfd;
    if (pthread_create(&route->accept_tid, NULL, route_accept_trampoline, a) != 0) {
        close(lfd);
        free(a);
        route->listen_fd = -1;
        if (reply && rsz) {
            snprintf(reply, rsz, "err: cannot start accept thread\n");
        }
        return -1;
    }
    __atomic_store_n(&route->listening, 1, __ATOMIC_RELEASE);
    return 0;
}

/* route add <name> <port> <host:port[,host:port...]> */
static int
route_add(char *rest, char *reply, size_t rsz)
{
    char name[FP_ROUTE_NAME] = "", targets[400] = "";
    int  port = 0;
    if (sscanf(rest, "%31s %d %399s", name, &port, targets) != 3) {
        if (reply && rsz) {
            snprintf(reply, rsz, "err: usage: route add <name> <port> <host:port,...>\n");
        }
        return 1;
    }
    if (port <= 0 || port > 65535) {
        if (reply && rsz) snprintf(reply, rsz, "err: bad port\n");
        return 1;
    }
    if (strcmp(name, "default") == 0) {
        if (reply && rsz) snprintf(reply, rsz, "err: 'default' is reserved\n");
        return 1;
    }

    pthread_mutex_lock(&g_route_lock);
    fp_route *r = find_by_name(name);
    int reused = r != NULL;
    if (r == NULL) {
        r = alloc_slot();
        if (r == NULL) {
            pthread_mutex_unlock(&g_route_lock);
            if (reply && rsz) snprintf(reply, rsz, "err: route table full\n");
            return 1;
        }
    } else if (__atomic_load_n(&r->listening, __ATOMIC_ACQUIRE)) {
        pthread_mutex_unlock(&g_route_lock);
        if (reply && rsz) snprintf(reply, rsz, "err: route '%s' already exists\n", name);
        return 1;
    }

    /* Populate/refresh identity + pool (counters persist across a restart). */
    if (!reused) {
        snprintf(r->name, sizeof r->name, "%s", name);
        r->conns = r->up_bytes = r->down_bytes = 0;
        r->rr = 0;
    }
    r->listen_port = port;
    r->is_default  = 0;
    r->listen_fd   = -1;
    if (parse_targets(r, targets) != 0) {
        if (!reused) {
            memset(r, 0, sizeof *r);    /* release a freshly-taken slot */
        }
        pthread_mutex_unlock(&g_route_lock);
        if (reply && rsz) snprintf(reply, rsz, "err: bad target list\n");
        return 1;
    }
    r->in_use = 1;

    if (start_listener(r, reply, rsz) != 0) {
        if (!reused) {
            memset(r, 0, sizeof *r);
        }
        pthread_mutex_unlock(&g_route_lock);
        return 1;                       /* start_listener wrote the reply */
    }
    pthread_mutex_unlock(&g_route_lock);
    if (reply && rsz) {
        snprintf(reply, rsz, "ok: route %s listening on port %d\n", name, port);
    }
    return 1;
}

/* route del <name> — stop the listener; keep the (now idle) slot + counters. */
static int
route_del(char *rest, char *reply, size_t rsz)
{
    char name[FP_ROUTE_NAME] = "";
    if (sscanf(rest, "%31s", name) != 1) {
        if (reply && rsz) snprintf(reply, rsz, "err: usage: route del <name>\n");
        return 1;
    }
    if (strcmp(name, "default") == 0) {
        if (reply && rsz) snprintf(reply, rsz, "err: cannot delete default route\n");
        return 1;
    }

    pthread_mutex_lock(&g_route_lock);
    fp_route *r = find_by_name(name);
    if (r == NULL || !__atomic_load_n(&r->listening, __ATOMIC_ACQUIRE)) {
        pthread_mutex_unlock(&g_route_lock);
        if (reply && rsz) snprintf(reply, rsz, "err: no such route\n");
        return 1;
    }
    pthread_t tid = r->accept_tid;
    __atomic_store_n(&r->alive, 0, __ATOMIC_RELEASE);   /* accept loop will return */
    pthread_mutex_unlock(&g_route_lock);

    pthread_join(tid, NULL);            /* wait for the accept loop + fd close */
    if (reply && rsz) snprintf(reply, rsz, "ok: route %s removed\n", name);
    return 1;
}

static int
route_list(const char *rest, char *reply, size_t rsz)
{
    if (!reply || !rsz) {
        return 1;
    }
    int json = strncmp(rest, "json", 4) == 0;
    size_t o = 0;

    pthread_mutex_lock(&g_route_lock);
    if (json) {
        o += (size_t) snprintf(reply + o, rsz - o, "{\"routes\":[");
        int first = 1;
        for (int i = 0; i < FP_ROUTE_MAX && o < rsz; i++) {
            fp_route *r = &g_routes[i];
            if (!r->in_use || (!r->is_default && !r->listening)) {
                continue;
            }
            o += (size_t) snprintf(reply + o, rsz - o,
                "%s{\"name\":\"%s\",\"port\":%d,\"targets\":%d,"
                "\"conns\":%lu,\"up_bytes\":%lu,\"down_bytes\":%lu}",
                first ? "" : ",", r->name, r->listen_port, r->ntargets,
                r->conns, r->up_bytes, r->down_bytes);
            first = 0;
        }
        if (o < rsz) o += (size_t) snprintf(reply + o, rsz - o, "]}\n");
    } else {
        for (int i = 0; i < FP_ROUTE_MAX && o < rsz; i++) {
            fp_route *r = &g_routes[i];
            if (!r->in_use || (!r->is_default && !r->listening)) {
                continue;
            }
            o += (size_t) snprintf(reply + o, rsz - o,
                "route %s port=%d targets=%d conns=%lu up=%lu down=%lu\n",
                r->name, r->listen_port, r->ntargets,
                r->conns, r->up_bytes, r->down_bytes);
        }
    }
    pthread_mutex_unlock(&g_route_lock);
    return 1;
}

int
fp_route_cmd(char *args, char *reply, size_t rsz)
{
    char sub[16] = "";
    int  off = 0;
    sscanf(args, "%15s %n", sub, &off);
    char *rest = args + off;

    if (strcmp(sub, "add") == 0)  return route_add(rest, reply, rsz);
    if (strcmp(sub, "del") == 0)  return route_del(rest, reply, rsz);
    if (strcmp(sub, "list") == 0) return route_list(rest, reply, rsz);

    if (reply && rsz) {
        snprintf(reply, rsz, "err: usage: route add|del|list ...\n");
    }
    return 1;
}

/* --- relay-engine hooks --- */

int
fp_route_alive(fp_route *route)
{
    return __atomic_load_n(&route->alive, __ATOMIC_ACQUIRE);
}

const char *
fp_route_name(fp_route *route)
{
    return route->name;
}

int
fp_route_target_count(fp_route *route)
{
    return route->ntargets;
}

unsigned
fp_route_rr_next(fp_route *route)
{
    return __atomic_fetch_add(&route->rr, 1, __ATOMIC_RELAXED);
}

void
fp_route_get_target(fp_route *route, unsigned idx, char *host, size_t hostsz,
                    int *port)
{
    unsigned n = (unsigned) route->ntargets;
    unsigned i = n ? idx % n : 0;
    snprintf(host, hostsz, "%s", route->targets[i].host);
    *port = route->targets[i].port;
}

void
fp_route_inc_conns(fp_route *route)
{
    __atomic_add_fetch(&route->conns, 1, __ATOMIC_RELAXED);
}

void
fp_route_add_bytes(fp_route *route, unsigned long up, unsigned long down)
{
    if (up) {
        __atomic_add_fetch(&route->up_bytes, up, __ATOMIC_RELAXED);
    }
    if (down) {
        __atomic_add_fetch(&route->down_bytes, down, __ATOMIC_RELAXED);
    }
}
