/* Finite admission and startup through the real fault-proxy entry point. */
#include "brix_fault_proxy_state.h"
#include "brix_fault_priv.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#undef main

typedef struct {
    const char *mode;
    int armed, turns, polls, accepts, creates, detached, sleeps, listens;
    int client, peer, relay_closed, priv_calls, teardown;
    void *owned[8];
    void *(*entry[8])(void *);
} fixture;
static fixture *state(void) { static fixture f; return &f; }
static int mode(const char *name) { return !strcmp(state()->mode,name); }
int brix_fault_unused_main(int argc,char **argv);
void *__real_malloc(size_t n);
void *__real_calloc(size_t n,size_t size);
int __real_poll(struct pollfd *,nfds_t,int);
int __real_accept(int,struct sockaddr *,socklen_t *);
int __real_usleep(useconds_t);
void *__wrap_malloc(size_t n)
{
    if(state()->armed && mode("allocation-error") && n==sizeof(relay_arg)) { return NULL; }
    return __real_malloc(n);
}
void *__wrap_calloc(size_t n,size_t size)
{
    if(mode("udp-allocation-error") && size==sizeof(fp_udp_cfg)) { return NULL; }
    return __real_calloc(n,size);
}
int __wrap_fp_route_alive(fp_route *route)
{
    assert(route);
    if(!state()->armed) { return 0; }
    return state()->turns++<2;
}
int __wrap_poll(struct pollfd *p,nfds_t n,int timeout)
{
    if(!state()->armed) { return __real_poll(p,n,timeout); }
    assert(n==1 && timeout==200 && p->events==POLLIN);
    state()->polls++;
    if(state()->polls==1 && mode("poll-interrupted")) { errno=EINTR;return -1; }
    if(state()->polls==1 && mode("poll-timeout")) { return 0; }
    return 1;
}
int __wrap_accept(int fd,struct sockaddr *address,socklen_t *length)
{
    if(!state()->armed) { return __real_accept(fd,address,length); }
    assert(address==NULL && length==NULL);state()->accepts++;
    if(state()->accepts==1 && mode("accept-interrupted")) { errno=EINTR;return -1; }
    if(state()->accepts>1 || mode("accept-error")) { errno=EBADF;return -1; }
    return state()->client;
}
int __wrap_usleep(useconds_t us)
{
    if(!state()->armed) { return __real_usleep(us); }
    assert(us==3000);state()->sleeps++;return 0;
}
int __wrap_pthread_create(pthread_t *thread,const pthread_attr_t *attr,
                          void *(*entry)(void *),void *arg)
{
    fixture *f=state();assert(attr==NULL && f->creates<8);
    int slot=f->creates++;f->entry[slot]=entry;
    if(mode("create-error") || mode("startup-create-error")) { return EAGAIN; }
    f->owned[slot]=arg;*thread=(pthread_t)(slot+11);return 0;
}
int __wrap_pthread_detach(pthread_t thread)
{ assert((unsigned long)thread>=11);state()->detached++;return 0; }
int __wrap_listen_sa(const struct sockaddr_storage *address,socklen_t length,int port)
{
    assert(address && length>0 && (port==18080 || port==18081));
    state()->listens++;
    if(mode("listen-error")) { errno=EADDRINUSE;return -1; }
    return dup(STDERR_FILENO);
}
int __wrap_fp_priv_enable(const char *iface,int port,const int *targets,int count,const char **error)
{
    assert(iface && !strcmp(iface,"fixture0") && port==18080);
    assert(count==2 && targets[0]==18082 && targets[1]==18083);state()->priv_calls++;
    if(mode("priv-error")) { *error="fixture provider refusal";return -1; }
    return 0;
}
void __wrap_fp_priv_teardown(void) { state()->teardown++; }

/* WHAT: Verify socket ownership and gauge rollback. WHY: Failed admission must
 * not leak a connection slot. HOW: Run two bounded accept iterations. */
static void admission(void)
{
    fixture *f=state();int pair[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);
    f->client=pair[0];f->peer=pair[1];f->armed=1;
    g_blocked=mode("blocked");g_refuse_ppm=mode("refused")?1000000:0;
    g_syn_drop_ppm=mode("syn-dropped")?1000000:0;
    g_max_conns=mode("capped")?1:0;C.active=g_max_conns;
    g_seed=mode("seeded")?1234:0;
    if(mode("seeded")) { g_refuse_ppm=1000000; }
    g_accept_pause_ms=mode("pause")?3:0;
    fp_route *route=fp_route_register_default(18080);
    fp_accept_loop(route,19);f->armed=0;
    for(int i=0;i<f->creates;i++) {
        if(f->owned[i]) {
            relay_arg *arg=f->owned[i];
            assert(f->entry[i]==relay_thread && arg->client_fd==f->client);
            assert(arg->route==route && arg->conn_id==1 && arg->epoch==g_drop_epoch);
            close(arg->client_fd);free(arg);CDEC(active);f->relay_closed++;
        }
    }
    int open=fcntl(f->client,F_GETFD)!=-1;
    printf("{\"open\":%d,\"active\":%lu,\"conns\":%lu,\"refused\":%lu,"
           "\"syn\":%lu,\"creates\":%d,\"detached\":%d,\"relays\":%d,\"sleeps\":%d}\n",
           open,C.active,C.conns,C.refused,C.syn_dropped,f->creates,f->detached,f->relay_closed,f->sleeps);
    if(open) { close(f->client); }close(f->peer);
}

/* WHAT: Exercise optional startup jobs. WHY: Their failures must not widen the
 * bind gate or misconfigure the targets. HOW: Capture thread ownership only. */
static void startup(void)
{
    fixture *f=state();char *args[32]={"brix-fault-proxy","--listen","18080",
        "--control","18081","--target","127.0.0.1:18082","--target","127.0.0.1:18083"};
    int n=9;
    if(!strncmp(f->mode,"priv-",5)) {
        if(!mode("priv-without-enable")) { args[n++]="--privileged"; }
        args[n++]="--priv-iface";args[n++]="fixture0";
    } else if(mode("unsafe-bind")) { args[n++]="--bind";args[n++]="0.0.0.0"; }
    else if(mode("event-error")) { args[n++]="--event-log";args[n++]="/missing-fixture-parent/events"; }
    else {
        args[n++]="--script";args[n++]="fixture-scenario";
        args[n++]="--udp";args[n++]=mode("bad-udp")?"broken":"18084 127.0.0.1:18085";
    }
    if(mode("quiet")) { args[n++]="--quiet"; }
    int rc=brix_fault_unused_main(n,args);
    for(int i=0;i<f->creates;i++) {
        void *arg=f->owned[i];
        if(!arg) { continue; }
        if(f->entry[i]==script_thread) { assert(!strcmp(arg,"fixture-scenario")); }
        else if(f->entry[i]==fp_udp_thread) {
            fp_udp_cfg *udp=arg;
            assert(udp->listen_port==18084 && udp->port==18085 && !strcmp(udp->host,"127.0.0.1"));free(arg);
        } else { assert(f->entry[i]==control_thread);close(*(int *)arg);free(arg); }
    }
    printf("{\"rc\":%d,\"creates\":%d,\"detached\":%d,\"listens\":%d,\"priv\":%d}\n",
           rc,f->creates,f->detached,f->listens,f->priv_calls);
}
int main(int argc,char **argv)
{
    assert(argc==3);state()->mode=argv[2];
    if(!strcmp(argv[1],"admission")) { admission(); }else { startup(); }
    return 0;
}
