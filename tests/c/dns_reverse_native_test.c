/* Reverse DNS retains real cache identity, TTL policy, callbacks and cancellation. */
#include "net/dns/dns.h"
#include <assert.h>
#include <netdb.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    const char *backend, *mode;
    brix_dns_policy_t policy;
    ngx_resolver_t resolver;
    ngx_resolver_ctx_t resolver_ctx;
    ngx_thread_task_t *task;
    int thread_pool_token;
    int starts, resolver_done, lookups, callbacks, cached, posts;
    ngx_int_t result;
    time_t ttl;
    char name[512], answer[256];
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode,name); }

ngx_resolver_t *__wrap_brix_dns_policy_resolver(const brix_dns_policy_t *policy)
{ (void)policy;return !strcmp(state()->backend,"resolver")?&state()->resolver:NULL; }
ngx_resolver_ctx_t *__wrap_ngx_resolve_start(ngx_resolver_t *resolver,ngx_resolver_ctx_t *temporary)
{
    fixture *f=state();assert(resolver==&f->resolver && !temporary);f->starts++;
    if(mode("start-null")) { return NULL; }if(mode("no-resolver")) { return NGX_NO_RESOLVER; }
    return &f->resolver_ctx;
}
ngx_int_t __wrap_ngx_resolve_addr(ngx_resolver_ctx_t *ctx)
{
    assert(ctx==&state()->resolver_ctx && ctx->addr.sockaddr && ctx->timeout>=1000);
    return mode("resolve-error")?NGX_ERROR:NGX_OK;
}
void __wrap_ngx_resolve_addr_done(ngx_resolver_ctx_t *ctx)
{ assert(ctx==&state()->resolver_ctx);state()->resolver_done++; }
int __wrap_getnameinfo(const struct sockaddr *address,socklen_t length,char *host,
    socklen_t capacity,char *service,socklen_t service_capacity,int flags)
{
    fixture *f=state();assert(address && length && !service && !service_capacity && flags==NI_NAMEREQD);f->lookups++;
    if(mode("no-name")) { return EAI_NONAME; }if(mode("libc-error")) { return EAI_FAIL; }
    assert(strlen(f->name)<capacity);strcpy(host,f->name);return 0;
}
ngx_int_t __wrap_brix_dns_bridge_reverse(const brix_dns_policy_t *policy,
    const struct sockaddr *address,socklen_t length,char *out,size_t capacity,ngx_int_t *answer)
{
    (void)policy;assert(address && length);
    if(!mode("bridge")) { return NGX_DECLINED; }
    snprintf(out,capacity,"bridge.test");*answer=NGX_OK;return NGX_OK;
}
ngx_int_t __wrap_brix_dns_thread_task_new(ngx_log_t *log,size_t size,
    ngx_thread_pool_t **thread_pool,ngx_pool_t **pool,ngx_thread_task_t **task)
{
    fixture *f=state();f->starts++;
    if(mode("no-pool")) { return NGX_DECLINED; }if(mode("task-alloc")) { return NGX_ERROR; }
    *pool=ngx_create_pool(4096,log);assert(*pool);*task=ngx_thread_task_alloc(*pool,size);assert(*task);
    *thread_pool=(void *)&f->thread_pool_token;return NGX_OK;
}
ngx_int_t __wrap_brix_dns_thread_task_post(ngx_thread_pool_t *pool,
    ngx_thread_task_t *task,ngx_pool_t *owner_pool,void **owner)
{
    fixture *f=state();assert(pool==(void *)&f->thread_pool_token);f->posts++;
    if(mode("post-error")) { *owner=NULL;ngx_destroy_pool(owner_pool);return NGX_ERROR; }
    f->task=task;*owner=task;return NGX_OK;
}
static void completed(brix_dns_rev_req_t *req)
{
    fixture *f=state();assert(!req->task && !req->rctx);f->callbacks++;f->result=req->rc;f->cached=req->cached;
    if(!req->cached) { f->ttl=req->ttl; }
    snprintf(f->answer,sizeof(f->answer),"%s",req->name);
    if(req->rc!=NGX_OK) { assert(!req->name[0]); }
}
static void complete_provider(fixture *f)
{
    if(f->task) {
        ngx_thread_task_t *task=f->task;f->task=NULL;
        task->handler(task->ctx,&f->log);task->event.handler(&task->event);return;
    }
    ngx_resolver_ctx_t *ctx=&f->resolver_ctx;
    if(!ctx->handler || f->resolver_done || mode("resolve-error")) { return; }
    ctx->name=(ngx_str_t){strlen(f->name),(u_char *)f->name};ctx->valid=ngx_time()+100;
    if(mode("ttl-low")) { ctx->valid=ngx_time()-1; }
    if(mode("no-name")) { ctx->state=NGX_RESOLVE_NXDOMAIN; }
    if(mode("libc-error")) { ctx->state=NGX_RESOLVE_SERVFAIL; }
    if(mode("empty-name")) { ctx->name.len=0; }
    ctx->handler(ctx);
}
static void address(brix_dns_rev_req_t *req,int family)
{
    req->ss.ss_family=family;
    req->len=family==AF_INET?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6);
    if(family==AF_INET) { ((struct sockaddr_in *)&req->ss)->sin_addr.s_addr=htonl(0xc0000201); }
    else { assert(inet_pton(AF_INET6,"2001:db8::1",&((struct sockaddr_in6 *)&req->ss)->sin6_addr)==1); }
}
int main(int argc,char **argv)
{
    assert(argc==4);fixture f={0};ngx_cycle=&f.cycle;f.backend=argv[1];f.mode=argv[2];f.cycle.log=&f.log;
    ngx_open_file_t log_file={.fd=STDERR_FILENO};f.log=(ngx_log_t){.file=&log_file};
    ngx_time_init();assert(ngx_strerror_init()==NGX_OK);ngx_cached_time->sec=1000;
    f.policy.min_ttl=3;f.policy.max_ttl=8;f.policy.negative_ttl=2;f.policy.rc.timeout=0;
    strcpy(f.name,"reverse.example.test");
    if(mode("long-name")) { memset(f.name,'a',sizeof(f.name)-1); }
    brix_dns_rev_req_t req={.policy=mode("no-policy")?NULL:&f.policy,.handler=completed};address(&req,atoi(argv[3])==6?AF_INET6:AF_INET);
    if(mode("unsupported")) { req.ss.ss_family=AF_UNIX; }
    if(mode("short-address")) { req.len=1; }
    ngx_int_t rc;
    if(!strcmp(f.backend,"sync")) {
        rc=brix_dns_reverse_sync(req.policy,mode("null-address")?NULL:(struct sockaddr *)&req.ss,
            req.len,mode("null-buffer")?NULL:f.answer,mode("empty-buffer")?0:sizeof(f.answer));f.result=rc;
    } else if(!strcmp(f.backend,"prefetch")) {
        brix_dns_reverse_prefetch(req.policy,(struct sockaddr *)&req.ss,req.len);
        brix_dns_reverse_prefetch(req.policy,(struct sockaddr *)&req.ss,req.len);
        complete_provider(&f);rc=NGX_OK;
    } else {
        rc=brix_dns_reverse(&req);
        if(mode("cancel")) { brix_dns_reverse_cancel(&req);assert(!req.rctx && !req.task); }
        complete_provider(&f);
    }
    char cached[256]={0};ngx_int_t cache=brix_dns_reverse_cached((struct sockaddr *)&req.ss,req.len,cached,sizeof(cached));
    if(!mode("bridge") && f.result==NGX_OK && f.answer[0]) { assert(cache==NGX_OK && !strcmp(cached,f.answer)); }
    if(f.callbacks && cache==NGX_OK) {
        assert(brix_dns_reverse(&req)==NGX_OK && f.callbacks==2 && req.cached && !req.task && !req.rctx);
    }
    printf("%ld %ld %ld %d %d %d %d %ld %zu\n",(long)rc,(long)f.result,(long)cache,
        f.starts,f.lookups,f.callbacks,f.resolver_done,(long)f.ttl,strlen(f.answer));
    brix_dns_reverse_prefetch(NULL,NULL,0);brix_dns_reverse_cancel(&req);return 0;
}
