/* Real bootstrap credential selection/framing with finite event-loop seams. */
#include "net/proxy/events_bootstrap_internal.h"
#include "core/types/identity.h"
#include <assert.h>
#include <openssl/rand.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_connection_t connection;
    ngx_event_t write;
    brix_proxy_ctx_t proxy;
    brix_ctx_t context;
    brix_identity_t identity;
    ngx_stream_brix_srv_conf_t conf;
    brix_proxy_upstream_t upstream;
    ngx_array_t upstreams,keys;
    brix_sss_key_t key[2];
    const char *mode;
    int armed,aborted,flushes,events;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode,name); }
void *__real_ngx_palloc(ngx_pool_t *,size_t);
void *__wrap_ngx_palloc(ngx_pool_t *pool,size_t size)
{ return state()->armed && mode("allocation")?NULL:__real_ngx_palloc(pool,size); }
int __real_RAND_bytes(unsigned char *,int);
int __wrap_RAND_bytes(unsigned char *out,int size)
{ return mode("random-error")?0:__real_RAND_bytes(out,size); }
void __wrap_brix_proxy_abort(brix_proxy_ctx_t *proxy,const char *reason)
{ assert(proxy==&state()->proxy && reason && *reason);assert(state()->aborted++==0); }
ngx_int_t __wrap_brix_proxy_flush(brix_proxy_ctx_t *proxy)
{
    assert(proxy==&state()->proxy && proxy->bs_phase==XRD_PX_BS_AUTH);
    assert(!proxy->resp_body && !proxy->resp_dlen && !proxy->resp_body_pos && !proxy->rhdr_pos);
    state()->flushes++;
    if(mode("flush-error")) { return NGX_ERROR; }
    proxy->wbuf_pos=(mode("partial") || mode("event-error"))?7:proxy->wbuf_len;return NGX_OK;
}
ngx_int_t __wrap_ngx_handle_write_event(ngx_event_t *event,size_t lowat)
{ assert(event==&state()->write && !lowat);state()->events++;return mode("event-error")?NGX_ERROR:NGX_OK; }

/* WHAT: Seed separate key identities and an authenticated front principal.
 * WHY: Override precedence and identity forwarding must be visible.
 * HOW: Use real SSS crypto and caller-owned identity fields. */
static void configure(fixture *f,const char *source,const char *token_path)
{
    f->proxy.conf=&f->conf;f->proxy.conn=&f->connection;f->proxy.client_conn=&f->connection;
    f->proxy.client_ctx=&f->context;f->proxy.upstream_idx=0;
    f->context.metrics=calloc(1,sizeof(*f->context.metrics));assert(f->context.metrics);
    f->context.identity=&f->identity;f->identity.is_authenticated=1;
    ngx_str_set(&f->identity.dn,"client-dn");ngx_str_set(&f->identity.vo_csv,"group-a");
    ngx_str_set(&f->identity.acc_vorg_csv,"asserted-vo");ngx_str_set(&f->identity.acc_role_csv,"asserted-role");
    ngx_str_set(&f->identity.endorsements,"endorsement");ngx_str_set(&f->identity.creds,"credential");
    strcpy(f->identity.mapped_user,"mapped-client");f->identity.mapped_resolved=1;
    f->identity.acc_attrs_asserted=mode("asserted");
    f->conf.proxy.auth=BRIX_PROXY_AUTH_FORWARD;f->upstream.auth=-1;
    f->upstreams.elts=&f->upstream;f->upstreams.nelts=1;f->conf.proxy.upstreams=&f->upstreams;
    f->keys.elts=f->key;f->keys.nelts=2;f->conf.sss_keys=&f->keys;
    for(int i=0;i<2;i++) {
        f->key[i].id=7+i;f->key[i].key_len=16;memcpy(f->key[i].key,"0123456789abcdef",16);
        strcpy(f->key[i].name,i?"second":"first");strcpy(f->key[i].user,i?"second-service":"first-service");
    }
    if(!strcmp(source,"bearer") || !strcmp(source,"both")) { strcpy(f->context.bearer_token,"caller-token"); }
    if(!strcmp(source,"file") || !strcmp(source,"both")) {
        f->conf.upstream_token_file=(ngx_str_t){strlen(token_path),(u_char *)token_path};
    }
    if(!strcmp(source,"sss") || !strcmp(source,"entity")) {
        f->conf.proxy.auth=BRIX_PROXY_AUTH_SSS;
        strcpy(f->upstream.sss_keyname,mode("unknown-key")?"missing":"second");
        f->conf.proxy.sss_identity=!strcmp(source,"entity")?BRIX_PROXY_SSS_IDENT_CLIENT:0;
    }
    if(mode("override-forward")) { f->upstream.auth=BRIX_PROXY_AUTH_FORWARD;strcpy(f->context.bearer_token,"caller-token"); }
    if(mode("override-anonymous")) { f->upstream.auth=BRIX_PROXY_AUTH_ANONYMOUS; }
    if(mode("no-keys")) { f->keys.nelts=0; }
    if(mode("no-identity")) { f->context.identity=NULL; }
    if(mode("no-client")) { f->proxy.client_ctx=NULL; }
    if(mode("anonymous")) { f->identity.is_authenticated=0; }
    if(mode("empty-dn")) { f->identity.dn.len=0;f->identity.dn.data=(u_char *)""; }
    if(mode("unmapped")) { f->identity.mapped_resolved=0; }
    if(mode("empty-map")) { f->identity.mapped_user[0]=0; }
    if(mode("no-conf")) { f->proxy.conf=NULL; }
    if(mode("invalid-key")) { f->key[1].key_len=0; }
}
int main(int argc,char **argv)
{
    assert(argc==5);fixture *f=calloc(1,sizeof(*f));assert(f);ngx_cycle=&f->cycle;f->mode=argv[3];
    ngx_open_file_t file={.fd=STDERR_FILENO};ngx_log_t log={.log_level=NGX_LOG_ERR,.file=&file};
    f->cycle.log=&log;ngx_time_init();f->connection.log=&log;f->connection.write=&f->write;
    f->connection.pool=ngx_create_pool(4096,&log);assert(f->connection.pool);
    configure(f,argv[2],argv[4]);
    const char *hint=!strncmp(argv[2],"ss",2)||!strcmp(argv[2],"entity")?"&P=sss,0":"&P=ztn,0:4096:";
    if(mode("unknown-hint")) { hint="&P=unknown"; }
    f->proxy.resp_dlen=16+strlen(hint);f->proxy.resp_body=calloc(1,f->proxy.resp_dlen+1);assert(f->proxy.resp_body);
    memcpy(f->proxy.resp_body+16,hint,strlen(hint));f->proxy.resp_body_pos=f->proxy.resp_dlen;f->proxy.rhdr_pos=8;
    if(mode("short-hint")) { f->proxy.resp_dlen=16; }
    f->armed=1;
    int rc=!strcmp(argv[1],"hint")?proxy_bs_login_sec_hint(&f->proxy):proxy_bs_do_auth(&f->proxy);
    f->armed=0;
    printf("RESULT %d %d %d %d %d %lu %lu\n",rc,f->aborted,f->flushes,f->events,
        (int)f->proxy.policy_refusal,(unsigned long)f->context.metrics->proxy.upstream_auth_errors,
        (unsigned long)f->context.metrics->proxy.upstreams[0].upstream_auth_errors);
    if(f->proxy.wbuf) {
        printf("FRAME ");for(size_t i=0;i<f->proxy.wbuf_len;i++) { printf("%02x",f->proxy.wbuf[i]); }puts("");
    }
    free(f->proxy.resp_body);free(f->context.metrics);ngx_destroy_pool(f->connection.pool);free(f);return 0;
}
