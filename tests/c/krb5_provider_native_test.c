/* Kerberos orchestration with real names/caches and finite provider outcomes. */
#include "fs/cache/cache_internal.h"
#include "auth/krb5/forward.h"
#include "auth/krb5/carry.h"
#include "auth/krb5/apreq.h"
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>
#include <gssapi/gssapi_ext.h>
#include <krb5.h>
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode,*operation;
    int armed,imports,names,contexts,buffers,releases,steps,wires,sends,recvs;
    int krb_contexts,caches,stored,creds;
    unsigned char reply[8];
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return state() && state()->armed && !strcmp(state()->mode,name); }
static int raw(void) { return !strcmp(state()->operation,"raw"); }
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size)
{
    if(mode("hold-oom") || (mode("reply-oom") && size==3)) { return NULL; }
    return __real_malloc(size);
}
ngx_pool_t *__real_ngx_create_pool(size_t,ngx_log_t *);
ngx_pool_t *__wrap_ngx_create_pool(size_t size,ngx_log_t *log)
{ return mode("pool-oom")?NULL:__real_ngx_create_pool(size,log); }
void *__real_ngx_pnalloc(ngx_pool_t *,size_t);
void *__wrap_ngx_pnalloc(ngx_pool_t *pool,size_t size)
{ return mode("token-oom")?NULL:__real_ngx_pnalloc(pool,size); }
int __wrap_brix_krb5_forward_available(void) { return !mode("unavailable"); }
OM_uint32 __real_gss_import_name(OM_uint32 *,gss_buffer_t,gss_OID,gss_name_t *);
OM_uint32 __wrap_gss_import_name(OM_uint32 *minor,gss_buffer_t input,gss_OID kind,gss_name_t *out)
{
    state()->imports++;*minor=17;
    if(mode("import-error")) { return GSS_S_FAILURE; }
    OM_uint32 rc=__real_gss_import_name(minor,input,kind,out);
    if(!GSS_ERROR(rc)) { state()->names++; }return rc;
}
OM_uint32 __real_gss_release_name(OM_uint32 *,gss_name_t *);
OM_uint32 __wrap_gss_release_name(OM_uint32 *minor,gss_name_t *name)
{ assert(*name && state()->names>0);state()->names--;return __real_gss_release_name(minor,name); }
static void token(gss_buffer_t out,const char *text)
{ out->length=strlen(text);out->value=__real_malloc(out->length);assert(out->value);memcpy(out->value,text,out->length);state()->buffers++; }
OM_uint32 __wrap_gss_release_buffer(OM_uint32 *minor,gss_buffer_t out)
{
    *minor=0;
    if(out->value) { assert(state()->buffers>0);state()->buffers--;state()->releases++;free(out->value); }
    *out=(gss_buffer_desc)GSS_C_EMPTY_BUFFER;return GSS_S_COMPLETE;
}
OM_uint32 __wrap_gss_display_status(OM_uint32 *minor,OM_uint32 code,int kind,
    gss_OID mechanism,OM_uint32 *context,gss_buffer_t output)
{
    (void)code;(void)kind;assert(mechanism==GSS_C_NO_OID);*minor=0;
    if(mode("display-error")) { return GSS_S_FAILURE; }
    token(output,"provider diagnostic");*context=*context?0:1;return GSS_S_COMPLETE;
}
OM_uint32 __wrap_gss_init_sec_context(OM_uint32 *minor,gss_cred_id_t cred,gss_ctx_id_t *ctx,
    gss_name_t target,gss_OID mech,OM_uint32 flags,OM_uint32 lifetime,
    gss_channel_bindings_t binding,gss_buffer_t input,gss_OID *actual,gss_buffer_t output,
    OM_uint32 *returned,OM_uint32 *expiry)
{
    fixture *f=state();assert(cred==(gss_cred_id_t)f && target && mech==GSS_C_NO_OID);
    assert(flags==(GSS_C_MUTUAL_FLAG|GSS_C_REPLAY_FLAG) && !lifetime && !binding && !actual && !expiry);
    if(f->steps) { assert(input && input->length==3 && !memcmp(input->value,"REP",3)); }
    else { assert(!input || !input->length); }
    f->steps++;*minor=17;
    if(!*ctx) { *ctx=(gss_ctx_id_t)__real_malloc(1);assert(*ctx);f->contexts++; }
    *returned=mode("no-mutual")?0:GSS_C_MUTUAL_FLAG;
    int continuation=f->steps==1 || mode("runaway");
    if(!mode("empty-token") && (continuation || mode("final-token") || mode("closed-early"))) {
        token(output,f->steps==1?"INIT":"NEXT");
    }
    if(mode("context-error") || mode("display-error")) { return GSS_S_FAILURE; }
    return continuation?GSS_S_CONTINUE_NEEDED:GSS_S_COMPLETE;
}
OM_uint32 __wrap_gss_delete_sec_context(OM_uint32 *minor,gss_ctx_id_t *ctx,gss_buffer_t output)
{ assert(*ctx && !output && state()->contexts==1);free(*ctx);*ctx=NULL;*minor=0;state()->contexts--;return 0; }

static ngx_int_t exchange(void *opaque,const ngx_str_t *out,ngx_str_t *in,int *done,ngx_log_t *log)
{
    fixture *f=opaque;(void)log;assert(out->len==4 && !memcmp(out->data,f->wires?"NEXT":"INIT",4));
    f->wires++;if(mode("wire-error")) { return NGX_ERROR; }
    in->data=(u_char *)"REP";in->len=mode("empty-reply")?0:3;
    *done=mode("closed-early") || f->wires>1;return NGX_OK;
}
int __wrap_brix_cache_io_send(brix_cache_origin_conn_t *oc,const void *data,size_t len)
{
    fixture *f=state();assert(oc);f->sends++;
    if(mode("send-header") || (mode("send-body") && f->sends%2==0)) { errno=EPIPE;return -1; }
    if(f->sends%2) {
        const unsigned char *h=data;
        assert(len==24 && h[0]==0 && h[1]==1 && h[2]==11 && h[3]==184);
        for(unsigned i=4;i<16;i++) { assert(h[i]==0); }
        assert(!memcmp(h+16,"krb5",4) && h[20]==0 && h[21]==0 && h[22]==0);
        assert(h[23]==(raw()?10:4));
    } else {
        assert(len==(raw()?10u:4u));
        assert(!memcmp(data,raw()?"krb5\0APREQ":f->sends==2?"INIT":"NEXT",len));f->wires++;
    }
    return 0;
}
int __wrap_brix_cache_io_recv_exact(brix_cache_origin_conn_t *oc,void *data,size_t len)
{
    fixture *f=state();assert(oc);f->recvs++;
    if(mode("recv-header") || (mode("recv-body") && f->recvs%2==0)) { errno=ECONNRESET;return -1; }
    if(f->recvs%2) {
        assert(len==8);unsigned char *h=data;memset(h,0,8);h[1]=1;
        unsigned status=raw()?0:4002;
        if(mode("rejected")) { status=4003; }
        if(mode("closed-early")) { status=0; }
        if(mode("continued")) { status=4002; }
        h[2]=status>>8;h[3]=status&255;h[7]=mode("empty-reply")?0:3;
        if(mode("oversized")) { h[4]=1; }
    } else { assert(len==3);memcpy(data,"REP",3); }
    return 0;
}

krb5_error_code __real_krb5_init_context(krb5_context *);
krb5_error_code __wrap_krb5_init_context(krb5_context *ctx)
{ if(mode("krb-context")) { return ENOMEM; }int rc=__real_krb5_init_context(ctx);if(!rc) { state()->krb_contexts++; }return rc; }
void __real_krb5_free_context(krb5_context);
void __wrap_krb5_free_context(krb5_context ctx)
{ assert(ctx && state()->krb_contexts>0);state()->krb_contexts--;__real_krb5_free_context(ctx); }
krb5_error_code __real_krb5_cc_resolve(krb5_context,const char *,krb5_ccache *);
krb5_error_code __wrap_krb5_cc_resolve(krb5_context ctx,const char *name,krb5_ccache *cache)
{ if(mode("resolve-error")) { return KRB5_CC_BADNAME; }int rc=__real_krb5_cc_resolve(ctx,name,cache);if(!rc) { state()->caches++; }return rc; }
krb5_error_code __real_krb5_cc_close(krb5_context,krb5_ccache);
krb5_error_code __wrap_krb5_cc_close(krb5_context ctx,krb5_ccache cache)
{ assert(cache && state()->caches>0);state()->caches--;return __real_krb5_cc_close(ctx,cache); }
OM_uint32 __wrap_gss_krb5_import_cred(OM_uint32 *minor,krb5_ccache cache,krb5_principal principal,
    krb5_keytab keytab,gss_cred_id_t *credential)
{
    assert(cache && !principal && !keytab);*minor=0;
    if(mode("cred-error")) { return GSS_S_FAILURE; }
    *credential=(gss_cred_id_t)state();state()->creds++;return 0;
}
OM_uint32 __wrap_gss_release_cred(OM_uint32 *minor,gss_cred_id_t *credential)
{ assert(*credential==(gss_cred_id_t)state() && state()->creds==1);state()->creds--;*credential=NULL;*minor=0;return 0; }
OM_uint32 __wrap_gss_store_cred_into(OM_uint32 *minor,gss_cred_id_t credential,gss_cred_usage_t usage,
    gss_OID mechanism,OM_uint32 overwrite,OM_uint32 make_default,gss_const_key_value_set_t store,
    gss_OID_set *elements,gss_cred_usage_t *used)
{
    assert(credential==(gss_cred_id_t)state() && usage==GSS_C_INITIATE && !mechanism);
    assert(overwrite==1 && make_default==0 && !elements && !used);
    assert(store->count==1 && !strcmp(store->elements[0].key,"ccache"));
    assert(!strcmp(store->elements[0].value,"FILE:/fixture-credential"));
    state()->stored++;*minor=0;return mode("store-error")?GSS_S_FAILURE:0;
}

/* Name/cache providers stay real. Only ticket acquisition/rendering are finite
 * fixtures, allowing every acquired resource to use the real library cleanup. */
krb5_error_code __real_krb5_cc_get_principal(krb5_context,krb5_ccache,krb5_principal *);
krb5_error_code __wrap_krb5_cc_get_principal(krb5_context ctx,krb5_ccache cache,krb5_principal *out)
{ return mode("principal-error")?KRB5_CC_NOTFOUND:__real_krb5_cc_get_principal(ctx,cache,out); }
krb5_error_code __real_krb5_parse_name(krb5_context,const char *,krb5_principal *);
krb5_error_code __wrap_krb5_parse_name(krb5_context ctx,const char *name,krb5_principal *out)
{ return mode("parse-error")?KRB5_PARSE_MALFORMED:__real_krb5_parse_name(ctx,name,out); }
krb5_error_code __wrap_krb5_get_credentials(krb5_context ctx,krb5_flags options,krb5_ccache cache,
    krb5_creds *input,krb5_creds **out)
{
    assert(!options && cache && input->client && input->server);
    if(mode("ticket-error")) { return KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN; }
    *out=calloc(1,sizeof(**out));assert(*out);
    assert(!krb5_copy_principal(ctx,input->client,&(*out)->client));
    assert(!krb5_copy_principal(ctx,input->server,&(*out)->server));return 0;
}
krb5_error_code __wrap_krb5_mk_req_extended(krb5_context ctx,krb5_auth_context *auth,krb5_flags flags,
    krb5_data *input,krb5_creds *credential,krb5_data *out)
{
    assert(!flags && !input && credential->client && credential->server);
    if(mode("request-error")) { return KRB5KRB_ERR_GENERIC; }
    assert(!krb5_auth_con_init(ctx,auth));out->data=strdup("APREQ");out->length=5;return 0;
}

static ngx_int_t carry(ngx_log_t *log)
{
    char huge[NGX_MAX_PATH+32];memset(huge,'x',sizeof(huge)-1);huge[sizeof(huge)-1]=0;
    const char *path=mode("long-path")?huge:"/fixture-credential";
    if(mode("null-path")) { path=NULL; }
    if(!strcmp(state()->operation,"export")) {
        return brix_krb5_cred_to_ccache(mode("null-cred")?NULL:state(),path,log);
    }
    void *credential=NULL,*hold=NULL;
    ngx_int_t rc=brix_krb5_cred_from_ccache(path,mode("null-cred")?NULL:&credential,
                                           mode("null-hold")?NULL:&hold,log);
    if(rc==NGX_OK) { assert(credential==(void *)state() && hold); }
    else { assert(!credential && !hold); }
    brix_krb5_cred_carry_release(credential,hold,log);
    brix_krb5_cred_carry_release(NULL,NULL,log);return rc;
}

int main(int argc,char **argv)
{
    assert(argc==3);fixture f={.operation=argv[1],.mode=argv[2]};ngx_cycle=&f.cycle;
    ngx_open_file_t file={.fd=STDERR_FILENO};ngx_log_t log={.log_level=NGX_LOG_WARN,.file=&file};
    f.cycle.log=&log;ngx_time_init();ngx_pool_t *pool=ngx_create_pool(4096,&log);assert(pool);
    krb5_context ctx;krb5_ccache cache;krb5_principal principal;
    assert(!krb5_init_context(&ctx));assert(!krb5_cc_resolve(ctx,"MEMORY:provider-fixture",&cache));
    assert(!krb5_parse_name(ctx,"alice@TEST.INVALID",&principal));
    assert(!krb5_cc_initialize(ctx,cache,principal));krb5_free_principal(ctx,principal);
    f.armed=1;ngx_int_t rc;ngx_str_t payload=ngx_null_string;
    const char *spn=mode("null-spn")?NULL:mode("empty-spn")?"":"host/origin.test@TEST.INVALID";
    if(!strcmp(f.operation,"single")) {
        rc=brix_krb5_deleg_to_origin(mode("null-pool")?NULL:pool,&f,spn,
            mode("null-output")?NULL:&payload,&log);
        if(rc==NGX_OK) { assert(payload.len==4 && !memcmp(payload.data,"INIT",4)); }
    } else if(!strcmp(f.operation,"negotiate")) {
        rc=brix_krb5_deleg_negotiate(mode("null-pool")?NULL:pool,&f,spn,
            mode("null-wire")?NULL:exchange,&f,&log);
    } else if(!strcmp(f.operation,"import") || !strcmp(f.operation,"export")) { rc=carry(&log); }
    else if(!strcmp(f.operation,"apreq")) {
        rc=brix_krb5_apreq_from_ccache(pool,mode("null-cache")?NULL:"MEMORY:provider-fixture",spn,&payload,&log);
        if(rc==NGX_OK) { assert(payload.len==10 && !memcmp(payload.data,"krb5\0APREQ",10)); }
    } else {
        brix_cache_fill_t *task=calloc(1,sizeof(*task));assert(task);
        ngx_connection_t connection={.log=&log};task->c=mode("no-connection")?NULL:&connection;
        brix_cache_origin_conn_t origin={.fd=-1};
        rc=raw()?brix_cache_origin_auth_krb5_raw(task,&origin,"MEMORY:provider-fixture",spn)
                :brix_cache_origin_auth_krb5(task,&origin,&f,spn);
        printf("error=%d\n",task->xrd_error);free(task);
    }
    f.armed=0;krb5_cc_close(ctx,cache);krb5_free_context(ctx);
    assert(!f.names && !f.contexts && !f.buffers && !f.creds && !f.krb_contexts && !f.caches);
    printf("rc=%ld\nsteps=%d\nwires=%d\nstored=%d\nreleases=%d\n",(long)rc,f.steps,f.wires,f.stored,f.releases);
    ngx_destroy_pool(pool);ngx_cycle=NULL;return 0;
}
