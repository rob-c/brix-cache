/* Server authentication bookkeeping with real Kerberos owners and a finite verifier. */
#include "core/ngx_brix_module.h"
#include "auth/krb5/deleg_capture.h"
#include "observability/metrics/unified.h"
#include "protocols/root/session/registry.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    brix_ctx_t ctx;
    ngx_connection_t connection;
    ngx_stream_brix_srv_conf_t conf;
    brix_identity_t identity;
    ngx_brix_metrics_t *shared;
    ngx_shm_zone_t zone;
    krb5_context library;
    krb5_auth_context parked;
    const char *mode;
    int armed,created,freed,tickets,tickets_freed,verifies,bound,registered,tracked;
    int ok,error,metric,success,delegated;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *m) { return state()->armed && !strcmp(state()->mode,m); }
krb5_error_code __real_krb5_auth_con_init(krb5_context,krb5_auth_context *);
krb5_error_code __wrap_krb5_auth_con_init(krb5_context context,krb5_auth_context *out)
{
    if(mode("context-error")) { return ENOMEM; }
    int rc=__real_krb5_auth_con_init(context,out);if(!rc) { state()->created++; }return rc;
}
krb5_error_code __real_krb5_auth_con_free(krb5_context,krb5_auth_context);
krb5_error_code __wrap_krb5_auth_con_free(krb5_context c,krb5_auth_context auth)
{ assert(auth && ++state()->freed<=state()->created);return __real_krb5_auth_con_free(c,auth); }
krb5_error_code __real_krb5_auth_con_setaddrs(krb5_context,krb5_auth_context,krb5_address *,krb5_address *);
krb5_error_code __wrap_krb5_auth_con_setaddrs(krb5_context c,krb5_auth_context auth,krb5_address *local,krb5_address *remote)
{
    assert(!local && remote && (remote->length==4 || remote->length==16));state()->bound++;
    return mode("bind-error")?EINVAL:__real_krb5_auth_con_setaddrs(c,auth,local,remote);
}
krb5_error_code __wrap_krb5_rd_req(krb5_context c,krb5_auth_context *auth,const krb5_data *data,
    krb5_const_principal server,krb5_keytab keytab,krb5_flags *flags,krb5_ticket **out)
{
    fixture *f=state();assert(c==f->library && auth && *auth && server==f->conf.krb5.principal_obj);
    assert(keytab==f->conf.krb5.keytab_obj && !flags && data->length==3 && !memcmp(data->data,"req",3));
    f->verifies++;if(mode("verify-error")) { return KRB5KRB_AP_ERR_BAD_INTEGRITY; }
    if(mode("null-ticket")) { *out=NULL;return 0; }
    *out=calloc(1,sizeof(**out));assert(*out);f->tickets++;
    if(mode("no-enc-part")) { return 0; }
    (*out)->enc_part2=calloc(1,sizeof(*(*out)->enc_part2));assert((*out)->enc_part2);
    if(!mode("no-client")) { assert(!krb5_parse_name(c,"fixture@EXAMPLE.TEST",&(*out)->enc_part2->client)); }
    return 0;
}
void __real_krb5_free_ticket(krb5_context,krb5_ticket *);
void __wrap_krb5_free_ticket(krb5_context c,krb5_ticket *ticket)
{ if(ticket) { assert(++state()->tickets_freed<=state()->tickets); }__real_krb5_free_ticket(c,ticket); }
krb5_error_code __wrap_krb5_aname_to_localname(krb5_context c,krb5_const_principal p,int cap,char *out)
{
    assert(c==state()->library && p && cap>=7);
    if(mode("principal-name") || mode("name-error") || mode("null-name")) { return KRB5_LNAME_NOTRANS; }
    strcpy(out,mode("empty-name")?"":"mapped");return 0;
}
krb5_error_code __real_krb5_unparse_name(krb5_context,krb5_const_principal,char **);
krb5_error_code __wrap_krb5_unparse_name(krb5_context c,krb5_const_principal p,char **out)
{
    if(mode("name-error")) { return ENOMEM; }
    if(mode("null-name")) { *out=NULL;return 0; }
    return __real_krb5_unparse_name(c,p,out);
}
ngx_int_t __wrap_brix_send_error(brix_ctx_t *ctx,ngx_connection_t *c,uint16_t code,const char *msg)
{ assert(ctx==&state()->ctx && c==&state()->connection && msg && *msg);state()->error=code;return NGX_OK; }
ngx_int_t __wrap_brix_send_ok(brix_ctx_t *ctx,ngx_connection_t *c,const void *body,uint32_t length)
{ assert(ctx==&state()->ctx && c==&state()->connection && !body && !length);state()->ok++;return NGX_OK; }
void __wrap_brix_metric_auth(brix_proto_t proto,ngx_uint_t method,unsigned int success)
{ assert(proto==BRIX_PROTO_ROOT && method==BRIX_AUTHN_KRB5);state()->metric++;state()->success=success; }
void __wrap_brix_log_access(brix_ctx_t *ctx,ngx_connection_t *c,const char *verb,const char *path,
    const char *detail,ngx_uint_t ok,uint16_t code,const char *msg,size_t bytes)
{ (void)ctx;(void)c;(void)verb;(void)path;(void)detail;(void)ok;(void)code;(void)msg;(void)bytes; }
int __wrap_brix_session_register(const u_char *session,const char *dn,const char *vo,ngx_uint_t token,ngx_uint_t signing)
{
    assert(session==state()->ctx.login.sessid && dn==state()->ctx.login.dn && vo==state()->ctx.login.vo_list);
    assert(!token && !signing);state()->registered++;return 19;
}
ngx_shm_zone_t *__wrap_brix_metrics_get_shm_zone(void)
{ return mode("no-metrics")?NULL:&state()->zone; }
ngx_int_t __wrap_brix_track_unique_user(ngx_brix_metrics_t *shared,const char *dn,size_t n)
{ assert(shared==state()->shared && n==strlen(dn) && n);state()->tracked++;return NGX_OK; }
ngx_int_t __wrap_brix_krb5_deleg_park(brix_ctx_t *ctx,ngx_connection_t *c,krb5_context lib,
    krb5_auth_context auth,krb5_principal principal,const char *name)
{
    assert(ctx==&state()->ctx && c==&state()->connection && lib==state()->library && principal && name);
    if(mode("park-error")) { return NGX_ERROR; }
    state()->parked=auth;strcpy(ctx->krb5.cname,name);ctx->krb5.round=1;return NGX_OK;
}
ngx_int_t __wrap_brix_krb5_send_fwdtgt(brix_ctx_t *ctx,ngx_connection_t *c)
{ assert(ctx==&state()->ctx && c==&state()->connection && ctx->krb5.round==1);state()->delegated++;return NGX_OK; }
ngx_int_t __wrap_brix_krb5_deleg_capture(brix_ctx_t *ctx,ngx_connection_t *c,ngx_stream_brix_srv_conf_t *conf)
{
    assert(ctx==&state()->ctx && c==&state()->connection && conf==&state()->conf && ctx->krb5.round==1);
    ctx->krb5.round=0;return mode("capture-error")?NGX_ERROR:NGX_OK;
}
static void configure(fixture *f,int family,int delegation)
{
    assert(!krb5_init_context(&f->library));f->conf.krb5.context=f->library;
    assert(!krb5_parse_name(f->library,"host/server@EXAMPLE.TEST",&f->conf.krb5.principal_obj));
    assert(!krb5_kt_resolve(f->library,"MEMORY:finite-auth",&f->conf.krb5.keytab_obj));
    f->conf.krb5.ip_check=family!=0;f->conf.krb5.delegate=delegation;
    struct sockaddr_storage *peer=ngx_pcalloc(f->connection.pool,sizeof(*peer));assert(peer);
    peer->ss_family=family;f->connection.sockaddr=(struct sockaddr *)peer;
    f->ctx.metrics=calloc(1,sizeof(*f->ctx.metrics));assert(f->ctx.metrics);
    f->shared=calloc(1,sizeof(*f->shared));assert(f->shared);
    f->zone.data=f->shared;
    f->ctx.identity=&f->identity;f->ctx.token.auth=1;
    f->ctx.recv.payload=(u_char *)"krb5req";f->ctx.recv.cur_dlen=7;
    if(!strcmp(f->mode,"nul-prefix")) { f->ctx.recv.payload=(u_char *)"krb5\0req";f->ctx.recv.cur_dlen=8; }
    if(!strcmp(f->mode,"null-payload")) { f->ctx.recv.payload=NULL; }
    if(!strcmp(f->mode,"short-payload")) { f->ctx.recv.cur_dlen=4; }
    if(!strcmp(f->mode,"wrong-prefix")) { f->ctx.recv.payload=(u_char *)"oopsreq"; }
    if(!strcmp(f->mode,"no-peer")) { f->connection.sockaddr=NULL; }
    if(!strcmp(f->mode,"no-identity")) { f->ctx.identity=NULL; }
    if(delegation==2) { f->ctx.krb5.round=1;strcpy(f->ctx.krb5.cname,"mapped"); }
}
int main(int argc,char **argv)
{
    assert(argc==4);fixture *f=calloc(1,sizeof(*f));assert(f);ngx_cycle=&f->cycle;f->mode=argv[1];
    ngx_open_file_t file={.fd=STDERR_FILENO};ngx_log_t log={.log_level=NGX_LOG_ERR,.file=&file};
    f->cycle.log=&log;f->connection.log=&log;ngx_time_init();
    f->connection.pool=ngx_create_pool(4096,&log);assert(f->connection.pool);
    int family=atoi(argv[2]);configure(f,family==4?AF_INET:family==6?AF_INET6:family,atoi(argv[3]));
    krb5_principal principal=f->conf.krb5.principal_obj;krb5_keytab keytab=f->conf.krb5.keytab_obj;
    f->armed=1;
    if(mode("no-context")) { f->conf.krb5.context=NULL; }
    if(mode("no-principal")) { f->conf.krb5.principal_obj=NULL; }
    if(mode("no-keytab")) { f->conf.krb5.keytab_obj=NULL; }
    assert(brix_handle_krb5_auth(&f->ctx,&f->connection,&f->conf)==NGX_OK);
    if(f->ok) {
        assert(f->ctx.login.auth_done && !f->ctx.token.auth && f->ctx.login.session_slot_hint==19);
        assert(!strcmp(f->ctx.login.dn,mode("principal-name")?"fixture@EXAMPLE.TEST":mode("empty-name")?"":"mapped"));
        if(f->ctx.identity) { assert(f->identity.auth_method==BRIX_AUTHN_KRB5); }
    } else { assert(!f->ctx.login.auth_done && !f->registered); }
    if(f->parked) { assert(f->created-f->freed==1);__wrap_krb5_auth_con_free(f->library,f->parked); }
    assert(f->created==f->freed && f->tickets==f->tickets_freed);
    printf("%d %d %d %d %d %d %d %d %d\n",f->ok,f->error,f->verifies,f->bound,
        f->registered,f->tracked,f->metric,f->success,f->delegated);
    f->armed=0;krb5_kt_close(f->library,keytab);krb5_free_principal(f->library,principal);
    krb5_free_context(f->library);free(f->shared);free(f->ctx.metrics);ngx_destroy_pool(f->connection.pool);free(f);return 0;
}
