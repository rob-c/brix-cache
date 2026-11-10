/* TLS policy uses real SSL objects; finite provider replies drive retry edges. */
#include "brix.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>

typedef struct {
    const char *mode;
    int contexts,sessions,connects,polls,handshakes,shutdowns,error;
    brix_conn connection;
    SSL_SESSION *resume;
} fixture;
static fixture *state(void)
{ return (fixture *)(uintptr_t)strtoull(getenv("BRIX_TLS_HANDSHAKE_FIXTURE"),NULL,16); }
static int mode(const char *name) { return !strcmp(state()->mode,name); }
SSL_CTX *__real_SSL_CTX_new(const SSL_METHOD *method);
SSL_CTX *__wrap_SSL_CTX_new(const SSL_METHOD *method)
{
    if(mode("context-oom")) { return NULL; }
    SSL_CTX *ctx=__real_SSL_CTX_new(method);assert(ctx);state()->contexts++;return ctx;
}
void __real_SSL_CTX_free(SSL_CTX *ctx);
void __wrap_SSL_CTX_free(SSL_CTX *ctx)
{ if(ctx) { assert(state()->contexts==1);state()->contexts--; }__real_SSL_CTX_free(ctx); }
SSL *__real_SSL_new(SSL_CTX *ctx);
SSL *__wrap_SSL_new(SSL_CTX *ctx)
{
    if(mode("session-oom")) { return NULL; }
    SSL *ssl=__real_SSL_new(ctx);assert(ssl);state()->sessions++;return ssl;
}
void __real_SSL_free(SSL *ssl);
void __wrap_SSL_free(SSL *ssl)
{ if(ssl) { assert(state()->sessions==1);state()->sessions--; }__real_SSL_free(ssl); }
int __real_SSL_CTX_load_verify_locations(SSL_CTX *,const char *,const char *);
int __wrap_SSL_CTX_load_verify_locations(SSL_CTX *ctx,const char *file,const char *directory)
{ return mode("ca-error")?0:__real_SSL_CTX_load_verify_locations(ctx,file,directory); }
int __real_SSL_CTX_use_certificate_chain_file(SSL_CTX *,const char *);
int __wrap_SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx,const char *file)
{ return mode("certificate-error")?0:__real_SSL_CTX_use_certificate_chain_file(ctx,file); }
int __real_SSL_CTX_use_PrivateKey_file(SSL_CTX *,const char *,int);
int __wrap_SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx,const char *file,int kind)
{ return mode("key-error")?0:__real_SSL_CTX_use_PrivateKey_file(ctx,file,kind); }
int __real_SSL_CTX_check_private_key(const SSL_CTX *);
int __wrap_SSL_CTX_check_private_key(const SSL_CTX *ctx)
{ return mode("mismatch")?0:__real_SSL_CTX_check_private_key(ctx); }
int __real_X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *,const char *,size_t);
int __wrap_X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *parameters,const char *host,size_t length)
{ assert(!strcmp(host,"origin.test"));return mode("hostname-error")?0:__real_X509_VERIFY_PARAM_set1_host(parameters,host,length); }
int __wrap_SSL_connect(SSL *ssl)
{
    assert(ssl && state()->sessions==1);state()->connects++;
    if(mode("connect-error") || mode("verify-connect-error")) { return -1; }
    if(state()->error && state()->connects==1) { return -1; }
    return 1;
}
int __wrap_SSL_get_error(const SSL *ssl,int result)
{ assert(ssl && result<1);return state()->error?state()->error:SSL_ERROR_SSL; }
long __wrap_SSL_get_verify_result(const SSL *ssl)
{ assert(ssl);return (mode("verify-error") || mode("verify-connect-error"))?X509_V_ERR_CERT_HAS_EXPIRED:X509_V_OK; }
int __wrap_poll(struct pollfd *fds,nfds_t count,int timeout)
{
    fixture *f=state();f->polls++;assert(count==1 && fds->fd==f->connection.io.fd && timeout==31);
    assert(fds->events==(f->error==SSL_ERROR_WANT_WRITE?POLLOUT:POLLIN));
    if(mode("poll-interrupt") && f->polls==1) { errno=EINTR;return -1; }
    if(mode("poll-error")) { errno=EBADF;return -1; }
    return mode("timeout")?0:1;
}
int __wrap_SSL_set_session(SSL *ssl,SSL_SESSION *session)
{ assert(ssl && session==state()->resume);return !mode("resume-error"); }
int __wrap_SSL_session_reused(const SSL *ssl) { assert(ssl);return mode("resumed"); }
int __wrap_SSL_shutdown(SSL *ssl) { assert(ssl);state()->shutdowns++;return 1; }
int __wrap_SSL_version(const SSL *ssl) { assert(ssl);return mode("wrong-version")?TLS1_3_VERSION:TLS1_2_VERSION; }
int __wrap_SSL_renegotiate(SSL *ssl) { assert(ssl);return !mode("renegotiate-error"); }
int __wrap_SSL_do_handshake(SSL *ssl)
{
    fixture *f=state();assert(ssl);f->handshakes++;
    if(mode("refused") || mode("runaway") || (f->error && f->handshakes==1)) { return -1; }
    return 1;
}
SSL_SESSION *__wrap_SSL_get1_session(SSL *ssl)
{ assert(ssl && state()->resume);assert(SSL_SESSION_up_ref(state()->resume));return state()->resume; }

static void validate_policy(SSL *ssl,int peer,int host,int legacy)
{
    SSL_CTX *ctx=SSL_get_SSL_CTX(ssl);
    assert(SSL_CTX_get_verify_mode(ctx)==(peer?SSL_VERIFY_PEER:SSL_VERIFY_NONE));
    assert(SSL_CTX_get_min_proto_version(ctx)==(legacy?TLS1_VERSION:TLS1_2_VERSION));
    if(legacy) { assert(SSL_CTX_get_max_proto_version(ctx)==TLS1_2_VERSION && SSL_CTX_get_security_level(ctx)==0); }
    if(peer && host) { assert(!strcmp(X509_VERIFY_PARAM_get0_host(SSL_get0_param(ssl),0),"origin.test")); }
    if(peer) { assert(X509_VERIFY_PARAM_get_flags(SSL_CTX_get0_param(ctx))&X509_V_FLAG_ALLOW_PROXY_CERTS); }
}
int main(int argc,char **argv)
{
    assert(argc==7);fixture f={.mode=argv[2]};brix_status status={0};char pointer[32];
    snprintf(pointer,sizeof(pointer),"%llx",(unsigned long long)(uintptr_t)&f);
    assert(setenv("BRIX_TLS_HANDSHAKE_FIXTURE",pointer,1)==0);
    int pair[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);
    f.connection.io.fd=pair[0];f.connection.io.timeout_ms=31;strcpy(f.connection.host,"origin.test");
    f.resume=SSL_SESSION_new();assert(f.resume);
    if(mode("want-read") || mode("poll-interrupt") || mode("poll-error") || mode("timeout") || mode("runaway")) { f.error=SSL_ERROR_WANT_READ; }
    if(mode("want-write")) { f.error=SSL_ERROR_WANT_WRITE; }
    int peer=atoi(argv[3]),host=atoi(argv[4]);const char *ca=argv[5],*certificate=argv[6];
    if(!strcmp(ca,"-")) { ca=NULL; }if(!strcmp(certificate,"-")) { certificate=NULL; }
    int rc;void *ctx=NULL;
    if(!strcmp(argv[1],"renegotiate")) {
        ctx=SSL_CTX_new(TLS_client_method());assert(ctx);f.connection.io.ssl=SSL_new(ctx);assert(f.connection.io.ssl);
        rc=brix_tls_probe_renegotiate(mode("null-connection")?NULL:&f.connection,&status);
    } else if(!strcmp(argv[1],"client")) {
        rc=brix_tls_client(&f.connection.io,mode("no-host")?NULL:"origin.test",peer,host,ca,certificate,&ctx,&status);
    } else {
        if(mode("legacy")) { f.connection.opts.tls_max_version=TLS1_2_VERSION; }
        if(mode("resumed") || mode("resume-error")) { f.connection.opts.tls_resume_session=f.resume; }
        rc=brix_tls_upgrade(&f.connection,peer,host,ca,&status);ctx=f.connection.ssl_ctx;
        if(!rc) { assert(f.connection.tls_session_reused==mode("resumed")); }
    }
    if(!strcmp(argv[1],"renegotiate")) { /* The probe keeps the caller's session alive on every result. */
        assert(f.connection.io.ssl && f.contexts==1 && f.sessions==1);
    } else if(rc==0) {
        validate_policy(f.connection.io.ssl,peer,host && !mode("no-host"),mode("legacy"));
        void *session=brix_tls_session_get(&f.connection);assert(session==f.resume);brix_tls_session_free(session);
    } else { assert(!f.connection.io.ssl && !ctx && !f.contexts && !f.sessions); }
    brix_tls_client_free(&f.connection.io,ctx);assert(!f.connection.io.ssl && !f.contexts && !f.sessions);
    brix_tls_client_free(NULL,NULL);assert(brix_tls_session_get(NULL)==NULL);
    SSL_SESSION_free(f.resume);close(pair[0]);close(pair[1]);
    printf("%d %d %d %d %d %d\n",rc,status.kxr,status.sys_errno,f.connects,f.polls,f.handshakes);return 0;
}
