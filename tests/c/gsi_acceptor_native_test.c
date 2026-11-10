/* GSI acceptor failures retain real trust checks, credentials and pool cleanup. */
#include "auth/gssapi/gsi_mech.h"
#include "auth/gsi/proxy_req.h"
#include <openssl/pem.h>
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    int armed,ssl_live,bio_live,bios,accepts,writes;
    SSL *ssl;
    X509 *leaf;
    STACK_OF(X509) *chain;
    const u_char *application;
    size_t length,consumed;
    u_char request[8192];
    size_t request_len;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return state()->armed && !strcmp(state()->mode,name); }
SSL *__real_SSL_new(SSL_CTX *);
SSL *__wrap_SSL_new(SSL_CTX *ctx)
{
    if(mode("session-oom")) { return NULL; }
    SSL *ssl=__real_SSL_new(ctx);assert(ssl);state()->ssl=ssl;state()->ssl_live++;return ssl;
}
void __real_SSL_free(SSL *);
void __wrap_SSL_free(SSL *ssl)
{ if(ssl) { assert(ssl==state()->ssl && state()->ssl_live==1);state()->ssl_live--; }__real_SSL_free(ssl); }
static long bio_observer(BIO *bio,int operation,const char *data,size_t size,int arg,long argl,int rc,size_t *done)
{
    (void)bio;(void)data;(void)size;(void)arg;(void)argl;(void)done;
    if(operation==BIO_CB_FREE) { state()->bio_live--;assert(state()->bio_live>=0); }
    return rc;
}
BIO *__real_BIO_new(const BIO_METHOD *);
BIO *__wrap_BIO_new(const BIO_METHOD *method)
{
    fixture *f=state();f->bios++;
    if(mode("bio-oom") || (mode("second-bio-oom") && f->bios==2)) { return NULL; }
    BIO *bio=__real_BIO_new(method);assert(bio);f->bio_live++;BIO_set_callback_ex(bio,bio_observer);return bio;
}
void *__real_ngx_pcalloc(ngx_pool_t *,size_t);
void *__wrap_ngx_pcalloc(ngx_pool_t *pool,size_t size)
{ return mode("context-oom")?NULL:__real_ngx_pcalloc(pool,size); }
void *__real_ngx_palloc(ngx_pool_t *,size_t);
void *__wrap_ngx_palloc(ngx_pool_t *pool,size_t size)
{ return mode("output-oom")?NULL:__real_ngx_palloc(pool,size); }
void *__real_ngx_pnalloc(ngx_pool_t *,size_t);
void *__wrap_ngx_pnalloc(ngx_pool_t *pool,size_t size)
{ return mode("identity-oom")?NULL:__real_ngx_pnalloc(pool,size); }
ngx_pool_cleanup_t *__real_ngx_pool_cleanup_add(ngx_pool_t *,size_t);
ngx_pool_cleanup_t *__wrap_ngx_pool_cleanup_add(ngx_pool_t *pool,size_t size)
{ return mode("cleanup-oom")?NULL:__real_ngx_pool_cleanup_add(pool,size); }
int __wrap_SSL_accept(SSL *ssl)
{
    assert(ssl==state()->ssl);state()->accepts++;
    if(mode("handshake-error")) { return -1; }
    assert(BIO_write(SSL_get_wbio(ssl),"flight",6)==6);
    return (mode("want-read") || mode("want-write"))?-1:1;
}
int __wrap_SSL_get_error(const SSL *ssl,int rc)
{
    assert(ssl==state()->ssl && rc==-1);
    if(mode("want-read")) { return SSL_ERROR_WANT_READ; }
    return mode("want-write")?SSL_ERROR_WANT_WRITE:SSL_ERROR_SSL;
}
X509 *__wrap_SSL_get1_peer_certificate(const SSL *ssl)
{
    assert(ssl==state()->ssl);if(mode("no-peer")) { return NULL; }
    assert(X509_up_ref(state()->leaf));return state()->leaf;
}
STACK_OF(X509) *__wrap_SSL_get_peer_cert_chain(const SSL *ssl)
{ assert(ssl==state()->ssl);return mode("no-chain")?NULL:state()->chain; }
int __wrap_SSL_read(SSL *ssl,void *data,int cap)
{
    fixture *f=state();assert(ssl==f->ssl && cap>0);size_t n=f->length-f->consumed;
    if(n>(size_t)cap) { n=(size_t)cap; }if(!n) { return -1; }
    memcpy(data,f->application+f->consumed,n);f->consumed+=n;return (int)n;
}
int __wrap_SSL_write(SSL *ssl,const void *data,int length)
{
    fixture *f=state();assert(ssl==f->ssl && length>0);f->writes++;
    if(mode("write-error")) { return -1; }
    assert((size_t)length<sizeof(f->request));memcpy(f->request,data,length);f->request_len=(size_t)length;
    assert(BIO_write(SSL_get_wbio(ssl),"record",6)==6);return length;
}
int __real_BIO_write(BIO *,const void *,int);
int __wrap_BIO_write(BIO *bio,const void *data,int n)
{
    if(mode("input-error") && bio==SSL_get_rbio(state()->ssl)) { return -1; }
    return __real_BIO_write(bio,data,n);
}
int __real_BIO_read(BIO *,void *,int);
int __wrap_BIO_read(BIO *bio,void *data,int n)
{
    if(mode("drain-error") && bio==SSL_get_wbio(state()->ssl)) { return -1; }
    return __real_BIO_read(bio,data,n);
}
int __real_PEM_write_bio_X509(BIO *,const X509 *);
int __wrap_PEM_write_bio_X509(BIO *bio,const X509 *cert)
{
    if(mode("pem-error")) { return 0; }if(mode("empty-pem")) { return 1; }
    return __real_PEM_write_bio_X509(bio,cert);
}
static void peer_contract(brix_gssapi_srv_t *g)
{
    ngx_str_t dn={0},proxy={0};X509 *leaf=NULL;STACK_OF(X509) *chain=NULL;
    assert(brix_gssapi_srv_peer(g,&dn,&proxy)==NGX_OK && dn.len && !proxy.len);
    assert(brix_gssapi_srv_peer(g,NULL,NULL)==NGX_OK);
    assert(brix_gssapi_srv_peer_x509(g,&leaf,&chain)==NGX_OK && leaf==state()->leaf && chain==state()->chain);
    X509_free(leaf);assert(brix_gssapi_srv_peer_x509(g,NULL,NULL)==NGX_OK);
}
int main(int argc,char **argv)
{
    assert(argc==5);fixture f={0};ngx_cycle=&f.cycle;f.mode=argv[2];
    ngx_open_file_t output={.fd=STDERR_FILENO};ngx_log_t log={.log_level=NGX_LOG_ERR,.file=&output};
    f.cycle.log=&log;ngx_time_init();ngx_os_argv=argv;assert(ngx_os_init(&log)==NGX_OK);
    ngx_pool_t *pool=ngx_create_pool(16384,&log);assert(pool);
    SSL_CTX *ctx=SSL_CTX_new(TLS_server_method());assert(ctx);X509_STORE *store=X509_STORE_new();assert(store);
    BIO *input=BIO_new_file(argv[3],"r");assert(input);f.leaf=PEM_read_bio_X509(input,NULL,NULL,NULL);assert(f.leaf);BIO_free(input);
    if(strcmp(f.mode,"untrusted")) { assert(X509_STORE_add_cert(store,f.leaf)); }
    f.chain=sk_X509_new_null();assert(f.chain && sk_X509_push(f.chain,f.leaf));
    int create=!strcmp(argv[1],"create"),delegating=!strcmp(argv[1],"marker");
    f.armed=create;brix_gssapi_srv_t *g=brix_gssapi_srv_create(pool,&log,ctx,store,delegating);f.armed=0;
    int rc=g!=NULL;ngx_str_t result={0};
    if(!create) {
        assert(g);assert(brix_gssapi_srv_peer_x509(g,NULL,NULL)==NGX_ERROR);
        assert(brix_gssapi_srv_peer(g,NULL,NULL)==NGX_ERROR);
        if(strcmp(argv[1],"handshake")) {
            assert(brix_gssapi_srv_step(g,NULL,0,&result)==(delegating?BRIX_GSS_CONTINUE:BRIX_GSS_COMPLETE));
            if(!delegating) { peer_contract(g); }
        }
        f.armed=1;
        if(!strcmp(argv[1],"handshake")) {
            rc=brix_gssapi_srv_step(g,(u_char *)"peer",4,&result);
            if(rc==BRIX_GSS_FAILED) { assert(brix_gssapi_srv_step(g,NULL,0,&result)==BRIX_GSS_FAILED); }
            if(rc==BRIX_GSS_COMPLETE) { peer_contract(g);assert(brix_gssapi_srv_step(g,NULL,0,&result)==BRIX_GSS_COMPLETE); }
        } else if(delegating) {
            f.application=(u_char *)(mode("bad-marker")?"X":"D");f.length=mode("empty")?0:1;
            rc=brix_gssapi_srv_step(g,NULL,0,&result);
            if(rc==BRIX_GSS_CONTINUE) {
                const unsigned char *p=f.request;X509_REQ *req=d2i_X509_REQ(NULL,&p,(long)f.request_len);
                assert(req && p==f.request+f.request_len);EVP_PKEY *key=X509_REQ_get_pubkey(req);assert(key && X509_REQ_verify(req,key)==1);
                EVP_PKEY_free(key);X509_REQ_free(req);
            }
        } else if(!strcmp(argv[1],"peer")) {
            if(mode("freed")) { brix_gssapi_srv_free(g); }
            rc=brix_gssapi_srv_peer_cert_pem(g,&result);
            if(rc==NGX_OK) {
                BIO *pem=BIO_new_mem_buf(result.data,(int)result.len);X509 *cert=PEM_read_bio_X509(pem,NULL,NULL,NULL);
                assert(cert && X509_cmp(cert,f.leaf)==0);X509_free(cert);BIO_free(pem);
            }
        } else if(!strcmp(argv[1],"wrap")) {
            rc=brix_gssapi_wrap(g,(u_char *)"command",7,&result);
            if(rc==NGX_OK) { assert(result.len==6 && !memcmp(result.data,"record",6)); }
        } else {
            f.application=(u_char *)"reply";f.length=mode("empty")?0:5;
            rc=brix_gssapi_unwrap(g,(u_char *)"token",5,&result);
            if(rc==NGX_OK) { assert(result.len==f.length && !memcmp(result.data,f.application,f.length)); }
        }
    }
    f.armed=0;assert(rc==atoi(argv[4]));brix_gssapi_srv_free(g);brix_gssapi_srv_free(g);brix_gssapi_srv_free(NULL);
    ngx_destroy_pool(pool);assert(!f.ssl_live && !f.bio_live);
    sk_X509_free(f.chain);X509_free(f.leaf);X509_STORE_free(store);SSL_CTX_free(ctx);
    printf("%d %d %d\n",rc,f.accepts,f.writes);return 0;
}
