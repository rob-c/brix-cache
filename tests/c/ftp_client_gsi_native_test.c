/* Real client GSI credential loading and delegation, finite SSL record provider. */
#include "protocols/ftp/ftp_gsi_int.h"
#include "auth/gsi/proxy_req.h"
#include <openssl/pem.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
typedef struct {
    const char *mode;
    struct brix_ftp_gss *g;
    int armed, allocation, connects, writes, issued, bio_count, credential_fd;
    const unsigned char *application;
    size_t length, consumed;
} fixture;
static fixture *state(void)
{
    const char *value=getenv("BRIX_CLIENT_GSI_FIXTURE");
    return value?(fixture *)(uintptr_t)strtoull(value,NULL,16):NULL;
}
static int mode(const char *name) { return state() && !strcmp(state()->mode,name); }
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size) { return state() && state()->allocation==1?NULL:__real_malloc(size); }
void *__real_realloc(void *,size_t);
void *__wrap_realloc(void *p,size_t n) { return state() && state()->allocation==2?NULL:__real_realloc(p,n); }
void *__real_calloc(size_t,size_t);
void *__wrap_calloc(size_t n,size_t size)
{ return state() && state()->armed && mode("context-allocation")?NULL:__real_calloc(n,size); }
SSL_CTX *__real_SSL_CTX_new(const SSL_METHOD *);
SSL_CTX *__wrap_SSL_CTX_new(const SSL_METHOD *m)
{ return state() && state()->armed && mode("context-error")?NULL:__real_SSL_CTX_new(m); }
SSL *__real_SSL_new(SSL_CTX *);
SSL *__wrap_SSL_new(SSL_CTX *ctx)
{ return state() && state()->armed && mode("session-error")?NULL:__real_SSL_new(ctx); }
long __real_SSL_CTX_ctrl(SSL_CTX *,int,long,void *);
long __wrap_SSL_CTX_ctrl(SSL_CTX *ctx,int command,long value,void *p)
{
    if(state() && state()->armed && mode("version-error") && command==SSL_CTRL_SET_MAX_PROTO_VERSION) { return 0; }
    return __real_SSL_CTX_ctrl(ctx,command,value,p);
}
int __real_SSL_CTX_load_verify_locations(SSL_CTX *,const char *,const char *);
int __wrap_SSL_CTX_load_verify_locations(SSL_CTX *ctx,const char *file,const char *dir)
{ return mode("ca-error")?0:__real_SSL_CTX_load_verify_locations(ctx,file,dir); }
int __real_SSL_CTX_use_certificate(SSL_CTX *,X509 *);
int __wrap_SSL_CTX_use_certificate(SSL_CTX *ctx,X509 *cert)
{ return mode("certificate-error")?0:__real_SSL_CTX_use_certificate(ctx,cert); }
int __real_SSL_CTX_use_PrivateKey(SSL_CTX *,EVP_PKEY *);
int __wrap_SSL_CTX_use_PrivateKey(SSL_CTX *ctx,EVP_PKEY *key)
{ return mode("key-error")?0:__real_SSL_CTX_use_PrivateKey(ctx,key); }
FILE *__real_fdopen(int,const char *);
FILE *__wrap_fdopen(int fd,const char *access)
{
    if(state()) { state()->credential_fd=fd; }
    if(mode("file-stream-error")) { errno=ENOMEM;return NULL; }
    return __real_fdopen(fd,access);
}
BIO *__real_BIO_new_fp(FILE *,int);
BIO *__wrap_BIO_new_fp(FILE *fp,int flags)
{ return mode("file-bio-error")?NULL:__real_BIO_new_fp(fp,flags); }
BIO *__real_BIO_new(const BIO_METHOD *);
BIO *__wrap_BIO_new(const BIO_METHOD *method)
{
    if(state() && state()->armed) { state()->bio_count++; }
    if(state() && state()->armed && mode("credential-bio-error") && state()->bio_count==1) { return NULL; }
    return __real_BIO_new(method);
}
int __wrap_SSL_connect(SSL *ssl)
{
    fixture *f=state();assert(ssl==f->g->ssl);f->connects++;
    if(mode("want-read") || mode("want-write")) { assert(BIO_write(f->g->wbio,"token",5)==5);return -1; }
    return mode("handshake-error")?-1:1;
}
int __wrap_SSL_get_error(const SSL *ssl,int rc)
{
    assert(ssl==state()->g->ssl && rc==-1);
    if(mode("want-read")) { return SSL_ERROR_WANT_READ; }
    return mode("want-write")?SSL_ERROR_WANT_WRITE:SSL_ERROR_SSL;
}
int __wrap_SSL_write(SSL *ssl,const void *data,int length)
{
    fixture *f=state();assert(ssl==f->g->ssl);f->writes++;
    if(mode("write-error") || (mode("issue-write-error") && length>1)) { return -1; }
    if(length==1) { assert(!memcmp(data,"D",1)); }
    else if(length==7) { assert(!memcmp(data,"command",7)); }
    else {
        const unsigned char *cursor=data;X509 *cert=d2i_X509(NULL,&cursor,length);
        assert(cert && cursor==(const unsigned char *)data+length);
        assert(X509_verify(cert,f->g->key)==1 && X509_get_ext_by_NID(cert,NID_proxyCertInfo,-1)>=0);
        X509_free(cert);f->issued++;
    }
    assert(BIO_write(f->g->wbio,"record",6)==6);return length;
}
int __wrap_SSL_read(SSL *ssl,void *data,int capacity)
{
    fixture *f=state();assert(ssl==f->g->ssl && capacity>0);
    size_t n=f->length-f->consumed;if(n>(size_t)capacity) { n=(size_t)capacity; }
    if(!n) { return -1; }memcpy(data,f->application+f->consumed,n);f->consumed+=n;return (int)n;
}
int __real_BIO_write(BIO *,const void *,int);
int __wrap_BIO_write(BIO *bio,const void *data,int n)
{
    if(state() && state()->g && mode("input-error") && bio==state()->g->rbio) { return -1; }
    return __real_BIO_write(bio,data,n);
}
static int handshake(brix_status *status)
{
    fixture *f=state();uint8_t *out=NULL;size_t n=0;
    if(mode("drain-allocation")) { f->allocation=1; }
    int rc=brix_ftp_gss_step(f->g,(uint8_t *)"peer",4,&out,&n,status);f->allocation=0;
    if(rc>0) { assert(out && n); }else { assert(!out && !n); }free(out);
    if(mode("handshake-error") || mode("write-error") || mode("input-error")) {
        assert(brix_ftp_gss_step(f->g,NULL,0,&out,&n,status)==-1 && !out && !n);
    }
    return rc;
}
static int delegate(brix_status *status)
{
    fixture *f=state();uint8_t *out=NULL;size_t n=0;EVP_PKEY *key=NULL;
    brix_gsi_blob_t parent={f->g->pem,f->g->pem_len};brix_gsi_buf_t request={0};
    assert(brix_ftp_gss_step(f->g,NULL,0,&out,&n,status)==1);free(out);
    assert(brix_gsi_build_pxyreq(&parent,&key,&request,NULL)==0);
    f->application=request.data;f->length=request.len;
    if(mode("empty")) { f->length=0; }if(mode("bad-request")) { request.data[0]^=0xff; }
    if(mode("payload-allocation")) { f->allocation=1; }
    int rc=brix_ftp_gss_step(f->g,NULL,0,&out,&n,status);f->allocation=0;free(out);
    if(rc>0) {
        assert(f->issued==1 && f->g->state==FTP_GSS_DELEG_ACK);
        assert(brix_ftp_gss_step(f->g,NULL,0,&out,&n,status)==0);
        assert(f->g->state==FTP_GSS_DONE && !out && !n);
        assert(brix_ftp_gss_step(f->g,NULL,0,&out,&n,status)==0);
    } else { assert(f->g->state==FTP_GSS_FAIL && !out && !n); }
    EVP_PKEY_free(key);free(request.data);return rc;
}
static int application(brix_status *status,size_t length)
{
    fixture *f=state();uint8_t *out=NULL;size_t n=0;
    unsigned char *data=malloc(length+1);assert(data);memset(data,'p',length);
    f->application=data;f->length=length;
    if(mode("payload-allocation") || mode("drain-allocation")) { f->allocation=1; }
    if(mode("payload-growth")) { f->allocation=2; }int rc;
    if(mode("wrap") || mode("write-error") || mode("drain-allocation")) {
        rc=brix_ftp_gss_wrap(f->g,"command",7,&out,&n,status);
        if(rc==0) { assert(n==6 && !memcmp(out,"record",6)); }
    } else {
        rc=brix_ftp_gss_unwrap(f->g,"peer",4,&out,&n,status);
        if(rc==0) { assert(n==length && !memcmp(out,data,length)); }
    }
    f->allocation=0;free(out);free(data);return rc;
}
int main(int argc,char **argv)
{
    assert(argc==7);fixture f={.mode=argv[2],.credential_fd=-1};brix_status status={0};char pointer[32];
    snprintf(pointer,sizeof(pointer),"%llx",(unsigned long long)(uintptr_t)&f);
    assert(setenv("BRIX_CLIENT_GSI_FIXTURE",pointer,1)==0);brix_ftp_gss_free(NULL);
    f.armed=1;if(mode("chain-allocation")) { f.allocation=1; }
    f.g=brix_ftp_gss_create(mode("environment-proxy")?NULL:argv[3],
        mode("default-ca")?NULL:argv[4],mode("insecure"),&status);
    f.armed=0;f.allocation=0;int rc=f.g!=NULL;
    if(strcmp(argv[1],"create")) {
        assert(f.g);
        if(!strcmp(argv[1],"handshake")) { rc=handshake(&status); }
        else if(!strcmp(argv[1],"delegate")) { rc=delegate(&status); }
        else { rc=application(&status,(size_t)atoi(argv[6])); }
    } else if(f.g) {
        assert(SSL_CTX_get_min_proto_version(f.g->ctx)==TLS1_VERSION);
        assert(SSL_CTX_get_max_proto_version(f.g->ctx)==TLS1_2_VERSION);
        assert(SSL_CTX_get_verify_mode(f.g->ctx)==(mode("insecure")?SSL_VERIFY_NONE:SSL_VERIFY_PEER));
    }
    assert(rc==atoi(argv[5]));brix_ftp_gss_free(f.g);
    if(f.credential_fd>=0) { assert(fcntl(f.credential_fd,F_GETFD)==-1 && errno==EBADF); }
    printf("%d %d %d %d\n",rc,f.connects,f.writes,f.issued);
    assert(unsetenv("BRIX_CLIENT_GSI_FIXTURE")==0);return 0;
}
