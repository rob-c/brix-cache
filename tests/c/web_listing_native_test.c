/* Listing request policy and hostile page boundaries over a finite HTTP provider. */
#include "brix.h"
#include "core/compat/uri.h"
#include "core/compat/crypto.h"
#include <assert.h>
#include <stdlib.h>

typedef struct {
    const char *mode,*operation;
    char *page;
    int armed,calls,freed,strings,status;
} fixture;
static fixture *state(void)
{ const char *p=getenv("BRIX_WEB_LIST_FIXTURE");return p?(fixture *)(uintptr_t)strtoull(p,NULL,16):NULL; }
static int mode(const char *s) { return state() && state()->armed && !strcmp(state()->mode,s); }
void *__real_realloc(void *,size_t);
void *__wrap_realloc(void *p,size_t n) { return mode("array-oom")?NULL:__real_realloc(p,n); }
char *__real_strdup(const char *);
char *__wrap_strdup(const char *s)
{
    if(state() && state()->armed) { state()->strings++; }
    if(mode("item-oom") || (mode("second-item-oom") && state()->strings==2)) { return NULL; }
    return __real_strdup(s);
}
ssize_t __real_brix_http_urlencode(const unsigned char *,size_t,char *,size_t,const char *);
ssize_t __wrap_brix_http_urlencode(const unsigned char *p,size_t n,char *out,size_t cap,const char *safe)
{ return mode("encode-error")?-1:__real_brix_http_urlencode(p,n,out,cap,safe); }
int __real_brix_s3_sign_v4_q(const char *,const char *,const char *,const char *,const char *,const char *,const char *,const char *,char *,size_t);
int __wrap_brix_s3_sign_v4_q(const char *m,const char *host,const char *uri,const char *query,const char *ak,const char *sk,const char *region,const char *hash,char *headers,size_t cap)
{
    assert(!strcmp(ak,"test-access") && !strcmp(sk,"test-secret"));
    return mode("sign-error")?-1:__real_brix_s3_sign_v4_q(m,host,uri,query,ak,sk,region,hash,headers,cap);
}
int __wrap_brix_http_req(const char *host,int port,int tls,const char *method,const char *path,
    const char *headers,const void *body,size_t blen,int timeout,int verify,const char *ca,const char *cert,
    brix_http_resp *response,brix_status *status)
{
    fixture *f=state();f->calls++;
    assert(!strcmp(host,"origin.test") && port==8443 && tls==1 && !body && !blen && timeout==60000 && verify==1);
    assert(ca && !strcmp(ca,"fixture-ca"));
    if(!strcmp(f->operation,"s3")) {
        assert(!strcmp(method,"GET") && !cert);
        if(!mode("unsigned") && !mode("runaway")) { assert(headers && strstr(headers,"AWS4-HMAC-SHA256")); }
    } else {
        assert(cert && !strcmp(cert,"fixture-identity"));
        if(!mode("anonymous")) { assert(headers && strstr(headers,"Authorization: Bearer fixture-token\r\n")); }
        if(!strcmp(f->operation,"dav")) { assert(!strcmp(method,"PROPFIND") && strstr(headers,"Depth: infinity\r\n")); }
    }
    if(f->calls<=2) { printf("REQUEST %s %s\n",method,path); }
    if(mode("transport") || (mode("second-transport") && f->calls==2)) {
        brix_status_set(status,XRDC_ESOCK,0,"provider unavailable");return -1;
    }
    memset(response,0,sizeof(*response));response->status=f->status;
    if(!mode("null-body")) {
        char *next=strstr(f->page,"\n<page-break/>\n");
        if(next) { *next=0; }
        response->body=__real_strdup(f->page);assert(response->body);
        if(next) { f->page=next+strlen("\n<page-break/>\n"); }
    }
    return 0;
}
void __real_brix_http_resp_free(brix_http_resp *);
void __wrap_brix_http_resp_free(brix_http_resp *response)
{ state()->freed++;__real_brix_http_resp_free(response); }
int main(int argc,char **argv)
{
    assert(argc==6);fixture f={.mode=argv[2],.operation=argv[1],.status=atoi(argv[5])};char address[32];
    snprintf(address,sizeof(address),"%llx",(unsigned long long)(uintptr_t)&f);
    assert(setenv("BRIX_WEB_LIST_FIXTURE",address,1)==0);
    assert(brix_crypto_init());
    FILE *input=fopen(argv[4],"rb");assert(input && !fseek(input,0,SEEK_END));long size=ftell(input);assert(size>=0);
    rewind(input);char *pages=malloc((size_t)size+1);assert(pages && fread(pages,1,(size_t)size,input)==(size_t)size);
    pages[size]=0;fclose(input);f.page=pages;
    brix_weburl url={.port=8443,.tls=1};strcpy(url.host,"origin.test");assert(strlen(argv[3])<sizeof(url.path));strcpy(url.path,argv[3]);
    char **items=NULL;size_t count=0;brix_status status={0};int rc;f.armed=1;
    const char *token=mode("anonymous")?NULL:"fixture-token";
    if(!strcmp(f.operation,"s3")) {
        int sign=!(mode("unsigned") || mode("runaway"));url.is_s3=1;
        rc=brix_s3_list(&url,sign?"test-access":NULL,sign?"test-secret":NULL,NULL,1,"fixture-ca",&items,&count,&status);
    } else if(!strcmp(f.operation,"dav")) {
        url.is_s3=mode("wrong-protocol");
        rc=brix_webdav_list(&url,token,1,"fixture-ca","fixture-identity",&items,&count,&status);
    } else if(!strcmp(f.operation,"mkcol")) {
        rc=brix_webdav_mkcol(&url,url.path,token,1,"fixture-ca","fixture-identity",&status);
    } else if(!strcmp(f.operation,"delete")) {
        rc=brix_webdav_delete(&url,url.path,token,1,"fixture-ca","fixture-identity",&status);
    } else {
        rc=brix_webdav_move(&url,url.path,"https://origin.test:8443/destination",token,1,"fixture-ca","fixture-identity",&status);
    }
    f.armed=0;if(rc<0) { assert(!items && !count); }
    printf("RESULT %d %d %d %d %zu\n",rc,status.kxr,f.calls,f.freed,count);
    for(size_t i=0;i<count;i++) { printf("ITEM %s\n",items[i]); }
    brix_strv_free(items,count);brix_strv_free(NULL,0);free(pages);brix_crypto_cleanup();
    assert(unsetenv("BRIX_WEB_LIST_FIXTURE")==0);return 0;
}
