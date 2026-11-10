/* Local proxy inspection and destruction over real private credential files. */
#include "brix.h"
#include <openssl/pem.h>
#include <pwd.h>
#include <assert.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>

typedef struct { const char *mode,*path,*root;struct passwd user;int armed,writes; } fixture;
static fixture *state(void)
{ const char *p=getenv("BRIX_PROXY_LIFETIME_FIXTURE");return p?(fixture *)(uintptr_t)strtoull(p,NULL,16):NULL; }
static int mode(const char *s) { return state() && state()->armed && !strcmp(state()->mode,s); }
struct passwd *__wrap_getpwuid(uid_t uid)
{ assert(uid==geteuid());state()->user.pw_dir=(char *)state()->root;return &state()->user; }
int __real_ASN1_TIME_diff(int *,int *,const ASN1_TIME *,const ASN1_TIME *);
int __wrap_ASN1_TIME_diff(int *days,int *seconds,const ASN1_TIME *from,const ASN1_TIME *to)
{
    if(mode("invalid-time")) { return 0; }
    if(mode("expired")) { *days=-1;*seconds=-17;return 1; }
    return __real_ASN1_TIME_diff(days,seconds,from,to);
}
ssize_t __real_write(int,const void *,size_t);
ssize_t __wrap_write(int fd,const void *p,size_t n)
{
    fixture *f=state();
    if(f && f->armed && fd>2) {
        f->writes++;const unsigned char *bytes=p;for(size_t i=0;i<n;i++) { assert(!bytes[i]); }
        if(mode("write-error")) { errno=EIO;return -1; }
        if(mode("write-zero")) { return 0; }
        if(mode("short-write") && n>17) { n=17; }
    }
    return __real_write(fd,p,n);
}
int __real_unlink(const char *);
int __wrap_unlink(const char *path)
{ if(mode("unlink-error")) { errno=EACCES;return -1; }return __real_unlink(path); }
static void inspect(const char *operation,const char *path,brix_status *status)
{
    long left=7654321;int rc;
    if(!strcmp(operation,"remaining")) {
        rc=brix_proxy_remaining(path,mode("null-output")?NULL:&left);
        if(rc) { assert(left==7654321); }
        printf("RESULT %d %ld\n",rc,left);
    } else {
        FILE *out=tmpfile();assert(out);rc=brix_proxy_info(path,out,status);
        assert(!fflush(out) && !fseek(out,0,SEEK_SET));char text[4096]={0};
        size_t n=fread(text,1,sizeof(text)-1,out);assert(!ferror(out));fclose(out);
        if(rc) { assert(!n); }
        else { assert(strstr(text,"subject  :") && strstr(text,"issuer   :")); }
        printf("RESULT %d %d\n%s",rc,status->kxr,text);
    }
}
static void destroy(const char *path,brix_status *status)
{
    fixture *f=state();int fd=open(f->path,O_RDONLY);struct stat sb;
    assert(fd>=0 && !fstat(fd,&sb));int rc=brix_proxy_destroy(path,status);
    int exists=access(f->path,F_OK)==0;
    if(!rc && !mode("write-error") && !mode("write-zero")) {
        unsigned char bytes[4096];ssize_t n;
        while((n=read(fd,bytes,sizeof(bytes)))>0) { for(ssize_t i=0;i<n;i++) { assert(!bytes[i]); } }
        assert(n==0);
    }
    close(fd);printf("RESULT %d %d %d %d\n",rc,status->kxr,exists,f->writes);
}
int main(int argc,char **argv)
{
    assert(argc==5);fixture f={.mode=argv[2],.path=argv[3],.root=argv[4]};char address[32];
    snprintf(address,sizeof(address),"%llx",(unsigned long long)(uintptr_t)&f);
    assert(!setenv("BRIX_PROXY_LIFETIME_FIXTURE",address,1));
    assert(!setenv("X509_USER_PROXY",f.path,1));brix_status status={0};f.armed=1;
    const char *path=mode("default")?NULL:f.path;
    if(!strcmp(argv[1],"remaining") || !strcmp(argv[1],"info")) { inspect(argv[1],path,&status); }
    else if(!strcmp(argv[1],"destroy")) { destroy(path,&status); }
    else if(!strcmp(argv[1],"missing-destroy")) { printf("RESULT %d\n",brix_proxy_destroy(path,&status)); }
    else if(!strcmp(argv[1],"default-path")) {
        if(mode("unset")) { unsetenv("X509_USER_PROXY"); }
        char out[1024];brix_proxy_default_path(out,sizeof(out));puts(out);
    } else {
        brix_proxy_opts options={0};options.out_path=f.path;options.bits=1024;
        if(mode("environment")) {
            char cert[4096],key[4096];snprintf(cert,sizeof(cert),"%s/.globus/usercert.pem",f.root);
            snprintf(key,sizeof(key),"%s/.globus/userkey.pem",f.root);
            assert(!setenv("X509_USER_CERT",cert,1) && !setenv("X509_USER_KEY",key,1));
        } else { unsetenv("X509_USER_CERT");unsetenv("X509_USER_KEY"); }
        int rc=brix_proxy_create(mode("null-options")?NULL:&options,&status);
        printf("RESULT %d %d\n",rc,status.kxr);
        if(!rc) { struct stat sb;assert(!stat(f.path,&sb) && (sb.st_mode&0777)==0400); }
    }
    f.armed=0;assert(!unsetenv("BRIX_PROXY_LIFETIME_FIXTURE"));return 0;
}
