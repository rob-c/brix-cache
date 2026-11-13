/* Packed-block transform I/O against real files, with finite allocation/I/O failures. */
#include "fs/backend/pblock/pblock_xform.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <assert.h>
#include <zstd.h>

typedef struct { ngx_cycle_t cycle;const char *mode;int armed,reads,writes; } fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode,name); }
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size)
{ if(ngx_cycle && state()->armed && mode("allocate")) { state()->armed=0;return NULL; }return __real_malloc(size); }
ssize_t __real_pread64(int,void *,size_t,off_t);
ssize_t __wrap_pread64(int fd,void *bytes,size_t size,off_t offset)
{
    fixture *f=state();if(!f || !f->armed) { return __real_pread64(fd,bytes,size,offset); }f->reads++;
    if(mode("read-error") || (mode("body-error") && offset>=PBLOCK_XFORM_HDR)) { errno=EIO;return -1; }
    if(mode("read-interrupt") && f->reads==1) { errno=EINTR;return -1; }
    if(mode("short-read") && size>2) { size=2; }return __real_pread64(fd,bytes,size,offset);
}
ssize_t __real_write(int,const void *,size_t);
ssize_t __wrap_write(int fd,const void *bytes,size_t size)
{
    fixture *f=state();if(!f || !f->armed) { return __real_write(fd,bytes,size); }f->writes++;
    if(mode("write-error") || (mode("body-write") && f->writes>1)) { errno=ENOSPC;return -1; }
    if(mode("write-interrupt") && f->writes==1) { errno=EINTR;return -1; }
    if(mode("short-write") && size>2) { size=2; }return __real_write(fd,bytes,size);
}
int __real_ftruncate64(int,off_t);
int __wrap_ftruncate64(int fd,off_t length)
{ if(state() && state()->armed && mode("truncate")) { errno=EIO;return -1; }return __real_ftruncate64(fd,length); }
size_t __real_ZSTD_compress(void *,size_t,const void *,size_t,int);
size_t __wrap_ZSTD_compress(void *output,size_t cap,const void *input,size_t length,int level)
{ if(state() && state()->armed && mode("compress")) { return (size_t)-1; }return __real_ZSTD_compress(output,cap,input,length,level); }

int main(int argc,char **argv)
{
    assert(argc==5);fixture f={.mode=argv[2]};ngx_cycle=&f.cycle;
    pblock_xform_t transform={0};int rc,error;uint32_t length=0;unsigned char bytes[64];
    for(size_t i=0;i<sizeof(bytes);i++) { bytes[i]=(unsigned char)(i%7); }
    if(!strcmp(argv[1],"config")) {
        f.armed=1;rc=pblock_xform_config(&transform,!strcmp(argv[3],"<null>")?NULL:argv[3],strlen(argv[3]));
    } else {
        transform.kind=pblock_xform_kind_from_name(argv[3]);memset(transform.key,0x5a,sizeof(transform.key));
        assert(pblock_xform_active(&transform)==(transform.kind!=PBLOCK_XFORM_NONE));
        f.armed=1;
        if(!strcmp(argv[1],"store")) { rc=pblock_xform_block_store(&transform,17,argv[4],bytes,37,sizeof(bytes)); }
        else { rc=pblock_xform_block_load(&transform,17,argv[4],bytes,sizeof(bytes),&length); }
    }
    error=rc<0?errno:0;f.armed=0;
    printf("%d %d %u %d\n",rc,error,length,(int)transform.kind);
    if(!strcmp(argv[1],"load") && !rc) {
        for(size_t i=0;i<sizeof(bytes);i++) { printf("%02x",bytes[i]); }putchar('\n');
    }
    /* Coverage flush allocates after main returns; never retain this stack fixture. */
    ngx_cycle=NULL;
    return 0;
}
