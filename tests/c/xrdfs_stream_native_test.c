/* CLI stream algorithms keep their real parsing, pumps, sinks and formatting. */
#include "apps/fs/xrdfs_internal.h"
#include "fs/vfs.h"
#include <assert.h>

typedef struct {
    brix_conn connection;
    const char *mode, *text;
    size_t length;
    int opens, closes, reads, stats, sleeps, reconnects, allocations, armed;
    int slurps, checksums;
    uint64_t now;
    brix_vfs_file local;
    int local_opens, local_closes, commits, aborts, pipe_reads, pipe_writes, flags, uring;
    size_t transferred, pipe_offset;
    uint8_t delivered[512];
} fixture;
static fixture *state(void)
{
    const char *value=getenv("BRIX_STREAM_TEST_STATE");
    return value?(fixture *)(uintptr_t)strtoull(value,NULL,16):NULL;
}
static int mode(const char *name) { return !strcmp(state()->mode,name); }
static int failure(brix_status *st)
{ brix_status_set(st,XRDC_EIO,EIO,"finite remote failure");return -1; }

int __wrap_brix_rfile_open_read(brix_conn *c,const char *path,const char *opaque,
    int pgrw,int window,brix_rfile *file,brix_status *st)
{
    fixture *f=state();assert(c==(void *)f && path[0]=='/' && !pgrw && window==-1);f->opens++;
    if(opaque) { assert(!strcmp(opaque,"xrootd.compress=zstd")); }
    if(mode("open-error") || (mode("reopen-error") && f->opens>1)) { return failure(st); }
    memset(file,0,sizeof(*file));file->c=c;snprintf(file->path,sizeof(file->path),"%s",path);f->armed=1;return 0;
}
int __wrap_brix_rfile_close(brix_rfile *file,brix_status *st)
{ assert(file->c==(void *)state());(void)st;state()->closes++;return 0; }
ssize_t __wrap_brix_rfile_pread(brix_rfile *file,int64_t offset,void *bytes,size_t length,brix_status *st)
{
    fixture *f=state();assert(file->c==(void *)f && offset>=0);f->reads++;
    if(mode("read-error")) { return failure(st); }
    if(mode("empty") || ((mode("replaced") || mode("reopen-error")) && f->reads==1)) { return 0; }
    size_t n=(uint64_t)offset>=f->length?0:f->length-(size_t)offset;
    if(n>length) { n=length; }
    if(mode("fragmented") && n>2) { n=2; }
    memcpy(bytes,f->text+offset,n);return (ssize_t)n;
}
int __wrap_brix_rfile_drain_to_fd(brix_rfile *file,int64_t offset,int64_t limit,
    size_t chunk,int fd,int64_t *moved,brix_status *st)
{
    fixture *f=state();assert(file->c==(void *)f && !chunk && fd==1 && !moved);
    if(mode("drain-error")) { return failure(st); }
    size_t n=(uint64_t)offset>=f->length?0:f->length-(size_t)offset;
    if(limit>=0 && (uint64_t)limit<n) { n=(size_t)limit; }
    assert(fwrite(f->text+offset,1,n,stdout)==n);return 0;
}
int __wrap_brix_stat(brix_conn *c,const char *path,brix_statinfo *info,brix_status *st)
{
    fixture *f=state();assert(c==(void *)f && path[0]=='/');f->stats++;
    if(mode("stat-error")) { return failure(st); }
    if(mode("stat-retry") || mode("stat-deadline")) {
        if(f->stats==1 || mode("stat-deadline")) { brix_status_set(st,XRDC_ESOCK,ECONNRESET,"temporary disconnect");return -1; }
    }
    memset(info,0,sizeof(*info));info->size=mode("shrink")?0:(int64_t)f->length;return 0;
}
int __wrap_brix_resilient_window_ms(const brix_conn *c)
{ assert(c==(void *)state());return 1000; }
int __wrap_brix_status_retryable(const brix_status *st)
{ return st->sys_errno==ECONNRESET; }
int __wrap_brix_reconnect_home(brix_conn *c,brix_status *st)
{ assert(c==(void *)state());(void)st;state()->reconnects++;return 0; }
uint64_t __wrap_brix_mono_ns(void)
{ return state()->now+=1000000000ULL; }
int __wrap_nanosleep(const struct timespec *duration,struct timespec *remaining)
{
    fixture *f=state();assert(duration->tv_sec>=0 && !remaining);f->sleeps++;
    if(mode("stat-deadline")) { assert(f->sleeps==1);return 0; }
    if(!mode("stat-retry") || f->sleeps==2) { tail_stop=1; }return 0;
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t length)
{
    fixture *f=state();
    if(f && f->armed && mode("allocate-error")) { f->armed=0;return NULL; }
    return __real_malloc(length);
}
void *__real_realloc(void *,size_t);
void *__wrap_realloc(void *old,size_t length)
{
    fixture *f=state();
    if(f && f->armed && mode("grow-error")) { f->armed=0;return NULL; }
    return __real_realloc(old,length);
}
size_t __real_fwrite(const void *,size_t,size_t,FILE *);
size_t __wrap_fwrite(const void *data,size_t size,size_t count,FILE *stream)
{
    fixture *f=state();
    if(f && f->armed && mode("stdout-error") && stream==stdout) { errno=ENOSPC;return 0; }
    return __real_fwrite(data,size,count,stream);
}
int __real_fflush(FILE *);
int __wrap_fflush(FILE *stream)
{
    fixture *f=state();
    if(f && f->armed && mode("flush-error") && stream==stdout) { errno=ENOSPC;return EOF; }
    return __real_fflush(stream);
}
int __wrap_brix_query_cksum(brix_conn *c,const char *path,const char *algorithm,
    char *out,size_t capacity,brix_status *st)
{
    fixture *f=state();assert(c==(void *)f && path[0]=='/' && !strcmp(algorithm,"adler32"));f->checksums++;
    if(!strncmp(f->mode,"checksum",8)) {
        snprintf(out,capacity,"%d",mode("checksum-different")?f->checksums:1);return 0;
    }
    return failure(st);
}
int __wrap_brix_rfile_slurp(brix_conn *c,const char *path,const char *opaque,
    int64_t limit,uint8_t **bytes,int64_t *length,brix_status *st)
{
    fixture *f=state();assert(c==(void *)f && path[0]=='/' && !opaque && limit==-1);f->slurps++;
    if(mode("slurp-first") || (mode("slurp-second") && f->slurps==2)) { return failure(st); }
    *length=(int64_t)f->length;
    if(mode("different-size") && f->slurps==2) { (*length)--; }
    *bytes=malloc(f->length+1);assert(*bytes);memcpy(*bytes,f->text,f->length);
    if(mode("different-byte") && f->slurps==2) { (*bytes)[2]^=1; }return 0;
}
int __wrap_brix_report_err(FILE *stream,const char *tool,const char *verb,const char *path,
    const brix_status *st,int writing,const brix_url *url)
{ (void)writing;(void)url;assert(stream==stderr && !strcmp(tool,"xrdfs") && verb && path && st->kxr);return 52; }
void __wrap_rate_pace(const struct timespec *start,int64_t sent,double rate)
{ assert(start && sent>=0 && rate>=0); }

int __wrap_brix_rfile_open_write(brix_conn *c,const char *path,int force,int posc,
    int pgrw,int window,brix_rfile *file,brix_status *st)
{
    assert(force==0 || force==1);assert(!posc);state()->flags=force;
    return __wrap_brix_rfile_open_read(c,path,NULL,pgrw,window,file,st);
}
static int deliver(int64_t offset,const void *bytes,size_t length,brix_status *st,const char *error)
{
    fixture *f=state();assert(offset==(int64_t)f->transferred && f->transferred+length<=sizeof(f->delivered));
    if(mode(error)) { return failure(st); }
    memcpy(f->delivered+f->transferred,bytes,length);f->transferred+=length;return 0;
}
int __wrap_brix_rfile_pwrite(brix_rfile *file,int64_t offset,const void *bytes,size_t length,brix_status *st)
{ assert(file->c==(void *)state());return deliver(offset,bytes,length,st,"remote-write"); }
int __wrap_brix_vfs_open(const char *url,int flags,const brix_vfs_open_opts *options,brix_vfs_file **out,brix_status *st)
{
    fixture *f=state();assert(url && options->expected_size==-1 && !options->cred);f->local_opens++;
    f->flags=flags;f->uring=options->io_uring;
    if(mode("local-open")) { return failure(st); }*out=&f->local;return 0;
}
void __wrap_brix_vfs_close(brix_vfs_file *file)
{ assert(file==&state()->local);state()->local_closes++; }
void __wrap_brix_vfs_abort(brix_vfs_file *file)
{ assert(file==&state()->local);state()->aborts++; }
int __wrap_brix_vfs_commit(brix_vfs_file *file,brix_status *st)
{ assert(file==&state()->local);state()->commits++;return mode("commit-error")?failure(st):0; }
ssize_t __wrap_brix_vfs_pread(brix_vfs_file *file,int64_t offset,void *bytes,size_t length,brix_status *st)
{
    assert(file==&state()->local);brix_rfile remote={.c=(void *)state()};
    return __wrap_brix_rfile_pread(&remote,offset,bytes,length,st);
}
int __wrap_brix_vfs_pwrite(brix_vfs_file *file,int64_t offset,const void *bytes,size_t length,brix_status *st)
{ assert(file==&state()->local);return deliver(offset,bytes,length,st,"local-write"); }
ssize_t __real_read(int,void *,size_t);
ssize_t __wrap_read(int fd,void *bytes,size_t length)
{
    fixture *f=state();if(!f || fd!=0) { return __real_read(fd,bytes,length); }f->pipe_reads++;
    if(mode("pipe-interrupt") && f->pipe_reads==1) { errno=EINTR;return -1; }
    if(mode("pipe-error")) { errno=EIO;return -1; }
    brix_rfile remote={.c=(void *)f};brix_status st;
    ssize_t n=__wrap_brix_rfile_pread(&remote,(int64_t)f->pipe_offset,bytes,length,&st);
    assert(n>=0);f->pipe_offset+=(size_t)n;return n;
}
ssize_t __real_write(int,const void *,size_t);
ssize_t __wrap_write(int fd,const void *bytes,size_t length)
{
    fixture *f=state();if(!f || fd!=1) { return __real_write(fd,bytes,length); }f->pipe_writes++;
    if(mode("pipe-interrupt") && f->pipe_writes==1) { errno=EINTR;return -1; }
    if(mode("pipe-error")) { errno=EPIPE;return -1; }
    if(mode("pipe-zero")) { return 0; }
    if(mode("pipe-short") && length>2) { length=2; }
    return __real_write(fd,bytes,length);
}

static int invoke(int argc,char **argv,fixture *f)
{
    brix_conn *c=(void *)f;const char *op=argv[0];
    if(!strcmp(op,"cat")) { return do_cat(c,"/base",argc,argv); }
    if(!strcmp(op,"head")) { return do_head(c,"/base",argc,argv); }
    if(!strcmp(op,"tail")) { return do_tail(c,"/base",argc,argv); }
    if(!strcmp(op,"grep")) { return do_grep(c,"/base",argc,argv); }
    if(!strcmp(op,"hexdump")) { return do_hexdump(c,"/base",argc,argv); }
    if(!strcmp(op,"dd")) { return do_dd(c,"/base",argc,argv); }
    if(!strcmp(op,"cmp")) { return do_cmp(c,"/base",argc,argv); }
    if(!strcmp(op,"upload")) { return do_upload(c,"/base",argc,argv); }
    if(!strcmp(op,"download")) { return do_download(c,"/base",argc,argv); }
    brix_status st;brix_status_clear(&st);assert(!strcmp(op,"follow"));
    return tail_follow(c,"/base/file",mode("shrink")?5:0,0.001,&st);
}
int main(int argc,char **argv)
{
    assert(argc>=4);fixture f={.mode=argv[1],.text=argv[2]};f.length=strlen(f.text);
    char pointer[32];snprintf(pointer,sizeof(pointer),"%llx",(unsigned long long)(uintptr_t)&f);
    assert(setenv("BRIX_STREAM_TEST_STATE",pointer,1)==0);
    int rc=invoke(argc-3,argv+3,&f);f.armed=0;
    fprintf(stderr,"RESULT %d %d %d %d %d %d %d %d %d %d %d %zu %d %d\n",rc,f.opens,f.closes,
        f.reads,f.stats,f.reconnects,f.slurps,f.local_opens,f.local_closes,f.commits,f.aborts,f.transferred,f.flags,f.uring);
    assert(f.closes<=f.opens && f.opens-f.closes<=1);
    assert(f.local_closes<=f.local_opens && f.local_opens-f.local_closes<=1);
    if(!rc && f.transferred) { assert(f.transferred==f.length && !memcmp(f.delivered,f.text,f.length)); }
    unsetenv("BRIX_STREAM_TEST_STATE");return 0;
}
