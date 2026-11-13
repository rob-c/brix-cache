/* Real FRM staged handles and online files with deterministic MSS publication outcomes. */
#include "fs/backend/frm/sd_frm_internal.h"
#include "fs/xfer/stage_engine.h"
#include "fs/backend/posix/sd_posix_internal.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    brix_sd_instance_t *instance;
    brix_mss_adapter_t adapter;
    const brix_mss_adapter_t *original;
    void *original_context;
    frm_mss_head_t head;
    const char *mode;
    int armed, allocations, fd, purges, migrates, exchanges, seals, submitted;
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode,name); }
void *__real_calloc(size_t,size_t);
void *__wrap_calloc(size_t count,size_t size)
{
    fixture *f=state();
    if(f && f->armed) {
        f->allocations++;
        if((mode("alloc-state") && f->allocations==1) || (mode("alloc-handle") && f->allocations==2)) { return NULL; }
    }
    return __real_calloc(count,size);
}
ngx_int_t __real_sd_posix_reserve(brix_sd_obj_t *,off_t);
ngx_int_t __wrap_sd_posix_reserve(brix_sd_obj_t *obj,off_t length)
{
    if(mode("no-space") || mode("quota") || mode("advisory")) {
        errno=mode("no-space")?ENOSPC:(mode("quota")?EDQUOT:ENOTSUP);return NGX_ERROR;
    }
    return __real_sd_posix_reserve(obj,length);
}
const char *__wrap_brix_stage_engine_journal_dir(void)
{ return !strncmp(state()->mode,"deferred",8)?"/journal":""; }
int __wrap_brix_stage_on_loop(void) { return 1; }
const char *__wrap_brix_stage_submit(brix_stage_kind_t kind,brix_sd_instance_t *source,
    const char *source_key,brix_sd_instance_t *destination,const char *destination_key,const brix_stage_opts_t *options)
{
    fixture *f=state();assert(kind==BRIX_STAGE_ARCHIVE && source==f->instance && destination==source);
    assert(!strcmp(source_key,"a") && !strcmp(source_key,destination_key) && options->async);
    assert(!strcmp(options->export_root,"/export"));f->submitted++;return mode("deferred-refused")?NULL:"queued";
}
static int create_online(void *context,const char *key,mode_t permissions)
{
    fixture *f=context;assert(f==state());
    if(mode("create-error")) { errno=EACCES;return -1; }
    f->fd=f->original->create_online(f->original_context,key,permissions);return f->fd;
}
static int purge(void *context,const char *key)
{ fixture *f=context;f->purges++;return f->original->purge(f->original_context,key); }
static int migrate(void *context,const char *key)
{
    fixture *f=context;assert(!strcmp(key,f->migrates?"b":"a"));f->migrates++;
    if(mode("migrate-first") || mode("first-no-errno") || (mode("migrate-second") && f->migrates==2)) {
        errno=mode("first-no-errno")?0:ENOSPC;return -1;
    }
    if(!strncmp(f->mode,"deferred",8) || mode("inline-seal") || mode("seal-error")) { return BRIX_MSS_MIGRATE_DEFERRED; }
    return 0;
}
static int exchange(void *context,const char *a,const char *b)
{
    fixture *f=context;f->exchanges++;
    if(mode("exchange-error")) { errno=EACCES;return -1; }
    return frm_mss_exchange(&f->head,a,b);
}
static int seal(void *context,const char *key)
{ fixture *f=context;assert(!strcmp(key,"a"));f->seals++;if(mode("seal-error")) { errno=EIO;return -1; }return 0; }
static int residency(void *context,const char *key,off_t *size,time_t *stamp)
{ assert(context==state() && !strcmp(key,"a"));*size=3;*stamp=5;return mode("missing")?BRIX_RESIDENCY_ABSENT:BRIX_RESIDENCY_ONLINE; }
static int on_tape(void *context,const char *key)
{ assert(context==state() && !strcmp(key,"a"));return mode("existing"); }

static ngx_int_t staged(fixture *f,int *error)
{
    f->armed=1;brix_sd_staged_t *handle=sd_frm_staged_open(f->instance,"a",0600,3,error);f->armed=0;
    if(!handle) { return NGX_ERROR; }
    assert(sd_frm_staged_write(handle,"new",3,0)==3);
    brix_sd_precond_t pre={.kind=BRIX_SD_PRECOND_MATCH_META,.size=3,.mtime=5};
    if(mode("mismatch")) { pre.size=4; }
    if(mode("existing") || mode("absent")) { pre.kind=BRIX_SD_PRECOND_ABSENT; }
    ngx_int_t rc=sd_frm_staged_commit(handle,&pre);*error=rc==NGX_OK?0:errno;
    assert(!pre.atomic);
    if(rc!=NGX_OK) { sd_frm_staged_abort(handle); }
    return rc;
}
int main(int argc,char **argv)
{
    assert(argc==4);fixture f={.mode=argv[2],.fd=-1};ngx_cycle=&f.cycle;f.cycle.log=&f.log;
    ngx_open_file_t log_file={.fd=STDERR_FILENO};f.log=(ngx_log_t){.file=&log_file};ngx_time_init();assert(ngx_strerror_init()==NGX_OK);
    snprintf(f.head.base,sizeof(f.head.base),"%s",argv[3]);
    f.instance=brix_sd_frm_create("stub",argv[3],&f.log);assert(f.instance);
    sd_frm_state *storage=f.instance->state;f.original=storage->mss;f.original_context=storage->mss_ctx;
    f.adapter=*storage->mss;f.adapter.create_online=create_online;f.adapter.purge=purge;
    f.adapter.migrate=migrate;f.adapter.exchange=mode("unsupported")?NULL:exchange;
    f.adapter.seal=mode("unsupported")?NULL:seal;f.adapter.residency=residency;f.adapter.on_tape=on_tape;
    storage->mss=&f.adapter;storage->mss_ctx=&f;brix_sd_frm_set_export_root(f.instance,"/export");
    int error=0;ngx_int_t rc;
    if(!strcmp(argv[1],"exchange")) { errno=0;rc=sd_frm_exchange(f.instance,"a","b");error=rc==NGX_OK?0:errno; }
    else if(!strcmp(argv[1],"seal")) { rc=brix_sd_frm_seal(mode("invalid")?NULL:f.instance,mode("null-key")?NULL:"a");error=rc==NGX_OK?0:errno; }
    else { rc=staged(&f,&error); }
    if(f.fd>=0) { assert(fcntl(f.fd,F_GETFD)==-1 && errno==EBADF); }
    printf("%ld %d %d %d %d %d %d\n",(long)rc,error,f.purges,f.migrates,f.exchanges,f.seals,f.submitted);
    storage->mss=f.original;storage->mss_ctx=f.original_context;brix_sd_frm_destroy(f.instance);
    ngx_cycle=NULL;return 0;
}
