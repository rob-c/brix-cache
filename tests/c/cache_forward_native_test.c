/* Cache decorators preserve source outcomes, caller identity and eviction scope. */
#include "fs/backend/cache/sd_cache_internal.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    sd_cache_inst_state cache;
    brix_sd_instance_t outer, source;
    brix_sd_driver_t driver;
    brix_sd_cred_t credential;
    brix_sd_staged_t staged;
    brix_sd_dir_t directory;
    const char *operation, *mode;
    int calls, credentials, evictions;
    char keys[64];
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode,name); }
static void source_call(brix_sd_instance_t *source,const brix_sd_cred_t *credential)
{
    fixture *f=state();assert(source==&f->source);f->calls++;
    if(credential) { assert(credential==&f->credential);f->credentials++; }
}
ngx_int_t __wrap_brix_cstore_evict(brix_cstore_t *store,const char *key)
{
    fixture *f=state();assert(store==&f->cache.cstore);
    assert(f->calls || !strcmp(f->operation,"staged"));
    assert(strlen(f->keys)+strlen(key)<sizeof(f->keys));strcat(f->keys,key);f->evictions++;return NGX_OK;
}
static ngx_int_t unlink_batch_cred(brix_sd_instance_t *source,brix_sd_unlink_batch_t *batch,const brix_sd_cred_t *credential)
{
    source_call(source,credential);assert(batch->n==3 && !strcmp(batch->paths[0],"/a"));
    batch->done=mode("partial")?2:batch->n;
    for(size_t i=0;i<batch->done;i++) { batch->errs[i]=(mode("partial") && i==1)?EACCES:0; }
    if(mode("partial")) { errno=EIO;return NGX_ERROR; }return NGX_OK;
}
static ngx_int_t unlink_batch(brix_sd_instance_t *source,brix_sd_unlink_batch_t *batch)
{ return unlink_batch_cred(source,batch,NULL); }
static ngx_int_t sync_publish(brix_sd_instance_t *source,const char *path)
{ source_call(source,NULL);assert(!strcmp(path,"/a"));if(mode("partial")) { errno=EIO;return NGX_ERROR; }return NGX_OK; }
static brix_sd_staged_t *staged_cred(brix_sd_instance_t *source,const char *path,
    mode_t permissions,off_t size,const brix_sd_cred_t *credential,int *error)
{
    fixture *f=state();source_call(source,credential);assert(!strcmp(path,"/a") && permissions==0600 && size==19);
    assert(f->evictions==1);
    if(mode("partial")) { *error=EIO;return NULL; }f->staged.inst=source;return &f->staged;
}
static brix_sd_staged_t *staged(brix_sd_instance_t *source,const char *path,mode_t permissions,off_t size,int *error)
{ return staged_cred(source,path,permissions,size,NULL,error); }
static ngx_int_t unlink_one(brix_sd_instance_t *source,const char *path,int directory)
{ assert(!strcmp(path,"/a") && directory==1);return sync_publish(source,path); }
static ngx_int_t rename_one(brix_sd_instance_t *source,const char *from,const char *to,int noreplace)
{ assert(!strcmp(from,"/a") && !strcmp(to,"/b") && noreplace);return sync_publish(source,from); }
static brix_sd_dir_t *opendir_one(brix_sd_instance_t *source,const char *path,int *error)
{
    if(sync_publish(source,path)!=NGX_OK) { *error=EIO;return NULL; }
    state()->directory.inst=source;return &state()->directory;
}
static ngx_int_t reserve(fixture *f)
{ brix_sd_obj_t obj={.inst=&f->outer};return sd_cache_reserve(&obj,19); }
static ngx_int_t execute(fixture *f,const brix_sd_cred_t *credential,int *error)
{
    if(!strcmp(f->operation,"batch")) {
        const char *paths[]={"/a","/b","/c"};int errors[3]={99,99,99};
        brix_sd_unlink_batch_t batch={.paths=paths,.n=3,.errs=errors};
        ngx_int_t rc=credential?sd_cache_unlink_many_cred(&f->outer,&batch,credential):sd_cache_unlink_many(&f->outer,&batch);
        if(f->calls) { assert(batch.done==(mode("partial")?2:3)); }
        if(mode("partial")) { assert(errors[2]==99); }return rc;
    }
    if(!strcmp(f->operation,"staged")) {
        brix_sd_staged_t *handle=credential?sd_cache_staged_open_cred(&f->outer,"/a",0600,19,credential,error):sd_cache_staged_open(&f->outer,"/a",0600,19,error);
        if(handle) { assert(handle==&f->staged && handle->inst==&f->source); }return handle?NGX_OK:NGX_ERROR;
    }
    if(!strcmp(f->operation,"sync")) { return sd_cache_sync_publish(&f->outer,"/a"); }
    if(!strcmp(f->operation,"reserve")) { return reserve(f); }
    if(!strcmp(f->operation,"unlink")) { return sd_cache_unlink(&f->outer,"/a",1); }
    if(!strcmp(f->operation,"rename")) { return sd_cache_rename(&f->outer,"/a","/b",1); }
    assert(!strcmp(f->operation,"opendir"));
    brix_sd_dir_t *dir=sd_cache_opendir(&f->outer,"/a",error);
    if(dir) { assert(dir==&f->directory && dir->inst==&f->source); }return dir?NGX_OK:NGX_ERROR;
}
int main(int argc,char **argv)
{
    assert(argc==4);fixture f={0};ngx_cycle=&f.cycle;f.operation=argv[1];f.mode=argv[2];
    f.outer.state=&f.cache;f.cache.source=&f.source;f.source.driver=&f.driver;
    f.credential.fallback_deny=mode("denied");
    if(!mode("absent")) {
        f.driver.unlink_many=unlink_batch;f.driver.staged_open=staged;f.driver.sync_publish=sync_publish;
        f.driver.unlink=unlink_one;f.driver.rename=rename_one;f.driver.opendir=opendir_one;
        if(!mode("fallback") && !mode("denied")) { f.driver.unlink_many_cred=unlink_batch_cred;f.driver.staged_open_cred=staged_cred; }
    }
    int error=0;errno=0;ngx_int_t rc=execute(&f,atoi(argv[3])?&f.credential:NULL,&error);
    if(!error && rc!=NGX_OK) { error=errno; }
    printf("%ld %d %d %d %d %s\n",(long)rc,error,f.calls,f.credentials,f.evictions,f.keys[0]?f.keys:"-");return 0;
}
