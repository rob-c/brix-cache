/* Catalog and block faults must not publish partial new objects. */
#include "fs/backend/pblock/sd_pblock_internal.h"
#include "fs/backend/pblock/sd_pblock_catalog_internal.h"
#include "fs/backend/pblock/pblock_refs.h"
#include <assert.h>

typedef struct { ngx_cycle_t cycle;const char *fault;int armed,hits,allocs; } fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int fault(const char *name)
{
    fixture *f=state();if(f && f->armed && !strcmp(f->fault,name)) { f->hits++;errno=EIO;return 1; }return 0;
}
void *__real_calloc(size_t,size_t);
void *__wrap_calloc(size_t n,size_t s)
{
    fixture *f=state();
    if(f && f->armed) {
        f->allocs++;
        if((!strcmp(f->fault,"alloc-first") && f->allocs==1) ||
           (!strcmp(f->fault,"alloc-second") && f->allocs==2)) { f->hits++;errno=ENOMEM;return NULL; }
    }
    return __real_calloc(n,s);
}
int __real_cat_exec(pblock_catalog *,const char *);
int __wrap_cat_exec(pblock_catalog *cat,const char *sql)
{
    if((!strcmp(sql,"BEGIN IMMEDIATE;") && fault("begin")) ||
       (!strcmp(sql,"COMMIT;") && fault("commit"))) { return -1; }
    return __real_cat_exec(cat,sql);
}
int __real_pblock_catalog_lookup(pblock_catalog *,const char *,pblock_meta *);
int __wrap_pblock_catalog_lookup(pblock_catalog *cat,const char *path,pblock_meta *meta)
{
    if((!strcmp(path,"/target") && fault("lookup-target")) ||
       (!strcmp(path,"/source") && fault("lookup-source"))) { return -1; }
    return __real_pblock_catalog_lookup(cat,path,meta);
}
int __real_pblock_catalog_put(pblock_catalog *,const char *,const pblock_meta *);
int __wrap_pblock_catalog_put(pblock_catalog *cat,const char *path,const pblock_meta *meta)
{ return fault("put")?-1:__real_pblock_catalog_put(cat,path,meta); }
int __real_pblock_gen_blob_id(char *);
int __wrap_pblock_gen_blob_id(char *id) { return fault("blob-id")?-1:__real_pblock_gen_blob_id(id); }
int __real_pblock_ensure_obj_dir(const pblock_state_t *,const char *);
int __wrap_pblock_ensure_obj_dir(const pblock_state_t *st,const char *id)
{ return fault("object-dir")?-1:__real_pblock_ensure_obj_dir(st,id); }
int __real_pblock_block_path(const pblock_state_t *,const char *,int64_t,char *,size_t);
int __wrap_pblock_block_path(const pblock_state_t *st,const char *id,int64_t block,char *out,size_t cap)
{ return fault("block-path")?-1:__real_pblock_block_path(st,id,block,out,cap); }
ssize_t __real_pblock_copy_one_block(const char *,const char *);
ssize_t __wrap_pblock_copy_one_block(const char *src,const char *dst)
{ return fault("copy-block")?-1:__real_pblock_copy_one_block(src,dst); }
int __real_pblock_refs_bump(const pblock_state_t *,const char *,int64_t,int64_t);
int __wrap_pblock_refs_bump(const pblock_state_t *st,const char *id,int64_t size,int64_t block)
{ return fault("refs-bump")?-1:__real_pblock_refs_bump(st,id,size,block); }
int __real_pblock_catalog_child_count(pblock_catalog *,const char *);
int __wrap_pblock_catalog_child_count(pblock_catalog *cat,const char *path)
{ return fault("child-count")?-1:__real_pblock_catalog_child_count(cat,path); }
int __real_pblock_catalog_remove(pblock_catalog *,const char *);
int __wrap_pblock_catalog_remove(pblock_catalog *cat,const char *path)
{ return fault("remove")?-1:__real_pblock_catalog_remove(cat,path); }
int __real_pblock_catalog_rename(pblock_catalog *,const char *,const char *);
int __wrap_pblock_catalog_rename(pblock_catalog *cat,const char *src,const char *dst)
{ return fault("rename")?-1:__real_pblock_catalog_rename(cat,src,dst); }
static void publish(brix_sd_instance_t *inst,const char *path,const char *data)
{
    brix_sd_staged_t *s=inst->driver->staged_open(inst,path,0600,0,NULL);assert(s);
    assert(inst->driver->staged_write(s,data,strlen(data),0)==(ssize_t)strlen(data));
    assert(inst->driver->staged_commit(s,NULL)==NGX_OK);
}
static void check_bytes(brix_sd_instance_t *inst,const char *path,const char *data)
{
    brix_sd_obj_t *obj=inst->driver->open(inst,path,BRIX_SD_O_READ,0,NULL);assert(obj);
    char bytes[32]={0};assert(inst->driver->pread(obj,bytes,sizeof(bytes),0)==(ssize_t)strlen(data));
    assert(!memcmp(bytes,data,strlen(data)));assert(inst->driver->close(obj)==NGX_OK);free(obj);
}
static void staged(brix_sd_instance_t *inst,const char *operation)
{
    fixture *f=state();const brix_sd_driver_t *d=inst->driver;int error=0;
    int overwrite=!strcmp(operation,"overwrite");
    if(overwrite) { publish(inst,"/target","original"); }
    f->armed=!strcmp(operation,"open");
    brix_sd_staged_t *s=d->staged_open(inst,"/target",0600,7,&error);
    if(f->armed) { assert(!s && error && f->hits);f->armed=0;return; }
    assert(s);
    if(strcmp(operation,"empty") && strcmp(operation,"path")) { assert(d->staged_write(s,"payload",7,0)==7); }
    f->armed=1;
    if(!strcmp(operation,"path")) { assert(!d->staged_path(s)); }
    else { assert(d->staged_commit(s,NULL)==NGX_ERROR); }
    assert(f->hits);f->armed=0;brix_sd_stat_t meta;
    if(overwrite) { check_bytes(inst,"/target","original"); }
    else { assert(d->stat(inst,"/target",&meta)==NGX_ERROR && errno==ENOENT); }
    d->staged_abort(s);
    assert(((pblock_state_t *)inst->state)->open_files==0);
    /* Rollback must leave the connection usable for a subsequent publish. */
    publish(inst,"/target","recovered");check_bytes(inst,"/target","recovered");
}
static void copying(brix_sd_instance_t *inst)
{
    fixture *f=state();publish(inst,"/source","source-bytes");off_t bytes=-1;f->armed=1;
    assert(inst->driver->server_copy(inst,"/source","/target",&bytes)==NGX_ERROR);
    assert(f->hits && bytes==-1);f->armed=0;brix_sd_stat_t meta;
    assert(inst->driver->stat(inst,"/target",&meta)==NGX_ERROR && errno==ENOENT);
    check_bytes(inst,"/source","source-bytes");
    assert(inst->driver->server_copy(inst,"/source","/target",&bytes)==NGX_OK && bytes==12);
    check_bytes(inst,"/target","source-bytes");check_bytes(inst,"/source","source-bytes");
}
static void names(brix_sd_instance_t *inst,const char *operation)
{
    fixture *f=state();const brix_sd_driver_t *d=inst->driver;assert(d->mkdir(inst,"/source",0700)==NGX_OK);
    assert(d->mkdir(inst,"/target",0700)==NGX_OK);f->armed=1;brix_sd_stat_t st;int rc;
    if(!strcmp(operation,"stat")) { rc=d->stat(inst,"/source",&st); }
    else if(!strcmp(operation,"unlink")) { rc=d->unlink(inst,"/source",1); }
    else if(!strcmp(operation,"opendir")) {
        int err=0;brix_sd_dir_t *dir=d->opendir(inst,"/source",&err);assert(!dir && err);rc=NGX_ERROR;
    } else { rc=d->rename(inst,"/source","/target",0); }
    assert(rc==NGX_ERROR && f->hits);f->armed=0;
    assert(d->stat(inst,"/source",&st)==NGX_OK && S_ISDIR(st.mode));
}
/* WHAT: Compare committed and transaction-local metadata views.
 * WHY: A shared cache must neither expose pending writes nor retain old rows
 * after commit; rollback must restore the original visible namespace.
 * HOW: Seed, transact, observe from a second connection, finish and recheck. */
static void transaction(brix_sd_instance_t *inst,const char *root,const char *scenario)
{
    pblock_state_t *store=inst->state;pblock_catalog *writer=store->cat,*reader=NULL;
    pblock_meta before,changed,seen;int create=strstr(scenario,"create")!=NULL;
    int remove=strstr(scenario,"remove")!=NULL;int commit=strncmp(scenario,"commit-",7)==0;
    publish(inst,"/source","source-bytes");assert(!pblock_catalog_lookup(writer,"/source",&before));
    const char *path=create?"/target":"/source";
    if(writer->nsidx) {
        char database[4096];snprintf(database,sizeof(database),"%s/catalog.db",root);
        reader=pblock_catalog_open(database,1000);assert(reader);
        assert(!pblock_catalog_nsidx_arm(reader,root));
        assert(pblock_catalog_lookup(reader,path,&seen)==(create?1:0));
    }
    assert(!cat_exec(writer,"BEGIN IMMEDIATE;"));changed=before;changed.size=99;
    if(remove) { assert(!pblock_catalog_remove(writer,path)); }
    else { assert(!pblock_catalog_put(writer,path,&changed)); }
    assert(pblock_catalog_lookup(writer,path,&seen)==(remove?1:0));
    if(!remove) { assert(seen.size==99); }
    if(reader) {
        assert(pblock_catalog_lookup(reader,path,&seen)==(create?1:0));
        if(!create) { assert(seen.size==12); }
    }
    assert(!cat_exec(writer,commit?"COMMIT;":"ROLLBACK;"));
    int missing=(commit && remove) || (!commit && create);
    int64_t size=commit?99:12;
    assert(pblock_catalog_lookup(writer,path,&seen)==missing);
    if(!missing) { assert(seen.size==size); }
    if(reader) {
        assert(pblock_catalog_lookup(reader,path,&seen)==missing);
        if(!missing) { assert(seen.size==size); }
        pblock_catalog_close(reader);
    }
}
int main(int argc,char **argv)
{
    assert(argc==4);fixture f={.fault=argv[3]};ngx_cycle=&f.cycle;
    brix_sd_instance_t inst={.driver=&brix_sd_pblock_driver};inst.caps=inst.driver->caps;
    brix_sd_pblock_conf_t conf={.root=argv[1],.block_size=4096,.busy_timeout_ms=1000};
    assert(inst.driver->init(&inst,&conf)==NGX_OK);
    if(!strcmp(argv[2],"transaction")) { transaction(&inst,argv[1],argv[3]); }
    else if(!strcmp(argv[2],"copy")) { copying(&inst); }
    else if(!strcmp(argv[2],"stat") || !strcmp(argv[2],"unlink") ||
            !strcmp(argv[2],"rename") || !strcmp(argv[2],"opendir")) { names(&inst,argv[2]); }
    else { staged(&inst,argv[2]); }
    inst.driver->cleanup(&inst);puts("failure remained contained");ngx_cycle=NULL;return 0;
}
