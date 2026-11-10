/* Real Ceph driver state transitions over a deterministic librados boundary. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/rados/sd_ceph_internal.h"
#include "native_alloc_fail.h"

void *__real_ngx_pcalloc(ngx_pool_t *, size_t);
void *__wrap_ngx_pcalloc(ngx_pool_t *pool, size_t size) {
    return native_alloc_fails("ngx_pcalloc") ? NULL : __real_ngx_pcalloc(pool, size);
}

#if BRIX_HAVE_CEPH
typedef struct {
    const char *operation, *failure;
    int error, calls, shutdowns, destroys, reads, writes, truncates, removes, stats;
    int failed;
    int capacity, attribute_calls, iterations, iterator_open, iterator_end;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle->conf_ctx; }
static int failure(const char *name) {
    fixture *f = state();
    if (strcmp(f->failure, name)) { return 0; }
    f->failed++; return -f->error;
}
static void check_context(rados_ioctx_t io) { assert(io == state()); }

int __wrap_rados_create(rados_t *cluster, const char *id) {
    fixture *f = state(); f->calls++;
    assert(id == NULL || strcmp(id, "admin") == 0);
    int rc = failure("create"); if (rc) { return rc; }
    *cluster = f; return 0;
}
int __wrap_rados_conf_read_file(rados_t cluster, const char *path) {
    assert(cluster == state() && path != NULL); return failure("config");
}
int __wrap_rados_conf_set(rados_t cluster, const char *key, const char *value) {
    assert(cluster == state() && !strcmp(key, "keyring") && !strcmp(value, "fixture.keyring"));
    return 0;
}
int __wrap_rados_connect(rados_t cluster) { assert(cluster == state()); return failure("connect"); }
int __wrap_rados_ioctx_create(rados_t cluster, const char *pool, rados_ioctx_t *io) {
    assert(cluster == state() && !strcmp(pool, "fixture-pool"));
    int rc = failure("ioctx"); if (rc) { return rc; }
    *io = state(); return 0;
}
void __wrap_rados_shutdown(rados_t cluster) { assert(cluster == state()); state()->shutdowns++; }
void __wrap_rados_ioctx_destroy(rados_ioctx_t io) { check_context(io); state()->destroys++; }

int __wrap_rados_read(rados_ioctx_t io, const char *oid, char *buffer, size_t size, uint64_t off) {
    check_context(io); assert(!strcmp(oid, "prefix/object")); state()->reads++;
    int rc = failure("read");
    if (rc) { return rc; }
    if (off >= 10) { return 0; }
    size_t count = ngx_min(size, 10 - off); memcpy(buffer, "0123456789" + off, count);
    return (int) count;
}
int __wrap_rados_write(rados_ioctx_t io, const char *oid, const char *buffer, size_t size, uint64_t off) {
    check_context(io); assert(!strcmp(oid, "prefix/object"));
    assert(size == 3 && !memcmp(buffer, "abc", 3) && off == 20);
    state()->writes++; return failure("write");
}
int __wrap_rados_trunc(rados_ioctx_t io, const char *oid, uint64_t size) {
    check_context(io); assert(!strcmp(oid, "prefix/object") && (size == 0 || size == 4));
    state()->truncates++; return failure("truncate");
}
int __wrap_rados_stat(rados_ioctx_t io, const char *oid, uint64_t *size, time_t *mtime) {
    check_context(io); assert(!strcmp(oid, "prefix/object")); state()->stats++;
    int rc = failure("stat"); if (rc) { return rc; }
    *size = 10; *mtime = 12345; return 0;
}
int __wrap_rados_remove(rados_ioctx_t io, const char *oid) {
    check_context(io); assert(!strcmp(oid, "prefix/object"));
    state()->removes++; return failure("remove");
}
int __wrap_rados_cluster_stat(rados_t cluster, struct rados_cluster_stat_t *out) {
    assert(cluster == state()); int rc = failure("space"); if (rc) { return rc; }
    memset(out, 0, sizeof(*out)); out->kb = 20; out->kb_used = 7; out->kb_avail = 13; return 0;
}

/* OID and path-facing metadata must share error mapping and iterator ownership. */
static void attribute_context(rados_ioctx_t io,const char *oid) {
    check_context(io);assert(!strcmp(oid,"prefix/object"));state()->attribute_calls++;
}
int __wrap_rados_getxattr(rados_ioctx_t io,const char *oid,const char *name,char *out,size_t cap) {
    attribute_context(io,oid);assert(!strcmp(name,"user.a") && cap>=3);
    int rc=failure("get-attribute");if(rc) { return rc; }memcpy(out,"A\0B",3);return 3;
}
int __wrap_rados_setxattr(rados_ioctx_t io,const char *oid,const char *name,const char *value,size_t length) {
    attribute_context(io,oid);assert(!strcmp(name,"user.a") && length==3 && !memcmp(value,"A\0B",3));
    return failure("set-attribute");
}
int __wrap_rados_rmxattr(rados_ioctx_t io,const char *oid,const char *name) {
    attribute_context(io,oid);assert(!strcmp(name,"user.a"));return failure("remove-attribute");
}
int __wrap_rados_getxattrs(rados_ioctx_t io,const char *oid,rados_xattrs_iter_t *iterator) {
    attribute_context(io,oid);int rc=failure("open-iterator");if(rc) { return rc; }
    *iterator=state();state()->iterator_open++;return 0;
}
int __wrap_rados_getxattrs_next(rados_xattrs_iter_t iterator,const char **name,const char **value,size_t *size) {
    assert(iterator==state());int rc=failure("next-attribute");if(rc) { return rc; }
    *name=state()->iterations==0?"user.a":state()->iterations==1?"user.b":NULL;
    state()->iterations++;*value="value";*size=5;return 0;
}
void __wrap_rados_getxattrs_end(rados_xattrs_iter_t iterator) {
    assert(iterator==state() && state()->iterator_end++==0);
}
ngx_int_t __wrap_sd_ceph_enumerate_io(sd_ceph_state_t *st,rados_ioctx_t io,int flags,
    brix_sd_catalog_cb callback,void *context) {
    (void)st;check_context(io);assert(flags==0);int rc=failure("enumerate");
    if(rc) { errno=-rc;return NGX_ERROR; }
    if(strstr(state()->operation,"nonempty")) {
        brix_sd_catalog_ent_t child={.path="/object/child"};assert(callback(context,&child)==1);
    }
    return NGX_OK;
}

static int metadata_contract(brix_sd_instance_t *inst) {
    fixture *f=state();const char *op=f->operation;int direct=!strncmp(op,"oid-",4);
    const char *path=strstr(op,"unsafe")?"/../escape":"/object";
    sd_ceph_conn_t connection={.ioctx=f,.cluster=f,.connected=1};
    char buffer[32];memset(buffer,0x5a,sizeof(buffer));size_t capacity=(size_t)f->capacity;
    assert(capacity<sizeof(buffer));ssize_t count;
    if(strstr(op,"getattr")) {
        count=direct?sd_ceph_oid_getxattr(&connection,"prefix/object","user.a",buffer,capacity)
                    :sd_ceph_getxattr(inst,path,"user.a",buffer,capacity);
        if(count>=0) { assert(count==3 && (!capacity || !memcmp(buffer,"A\0B",3))); }
        else { assert(buffer[0]==0x5a); }
    } else if(strstr(op,"listattr")) {
        count=direct?sd_ceph_oid_listxattr(&connection,"prefix/object",buffer,capacity)
                    :sd_ceph_listxattr(inst,path,buffer,capacity);
        assert(f->iterator_open==f->iterator_end);
        if(count>=0) { assert(count==14 && (!capacity || !memcmp(buffer,"user.a\0user.b\0",14))); }
    } else if(strstr(op,"setattr")) {
        count=direct?sd_ceph_oid_setxattr(&connection,"prefix/object","user.a","A\0B",3)
                    :sd_ceph_setxattr(inst,path,"user.a","A\0B",3,0);
    } else if(strstr(op,"rmattr")) {
        count=direct?sd_ceph_oid_rmxattr(&connection,"prefix/object","user.a")
                    :sd_ceph_removexattr(inst,path,"user.a");
    } else if(strstr(op,"rmdir")) { count=sd_ceph_unlink(inst,strstr(op,"root")?"/":path,1); }
    else if(strstr(op,"mkdir")) { count=sd_ceph_mkdir(inst,path,0700); }
    else if(strstr(op,"remove")) {
        count=direct?sd_ceph_oid_remove(&connection,"prefix/object"):sd_ceph_unlink(inst,path,0);
    } else if(strstr(op,"read")) {
        count=sd_ceph_oid_read(&connection,"prefix/object",buffer,8,0);
        if(count>=0) { assert(count==8 && !memcmp(buffer,"01234567",8)); }
    } else if(strstr(op,"write")) { count=sd_ceph_oid_write(&connection,"prefix/object","abc",3,20); }
    else if(strstr(op,"trunc")) { count=sd_ceph_oid_trunc(&connection,"prefix/object",4); }
    else if(direct) {
        uint64_t size=0;time_t mtime=0;int nullable=strstr(op,"null")!=NULL;
        count=sd_ceph_oid_stat(&connection,"prefix/object",nullable?NULL:&size,nullable?NULL:&mtime);
        if(count>=0 && !nullable) { assert(size==10 && mtime==12345); }
    } else {
        brix_sd_stat_t snapshot={0};int root=strstr(op,"root")!=NULL;
        count=sd_ceph_stat(inst,root?"/":path,&snapshot);
        if(count>=0) { assert(root?snapshot.is_dir:(snapshot.is_reg && snapshot.size==10 && snapshot.mtime==12345)); }
    }
    assert(buffer[capacity]==0x5a || (strstr(op,"read") && capacity<8));
    return count<0?-1:0;
}
static void connection_contract(ngx_pool_t *pool) {
    fixture *f = state();
    brix_sd_ceph_conf_t config = {.pool = "fixture-pool", .user = "client.admin",
        .keyring = "fixture.keyring"};
    const brix_sd_ceph_conf_t *input = &config;
    if (!strcmp(f->operation, "null-config")) { input = NULL; }
    if (!strcmp(f->operation, "null-pool")) { config.pool = NULL; }
    if (!strcmp(f->operation, "default-user")) { config.user = NULL; }
    if (!strcmp(f->operation, "bare-user")) { config.user = "admin"; }
    int error = 0;
    sd_ceph_conn_t *conn = sd_ceph_conn_create(input, pool, &error);
    int should_fail = strcmp(f->failure, "none") || !strncmp(f->operation, "null-", 5);
    assert((conn == NULL) == should_fail);
    if (!conn) {
        int expected = f->error;
        if (!strncmp(f->operation, "null-", 5)) { expected = EINVAL; }
        if (!strcmp(f->failure, "allocation")) { expected = ENOMEM; }
        assert(error == expected && f->destroys == 0);
        assert(f->shutdowns == (f->calls && strcmp(f->failure, "create")));
        return;
    }
    assert(sd_ceph_conn_ioctx(conn) == f && sd_ceph_conn_cluster(conn) == f);
    sd_ceph_conn_pin(conn); sd_ceph_conn_pin(conn); conn->doomed = 1;
    sd_ceph_conn_unpin(conn); assert(f->shutdowns == 0 && conn->refs == 1);
    sd_ceph_conn_unpin(conn); assert(f->shutdowns == 1 && f->destroys == 1);
    sd_ceph_conn_unpin(conn); sd_ceph_conn_destroy(conn); sd_ceph_conn_destroy(NULL);
    assert(f->shutdowns == 1 && f->destroys == 1);
}

static int read_contract(brix_sd_obj_t *obj, const char *operation) {
    char first[8] = {0}, second[8] = {0}; ssize_t count;
    struct iovec vectors[] = {{first, sizeof(first)}, {second, sizeof(second)}};
    if (!strcmp(operation, "pread")) { count = sd_ceph_pread(obj, first, sizeof(first), 0); }
    else if (!strcmp(operation, "preadv")) { count = sd_ceph_preadv(obj, vectors, 2, 0); }
    else { count = sd_ceph_preadv2(obj, vectors, 2, 0, 123); }
    if (count < 0) { return -1; }
    assert(!memcmp(first, "01234567", 8));
    if (strcmp(operation, "pread")) { assert(count == 10 && !memcmp(second, "89", 2)); }
    else { assert(count == 8); }
    return 0;
}
static int data_contract(brix_sd_obj_t *obj) {
    const char *op = state()->operation;
    sd_ceph_obj_state_t *os = obj->state;
    if (!strncmp(op, "pread", 5)) { return read_contract(obj, op); }
    if (!strcmp(op, "pwrite")) {
        ssize_t rc = sd_ceph_pwrite(obj, "abc", 3, 20);
        assert(os->size == (rc < 0 ? 10u : 23u)); return rc < 0 ? -1 : 0;
    }
    if (!strcmp(op, "ftruncate")) {
        int rc = (int) sd_ceph_ftruncate(obj, 4);
        assert(os->size == (rc < 0 ? 10u : 4u)); return rc;
    }
    if (!strcmp(op, "fstat")) {
        brix_sd_stat_t out; int rc = (int) sd_ceph_fstat(obj, &out);
        if (!rc) { assert(out.size == 10 && out.mtime == 12345 && out.is_reg); }
        return rc;
    }
    brix_sd_space_t space;
    int rc = (int) sd_ceph_space(obj->inst, !strcmp(op, "null-space") ? NULL : &space);
    if (!rc) { assert(space.total_bytes == 20480 && space.used_bytes == 7168 && space.free_bytes == 13312); }
    return rc;
}

static int staged_contract(brix_sd_instance_t *inst) {
    fixture *f = state(); int error = 0;
    const char *path = !strcmp(f->operation, "staged-unsafe") ? "/../escape" : "/object";
    brix_sd_staged_t *h = sd_ceph_staged_open(inst, path, 0644, 3, &error);
    if (!h) { assert(error != 0); errno = error; return -1; }
    if (!strcmp(f->operation, "staged-write")) {
        ssize_t count = sd_ceph_staged_write(h, "abc", 3, 20);
        int saved = errno; sd_ceph_staged_abort(h); errno = saved;
        return count < 0 ? -1 : 0;
    }
    brix_sd_precond_t condition = {.kind = BRIX_SD_PRECOND_ABSENT};
    int rc = (int) sd_ceph_staged_commit(h, !strcmp(f->operation, "staged-conditional") ? &condition : NULL);
    int saved = errno; sd_ceph_staged_abort(h); errno = saved; return rc;
}

static int open_flags(const char *operation) {
    int flags = BRIX_SD_O_WRITE;
    if (!strcmp(operation, "open-create")) { flags |= BRIX_SD_O_CREATE; }
    if (!strcmp(operation, "open-exclusive")) { flags |= BRIX_SD_O_EXCL; }
    if (!strcmp(operation, "open-truncate")) { flags |= BRIX_SD_O_TRUNC; }
    return flags;
}
static int open_contract(brix_sd_instance_t *inst) {
    fixture *f = state();
    int flags = open_flags(f->operation);
    const char *path = !strcmp(f->operation, "open-unsafe") ? "/../escape" : "/object";
    sd_ceph_conn_t pin = {.cluster = f, .ioctx = f, .connected = 1, .doomed = 1};
    sd_ceph_open_req_t req = {.inst = inst, .st = inst->state, .ioctx = f,
        .pin_conn = &pin, .path = path, .sd_flags = flags, .mode = 0644};
    int error = 0;
    int pinned = !strcmp(f->operation, "open-pinned");
    brix_sd_obj_t *obj = pinned ? sd_ceph_open_on_ioctx(&req, &error)
        : sd_ceph_open(inst, path, flags, 0644, &error);
    if (!obj) { assert(error != 0 && pin.refs == 0); errno = error; return -1; }
    int empty = !strcmp(f->operation, "open-truncate") || f->failed;
    assert(obj->snap.size == (empty ? 0 : 10) && obj->snap.is_reg && obj->fd == NGX_INVALID_FILE);
    assert(sd_ceph_fsync(obj) == NGX_OK);
    assert(sd_ceph_read_sendfile_fd(obj, 0, 10, 1) == NGX_INVALID_FILE);
    assert(pin.refs == (unsigned) pinned && f->destroys == 0);
    assert(sd_ceph_close(obj) == NGX_OK && f->destroys == pinned && pin.refs == 0);
    assert(sd_ceph_close(obj) == NGX_OK && f->destroys == pinned);
    return 0;
}

static int perform(brix_sd_instance_t *inst, brix_sd_obj_t *obj) {
    if(!strncmp(state()->operation,"oid-",4) || !strncmp(state()->operation,"meta-",5)) { return metadata_contract(inst); }
    if (!strncmp(state()->operation, "staged", 6)) { return staged_contract(inst); }
    if (!strncmp(state()->operation, "open", 4)) { return open_contract(inst); }
    return data_contract(obj);
}

int main(int argc, char **argv) {
    assert(argc == 6);
    fixture f = {.operation = argv[1], .failure = argv[2], .error = atoi(argv[3]),.capacity=atoi(argv[4])};
    ngx_log_t log = {0}; ngx_cycle_t cycle = {.log = &log, .conf_ctx = (void ****) &f};
    ngx_cycle = &cycle; ngx_time_init(); ngx_pool_t *pool = ngx_create_pool(4096, &log); assert(pool);
    if (!strcmp(f.failure, "allocation")) { native_alloc_arm("ngx_pcalloc", (unsigned) atoi(argv[4])); }
    if (!strncmp(f.operation, "conn", 4) || strstr(f.operation, "user") || !strncmp(f.operation, "null-", 5)) {
        if (strcmp(f.operation, "null-space")) {
            connection_contract(pool); native_alloc_disarm(); ngx_destroy_pool(pool); return 0;
        }
    }
    sd_ceph_state_t driver_state = {.ioctx = &f, .cluster = &f, .key_prefix = "prefix", .connected = 1};
    brix_sd_instance_t inst = {.pool = pool, .state = &driver_state, .driver = &brix_sd_ceph_driver};
    sd_ceph_obj_state_t object_state = {.ioctx = &f, .size = 10}; strcpy(object_state.oid, "prefix/object");
    brix_sd_obj_t object = {.inst = &inst, .state = &object_state};
    if (!strcmp(f.operation, "disconnected")) { driver_state.connected = 0; }
    errno = 0;
    int rc = perform(&inst, &object);
    int saved = errno; native_alloc_disarm();
    int expected = atoi(argv[5]); assert(rc == (expected ? -1 : 0));
    if (expected) { assert(saved == expected); }
    printf("rc=%d errno=%d failed=%d reads=%d writes=%d truncates=%d removes=%d stats=%d\n",
        rc, saved, f.failed, f.reads, f.writes, f.truncates, f.removes, f.stats);
    ngx_destroy_pool(pool); return 0;
}
#else
int main(void) { return 77; }
#endif
