/* Complete real staged files while injecting finite publish and pool failures. */
#include "protocols/s3/s3.h"
#include "protocols/s3/multipart_internal.h"
#include "core/compat/copy_range.h"
#include "core/http/http_xml.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    const char *mode;
    ngx_thread_task_t *task;
    int pool_token, status, finalized, sent, posts, final_fd, part_fd, announcements;
    char xml[1024];
} fixture;
static fixture *state(void) { return (fixture *)ngx_cycle; }
static int mode(const char *name) { return !strcmp(state()->mode, name); }
void __wrap_brix_cns_emit_at(const char *root, uint8_t op, const char *path, uint64_t size, uint64_t mtime)
{
    assert(root && op == BRIX_CNS_ADD && strstr(path, "/object") && size == 9 && mtime > 0);
    state()->announcements++;
}
void __wrap_s3_build_vfs_ctx(ngx_http_request_t *r, const char *path,
    ngx_http_s3_loc_conf_t *conf, brix_vfs_ctx_t *ctx)
{
    brix_vfs_ctx_init(ctx, r->pool, r->connection->log, BRIX_PROTO_S3,
        conf->common.root_canon, NULL, brix_vfs_policy_from_write_enable(conf->common.allow_write),
        0, NULL, path);
}
ngx_int_t __wrap_brix_vfs_require_unlocked(brix_vfs_ctx_t *ctx, brix_vfs_mutation_op_t op)
{ assert(ctx && op == BRIX_VFS_MUTATE_RENAME); if (mode("locked")) { errno = EBUSY; return NGX_ERROR; } return NGX_OK; }
void __wrap_s3_metrics_finalize_request_method(ngx_http_request_t *r, ngx_uint_t slot, ngx_int_t rc)
{ (void)r; (void)slot; state()->finalized++; state()->status = (int)rc; }
ngx_int_t __wrap_s3_send_xml_error(ngx_http_request_t *r, ngx_uint_t status, const char *code, const char *message)
{ (void)r; assert(code && message); return (ngx_int_t)status; }
ngx_int_t __wrap_brix_http_send_xml_buffer(ngx_http_request_t *r, ngx_uint_t status,
    ngx_str_t type, ngx_buf_t *buffer)
{
    (void)r; assert(status == 200 && type.len == 15); size_t n = (size_t)(buffer->last - buffer->pos);
    assert(n < sizeof(state()->xml)); memcpy(state()->xml, buffer->pos, n); state()->sent++; return 200;
}
ngx_thread_pool_t *__wrap_s3_thread_pool(ngx_http_s3_loc_conf_t *conf)
{ (void)conf; return !strncmp(state()->mode, "async", 5) ? (void *)&state()->pool_token : NULL; }
ngx_thread_task_t *__real_ngx_thread_task_alloc(ngx_pool_t *, size_t);
ngx_thread_task_t *__wrap_ngx_thread_task_alloc(ngx_pool_t *pool, size_t size)
{ return mode("async-allocate") ? NULL : __real_ngx_thread_task_alloc(pool, size); }
ngx_int_t __wrap_ngx_thread_task_post(ngx_thread_pool_t *pool, ngx_thread_task_t *task)
{
    assert(pool == (void *)&state()->pool_token && !state()->task); state()->posts++;
    if (mode("async-post")) { return NGX_ERROR; }
    state()->task = task; return NGX_OK;
}
int __real_brix_vfs_export_open_fd(const brix_vfs_export_op_ctx_t *, const char *, int, mode_t);
int __wrap_brix_vfs_export_open_fd(const brix_vfs_export_op_ctx_t *ctx, const char *path, int flags, mode_t permissions)
{
    assert(permissions == 0600);
    if (mode("create") || mode("async-create")) { errno = ENOSPC; return -1; }
    state()->final_fd = __real_brix_vfs_export_open_fd(ctx, path, flags, permissions);
    return state()->final_fd;
}
int __real_brix_vfs_open_fd(ngx_log_t *, const char *, const char *, int, mode_t);
int __wrap_brix_vfs_open_fd(ngx_log_t *log, const char *root, const char *path, int flags, mode_t permissions)
{
    if (strstr(path, "/part.1")) {
        if (mode("part-open")) { errno = EACCES; return -1; }
        int fd = __real_brix_vfs_open_fd(log, root, path, flags, permissions);
        if (fd >= 0) { state()->part_fd = fd; } return fd;
    }
    return __real_brix_vfs_open_fd(log, root, path, flags, permissions);
}
int __real_fstat64(int, struct stat64 *);
int __wrap_fstat64(int fd, struct stat64 *st)
{
    if ((mode("part-stat") && fd == state()->part_fd) || (mode("final-stat") && fd == state()->final_fd)) {
        errno = EIO; return -1;
    }
    return __real_fstat64(fd, st);
}
ngx_int_t __real_brix_copy_range(ngx_log_t *, int, off_t, int, off_t, size_t, const char *, const char *);
ngx_int_t __wrap_brix_copy_range(ngx_log_t *log, int from, off_t source, int to, off_t destination,
    size_t length, const char *source_path, const char *destination_path)
{
    if (mode("copy")) { errno = EIO; return NGX_ERROR; }
    return __real_brix_copy_range(log, from, source, to, destination, length, source_path, destination_path);
}
int __real_brix_rename_confined_canon(ngx_log_t *, const char *, const char *, const char *);
int __wrap_brix_rename_confined_canon(ngx_log_t *log, const char *root, const char *from, const char *to)
{
    if (mode("rename")) { errno = EIO; return -1; }
    return __real_brix_rename_confined_canon(log, root, from, to);
}
int __real_mpu_rmdir_recursive(ngx_log_t *, const char *, const char *);
int __wrap_mpu_rmdir_recursive(ngx_log_t *log, const char *root, const char *path)
{ if (mode("cleanup")) { errno = EACCES; return -1; } return __real_mpu_rmdir_recursive(log, root, path); }
ngx_int_t __wrap_s3_object_crc64nvme_b64(ngx_http_request_t *r, int fd, const char *path,
    ngx_flag_t cached, char *out, size_t size)
{ (void)r; (void)path; assert(fd >= 0 && !cached && size >= 16); out[0] = 0; return NGX_DECLINED; }
ngx_buf_t *__real_ngx_create_temp_buf(ngx_pool_t *, size_t);
ngx_buf_t *__wrap_ngx_create_temp_buf(ngx_pool_t *pool, size_t size)
{ return mode("response-allocate") ? NULL : __real_ngx_create_temp_buf(pool, size); }

int main(int argc, char **argv)
{
    assert(argc == 4); fixture f = {0}; f.mode = argv[1]; f.final_fd = f.part_fd = -1; ngx_cycle = &f.cycle;
    ngx_log_t log = {0}; ngx_open_file_t file = {.fd=STDERR_FILENO}; log.file = &file;
    f.cycle.log = &log; ngx_time_init(); ngx_pool_t *pool = ngx_create_pool(8192, &log); assert(pool);
    ngx_http_brix_s3_module.ctx_index = 0;
    ngx_http_s3_loc_conf_t conf = {0}; snprintf(conf.common.root_canon, sizeof(conf.common.root_canon), "%s", argv[2]);
    conf.common.allow_write = !mode("readonly"); ngx_str_set(&conf.bucket, "bucket");
    char big_bucket[600]; memset(big_bucket, 'b', sizeof(big_bucket) - 1); big_bucket[599] = 0;
    if (mode("response-overflow")) { conf.bucket = (ngx_str_t){599, (u_char *)big_bucket}; }
    ngx_http_s3_req_ctx_t context = {0};
    if (!mode("empty-path")) { snprintf(context.fs_path, sizeof(context.fs_path), "%s/object", argv[2]); }
    void *configs[] = {&conf}, *contexts[] = {mode("no-context") ? NULL : &context};
    ngx_connection_t connection = {.pool=pool, .log=&log};
    ngx_http_request_t request = {.pool=pool, .connection=&connection, .loc_conf=configs, .ctx=contexts,
        .method=NGX_HTTP_POST, .count=1}; request.main = &request;
    request.args = (ngx_str_t){strlen(argv[3]), (u_char *)argv[3]};
    assert(brix_http_query_parse(pool, request.args, &context.query) >= 0);
    s3_multipart_complete_body_handler(&request);
    if (f.task) {
        assert(request.count == 2 && !f.finalized);
        f.task->handler(f.task->ctx, &log); f.task->event.handler(&f.task->event);
    }
    assert(request.count == 1 && f.finalized == 1);
    assert(f.announcements == (f.sent || mode("response-allocate") || mode("response-overflow")));
    printf("%d %d %d\n%s", f.status, f.sent, f.posts, f.xml);
    ngx_destroy_pool(pool); ngx_cycle = NULL; return 0;
}
