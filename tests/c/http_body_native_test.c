/* Real body-chain reads, writes and decoding against private temporary files. */
#include "core/http/http_body.h"
#include "core/compat/copy_range.h"
#include "fs/vfs/vfs.h"
#include "native_alloc_fail.h"

void *__real_ngx_pnalloc(ngx_pool_t *, size_t);
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size) {
    return native_alloc_fails("ngx_pnalloc") ? NULL : __real_ngx_pnalloc(pool, size);
}
void *__real_ngx_alloc(size_t, ngx_log_t *);
void *__wrap_ngx_alloc(size_t size, ngx_log_t *log) {
    return native_alloc_fails("ngx_alloc") ? NULL : __real_ngx_alloc(size, log);
}

typedef struct {
    ngx_http_request_t request;
    ngx_http_request_body_t body;
    ngx_buf_t buffers[3];
    ngx_chain_t chains[3];
    ngx_file_t file;
    unsigned char *bytes;
    size_t length;
    int input, output;
    off_t written;
    const char *mode;
} fixture;

/* The body walker owns framing and offsets; this finite sink observes them
 * while retaining real VFS writes and file-range copies. */
static ngx_int_t sink_write(fixture *f,const void *data,size_t length,off_t offset)
{
    assert(offset==f->written);
    if(!strcmp(f->mode,"sink-fail")) { errno=ENOSPC;return NGX_ERROR; }
    if(brix_vfs_pwrite_full(f->output,data,length,offset)!=NGX_OK) { return NGX_ERROR; }
    f->written+=(off_t)length;return NGX_OK;
}
ngx_int_t __wrap_brix_vfs_staged_write(brix_vfs_staged_t *st,const void *data,size_t length,off_t offset)
{ return sink_write((fixture *)st,data,length,offset); }
ngx_int_t __wrap_brix_vfs_writer_write(struct brix_vfs_writer_s *w,const void *data,size_t length,off_t offset)
{ return sink_write((fixture *)w,data,length,offset); }
ngx_int_t __wrap_brix_vfs_writer_write_fd(struct brix_vfs_writer_s *w,int fd,off_t source,size_t length,off_t offset)
{
    fixture *f=(fixture *)w;assert(offset==f->written);
    if(!strcmp(f->mode,"sink-fail")) { errno=ENOSPC;return NGX_ERROR; }
    ngx_int_t rc=brix_copy_range(f->request.connection->log,fd,source,f->output,offset,length,NULL,NULL);
    if(rc==NGX_OK) { f->written+=(off_t)length; }return rc;
}
ssize_t __real_pread64(int fd,void *data,size_t length,off_t offset);
ssize_t __wrap_pread64(int fd,void *data,size_t length,off_t offset)
{
    if(getenv("BRIX_BODY_INTERRUPT")) {
        unsetenv("BRIX_BODY_INTERRUPT");errno=EINTR;return -1;
    }
    return __real_pread64(fd,data,length,offset);
}

static void prepare(fixture *f, const char *input, const char *output, const char *layout) {
    f->input = open(input, O_RDONLY); assert(f->input >= 0);
    f->output = open(output, O_CREAT | O_TRUNC | O_RDWR, 0600); assert(f->output >= 0);
    struct stat st; assert(fstat(f->input, &st) == 0); f->length = (size_t) st.st_size;
    f->bytes = malloc(f->length + 1); assert(f->bytes);
    assert(pread(f->input, f->bytes, f->length, 0) == (ssize_t) f->length);
    f->file.fd = f->input;
    size_t memory = !strcmp(layout, "file") ? 0 : f->length;
    if (!strcmp(layout, "mixed")) { memory /= 2; }
    f->buffers[0].pos = f->bytes; f->buffers[0].last = f->bytes + memory;
    f->buffers[0].memory = 1;
    f->buffers[1].in_file = 1; f->buffers[1].file = &f->file;
    f->buffers[1].file_pos = (off_t) memory; f->buffers[1].file_last = (off_t) f->length;
    for (unsigned i = 0; i < 3; i++) {
        f->chains[i].buf = &f->buffers[i];
        f->chains[i].next = i < 2 ? &f->chains[i+1] : NULL;
    }
    if (!strcmp(layout, "memory")) { f->chains[0].next = NULL; }
    f->body.bufs = f->chains; f->request.request_body = &f->body;
}

static void alter(fixture *f, const char *mode) {
    f->mode=mode;
    if (!strcmp(mode,"interrupted")) { assert(setenv("BRIX_BODY_INTERRUPT","1",1)==0); }
    if (!strcmp(mode, "no-body")) { f->request.request_body = NULL; }
    if (!strcmp(mode, "no-chain")) { f->body.bufs = NULL; }
    if (!strcmp(mode, "null-buffer")) { f->chains[2].buf = NULL; }
    if (!strcmp(mode, "bad-fd")) { f->file.fd = NGX_INVALID_FILE; }
    if (!strcmp(mode, "missing-file")) { f->buffers[1].file = NULL; }
    if (!strcmp(mode, "reverse-file")) { f->buffers[1].file_last = -1; }
    if (!strcmp(mode, "short-file")) { f->buffers[1].file_last += 1; }
    if (!strcmp(mode, "closed-file")) { assert(close(f->input) == 0); f->input = -1; }
    if (!strcmp(mode, "closed-output")) { assert(close(f->output) == 0); f->output = -1; }
    if (!strcmp(mode, "pool-oom")) { native_alloc_arm("ngx_pnalloc", 0); }
    if (!strncmp(mode, "decode-oom", 10)) { native_alloc_arm("ngx_alloc", (unsigned) atoi(mode+10)); }
}

static ngx_int_t read_body(fixture *f, const char *mode, size_t limit) {
    u_char *out = NULL; size_t length = 0;
    ngx_int_t rc = brix_http_body_read_all(&f->request, limit,
        !strcmp(mode, "null-out") ? NULL : &out,
        !strcmp(mode, "null-length") ? NULL : &length);
    if (rc == NGX_OK) {
        assert(out && out[length] == 0);
        assert(write(f->output, out, length) == (ssize_t) length);
    }
    return rc;
}

static ngx_int_t operate(fixture *f, const char *op, const char *mode, int codec,
    size_t limit, ngx_int_t *status) {
    ngx_http_request_t *r = !strcmp(mode, "null-request") ? NULL : &f->request;
    brix_http_body_summary_t summary;
    if (!strcmp(op, "read")) { return read_body(f, mode, limit); }
    if (!strcmp(op, "summary")) {
        ngx_int_t rc = brix_http_body_summary(r, !strcmp(mode, "null-out") ? NULL : &summary);
        if (!rc && strcmp(mode, "null-out")) {
            printf("bytes=%zu memory=%ld file=%ld\n", summary.bytes, (long) summary.has_memory, (long) summary.has_spooled);
        }
        return rc;
    }
    if (!strcmp(op, "write")) { return brix_http_body_write_to_fd(r, f->output, NULL, NULL); }
    if (!strcmp(op, "write-at")) { return brix_http_body_write_to_fd_at(r, f->output, NULL, NULL, 7); }
    if (!strcmp(op,"staged")) {
        return brix_http_body_write_to_staged(r,!strcmp(mode,"null-sink")?NULL:(brix_vfs_staged_t *)f);
    }
    if (!strcmp(op,"writer")) {
        return brix_http_body_write_to_writer(r,!strcmp(mode,"null-sink")?NULL:(struct brix_vfs_writer_s *)f);
    }
    return brix_http_body_decode_to_fd(r, f->output, NULL, (brix_codec_id_t) codec, limit, NULL, status);
}

int main(int argc, char **argv) {
    assert(argc == 8);
    fixture f = {0}; ngx_log_t log = {0}; ngx_time_init();
    ngx_pool_t *pool = ngx_create_pool(4096, &log); assert(pool);
    ngx_connection_t connection = {.log = &log};
    f.request.pool = pool; f.request.connection = &connection;
    prepare(&f, argv[1], argv[2], argv[3]); alter(&f, argv[5]);
    ngx_int_t status = 0;
    ngx_int_t rc = operate(&f, argv[4], argv[5], atoi(argv[6]), (size_t) strtoull(argv[7], NULL, 10), &status);
    native_alloc_disarm();
    printf("RESULT rc=%ld status=%ld\n", (long) rc, (long) status);
    if (f.input >= 0) { assert(close(f.input) == 0); }
    if (f.output >= 0) { assert(close(f.output) == 0); }
    free(f.bytes); ngx_destroy_pool(pool); return 0;
}
