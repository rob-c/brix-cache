/* Controlled VFS handles around the actual production traversal. */
#include <assert.h>
#include <pthread.h>
#include <stdlib.h>

struct brix_vfs_dir_s { size_t depth; int visited; };
ngx_module_t ngx_http_brix_webdav_module = {0};

void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
    const char *format, ...)
{
    (void) level; (void) log; (void) error; (void) format;
}

static struct {
    const char *mode;
    unsigned opened, closed, emitted, allocations;
    void *memory[4096];
} fixture;

void *ngx_palloc(ngx_pool_t *pool, size_t size)
{
    (void) pool;
    if (strcmp(fixture.mode, "oom") == 0 && fixture.allocations == 2) {
        return NULL;
    }
    assert(fixture.allocations < 4096);
    void *memory = malloc(size);
    assert(memory != NULL);
    fixture.memory[fixture.allocations++] = memory;
    return memory;
}

ngx_int_t brix_dirlist_access_ok(ngx_log_t *log, const char *root,
    const char *path)
{
    (void) log; (void) root; (void) path;
    return strcmp(fixture.mode, "denied") == 0 ? NGX_ERROR : NGX_OK;
}

void webdav_vfs_ctx_build(ngx_http_request_t *request, const char *path,
    brix_vfs_ctx_t *context)
{
    (void) request;
    memset(context, 0, sizeof(*context));
    context->root_canon = path;
}

brix_vfs_dir_t *brix_vfs_opendir(brix_vfs_ctx_t *context, int *error)
{
    (void) error;
    brix_vfs_dir_t *directory = calloc(1, sizeof(*directory));
    assert(directory != NULL);
    directory->depth = (strlen(context->root_canon) - strlen("/export")) / 2;
    fixture.opened++;
    return directory;
}

ngx_int_t brix_vfs_readdir(brix_vfs_dir_t *directory, ngx_str_t *name,
    brix_vfs_stat_t *status)
{
    if (directory->visited++ || directory->depth >= 1600) {
        return NGX_DONE;
    }
    name->data = (u_char *) "a";
    name->len = 1;
    memset(status, 0, sizeof(*status));
    status->mode = strcmp(fixture.mode, "symlink") == 0 ? S_IFLNK : S_IFDIR;
    return NGX_OK;
}

ngx_int_t brix_vfs_closedir(brix_vfs_dir_t *directory, ngx_log_t *log)
{
    (void) log;
    fixture.closed++;
    free(directory);
    return NGX_OK;
}

ngx_int_t propfind_entry(ngx_http_request_t *request, ngx_chain_t **head,
    ngx_chain_t **tail, const char *href, const char *path, struct stat *status,
    const propfind_req_t *properties)
{
    (void) request; (void) head; (void) tail; (void) status; (void) properties;
    assert(strncmp(path, "/export/", 8) == 0);
    assert(href[0] == '/');
    fixture.emitted++;
    if (strcmp(fixture.mode, "emit-error") == 0 && fixture.emitted == 5) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static void *walk_thread(void *unused)
{
    (void) unused;
    ngx_http_request_t request = {0};
    ngx_connection_t connection = {0};
    ngx_log_t log = {0};
    ngx_http_brix_webdav_loc_conf_t config = {0};
    void *locations[] = {&config};
    void *contexts[] = {NULL};
    memcpy(config.common.root_canon, "/export", sizeof("/export"));
    connection.log = &log;
    request.connection = &connection;
    request.loc_conf = locations;
    request.ctx = contexts;
    ngx_uint_t count = 0;
    ngx_uint_t cap = strcmp(fixture.mode, "cap") == 0 ? 7 : 10000;
    ngx_chain_t *head = NULL, *tail = NULL;
    propfind_req_t properties = {0};
    ngx_int_t result = propfind_walk(&request, &head, &tail, "/export", "/",
                                    &count, cap, &properties, 1);
    assert(fixture.opened == fixture.closed);
    if (strcmp(fixture.mode, "emit-error") == 0
        || strcmp(fixture.mode, "oom") == 0) {
        assert(result == NGX_ERROR);
    } else {
        assert(result == NGX_OK);
    }
    if (strcmp(fixture.mode, "deep") == 0) assert(count == 1600);
    if (strcmp(fixture.mode, "cap") == 0) assert(count == 7);
    if (strcmp(fixture.mode, "denied") == 0) assert(fixture.opened == 0 && count == 0);
    if (strcmp(fixture.mode, "symlink") == 0) assert(fixture.opened == 1 && count == 1);
    return NULL;
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    fixture.mode = argv[1];
    pthread_attr_t attributes;
    pthread_t thread;
    assert(pthread_attr_init(&attributes) == 0);
    assert(pthread_attr_setstacksize(&attributes, 512 * 1024) == 0);
    assert(pthread_create(&thread, &attributes, walk_thread, NULL) == 0);
    assert(pthread_join(thread, NULL) == 0);
    pthread_attr_destroy(&attributes);
    for (unsigned index = 0; index < fixture.allocations; index++) {
        free(fixture.memory[index]);
    }
    return 0;
}
