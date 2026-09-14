/* Exercise the complete metadata handler with local transport/VFS boundaries. */
#include "protocols/root/query/query_internal.h"
#include "auth/impersonate/impersonate.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static int
scenario_is(const char *name)
{
    return strcmp(getenv("BRIX_XATTR_CASE"), name) == 0;
}

ngx_int_t
brix_send_error(brix_ctx_t *ctx, ngx_connection_t *connection,
    uint16_t code, const char *message)
{
    puts("error");
    return ctx->write_rc;
}

int
brix_extract_path(ngx_log_t *log, const u_char *payload, size_t length,
    char *output, size_t capacity, ngx_flag_t strip_cgi)
{
    puts("extract");
    if (scenario_is("invalid")) {
        return 0;
    }
    assert(capacity > sizeof("/record"));
    strcpy(output, "/record");
    return 1;
}

ngx_int_t
brix_auth_gate(brix_ctx_t *ctx, ngx_connection_t *connection,
    ngx_uint_t operation, const char *name, const char *request,
    const char *resolved, ngx_stream_brix_srv_conf_t *config,
    int level, int write_needed)
{
    puts("auth");
    if (scenario_is("auth")) {
        BRIX_OP_ERR(ctx, operation);
        return NGX_ERROR;
    }
    return NGX_OK;
}

void
brix_root_vfs_ctx_init(brix_ctx_t *ctx, ngx_connection_t *connection,
    ngx_stream_brix_srv_conf_t *config, brix_vfs_ctx_t *vfs,
    const char *resolved)
{
    puts("context");
    memset(vfs, 0, sizeof(*vfs));
}

ngx_int_t
brix_vfs_probe(brix_vfs_ctx_t *vfs, int nofollow, brix_vfs_stat_t *metadata)
{
    puts("probe");
    if (scenario_is("probe")) {
        errno = ENOENT;
        return NGX_ERROR;
    }
    memset(metadata, 0, sizeof(*metadata));
    metadata->is_regular = 1;
    metadata->mode = 0644;
    metadata->size = 7;
    return NGX_OK;
}

int brix_imp_client_active(void) { return 0; }

int
brix_vfs_open_fd(ngx_log_t *log, const char *root, const char *path,
    int flags, mode_t mode)
{
    abort();
}

ssize_t
brix_vfs_listxattr(brix_vfs_ctx_t *vfs, void *buffer, size_t capacity)
{
    puts("list");
    return 0;
}

ssize_t
brix_vfs_getxattr(brix_vfs_ctx_t *vfs, const char *name,
    void *buffer, size_t capacity)
{
    abort();
}

void
brix_log_access(brix_ctx_t *ctx, ngx_connection_t *connection,
    const char *verb, const char *path, const char *detail, ngx_uint_t ok,
    uint16_t error, const char *message, size_t bytes)
{
    puts("access");
}

ngx_int_t
brix_send_ok(brix_ctx_t *ctx, ngx_connection_t *connection,
    const void *body, uint32_t length)
{
    assert(length == strlen(body) + 1);
    assert(strstr(body, "oss.type=f&oss.used=7") != NULL);
    puts("ok");
    return NGX_OK;
}

int
main(int argc, char **argv)
{
    brix_ctx_t ctx = {0};
    ngx_connection_t connection = {0};
    ngx_stream_brix_srv_conf_t config = {0};
    ngx_int_t result;

    assert(argc == 3);
    assert(setenv("BRIX_XATTR_CASE", argv[1], 1) == 0);
    ctx.write_rc = strtol(argv[2], NULL, 10);
    ctx.recv.payload = (u_char *) "/record";
    ctx.recv.cur_dlen = scenario_is("missing") ? 0 : strlen("/record");
    ctx.metrics = calloc(1, sizeof(*ctx.metrics));
    assert(ctx.metrics != NULL);
    strcpy(config.common.root_canon, "/fixture");
    result = brix_query_xattr(&ctx, &connection, &config);
    assert(result == (scenario_is("success") ? NGX_OK : ctx.write_rc));
    assert(ctx.metrics->op_ok[BRIX_OP_QUERY_XATTR] == scenario_is("success"));
    assert(ctx.metrics->op_err[BRIX_OP_QUERY_XATTR] == !scenario_is("success"));
    free(ctx.metrics);
    return 0;
}
