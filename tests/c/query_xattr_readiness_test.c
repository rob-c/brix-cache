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

/* WHAT: Return the deterministic base metadata length used by the fixture.
 * WHY: Exact-fit coverage must derive the boundary rather than hard-code it.
 * HOW: Format the handler's fixed fields with the fixture metadata values. */
static size_t
fixture_base_length(void)
{
    char scratch[512];
    int  written;

    written = snprintf(scratch, sizeof(scratch),
                       "oss.cgroup=default&oss.type=f&oss.used=7"
                       "&oss.mt=0&oss.ct=0&oss.at=0"
                       "&oss.u=*&oss.g=*&oss.fs=w");
    assert(written > 0 && (size_t) written < sizeof(scratch));
    return (size_t) written;
}

/* WHAT: Return the fourth value length that exactly fills the response.
 * WHY: The last initialized byte and the first rejected byte need distinct tests.
 * HOW: Subtract the base and three maximum pairs from the text capacity. */
static size_t
fixture_exact_fourth_length(void)
{
    static const char *const first_names[] = {
        "user.U.first", "user.U.second", "user.U.third",
    };
    static const char fourth_name[] = "user.U.fourth";
    size_t used = fixture_base_length();
    size_t index;
    size_t overhead;

    for (index = 0; index < sizeof(first_names) / sizeof(first_names[0]);
         index++)
    {
        used += 2 + strlen(first_names[index] + 5)
                + BRIX_ROOT_FATTR_VAL_BUF / 4 - 1;
    }
    overhead = 2 + strlen(fourth_name + 5);
    assert(used + overhead < BRIX_ROOT_FATTR_VAL_BUF - 1);
    return BRIX_ROOT_FATTR_VAL_BUF - 1 - used - overhead;
}

ngx_int_t
brix_send_error(brix_ctx_t *ctx, ngx_connection_t *connection,
    uint16_t code, const char *message)
{
    if (scenario_is("overflow") || scenario_is("one_over")) {
        assert(code == kXR_ArgTooLong);
    }
    if (scenario_is("malformed_list") || scenario_is("oversized_value")) {
        assert(code == kXR_IOError);
    }
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

/* WHAT: Abort if the unit unexpectedly enters a handle-based query.
 * WHY: ELF sanitizer runtimes may retain those unrelated TU functions.
 * HOW: Supply only their unreachable boundary, never a successful validator. */
ngx_flag_t
brix_validate_file_handle(brix_ctx_t *ctx, ngx_connection_t *connection,
    int handle_index, const char *verb, ngx_uint_t operation, ngx_int_t *result)
{
    abort();
}

int
brix_vfs_open_fd(ngx_log_t *log, const char *root, const char *path,
    int flags, mode_t mode)
{
    abort();
}

ssize_t
brix_vfs_listxattr(brix_vfs_ctx_t *vfs, void *buffer, size_t capacity)
{
    static const char overflow_names[] =
        "user.U.first\0user.U.second\0user.U.third\0user.U.fourth\0";

    puts("list");
    if (scenario_is("malformed_list")) {
        static const char malformed_name[] = "user.U.unterminated";

        assert(capacity >= sizeof(malformed_name) - 1);
        memcpy(buffer, malformed_name, sizeof(malformed_name) - 1);
        return (ssize_t) (sizeof(malformed_name) - 1);
    }
    if (scenario_is("oversized_value") || scenario_is("embedded_nul")) {
        static const char one_name[] = "user.U.edge\0";

        assert(capacity >= sizeof(one_name) - 1);
        memcpy(buffer, one_name, sizeof(one_name) - 1);
        return (ssize_t) (sizeof(one_name) - 1);
    }
    if (scenario_is("overflow") || scenario_is("exact")
        || scenario_is("one_over"))
    {
        assert(capacity >= sizeof(overflow_names));
        memcpy(buffer, overflow_names, sizeof(overflow_names) - 1);
        return (ssize_t) (sizeof(overflow_names) - 1);
    }
    return 0;
}

ssize_t
brix_vfs_getxattr(brix_vfs_ctx_t *vfs, const char *name,
    void *buffer, size_t capacity)
{
    if (scenario_is("oversized_value")) {
        puts("get");
        return (ssize_t) capacity + 1;
    }
    if (scenario_is("embedded_nul")) {
        static const char value[] = "visible\0hidden";

        puts("get");
        assert(capacity >= sizeof(value) - 1);
        memcpy(buffer, value, sizeof(value) - 1);
        return (ssize_t) (sizeof(value) - 1);
    }
    if (scenario_is("overflow") || scenario_is("exact")
        || scenario_is("one_over"))
    {
        size_t value_length = capacity;

        puts("get");
        assert(strncmp(name, "user.U.", 7) == 0);
        if (strcmp(name, "user.U.fourth") == 0 && !scenario_is("overflow")) {
            value_length = fixture_exact_fourth_length()
                           + (size_t) scenario_is("one_over");
        }
        assert(value_length <= capacity);
        memset(buffer, 'V', value_length);
        return (ssize_t) value_length;
    }
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
    assert(length <= BRIX_ROOT_FATTR_VAL_BUF);
    assert(((const char *) body)[length - 1] == '\0');
    assert(length == strlen(body) + 1);
    assert(strstr(body, "oss.type=f&oss.used=7") != NULL);
    if (scenario_is("exact")) {
        assert(length == BRIX_ROOT_FATTR_VAL_BUF);
    }
    if (scenario_is("embedded_nul")) {
        assert(strstr(body, "&U.edge=visible") != NULL);
        assert(strstr(body, "hidden") == NULL);
    }
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
    int success;

    assert(argc == 3);
    assert(setenv("BRIX_XATTR_CASE", argv[1], 1) == 0);
    ctx.write_rc = strtol(argv[2], NULL, 10);
    ctx.recv.payload = (u_char *) "/record";
    ctx.recv.cur_dlen = scenario_is("missing") ? 0 : strlen("/record");
    ctx.metrics = calloc(1, sizeof(*ctx.metrics));
    assert(ctx.metrics != NULL);
    strcpy(config.common.root_canon, "/fixture");
    result = brix_query_xattr(&ctx, &connection, &config);
    success = scenario_is("success") || scenario_is("exact")
              || scenario_is("embedded_nul");
    assert(result == (success ? NGX_OK : ctx.write_rc));
    assert(ctx.metrics->op_ok[BRIX_OP_QUERY_XATTR] ==
           (uint64_t) success);
    assert(ctx.metrics->op_err[BRIX_OP_QUERY_XATTR] ==
           (uint64_t) !success);
    free(ctx.metrics);
    return 0;
}
