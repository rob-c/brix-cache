/* Tape endpoint orchestration with observed authorization/registry seams.
 * JSON decoding, checksum/state mapping and per-file response construction stay real. */
#include "core/ngx_brix_module.h"
#include "protocols/webdav/tape_rest_internal.h"
#include <assert.h>

typedef struct {
    ngx_cycle_t cycle;
    ngx_log_t log;
    ngx_http_request_t request;
    ngx_connection_t connection;
    ngx_http_brix_webdav_loc_conf_t conf;
    ngx_http_brix_webdav_req_ctx_t context;
    const char *operation, *mode;
    unsigned auth, adds, releases, owners, mutations, residency, allocations;
    int status, request_state, resident, nearline, ready, checksum;
    json_t *reply;
    char location[128];
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return strcmp(state()->mode, name) == 0; }

brix_stage_registry_t *__wrap_tape_queue(void)
{
    return mode("no-queue") ? NULL : (brix_stage_registry_t *) state();
}
ngx_int_t __wrap_tape_send_object(ngx_http_request_t *r, ngx_int_t status, json_t *object)
{
    assert(r == &state()->request && state()->reply == NULL);
    state()->status = (int) status; state()->reply = object; return status;
}
ngx_int_t __wrap_tape_error(ngx_http_request_t *r, ngx_int_t status, const char *detail)
{
    return __wrap_tape_send_object(r, status, json_pack("{s:s}", "detail", detail));
}
ngx_int_t __wrap_brix_http_set_header(ngx_http_request_t *r, const char *key,
                                     const char *value, ngx_table_elt_t **out)
{
    assert(r == &state()->request && strcmp(key, "Location") == 0 && out == NULL);
    snprintf(state()->location, sizeof(state()->location), "%s", value);
    return NGX_OK;
}
ngx_int_t __wrap_ngx_http_send_header(ngx_http_request_t *r)
{
    assert(r->header_only && r->headers_out.content_length_n == 0);
    state()->status = (int) r->headers_out.status;
    return NGX_OK;
}

ngx_int_t __wrap_tape_authz_path(ngx_http_request_t *r,
    ngx_http_brix_webdav_loc_conf_t *conf, ngx_http_brix_webdav_req_ctx_t *ctx,
    const char *logical, int write, char *absolute, size_t capacity)
{
    fixture *f = state();
    assert(r == &f->request && conf == &f->conf && ctx == &f->context);
    assert(write == (strcmp(f->operation, "archive") != 0));
    f->auth++;
    if (strcmp(logical, "/denied") == 0 || (mode("late-deny") && f->auth > 2)) {
        return NGX_HTTP_FORBIDDEN;
    }
    assert(snprintf(absolute, capacity, "/confined%s", logical) < (int) capacity);
    return NGX_OK;
}

ngx_int_t __wrap_brix_stage_request_add(brix_stage_registry_t *registry,
    const brix_stage_request_view_t *view, char *id, size_t size, ngx_log_t *log)
{
    fixture *f = state();
    assert(registry == (brix_stage_registry_t *) f && log == &f->log);
    assert(f->auth == 2 && strncmp(view->lfn, "/confined/", 10) == 0);
    f->adds++; f->checksum = view->cs_type;
    if (view->cs_value != NULL) { assert(strcmp(view->cs_value, "abcd") == 0); }
    snprintf(id, size, "%u.44@fixture", f->adds);
    if (mode("enqueue-error")) { return NGX_ERROR; }
    return mode("active") ? NGX_DECLINED : NGX_OK;
}

static void record(brix_stage_request_t *out)
{
    memset(out, 0, sizeof(*out));
    strcpy(out->reqid, "1.44@fixture"); strcpy(out->lfn, "/confined/a");
    out->status = state()->request_state; out->tod_added = 1234;
}
ngx_int_t __wrap_brix_stage_request_get(brix_stage_registry_t *registry,
    const char *id, brix_stage_request_t *out, ngx_log_t *log)
{
    (void) registry; (void) log;
    assert(strcmp(id, "1.44@fixture") == 0);
    if (mode("missing")) { return NGX_DECLINED; }
    record(out); return NGX_OK;
}
ngx_int_t __wrap_brix_stage_request_list_active(brix_stage_registry_t *registry,
    ngx_uint_t *cursor, brix_stage_request_t *out, ngx_log_t *log)
{
    (void) registry; (void) log;
    if (*cursor >= 2 || mode("empty")) { return NGX_DECLINED; }
    record(out); out->status = (*cursor)++; return NGX_OK;
}
ngx_int_t __wrap_brix_stage_request_owner_check(brix_stage_registry_t *registry,
    const char *id, const char *dn, ngx_log_t *log)
{
    (void) registry; (void) dn; (void) log;
    assert(strcmp(id, "1.44@fixture") == 0); state()->owners++;
    return mode("foreign-owner") ? NGX_DECLINED : NGX_OK;
}
static ngx_int_t mutate(const char *id)
{
    assert(state()->owners == 1 && strcmp(id, "1.44@fixture") == 0);
    state()->mutations++;
    return mode("missing") ? NGX_DECLINED : NGX_OK;
}
ngx_int_t __wrap_brix_stage_request_cancel(brix_stage_registry_t *q, const char *id, ngx_log_t *log)
{
    (void) q; (void) log; assert(strcmp(state()->operation, "cancel") == 0); return mutate(id);
}
ngx_int_t __wrap_brix_stage_request_delete(brix_stage_registry_t *q, const char *id, ngx_log_t *log)
{
    (void) q; (void) log; assert(strcmp(state()->operation, "delete") == 0); return mutate(id);
}
ngx_int_t __wrap_brix_stage_request_pin_release(brix_stage_registry_t *q,
    const char *path, ngx_log_t *log)
{
    (void) q; (void) log;
    assert(state()->auth >= 3 && strncmp(path, "/confined/", 10) == 0);
    state()->releases++; return mode("release-error") ? NGX_ERROR : NGX_OK;
}
ngx_int_t __wrap_tape_residency(ngx_http_request_t *r, const char *path,
    brix_sd_residency_t *residency, int *nearline)
{
    (void) r; assert(strncmp(path, "/confined/", 10) == 0);
    state()->residency++; *residency = state()->resident; *nearline = state()->nearline;
    if (mode("residency-error")) { return NGX_ERROR; }
    return mode("residency-missing") ? NGX_DECLINED : NGX_OK;
}

void *__real_ngx_pcalloc(ngx_pool_t *, size_t);
void *__real_ngx_pnalloc(ngx_pool_t *, size_t);
void *__wrap_ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    if (state()->ready && mode("array-allocation")) { return NULL; }
    return __real_ngx_pcalloc(pool, size);
}
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    if (state()->ready && mode("path-allocation") && size == TAPE_PATH_MAX) { return NULL; }
    return __real_ngx_pnalloc(pool, size);
}

static ngx_int_t dispatch(fixture *f, json_t *body)
{
    if (strcmp(f->operation, "stage") == 0) {
        return tape_stage_post(&f->request, &f->conf, &f->context, body);
    }
    if (strcmp(f->operation, "release") == 0) {
        return tape_release(&f->request, &f->conf, &f->context, body);
    }
    if (strcmp(f->operation, "archive") == 0) {
        return tape_archiveinfo(&f->request, &f->conf, &f->context, body);
    }
    if (strcmp(f->operation, "get") == 0) { return tape_stage_get(&f->request, "1.44@fixture"); }
    if (strcmp(f->operation, "list") == 0) { return tape_stage_list(&f->request); }
    return tape_stage_terminate(&f->request, &f->context, "1.44@fixture",
                                strcmp(f->operation, "cancel") == 0);
}

int main(int argc, char **argv)
{
    fixture f = {0}; json_error_t error; char *output; ngx_int_t rc;
    assert(argc == 7);
    f.operation = argv[1]; f.mode = argv[2]; f.request_state = atoi(argv[4]);
    f.resident = atoi(argv[5]); f.nearline = atoi(argv[6]);
    ngx_cycle = &f.cycle; f.cycle.log = &f.log; ngx_time_init();
    f.cycle.pool = ngx_create_pool(8192, &f.log); assert(f.cycle.pool != NULL);
    f.request.pool = f.cycle.pool; f.request.connection = &f.connection;
    f.connection.log = &f.log;
    json_t *body = json_loads(argv[3], 0, &error); assert(body != NULL);
    f.ready = 1; rc = dispatch(&f, body); f.ready = 0;
    if (f.status == 0) { f.status = (int) rc; }
    printf("result=%ld status=%d auth=%u adds=%u releases=%u owners=%u mutations=%u residency=%u checksum=%d\n",
        (long) rc, f.status, f.auth, f.adds, f.releases, f.owners, f.mutations, f.residency, f.checksum);
    output = json_dumps(f.reply ? f.reply : json_null(), JSON_COMPACT | JSON_ENCODE_ANY);
    assert(output != NULL); puts(output); free(output); puts(f.location);
    json_decref(f.reply); json_decref(body); ngx_destroy_pool(f.cycle.pool);
    return 0;
}
