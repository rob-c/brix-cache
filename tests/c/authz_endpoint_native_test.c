/* Gate-only endpoints must retain access verdicts and expose subjects only. */
#include "protocols/webdav/authz_endpoint.h"
#include "protocols/webdav/webdav_module_internal.h"
#include <assert.h>
#include <stdlib.h>

typedef struct {
    int access_status, access_calls, sent, redirects, list_calls, fail_header;
    const char *mode;
} fixture;
static fixture *state(ngx_http_request_t *r) { return r->connection->data; }

ngx_int_t __wrap_ngx_http_brix_webdav_access_handler(ngx_http_request_t *r) {
    fixture *f = state(r); f->access_calls++; return f->access_status;
}
ngx_int_t __wrap_ngx_http_send_header(ngx_http_request_t *r) {
    fixture *f = state(r); f->sent++;
    assert(r->headers_out.status == 204 && r->headers_out.content_length_n == 0);
    assert(r->header_only);
    return strcmp(f->mode, "send-error") == 0 ? NGX_ERROR : NGX_OK;
}
ngx_int_t __wrap_ngx_http_internal_redirect(ngx_http_request_t *r,
    ngx_str_t *uri, ngx_str_t *args) {
    fixture *f = state(r); f->redirects++;
    const char expected[] = "/internal/safe/object x";
    assert(uri->len == sizeof(expected) - 1 && memcmp(uri->data, expected, sizeof(expected) - 1) == 0);
    assert(args == &r->args && args->len == 3 && memcmp(args->data, "x=1", 3) == 0);
    return NGX_DONE;
}
void *__real_ngx_pnalloc(ngx_pool_t *, size_t);
void *__wrap_ngx_pnalloc(ngx_pool_t *pool, size_t size) {
    fixture *f = pool->log->data;
    return strcmp(f->mode, "allocation") == 0 ? NULL : __real_ngx_pnalloc(pool, size);
}
void *__real_ngx_list_push(ngx_list_t *);
void *__wrap_ngx_list_push(ngx_list_t *list) {
    fixture *f = list->pool->log->data;
    if (f->list_calls++ == f->fail_header) { return NULL; }
    return __real_ngx_list_push(list);
}

static void identity_headers(ngx_http_request_t *r, int expected) {
    unsigned count = 0;
    for (ngx_list_part_t *part = &r->headers_out.headers.part; part; part = part->next) {
        ngx_table_elt_t *headers = part->elts;
        for (unsigned i = 0; i < part->nelts; i++) {
            ngx_table_elt_t *h = &headers[i];
            assert(h->hash && h->key.len >= 7 && memcmp(h->key.data, "X-Brix-", 7) == 0);
            assert(h->value.len == 7 && memcmp(h->value.data, "subject", 7) == 0);
            printf("HEADER %.*s\n", (int) h->key.len, h->key.data); count++;
        }
    }
    assert(count == (unsigned) expected);
}

static int expected_headers(fixture *f, int admitted) {
    if (!admitted || !strcmp(f->mode, "allocation") || !strcmp(f->mode, "neither")) { return 0; }
    if (!strcmp(f->mode, "anonymous") || !strcmp(f->mode, "no-context")
        || !strcmp(f->mode, "empty")) { return 0; }
    return f->fail_header < 0 ? 4 : f->fail_header;
}
static void check(ngx_http_request_t *r, fixture *f, int accel, int sub, int expected) {
    ngx_http_brix_webdav_loc_conf_t config = {0};
    config.authz_endpoint = !accel;
    ngx_str_set(&config.accel_redirect, "/internal");
    if (strcmp(f->mode, "neither") == 0) {
        config.authz_endpoint = 0; config.accel_redirect.len = 0;
    }
    ngx_int_t rc = webdav_gate_only_dispatch(r, &config);
    assert(rc == expected);
    int admitted = !sub || f->access_status == NGX_OK;
    int published = admitted && f->fail_header < 0
        && strcmp(f->mode, "allocation") && strcmp(f->mode, "neither");
    assert(f->sent == (published && !accel));
    assert(f->redirects == (published && accel));
    int access = sub && strcmp(f->mode, "neither") && !(accel && !strcmp(f->mode, "allocation"));
    assert(f->access_calls == access);
    identity_headers(r, expected_headers(f, admitted));
    printf("rc=%ld access=%d sent=%d redirects=%d\n", (long) rc,
           f->access_calls, f->sent, f->redirects);
}

int main(int argc, char **argv) {
    assert(argc == 7);
    fixture f = {.mode = argv[1], .access_status = atoi(argv[4]), .fail_header = atoi(argv[5])};
    int accel = atoi(argv[2]), sub = atoi(argv[3]);
    ngx_log_t log = {.data = &f}; ngx_time_init();
    ngx_pool_t *pool = ngx_create_pool(4096, &log); assert(pool);
    ngx_connection_t connection = {.log = &log, .data = &f};
    ngx_http_request_t request = {.pool = pool, .connection = &connection}, parent = {0};
    request.main = sub ? &parent : &request;
    ngx_str_set(&request.uri, "/safe/object x"); ngx_str_set(&request.args, "x=1");
    assert(ngx_list_init(&request.headers_out.headers, pool, 1, sizeof(ngx_table_elt_t)) == NGX_OK);
    ngx_http_brix_webdav_module.ctx_index = 0;
    ngx_http_brix_webdav_req_ctx_t context = {0}; void *contexts[] = {&context};
    request.ctx = contexts;
    brix_identity_t identity = {0}; context.identity = &identity;
    ngx_str_set(&identity.creds, "secret bearer credential");
    ngx_str_set(&identity.endorsements, "private credential endorsement");
    ngx_str_set(&identity.dn, "subject"); identity.subject = identity.dn;
    identity.issuer = identity.dn; identity.vo_csv = identity.dn;
    if (!strcmp(f.mode, "empty")) {
        identity.dn.len = identity.subject.len = identity.issuer.len = identity.vo_csv.len = 0;
    }
    if (!strcmp(f.mode, "anonymous")) { context.identity = NULL; }
    if (!strcmp(f.mode, "no-context")) { contexts[0] = NULL; }
    check(&request, &f, accel, sub, atoi(argv[6]));
    ngx_destroy_pool(pool); return 0;
}
