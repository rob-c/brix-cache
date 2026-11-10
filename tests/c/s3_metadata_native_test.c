/* Real S3 metadata signing/parsing with a caller-supplied finite transport. */
#include <ngx_config.h>
#include <ngx_core.h>
#include "fs/backend/s3/sd_s3_list_internal.h"
#include "core/compat/crypto.h"
#include "native_alloc_fail.h"

typedef struct {
    ngx_cycle_t cycle;
    const char *action, *mode, *input;
    int status;
    unsigned requests, freed;
} fixture;
static fixture *state(void) { return (fixture *) ngx_cycle; }
static int mode(const char *name) { return state() && !strcmp(state()->mode, name); }
int __real_sd_s3_sign(const sd_s3_file *, const char *, const char *, char *, size_t);
int __wrap_sd_s3_sign(const sd_s3_file *f, const char *method, const char *query, char *out, size_t size)
{ return mode("sign") ? -1 : __real_sd_s3_sign(f, method, query, out, size); }
int __real_sd_s3_sign_ext(const sd_s3_file *, const sd_s3_sign_req_t *, char *, size_t);
int __wrap_sd_s3_sign_ext(const sd_s3_file *f, const sd_s3_sign_req_t *request, char *out, size_t size)
{ return mode("sign") ? -1 : __real_sd_s3_sign_ext(f, request, out, size); }

static int request(void *context, const char *host, int port, int tls,
    const char *verb, const char *path, const char *headers, const void *body,
    size_t length, int timeout, brix_s3_resp_t *response, char *error, size_t capacity)
{
    (void) error; (void) capacity;
    assert(context == state() && !strcmp(host, "origin.invalid") && port == 443 && tls == 1);
    assert(timeout == 1000 && !strncmp(path, "/bucket/object", 14));
    assert(strstr(headers, "AWS4-HMAC-SHA256") && strstr(headers, "SignedHeaders="));
    if (!strcmp(state()->action, "set")) {
        assert(!strcmp(verb, "PUT") && body == NULL && length == 0);
        assert(strstr(headers, "x-amz-metadata-directive: REPLACE"));
        assert(strstr(headers, "x-amz-meta-color: blue"));
    }
    state()->requests++;
    if (mode("transport")) { errno = EIO; return -1; }
    response->status = state()->status; response->opaque = state(); return 0;
}
static int response_header(const brix_s3_resp_t *response, const char *name, char *out, size_t capacity)
{
    assert(response->opaque == state());
    if (mode("absent")) { return -1; }
    const char *value = !strcmp(name, "x-amz-meta-color") ? "blue" : state()->input;
    if (strlen(value) >= capacity) { return -1; }
    strcpy(out, value); return 0;
}
static const char *raw_headers(const brix_s3_resp_t *response)
{ assert(response->opaque == state()); return mode("no-raw") ? NULL : state()->input; }
static void response_free(brix_s3_resp_t *response)
{ assert(response->opaque == state()); response->opaque = NULL; state()->freed++; }

static void hex(const char *data, size_t size)
{
    printf("hex=");
    for (size_t i = 0; i < size; ++i) { printf("%02x", (unsigned char) data[i]); }
    putchar('\n');
}
/* WHAT: Call the bounded XML and canonical-query helpers directly.
 * WHY: Hostile origin text must not overrun buffers or alter query ordering.
 * HOW: The Python oracle supplies independent expected UTF-8 and URL encodings. */
static long parse(const char *action, char *out, size_t capacity, int argument)
{
    const char *input = state()->input; char error[256];
    if (!strcmp(action, "xml")) {
        return sd_s3l_xml_unescape(input, input + strlen(input), out, capacity);
    }
    if (!strcmp(action, "query")) {
        long rc = sd_s3l_build_query_limit(input, strlen(input), state()->mode,
            1, (unsigned) argument, out, capacity, error, sizeof(error));
        return rc ? rc : (long) strlen(out);
    }
    int truncated = 0;
    sd_s3l_page_meta(input, input + strlen(input), &truncated, out, capacity);
    printf("truncated=%d\n", truncated); return (long) strlen(out);
}
static long read_meta(sd_s3_file *file, char *out, size_t capacity)
{
    char error[256]; sd_s3_meta_buf result = {out, capacity};
    const sd_s3_meta_buf *destination = mode("null-out") ? NULL : &result;
    const char *name = mode("null-name") ? NULL : mode("long-name") ? state()->input : "color";
    if (mode("null-file")) { file = NULL; }
    if (mode("null-buffer")) { result.buf = NULL; }
    if (!strcmp(state()->action, "get")) {
        return sd_s3_get_meta(file, name, destination, error, sizeof(error));
    }
    if (!strcmp(state()->action, "checksum")) {
        return sd_s3_get_checksum(file, name, destination, error, sizeof(error));
    }
    if (!strcmp(state()->action, "list")) {
        return sd_s3_list_meta(file, mode("probe") ? NULL : out, capacity, error, sizeof(error));
    }
    brix_meta_advisory_t metadata = {0};
    long rc = sd_s3_get_unixattr(file, mode("null-out") ? NULL : &metadata, error, sizeof(error));
    if (mode("unknown-fields")) {
        assert(rc == 1 && !metadata.have_mode && !metadata.have_owner && !metadata.have_mtime);
    }
    return rc;
}
static long write_meta(sd_s3_open_params *params)
{
    char error[256]; const char *action = state()->action;
    if (mode("null-params")) { params = NULL; }
    if (!strcmp(action, "copy")) {
        return sd_s3_copy(params, mode("null-source") ? NULL : state()->input, error, sizeof(error));
    }
    if (!strcmp(action, "restore")) { return sd_s3_restore(params, 3, error, sizeof(error)); }
    if (!strcmp(action, "set-unix")) {
        brix_meta_advisory_t metadata = {.have_mode = 1, .mode = 0600};
        return sd_s3_set_unixattr(params, mode("null-out") ? NULL : &metadata, error, sizeof(error));
    }
    sd_s3_meta_kv pairs[33];
    for (size_t i = 0; i < 33; i++) { pairs[i] = (sd_s3_meta_kv) {"COLOR", "blue"}; }
    if (mode("null-name")) { pairs[0].name = NULL; }
    if (mode("null-value")) { pairs[0].value = NULL; }
    if (mode("long-name")) { pairs[0].name = state()->input; }
    return sd_s3_set_meta(params, pairs, mode("too-many") ? 33 : 1, error, sizeof(error));
}
int main(int argc, char **argv)
{
    assert(argc == 7); fixture f = {0}; f.action = argv[1]; f.mode = argv[2]; f.input = argv[3];
    f.status = atoi(argv[4]); ngx_cycle = &f.cycle;
    char output[8192] = {0}; size_t capacity = (size_t) atoi(argv[5]); assert(capacity <= sizeof(output));
    long rc;
    if (!strcmp(f.action, "xml") || !strcmp(f.action, "query") || !strcmp(f.action, "page")) {
        rc = parse(f.action, output, capacity, atoi(argv[6]));
    } else {
        assert(brix_crypto_init());
        brix_s3_transport_t transport = {.request = request, .resp_header = response_header,
            .resp_headers_raw = raw_headers, .resp_free = response_free};
        if (mode("no-enumerator")) { transport.resp_headers_raw = NULL; }
        sd_s3_open_params params = {.host = "origin.invalid", .port = 443, .tls = 1,
            .key = "/bucket/object", .ak = "fixture", .sk = "fixture-secret", .region = "test-1",
            .transport = &transport, .tctx = &f, .timeout_ms = 1000};
        if (!strcmp(f.action, "get") || !strcmp(f.action, "checksum") || !strcmp(f.action, "list") || !strcmp(f.action, "get-unix")) {
            char error[256]; sd_s3_file *file = sd_s3_open_read(&params, error, sizeof(error)); assert(file);
            rc = read_meta(file, output, capacity); sd_s3_close(file);
        } else {
            if (mode("allocation")) { native_alloc_arm("calloc", 0); }
            rc = write_meta(&params); native_alloc_disarm();
        }
    }
    printf("rc=%ld\nerrno=%d\nrequests=%u\nfreed=%u\n", rc, errno, f.requests, f.freed);
    if (rc > 0 && strcmp(f.mode, "probe") && (size_t) rc <= sizeof(output)) { hex(output, (size_t) rc); }
    ngx_cycle = NULL; return 0;
}
