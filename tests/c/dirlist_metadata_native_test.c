/* Real listing accumulation and metadata parsing over finite wire responses. */
#include "brix.h"
#include "brix_net.h"
#include "brix_ops.h"
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    brix_conn connection;
    const char *mode, *operation;
    uint8_t *bytes;
    size_t length, offset, chunk;
    int receives, allocations, fail_allocation;
} fixture;
static fixture *state(void)
{
    const char *value = getenv("BRIX_DIRLIST_TEST_STATE");
    return value ? (fixture *)(uintptr_t)strtoull(value, NULL, 16) : NULL;
}
static int mode(const char *name) { return !strcmp(state()->mode, name); }
void *__real_realloc(void *, size_t);
void *__wrap_realloc(void *old, size_t size)
{
    fixture *f = state();
    if (f && ++f->allocations == f->fail_allocation) { return NULL; }
    return __real_realloc(old, size);
}
int __wrap_brix_resilient_window_ms(const brix_conn *c)
{ assert(c == &state()->connection); return 0; }
static int reply(brix_resp_out *out, brix_status *st)
{
    fixture *f = state();
    f->receives++;
    if (mode("send-error") || (mode("recv-error") && f->receives == 2)) {
        brix_status_set(st, XRDC_ESOCK, ECONNRESET, "finite transport refusal");
        return -1;
    }
    size_t n = f->length - f->offset;
    if (n > f->chunk) { n = f->chunk; }
    *out->body = n ? malloc(n) : NULL;
    assert(!n || *out->body);
    if (n) { memcpy(*out->body, f->bytes + f->offset, n); }
    f->offset += n;
    *out->blen = (uint32_t)n;
    *out->status = f->offset < f->length ? kXR_oksofar : kXR_ok;
    return 0;
}
int __wrap_brix_roundtrip(brix_conn *c, void *header, const brix_payload *payload,
    brix_resp_out *out, brix_status *st)
{
    fixture *f = state();
    ClientDirlistRequest *request = header;
    assert(c == &f->connection && f->receives == 0);
    assert(ntohs(request->requestid) == kXR_dirlist);
    const char *expected = !strcmp(f->operation, "checksum") ? "/data?cks.type=sha256" : "/data";
    assert(payload->len == strlen(expected) && !memcmp(payload->data, expected, payload->len));
    return reply(out, st);
}
int __wrap_brix_recv(brix_conn *c, uint16_t sid, brix_resp_out *out, brix_status *st)
{ assert(c == &state()->connection && sid == 0xffff); return reply(out, st); }

int main(int argc, char **argv)
{
    assert(argc == 6);
    fixture f = {0};
    f.operation = argv[1]; f.mode = argv[2]; f.chunk = strtoul(argv[4], NULL, 10);
    f.fail_allocation = atoi(argv[5]); assert(f.chunk > 0);
    FILE *input = fopen(argv[3], "rb"); assert(input);
    assert(fseek(input, 0, SEEK_END) == 0); long length = ftell(input); assert(length >= 0);
    f.length = (size_t)length; rewind(input); f.bytes = malloc(f.length + 1); assert(f.bytes);
    assert(fread(f.bytes, 1, f.length, input) == f.length); assert(fclose(input) == 0);
    char address[40]; snprintf(address, sizeof(address), "%lx", (unsigned long)(uintptr_t)&f);
    assert(setenv("BRIX_DIRLIST_TEST_STATE", address, 1) == 0);
    brix_dirent *entries = NULL; size_t count = 0, continuations = 0;
    brix_status status = {0}; int rc;
    char long_path[XRDC_PATH_MAX + 1]; memset(long_path, 'x', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = 0;
    if (!strcmp(f.operation, "checksum")) {
        const char *path = mode("null-path") ? NULL : mode("query-path") ? "/data?token=x" :
            mode("long-path") ? long_path : "/data";
        const char *algo = mode("null-algo") ? NULL : "sha256";
        rc = brix_dirlist_cksum(&f.connection, path, algo, &entries, &count, &status);
    } else {
        rc = brix_dirlist_observe(&f.connection, "/data", !strcmp(f.operation, "stat"),
            &entries, &count, &continuations, &status);
    }
    if (rc != 0) { assert(entries == NULL && count == 0); }
    printf("%d %d %zu %d %zu\n", rc, status.kxr, count, f.receives, continuations);
    for (size_t i = 0; i < count; i++) {
        printf("%s|%d|%lld|%s\n", entries[i].name, entries[i].have_stat,
            (long long)entries[i].st.size, entries[i].checksum);
    }
    free(entries); free(f.bytes); unsetenv("BRIX_DIRLIST_TEST_STATE"); return 0;
}
