/* Real OCI verbs and upload callbacks, with scripted HTTP responses. */
#include "oci/reg_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    brix_oci_reg_t registry;
    const char *directory;
    unsigned calls;
} registry_fixture_t;

/* WHAT: Read one optional script value. WHY: Tests control transport, not verb logic.
 * HOW: Read a bounded ordinary file in the caller's private directory. */
static char *script(const char *directory, const char *key)
{
    char path[4096]; snprintf(path, sizeof(path), "%s/%s", directory, key);
    FILE *file = fopen(path, "rb");
    if (file == NULL) { assert(errno == ENOENT); return NULL; }
    assert(fseek(file, 0, SEEK_END) == 0); long size = ftell(file);
    assert(size >= 0 && size <= 65536 && fseek(file, 0, SEEK_SET) == 0);
    char *body = malloc((size_t)size + 1); assert(body);
    assert(fread(body, 1, (size_t)size, file) == (size_t)size);
    body[size] = '\0'; assert(fclose(file) == 0); return body;
}

/* WHAT: Select one response component. WHY: Each request has its own response.
 * HOW: Prefix its filename with a caller-owned request counter. */
static char *response_part(registry_fixture_t *fixture, const char *kind)
{
    char key[64]; snprintf(key, sizeof(key), "%u.%s", fixture->calls, kind);
    return script(fixture->directory, key);
}

/* WHAT: Supply an owned HTTP reply at the transport boundary.
 * WHY: Invalid replies must exercise the real parsing, digest and ownership code.
 * HOW: Record the request; publish explicit status, headers and owned body. */
int __wrap_regc_call(brix_oci_reg_t *registry, const char *method, const char *path,
                     const char *scope, const char *extra, const void *body,
                     size_t length, brix_http_resp *response, char *error, size_t cap)
{
    registry_fixture_t *fixture = (registry_fixture_t *)registry;
    assert(!strncmp(scope, "repository:lab/app:", strlen("repository:lab/app:")));
    assert(!strncmp(path, "/v2/lab/app/", strlen("/v2/lab/app/")));
    if (!strcmp(method, "PUT")) {
        assert(extra && strstr(extra, "Content-Type:") && length == 7);
        assert(!memcmp(body, "payload", 7));
    }
    printf("request=%s %s\n", method, path);
    char *result = response_part(fixture, "result");
    if (result) {
        int rc = atoi(result); free(result); fixture->calls++;
        snprintf(error, cap, "scripted transport refusal"); return rc;
    }
    memset(response, 0, sizeof(*response));
    char *status = response_part(fixture, "status"); assert(status);
    response->status = atoi(status); free(status);
    char *headers = response_part(fixture, "headers");
    if (headers) { snprintf(response->headers, sizeof(response->headers), "%s", headers); free(headers); }
    response->body = response_part(fixture, "body");
    if (response->body) { response->body_len = strlen(response->body); }
    char *fault = response_part(fixture, "fault");
    if (fault) { assert(setenv("BRIX_REGISTRY_ALLOC_FAULT", fault, 1) == 0); free(fault); }
    fixture->calls++; return BRIX_OCI_REG_OK;
}

/* WHAT: Refuse one output allocation after response construction.
 * WHY: OOM must not publish a partially owned tag listing.
 * HOW: Consume the selected process-local flag; leave cleanup allocations real. */
static int allocation_fault(const char *operation)
{
    const char *armed = getenv("BRIX_REGISTRY_ALLOC_FAULT");
    if (armed == NULL || strcmp(armed, operation)) { return 0; }
    assert(unsetenv("BRIX_REGISTRY_ALLOC_FAULT") == 0); return 1;
}
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void *__wrap_calloc(size_t count, size_t size) {
    return allocation_fault("calloc") ? NULL : __real_calloc(count, size);
}
void *__wrap_realloc(void *pointer, size_t size) {
    return allocation_fault("realloc") ? NULL : __real_realloc(pointer, size);
}

/* WHAT: Observe an upload and execute the real file-source callback.
 * WHY: Source errors, session URLs and digest queries must reach the verb layer.
 * HOW: Read callback bytes, then supply the scripted HTTP or transport status. */
int __wrap_brix_http_upload(const char *host, int port, int tls, const char *path,
    const char *headers, brix_http_body_src_fn source, void *source_context,
    long long length, int verify, const char *ca, const char *certificate,
    int timeout, int *status, brix_status *error)
{
    (void)verify; (void)ca; (void)certificate; (void)timeout;
    assert(!strcmp(host, "registry.test") && port == 5000 && !tls && length == 7);
    assert(strstr(headers, "Content-Type: application/octet-stream"));
    assert(strstr(path, "digest=sha256%3A")); printf("upload=%s\n", path);
    uint8_t bytes[16]; ssize_t count = source(source_context, bytes, 0, sizeof(bytes), error);
    if (count < 0) { return -1; }
    assert(count == 7 && !memcmp(bytes, "payload", 7));
    const char *directory = getenv("BRIX_REGISTRY_SCRIPT"); assert(directory);
    char *result = script(directory, "upload.result");
    if (result) {
        free(result); brix_status_set(error, XRDC_ESOCK, EIO, "scripted upload error"); return -1;
    }
    char *reply = script(directory, "upload.status"); assert(reply);
    *status = atoi(reply); free(reply); return 0;
}

/* WHAT: Fetch or resolve a manifest and inspect owned output.
 * WHY: Success must contain verified bytes; failure must retain no body.
 * HOW: Call the real digest/JSON logic, report its descriptor, then free it. */
static int manifest(registry_fixture_t *fixture, brix_oci_ref_t *ref,
                     const char *verb, const char *parameter, char *error, size_t cap)
{
    brix_oci_desc_t desc; int rc;
    if (!strcmp(verb, "resolve")) {
        const char *platform = !strcmp(parameter, "default") ? NULL : parameter;
        rc = brix_oci_reg_resolve(&fixture->registry, ref, platform, &desc, error, cap);
    } else { rc = brix_oci_reg_manifest(&fixture->registry, ref, NULL, &desc, error, cap); }
    if (rc == 0) { printf("body=%s\nmedia=%s\ndigest=%s\n", desc.body, desc.mediatype, desc.digest); }
    else { assert(desc.body == NULL); }
    brix_oci_desc_free(&desc); return rc;
}

/* WHAT: Invoke a registry verb. WHY: Each API has its own output ownership.
 * HOW: Free returned listings and close only the fixture-owned upload source. */
static int invoke(registry_fixture_t *fixture, brix_oci_ref_t *ref,
                   const char *verb, const char *parameter, char *error, size_t cap)
{
    if (!strcmp(verb, "manifest") || !strcmp(verb, "resolve")) {
        return manifest(fixture, ref, verb, parameter, error, cap);
    }
    if (!strcmp(verb, "tags")) {
        char *tags = NULL; int rc = brix_oci_reg_tags(&fixture->registry, ref->name, &tags, error, cap);
        if (rc == 0) { assert(tags); printf("tags=%s\n", tags); }
        else { assert(tags == NULL); }
        free(tags); return rc;
    }
    if (!strcmp(verb, "put")) {
        return brix_oci_reg_manifest_put(&fixture->registry, ref, parameter, "payload", 7, error, cap);
    }
    if (!strcmp(verb, "delete")) {
        return brix_oci_reg_manifest_del(&fixture->registry, ref, error, cap);
    }
    assert(!strcmp(verb, "push")); char path[4096];
    snprintf(path, sizeof(path), "%s/source", fixture->directory);
    int fd = open(path, O_RDONLY);
    assert(setenv("BRIX_REGISTRY_SCRIPT", fixture->directory, 1) == 0);
    int rc = brix_oci_reg_blob_push(&fixture->registry, ref->name, parameter, fd, 7, error, cap);
    if (fd >= 0) { close(fd); } return rc;
}

/* WHAT: Run one isolated script. WHY: No registry or personal credentials are needed.
 * HOW: Parse a public ref, configure its endpoint, then assert result and call count. */
int main(int argc, char **argv)
{
    assert(argc == 7); registry_fixture_t fixture = {0}; brix_oci_ref_t ref;
    char error[512] = {0}, name[512]; fixture.directory = argv[6];
    assert(brix_oci_ref_parse(argv[2], &ref, error, sizeof(error)) == 0);
    assert(brix_oci_reg_from_ref(&fixture.registry, &ref, 1, name, sizeof(name), error, sizeof(error)) == 0);
    int rc = invoke(&fixture, &ref, argv[1], argv[3], error, sizeof(error));
    printf("result=%d\ncalls=%u\nerror=%s\n", rc, fixture.calls, error);
    assert(rc == atoi(argv[4]) && fixture.calls == (unsigned)atoi(argv[5]));
    assert(getenv("BRIX_REGISTRY_ALLOC_FAULT") == NULL);
    if (rc != 0) { assert(error[0]); } return 0;
}

