/* Real OCI layouts: byte integrity, atomic index replacement and failed ownership. */
#include "oci/layout.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* WHAT: Consume a single explicitly armed fault. WHY: Cleanup must remain real.
 * HOW: Clear the environment flag before returning an I/O or allocation error. */
static int fail(const char *operation)
{
    const char *mode = getenv("BRIX_LAYOUT_FAULT");
    if (mode == NULL || strcmp(mode, operation)) { return 0; }
    assert(unsetenv("BRIX_LAYOUT_FAULT") == 0);
    errno = !strcmp(operation, "malloc") ? ENOMEM : EIO;
    return 1;
}

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
ssize_t __real_read(int, void *, size_t);
ssize_t __real_write(int, const void *, size_t);
int __real_fsync(int);
int __real_fchmod(int, mode_t);
int __real_rename(const char *, const char *);

/* WHAT: Allocation refusals. WHY: Owned buffers must unwind at each stage.
 * HOW: Otherwise call the original allocator with its exact arguments. */
void *__wrap_malloc(size_t size) { return fail("malloc") ? NULL : __real_malloc(size); }
void *__wrap_calloc(size_t n, size_t size) {
    return fail("calloc") ? NULL : __real_calloc(n, size);
}
void *__wrap_realloc(void *ptr, size_t size) {
    return fail("realloc") ? NULL : __real_realloc(ptr, size);
}

/* WHAT: Interrupt file transfer or publication. WHY: Failures must not publish data.
 * HOW: Only the armed operation fails, including an unexpected early read EOF. */
ssize_t __wrap_read(int fd, void *data, size_t size) {
    if (fail("short")) { return 0; }
    return fail("read") ? -1 : __real_read(fd, data, size);
}
ssize_t __wrap_write(int fd, const void *data, size_t size) {
    return fail("write") ? -1 : __real_write(fd, data, size);
}
int __wrap_fsync(int fd) { return fail("fsync") ? -1 : __real_fsync(fd); }
int __wrap_fchmod(int fd, mode_t mode) {
    return fail("fchmod") ? -1 : __real_fchmod(fd, mode);
}
int __wrap_rename(const char *from, const char *to) {
    return fail("rename") ? -1 : __real_rename(from, to);
}

/* WHAT: Initialize a real content-addressed object. WHY: Every case needs real bytes.
 * HOW: Store a fixed payload and keep its computed digest for later assertions. */
static void seed(brix_oci_layout_t *layout, const char *dir, char *digest)
{
    char err[512];
    assert(brix_oci_layout_open(layout, dir, 1, err, sizeof(err)) == 0);
    assert(brix_oci_layout_blob_put_mem(layout, "payload", 7, digest, 80,
                                       err, sizeof(err)) == 0);
}

/* WHAT: Verify successful storage and both digest-integrity gates.
 * WHY: A pathname digest cannot authenticate modified content by itself.
 * HOW: Read the original bytes, alter the on-disk blob, and require verification errors. */
static void roundtrip(brix_oci_layout_t *layout, const char *digest)
{
    char err[512], *body = NULL, bytes[8], path[1200];
    size_t length = 0; long long size = -1;
    assert(brix_oci_layout_blob_load(layout, digest, 7, &body, &length, err, sizeof(err)) == 0);
    assert(length == 7 && !memcmp(body, "payload", 8)); free(body);
    assert(brix_oci_layout_blob_verify(layout, digest, &size, err, sizeof(err)) == 0);
    assert(size == 7);
    int fd = brix_oci_layout_blob_open(layout, digest, err, sizeof(err));
    assert(fd >= 0 && read(fd, bytes, sizeof(bytes)) == 7);
    assert(!memcmp(bytes, "payload", 7)); close(fd);
    assert(brix_oci_layout_blob_load(layout, digest, 6, &body, &length, err, sizeof(err))
           == BRIX_OCI_REG_ETRANSPORT && body == NULL);
    snprintf(path, sizeof(path), "%s/blobs/sha256/%s", layout->dir, digest + 7);
    fd = open(path, O_WRONLY); assert(fd >= 0 && write(fd, "changed", 7) == 7); close(fd);
    assert(brix_oci_layout_blob_verify(layout, digest, NULL, err, sizeof(err))
           == BRIX_OCI_REG_EVERIFY);
    assert(brix_oci_layout_blob_load(layout, digest, 7, &body, &length, err, sizeof(err))
           == BRIX_OCI_REG_EVERIFY && body == NULL);
}

/* WHAT: Reject hostile digest names and undersized caller buffers.
 * WHY: Invalid inputs must not escape the blob store or leave a staged file.
 * HOW: Exercise every public digest consumer and inspect stage ownership. */
static void invalid(brix_oci_layout_t *layout)
{
    char err[512], temp[1200], digest[80], *body = NULL; size_t length = 0;
    const char *bad = "sha256:../../outside";
    assert(brix_oci_layout_blob_open(layout, bad, err, sizeof(err)) == BRIX_OCI_REG_EPROTO);
    assert(brix_oci_layout_blob_verify(layout, bad, NULL, err, sizeof(err)) == BRIX_OCI_REG_EPROTO);
    assert(brix_oci_layout_blob_load(layout, bad, 20, &body, &length, err, sizeof(err))
           == BRIX_OCI_REG_EPROTO && body == NULL);
    assert(brix_oci_layout_stage(layout, temp, 1, err, sizeof(err)) == BRIX_OCI_REG_EPROTO);
    int fd = brix_oci_layout_stage(layout, temp, sizeof(temp), err, sizeof(err));
    assert(fd >= 0); close(fd);
    assert(brix_oci_layout_commit(layout, temp, bad, err, sizeof(err)) == BRIX_OCI_REG_EPROTO);
    assert(access(temp, F_OK) == -1 && errno == ENOENT);
    assert(brix_oci_layout_blob_put_mem(layout, "bytes", 5, digest, 1, err, sizeof(err))
           == BRIX_OCI_REG_EPROTO);
}

/* WHAT: Keep tagged and untagged index entries independently addressable.
 * WHY: Replacing one reference must preserve other references and unknown metadata.
 * HOW: Insert and replace entries, then resolve each and inspect the listing. */
static void index_roundtrip(brix_oci_layout_t *layout, const char *digest)
{
    char err[512], out[80], type[128], *listing;
    const char *media = "application/vnd.oci.image.manifest.v1+json";
    assert(brix_oci_layout_index_get(layout, NULL, out, sizeof(out), type, sizeof(type),
                                     err, sizeof(err)) == BRIX_OCI_REG_ENOTFOUND);
    const char *refs[] = {"v1", "v2", "v1", NULL, NULL};
    for (size_t i = 0; i < sizeof(refs) / sizeof(refs[0]); ++i) {
        assert(brix_oci_layout_index_set(layout, refs[i], digest, media, 7, err, sizeof(err)) == 0);
    }
    assert(brix_oci_layout_index_get(layout, "v1", out, sizeof(out), type, sizeof(type),
                                     err, sizeof(err)) == 0);
    assert(!strcmp(out, digest) && !strcmp(type, media));
    assert(brix_oci_layout_index_get(layout, "absent", out, sizeof(out), type, sizeof(type),
                                     err, sizeof(err)) == BRIX_OCI_REG_ENOTFOUND);
    assert(brix_oci_layout_ls(layout, &listing, err, sizeof(err)) == 0);
    assert(strstr(listing, "v1 sha256:") && strstr(listing, "v2 sha256:")
           && strstr(listing, "- sha256:")); free(listing);
}

/* WHAT: Reject index text injection. WHY: Caller fields are embedded in JSON.
 * HOW: Supply invalid tags, digest traversals and unsafe media-type bytes. */
static void index_invalid(brix_oci_layout_t *layout, const char *digest)
{
    char err[512], *listing;
    assert(brix_oci_layout_index_set(layout, "../escape", digest, "text/plain", 7,
                                     err, sizeof(err)) == BRIX_OCI_REG_EPROTO);
    assert(brix_oci_layout_index_set(layout, "v1", "sha256:../escape", "text/plain", 7,
                                     err, sizeof(err)) == BRIX_OCI_REG_EPROTO);
    const char *bad[] = {"a\"b", "a\\b", "a\nb", "a\xff"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        assert(brix_oci_layout_index_set(layout, "v1", digest, bad[i], 7,
                                         err, sizeof(err)) == BRIX_OCI_REG_EPROTO);
    }
    assert(brix_oci_layout_ls(layout, &listing, err, sizeof(err)) == 0);
    assert(listing[0] == '\0'); free(listing);
}

/* WHAT: Dispatch one failed operation. WHY: Each public ownership boundary differs.
 * HOW: Invoke the requested operation and require a transport error. */
static void operation_failure(brix_oci_layout_t *layout, const char *digest, const char *mode)
{
    char err[512], output[80], *body = NULL; size_t length = 0;
    int rc;
    if (!strncmp(mode, "load-", 5)) {
        rc = brix_oci_layout_blob_load(layout, digest, 7, &body, &length, err, sizeof(err));
        assert(body == NULL);
    } else if (!strncmp(mode, "verify-", 7)) {
        rc = brix_oci_layout_blob_verify(layout, digest, NULL, err, sizeof(err));
    } else if (!strncmp(mode, "put-", 4)) {
        rc = brix_oci_layout_blob_put_mem(layout, "another", 7, output, sizeof(output),
                                         err, sizeof(err));
    } else if (!strncmp(mode, "list-", 5)) {
        rc = brix_oci_layout_ls(layout, &body, err, sizeof(err)); assert(body == NULL);
    } else {
        rc = brix_oci_layout_index_set(layout, "new", digest, "text/plain", 7, err, sizeof(err));
    }
    assert(rc == BRIX_OCI_REG_ETRANSPORT && err[0] != '\0');
    assert(getenv("BRIX_LAYOUT_FAULT") == NULL);
}

/* WHAT: Test a failed storage stage and preserve the previous index.
 * WHY: Errors must not damage already-published metadata or leave staging debris.
 * HOW: Arm only after real setup, run one operation, then compare a fresh listing. */
static void failure(brix_oci_layout_t *layout, const char *digest, const char *mode)
{
    char err[512], *before, *after;
    if (strcmp(mode, "list-calloc")) {
        assert(brix_oci_layout_index_set(layout, "old", digest, "text/plain", 7, err, sizeof(err)) == 0);
    }
    assert(brix_oci_layout_ls(layout, &before, err, sizeof(err)) == 0);
    assert(setenv("BRIX_LAYOUT_FAULT", strchr(mode, '-') + 1, 1) == 0);
    operation_failure(layout, digest, mode);
    assert(brix_oci_layout_ls(layout, &after, err, sizeof(err)) == 0);
    assert(!strcmp(before, after)); free(before); free(after);
}

/* WHAT: Check missing stage storage. WHY: A disappeared directory cannot be success.
 * HOW: Call commit on an absent temp, or move the layout descriptor to an absent dir. */
static void missing(brix_oci_layout_t *layout, const char *digest, const char *mode)
{
    char err[512], temp[1200];
    snprintf(temp, sizeof(temp), "%s/missing-stage", layout->dir);
    if (!strcmp(mode, "commit-missing")) {
        assert(brix_oci_layout_commit(layout, temp, digest, err, sizeof(err)) == BRIX_OCI_REG_ETRANSPORT);
        return;
    }
    assert(strlen(layout->dir) + 8 < sizeof(layout->dir));
    strcat(layout->dir, "/absent");
    assert(brix_oci_layout_stage(layout, temp, sizeof(temp), err, sizeof(err)) == BRIX_OCI_REG_ETRANSPORT);
}

/* WHAT: Execute one isolated native contract. WHY: Fault injection is process local.
 * HOW: Seed a real layout, select a scenario, and return only after its assertions. */
int main(int argc, char **argv)
{
    assert(argc == 3);
    brix_oci_layout_t layout; char digest[80];
    seed(&layout, argv[2], digest);
    if (!strcmp(argv[1], "roundtrip")) { roundtrip(&layout, digest); }
    else if (!strcmp(argv[1], "invalid")) { invalid(&layout); }
    else if (!strcmp(argv[1], "index")) { index_roundtrip(&layout, digest); }
    else if (!strcmp(argv[1], "index-invalid")) { index_invalid(&layout, digest); }
    else if (strstr(argv[1], "-missing")) { missing(&layout, digest, argv[1]); }
    else { failure(&layout, digest, argv[1]); }
    return 0;
}
