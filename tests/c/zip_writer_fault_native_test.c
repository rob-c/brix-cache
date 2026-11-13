/* Native ZIP writer fault boundaries; successful output is checked by Python zipfile. */
#include "protocols/shared/zip_internal.h"
#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>

typedef struct {
    const char *mode;
    int source, dest, armed, sink_failure;
    unsigned reads, emits;
} fixture;
static fixture *state(void)
{
    const char *value = getenv("BRIX_ZIP_WRITER_STATE");
    return value ? (fixture *)(uintptr_t) strtoull(value, NULL, 16) : NULL;
}
static int mode(const char *name) { return strcmp(state()->mode, name) == 0; }
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t count, size_t size)
{
    fixture *f = state();
    if (f && f->armed && mode("calloc")) { return NULL; }
    return __real_calloc(count, size);
}
void *__real_realloc(void *, size_t);
void *__wrap_realloc(void *pointer, size_t size)
{
    fixture *f = state();
    if (f && f->armed && (mode("realloc") || mode("seed-realloc"))) { return NULL; }
    return __real_realloc(pointer, size);
}
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *buffer, size_t size, off_t offset)
{
    fixture *f = state();
    if (!f || !f->armed || fd != f->source) { return __real_pread(fd, buffer, size, offset); }
    unsigned index = ++f->reads; assert(index < 10);
    if ((mode("crc-intr") && index == 1) || (mode("data-intr") && index == 2)) {
        errno = EINTR; return -1;
    }
    if ((mode("crc-error") && index == 1) || (mode("data-error") && index == 2)) {
        errno = EIO; return -1;
    }
    if ((mode("crc-shrink") && index == 1) || (mode("data-shrink") && index == 2)) { return 0; }
    return __real_pread(fd, buffer, size, offset);
}
static int sink(void *context, const void *bytes, size_t length)
{
    fixture *f = context; f->emits++;
    assert(f->emits < 20);
    if ((int) f->emits == f->sink_failure) { return -1; }
    assert(write(f->dest, bytes, length) == (ssize_t) length); return 0;
}

static brix_zip_writer *new_writer(fixture *f, uint64_t base)
{
    brix_zip_seed seed = {0};
    if (mode("seed-realloc")) { seed.cd = (const uint8_t *) "x"; seed.cd_len = 1; }
    if (mode("null-sink")) { return brix_zip_writer_new(NULL, f); }
    return brix_zip_writer_new_append(sink, f, base, &seed);
}
static int add_member(brix_zip_writer *writer, fixture *f)
{
    char too_long[XRDC_ZIP_MAX_NAME + 2];
    memset(too_long, 'a', sizeof(too_long) - 1); too_long[sizeof(too_long) - 1] = '\0';
    const char *name = "payload";
    if (mode("name-empty")) { name = ""; }
    if (mode("name-long")) { name = too_long; }
    if (mode("name-null")) { name = NULL; }
    int fd = mode("fd-invalid") ? -1 : f->source;
    return brix_zip_writer_add_fd(writer, name, fd);
}
static int run_writer(fixture *f, uint64_t base)
{
    brix_zip_writer *writer = new_writer(f, base);
    if (!writer) { return XRDC_ZIP_ENOMEM; }
    int result = add_member(writer, f);
    if (!result) { result = brix_zip_writer_finish(writer); }
    if (writer->err) {
        unsigned emitted = f->emits;
        assert(brix_zip_writer_add_fd(writer, "again", f->source) == result);
        assert(brix_zip_writer_finish(writer) == result && emitted == f->emits);
    }
    brix_zip_writer_free(writer); return result;
}
int main(int argc, char **argv)
{
    assert(argc == 7);
    fixture f = {.mode = argv[3], .sink_failure = atoi(argv[5])}; char pointer[32];
    f.source = open(argv[1], O_RDONLY); f.dest = open(argv[2], O_CREAT | O_TRUNC | O_WRONLY, 0600);
    assert(f.source >= 0 && f.dest >= 0);
    uint64_t base = strtoull(argv[4], NULL, 10);
    assert(lseek(f.dest, (off_t) base, SEEK_SET) == (off_t) base);
    snprintf(pointer, sizeof(pointer), "%llx", (unsigned long long) (uintptr_t) &f);
    assert(setenv("BRIX_ZIP_WRITER_STATE", pointer, 1) == 0); f.armed = 1;
    assert(brix_zip_writer_add_fd(NULL, "payload", f.source) == XRDC_ZIP_EBADF);
    assert(brix_zip_writer_finish(NULL) == XRDC_ZIP_EBADF); brix_zip_writer_free(NULL);
    int result = run_writer(&f, base); f.armed = 0;
    fprintf(stderr, "result=%d reads=%u emits=%u\n", result, f.reads, f.emits);
    assert(result == atoi(argv[6]));
    assert(close(f.source) == 0 && close(f.dest) == 0);
    assert(unsetenv("BRIX_ZIP_WRITER_STATE") == 0); return 0;
}
