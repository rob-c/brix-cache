/* Scoped, ordinal allocator failures for finite native contract processes.
 * State lives in caller-owned environment strings, with no production hook. */
#ifndef BRIX_TEST_NATIVE_ALLOC_FAIL_H
#define BRIX_TEST_NATIVE_ALLOC_FAIL_H
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
native_alloc_fails(const char *name)
{
    const char *kind = getenv("BRIX_NATIVE_FAIL_ALLOC");
    char *remaining = getenv("BRIX_NATIVE_FAIL_SKIP");
    unsigned long count;

    if (kind == NULL || strcmp(kind, name) != 0 || remaining == NULL) {
        return 0;
    }
    count = strtoul(remaining, NULL, 10);
    if (count != 0) {
        snprintf(remaining, 32, "%031lu", count - 1);
        return 0;
    }
    errno = ENOMEM;
    return 1;
}

static inline void
native_alloc_arm(const char *kind, unsigned skip)
{
    char count[32];
    snprintf(count, sizeof(count), "%031u", skip);
    assert(setenv("BRIX_NATIVE_FAIL_SKIP", count, 1) == 0);
    assert(setenv("BRIX_NATIVE_FAIL_ALLOC", kind, 1) == 0);
}

static inline void
native_alloc_disarm(void)
{
    assert(unsetenv("BRIX_NATIVE_FAIL_ALLOC") == 0);
}

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *pointer, size_t size);
char *__real_strdup(const char *value);
char *__real_strndup(const char *value, size_t size);
void *__real_ngx_calloc(size_t size, ngx_log_t *log);

void *__wrap_malloc(size_t size) {
    return native_alloc_fails("malloc") ? NULL : __real_malloc(size);
}
void *__wrap_calloc(size_t count, size_t size) {
    return native_alloc_fails("calloc") ? NULL : __real_calloc(count, size);
}
void *__wrap_realloc(void *pointer, size_t size) {
    return native_alloc_fails("realloc") ? NULL : __real_realloc(pointer, size);
}
char *__wrap_strdup(const char *value) {
    return native_alloc_fails("strdup") ? NULL : __real_strdup(value);
}
char *__wrap_strndup(const char *value, size_t size) {
    return native_alloc_fails("strndup") ? NULL : __real_strndup(value, size);
}
void *__wrap_ngx_calloc(size_t size, ngx_log_t *log) {
    return native_alloc_fails("ngx_calloc") ? NULL : __real_ngx_calloc(size, log);
}
#endif
