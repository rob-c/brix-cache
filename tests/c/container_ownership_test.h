/* Native ownership fixture support. Requires the configured nginx SDK.
 * Allocator interception is local to the generated test translation unit;
 * the production append/free bodies are included after this header. */
#pragma once

#include <ngx_config.h>
#include <ngx_core.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "fs/backend/sd.h"
#include "fs/backend/frm/frm_zip.h"
#include "fs/backend/frm/sd_frm_purge_internal.h"
#include "observability/metrics/unified.h"

static void ownership_success(void);
static void ownership_allocation_failure(void);
static void ownership_stop_cleanup(void);

static inline void
ownership_fail(const char *family)
{
    if (family == NULL) {
        assert(unsetenv("BRIX_OWNERSHIP_FAIL") == 0);
    } else {
        assert(setenv("BRIX_OWNERSHIP_FAIL", family, 1) == 0);
    }
    errno = 0;
}

static inline int
ownership_fails(const char *family)
{
    const char *requested = getenv("BRIX_OWNERSHIP_FAIL");

    if (requested != NULL && strcmp(requested, family) == 0) {
        errno = ENOMEM;
        return 1;
    }
    return 0;
}

static inline char *
ownership_strdup(const char *text)
{
    return ownership_fails("strdup") ? NULL : strdup(text);
}

static inline char *
ownership_strndup(const char *text, size_t length)
{
    return ownership_fails("strndup") ? NULL : strndup(text, length);
}

static inline void *
ownership_realloc(void *allocation, size_t size)
{
    return ownership_fails("realloc") ? NULL : realloc(allocation, size);
}

#define strdup ownership_strdup
#define strndup ownership_strndup
#define realloc ownership_realloc

int
main(int argc, char **argv)
{
    assert(argc == 2);
    ownership_fail(NULL);
    if (strcmp(argv[1], "success") == 0) {
        ownership_success();
    } else if (strcmp(argv[1], "allocation-failure") == 0) {
        ownership_allocation_failure();
    } else {
        assert(strcmp(argv[1], "stop-cleanup") == 0);
        ownership_stop_cleanup();
    }
    ownership_fail(NULL);
    return 0;
}
