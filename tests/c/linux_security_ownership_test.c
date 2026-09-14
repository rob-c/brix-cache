/* Observe the real PAL wrapper with libseccomp calls confined to this binary. */
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <seccomp.h>

int brix_security_init(const char *profile);

/* Keep a real heap allocation so LeakSanitizer sees every filter lifetime. */
scmp_filter_ctx
seccomp_init(uint32_t action)
{
    uint32_t *context;

    puts("init");
    if (strcmp(getenv("BRIX_SECCOMP_TEST_MODE"), "init-error") == 0) {
        return NULL;
    }
    context = malloc(sizeof(*context));
    assert(context != NULL);
    *context = action;
    return context;
}

/* Record the policy only: the test never invokes the kernel seccomp API. */
int
seccomp_load(const scmp_filter_ctx context)
{
    printf("load %u\n", *(uint32_t *) context);
    return strcmp(getenv("BRIX_SECCOMP_TEST_MODE"), "load-error") == 0
               ? -EPERM : 0;
}

/* Release must follow the load attempt exactly once. */
void
seccomp_release(scmp_filter_ctx context)
{
    assert(context != NULL);
    puts("release");
    free(context);
}

int
main(int argc, char **argv)
{
    const char *profile;
    int result, saved_errno;

    assert(argc == 3);
    assert(setenv("BRIX_SECCOMP_TEST_MODE", argv[2], 1) == 0);
    profile = strcmp(argv[1], "null") == 0 ? NULL : argv[1];
    errno = 0;
    result = brix_security_init(profile);
    saved_errno = errno;
    printf("result %d errno %d\n", result, saved_errno);
    return 0;
}
