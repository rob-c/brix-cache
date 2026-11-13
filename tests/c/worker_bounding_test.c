/* Real worker bounding-set regression: fault injection is confined to the
 * executable's PAL call boundary; the successful path changes its own kernel
 * credentials. Each invocation exits without affecting the pytest parent. */
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "auth/impersonate/lifecycle.h"
#include "platform/platform_api.h"

int __real_brix_plat_prctl(int option, unsigned long arg);

/* WHAT: Substitute only explicit syscall failures or a dishonest drop result.
 * WHY: Kernel success and refusal both need behavioural assertions.
 * HOW: 1. Read the per-process case. 2. Inject its error. 3. Otherwise call PAL. */
int
__wrap_brix_plat_prctl(int option, unsigned long arg)
{
    const char *mode = getenv("BRIX_BOUNDS_CASE");

    if (option == PR_CAPBSET_DROP && strcmp(mode, "drop-error") == 0) {
        errno = EPERM;
        return -1;
    }
    if (option == PR_CAPBSET_DROP && strcmp(mode, "false-success") == 0) {
        return 0;
    }
    if (option == PR_CAPBSET_READ && strcmp(mode, "read-error") == 0) {
        errno = EACCES;
        return -1;
    }
    if (option == PR_CAPBSET_READ && strcmp(mode, "invalid-read") == 0) {
        errno = EINVAL;
        return -1;
    }
    return __real_brix_plat_prctl(option, arg);
}

/* WHAT: Supply the inert nginx log sink needed by a standalone object unit.
 * WHY: This driver passes NULL logs and tests credentials, not formatting.
 * HOW: 1. Consume the unused arguments; no production logging is replaced. */
void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t error,
    const char *format, ...)
{
    (void) level; (void) log; (void) error; (void) format;
}

/* WHAT: Assert all kernel-supported bounding bits were cleared.
 * WHY: Clearing the bounding set must preserve current identity-drop authority.
 * HOW: 1. Read every supported bit. 2. Verify effective SETUID/SETGID survive. */
static void
assert_sealed(void)
{
    unsigned cap;

    for (cap = 0; ; cap++) {
        int present = __real_brix_plat_prctl(PR_CAPBSET_READ, cap);

        if (present < 0) {
            assert(errno == EINVAL && cap > 0);
            break;
        }
        assert(present == 0);
    }
    assert(brix_imp_cap_held(CAP_SETUID));
    assert(brix_imp_cap_held(CAP_SETGID));
}

/* WHAT: Run one irreversible transition or injected refusal in this child.
 * WHY: Parent test credentials must remain untouched.
 * HOW: 1. Select a case. 2. Call the production helper. 3. Assert its result. */
int
main(int argc, char **argv)
{
    ngx_int_t result;

    assert(argc == 2);
    assert(brix_imp_cap_held(CAP_SETPCAP));
    assert(setenv("BRIX_BOUNDS_CASE", argv[1], 1) == 0);
    result = brix_imp_worker_drop_bounds(NULL);
    if (strcmp(argv[1], "success") == 0) {
        assert(result == NGX_OK);
        assert_sealed();
        return 0;
    }
    assert(result == NGX_ERROR);
    return 0;
}
