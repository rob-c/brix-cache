/*
 * lifecycle_worker_caps.c — worker capability-state inspection.
 *
 * This translation unit owns the small host-capability probe shared by worker
 * hardening and identity transition logic.  Keeping the PAL-facing inspection
 * separate leaves lifecycle_worker.c focused on the transition policy.
 */

#include "lifecycle.h"
#include "platform/platform_api.h"

#include <errno.h>


/* ---- Report whether a worker capability remains available ----
 *
 * WHAT: Return 1 when `cap` is effective or permitted, otherwise return 0.
 * WHY: Worker identity transitions must distinguish an ordinary account from
 *      one that can still change uid or gid without duplicating PAL details.
 * HOW: Read both v3 capability words through the PAL; all capabilities queried
 *      by this subsystem are in word zero.  Fail closed to "not held" when the
 *      host has no capability API or the state cannot be read.
 */
int
brix_imp_cap_held(int cap)
{
#if BRIX_HAS_CAPABILITIES
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct   data[2];

    ngx_memzero(&hdr, sizeof(hdr));
    ngx_memzero(data, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0;
    if (brix_plat_capget(&hdr, data) != 0) {
        return 0;
    }
    return (data[0].effective & (1u << cap)) != 0
        || (data[0].permitted & (1u << cap)) != 0;
#else
    (void) cap;
    return 0;
#endif
}


#if BRIX_HAS_CAPABILITIES
/* ---- Clear one capability ceiling ----
 * WHAT: Return NGX_OK only after the kernel confirms a bounding bit is clear.
 * WHY: A successful syscall alone must not attest the terminal privilege state.
 * HOW: 1. Drop the bit. 2. Read it back. 3. Refuse any retained authority. */
static ngx_int_t
imp_worker_clear_bound(unsigned cap)
{
    if (brix_plat_prctl(PR_CAPBSET_DROP, cap) != 0) {
        return NGX_ERROR;
    }
    if (brix_plat_prctl(PR_CAPBSET_READ, cap) != 0) {
        errno = EPERM;
        return NGX_ERROR;
    }
    return NGX_OK;
}
#endif


/* ---- Seal the worker's capability bounding set ----
 * WHAT: Clear every supported bounding bit when the worker can change it.
 * WHY: CAP_SETPCAP must still be effective; clearing it first makes every
 *      later bounding-set drop fail. Current SETUID/SETGID remain available
 *      for the identity transition because a bounding drop does not clear them.
 * HOW: 1. Check current authority. 2. Enumerate kernel-supported bits.
 *      3. Clear and verify each bit, failing startup on any unexpected error.
 * Ordinary workers without SETPCAP rely on the caller's no-new-privileges gate. */
ngx_int_t
brix_imp_worker_drop_bounds(ngx_log_t *log)
{
#if BRIX_HAS_CAPABILITIES
    unsigned cap;

    if (!brix_imp_cap_held(CAP_SETPCAP)) {
        return NGX_OK;
    }
    for (cap = 0; ; cap++) {
        int present = brix_plat_prctl(PR_CAPBSET_READ, cap);

        if (present < 0 && errno == EINVAL && cap != 0) {
            return NGX_OK;
        }
        if (present < 0 || (present != 0 && imp_worker_clear_bound(cap) != NGX_OK)) {
            BRIX_LOG(NGX_LOG_EMERG, log, errno,
                "impersonate: worker capability bounding set cannot be cleared; "
                "refusing to serve");
            return NGX_ERROR;
        }
    }
#else
    (void) log;
    return NGX_OK;
#endif
}
