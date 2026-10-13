/*
 * lifecycle_worker_caps.c — worker capability-state inspection.
 *
 * This translation unit owns the small host-capability probe shared by worker
 * hardening and identity transition logic.  Keeping the PAL-facing inspection
 * separate leaves lifecycle_worker.c focused on the transition policy.
 */

#include "lifecycle.h"
#include "platform/platform_api.h"


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
