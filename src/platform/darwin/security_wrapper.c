/*
 * src/platform/darwin/security_wrapper.c - honest Darwin confinement residue.
 *
 * WHAT: Preserves the legacy brix_security_* ABI while refusing every
 *       requested confinement mode that this API cannot actually enforce.
 * WHY: Returning success for audit, enforce, or a custom profile caused the
 *      caller to believe a sandbox was active when no policy had been loaded.
 * HOW: The explicitly disabled modes remain successful; every mode which
 *      promises confinement returns -1 with ENOTSUP.
 */

#include <errno.h>
#include <string.h>

/* ---- Initialize the legacy Darwin security adapter ----
 *
 * WHAT: Return 0 only when confinement is explicitly disabled; return -1 with
 *       ENOTSUP for audit, enforce, default, and custom profiles.
 * WHY: Darwin has no implementation behind this legacy ABI, so accepting a
 *      non-off mode would be a silent security downgrade.
 * HOW: 1. Recognize NULL and "off" as disabled. 2. Refuse every other value.
 */
int
brix_security_init(const char *profile)
{
    if (profile == NULL || strcmp(profile, "off") == 0) {
        return 0;
    }

    errno = ENOTSUP;
    return -1;
}

/* ---- Refuse unavailable Darwin audit confinement ----
 *
 * WHAT: Return -1 with ENOTSUP because this adapter cannot enable auditing.
 * WHY: A successful no-op would falsely attest that sandbox violations are
 *      being recorded.
 * HOW: Set the stable unsupported errno and fail.
 */
int
brix_security_enable_audit(void)
{
    errno = ENOTSUP;
    return -1;
}

/* ---- Refuse unavailable custom Darwin profiles ----
 *
 * WHAT: Return -1 with ENOTSUP for every profile path.
 * WHY: This legacy adapter does not parse or install Seatbelt policies, so it
 *      must never acknowledge a supplied policy file.
 * HOW: Ignore the path only after classifying the operation as unsupported.
 */
int
brix_security_load_profile(const char *path)
{
    (void) path;
    errno = ENOTSUP;
    return -1;
}
