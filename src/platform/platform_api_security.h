/* Process confinement, identity and entropy.
 * Requires: platform_api.h platform selection and system types before inclusion.
 * Include platform/platform_api.h at call sites.
 */
#pragma once

/* ==========================================================================
 * SECURITY & CONFINEMENT
 *
 * Security context and credential manipulation.
 * Note: Windows support is limited (stubbed) due to different security model.
 * ========================================================================== */

/**
 * Initialize security context
 *
 * Linux: seccomp_init() + profile loading
 * macOS: sandbox_init() (stub - relies on system security)
 * Windows: Job Objects (stub)
 *
 * Windows Implementation:
 * - Stub returns 0 (success)
 * - Windows security model differs fundamentally (ACLs, tokens, SIDs)
 * - Future: Implement via Job Objects or AppContainer
 * - Profile parameter ignored
 *
 * @param profile Security profile name (or NULL for default)
 * @return 0 on success, -1 on error
 */
int brix_plat_security_init(const char *profile);

/**
 * Enter security confinement
 *
 * Linux: seccomp_load()
 * macOS: sandbox_exec() (stub)
 * Windows: Job Object assignment (stub)
 *
 * Windows Implementation:
 * - Stub returns 0 (success)
 * - No-op until Job Objects implementation
 * - Profile parameter ignored
 *
 * @param profile Security profile name
 * @return 0 on success, -1 on error
 */
int brix_plat_security_enter(const char *profile);

/**
 * Set filesystem user ID (Linux only, stubbed on macOS/Windows)
 *
 * Linux: setfsuid()
 * macOS: seteuid() (affects both real and effective)
 * Windows: stub (returns 0)
 *
 * Windows Implementation:
 * - Stub returns 0 (success)
 * - Windows uses impersonation, not UID switching
 * - Future: Implement via ImpersonateLoggedOnUser()
 *
 * @param uid User ID
 * @return the previous filesystem uid (Linux setfsuid contract, so a
 *         `(uid_t) -1` call reads the current value); -1 on error
 */
int brix_plat_setfsuid(uid_t uid);

/**
 * Set filesystem group ID (Linux only, stubbed on macOS/Windows)
 *
 * Linux: setfsgid()
 * macOS: setegid()
 * Windows: stub (returns 0)
 *
 * Windows Implementation:
 * - Stub returns 0 (success)
 * - Windows uses security groups, not GID switching
 * - Future: Implement via token manipulation
 *
 * @param gid Group ID
 * @return the previous filesystem gid (Linux setfsgid contract); -1 on error
 */
int brix_plat_setfsgid(gid_t gid);

/* ==========================================================================
 * RANDOM NUMBER GENERATION
 *
 * Cryptographically secure random number generation.
 * ========================================================================== */

/**
 * Generate cryptographically secure random bytes
 *
 * Linux: getrandom() or /dev/urandom
 * macOS: SecRandomCopyBytes() or /dev/urandom
 * Windows: BCryptGenRandom()
 *
 * Windows Implementation:
 * - Uses BCryptGenRandom() from bcrypt.dll
 * - BCRYPT_USE_SYSTEM_PREFERRED_RNG flag
 * - Algorithm handle cached for performance
 * - Fallback to CryptGenRandom() if BCrypt unavailable
 *
 * @param buf Output buffer
 * @param len Number of bytes
 * @return 0 on success, -1 on error
 */
int brix_plat_random(void *buf, size_t len);
