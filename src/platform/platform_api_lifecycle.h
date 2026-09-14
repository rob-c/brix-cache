/* PAL initialization and cleanup.
 * Requires: platform_api.h platform selection and system types before inclusion.
 * Include platform/platform_api.h at call sites.
 */
#pragma once

/* ==========================================================================
 * INITIALIZATION
 *
 * PAL lifecycle management. Call brix_plat_init() once at startup.
 * ========================================================================== */

/**
 * Initialize the Platform Abstraction Layer
 *
 * Called once at module initialization.
 *
 * CURRENT IMPLEMENTATION: Minimal stub returning 0.
 *
 * FUTURE ENHANCEMENT: May perform platform-specific initialization such as:
 *   - Linux: io_uring capability detection, seccomp availability
 *   - macOS: Accelerate framework init, kqueue setup
 *   - Windows: Handle registry init, BCrypt algorithm setup
 *
 * @return 0 on success (currently always succeeds), -1 on error
 */
int brix_plat_init(void);

/**
 * Clean up the Platform Abstraction Layer
 *
 * Called once at module shutdown.
 *
 * CURRENT IMPLEMENTATION: Empty stub (no-op).
 *
 * FUTURE ENHANCEMENT: May release PAL resources such as:
 *   - Linux: io_uring ring cleanup, seccomp context
 *   - macOS: kqueue fd cleanup
 *   - Windows: Handle registry cleanup, BCrypt handle closure
 *
 * @return void
 */
void brix_plat_cleanup(void);
