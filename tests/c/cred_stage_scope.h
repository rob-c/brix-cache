/* Test-only root override. Requires the platform API; never used by production.
 * Negative tests loosen/remove this directory, so it MUST be private to the
 * harness working directory, not the uid's live credential staging area. */
#pragma once
#include "platform/platform_api.h"
#undef BRIX_PLAT_SHM_DIR
#define BRIX_PLAT_SHM_DIR "."
#define BRIX_CRED_STAGE_TEST_SCOPE 1
