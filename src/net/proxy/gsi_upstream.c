/*
 * gsi_upstream.c — Phase-4b GSI delegation: secure-temp writer (Task 2).
 *
 * The threaded blocking GSI client (Task 3) reuses the cache origin client, which
 * reads the proxy credential from a FILE path; so the in-memory delegated proxy
 * PEM is first written to an owner-only temp here. The staging (0600 file in a
 * private 0700 tmpfs dir, never world-traversable /tmp) is the shared
 * brix_cred_stage_write() facility used by every credential stager. Kept as a thin
 * named wrapper so its three callers and the standalone unit test are unchanged.
 */

#include "gsi_upstream.h"
#include "core/compat/cred_stage.h"

#include <errno.h>

int
brix_proxy_gsi_write_pem_temp(const unsigned char *pem, size_t len,
    char *out, size_t cap)
{
    if (pem == NULL || len == 0 || out == NULL) {
        errno = EINVAL;
        return -1;
    }

    return brix_cred_stage_write("xrd-deleg-", pem, len, out, cap);
}
