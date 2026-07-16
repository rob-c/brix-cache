/*
 * test_error_mapping.c — the pure errno↔kXR mapping table (P80.4).
 *
 * Pins the honest kXR_Unsupported mapping for missing-operation errnos
 * (ENOTSUP/ENOSYS/EOPNOTSUPP → 3013) alongside the pre-existing entries, and
 * the forward/reverse symmetry for kXR_Unsupported. Compiled standalone with
 * -DXRDPROTO_NO_NGX (sections 1-2 of error_mapping.c are ngx-free).
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include "core/compat/error_mapping.h"

int main(void) {
    /* P80.4: missing-operation errnos map to kXR_Unsupported, not IOError */
    assert(brix_kxr_from_errno(ENOTSUP) == kXR_Unsupported);
    assert(brix_kxr_from_errno(ENOSYS) == kXR_Unsupported);
#ifdef EOPNOTSUPP
    assert(brix_kxr_from_errno(EOPNOTSUPP) == kXR_Unsupported);
#endif

    /* pre-existing entries stay unchanged */
    assert(brix_kxr_from_errno(EIO) == kXR_IOError);
    assert(brix_kxr_from_errno(ENOENT) == kXR_NotFound);
    assert(brix_kxr_from_errno(EACCES) == kXR_NotAuthorized);
    assert(brix_kxr_from_errno(ENOSPC) == kXR_NoSpace);
    assert(brix_kxr_from_errno(EINVAL) == kXR_ArgInvalid);
    assert(brix_kxr_from_errno(ENOTEMPTY) == kXR_ItExists);

    /* an unrecognised errno still falls back to the generic I/O error */
    assert(brix_kxr_from_errno(EPIPE) == kXR_IOError);

    /* forward/reverse symmetry: the reverse table's kXR_Unsupported → ENOSYS
     * entry roundtrips through the new forward cases */
    assert(brix_errno_from_kxr(kXR_Unsupported) == ENOSYS);
    assert(brix_kxr_from_errno(brix_errno_from_kxr(kXR_Unsupported))
           == kXR_Unsupported);

    printf("test_error_mapping: ALL PASS\n");
    return 0;
}
