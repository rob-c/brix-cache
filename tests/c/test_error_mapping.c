/*
 * test_error_mapping.c — the pure errno↔kXR mapping table (P80.4, phase-105).
 *
 * Pins every native errno arm in the Phase-118 error ledger, its deliberate
 * collapse groups, and the kXR_FSError default. Compiled standalone with
 * -DXRDPROTO_NO_NGX (sections 1-2 of error_mapping.c are ngx-free).
 *
 * Phase-105 adds the read-only endpoint round trip: the VFS mutation kernel
 * refuses with EROFS, and the wire must carry kXR_fsReadOnly — a statement
 * about the SERVER — rather than kXR_NotAuthorized, which tells a client its
 * credentials were the problem and invites a retry with better ones. The two
 * codes therefore have to stay distinguishable in BOTH directions, which is
 * what the asserts below hold: EROFS and EACCES never collapse onto each
 * other, and neither does the reverse table.
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include "core/compat/error_mapping.h"

int main(void) {
    /* Phase-118 ERR-001..035: every host-native mapError arm. */
    assert(brix_kxr_from_errno(ENOENT) == kXR_NotFound);
    assert(brix_kxr_from_errno(EINVAL) == kXR_ArgInvalid);
    assert(brix_kxr_from_errno(EPERM) == kXR_NotAuthorized);
    assert(brix_kxr_from_errno(EACCES) == kXR_NotAuthorized);
    assert(brix_kxr_from_errno(EROFS) == kXR_fsReadOnly);
    assert(brix_kxr_from_errno(EEXIST) == kXR_ItExists);
    assert(brix_kxr_from_errno(ENOTEMPTY) == kXR_ItExists);
    assert(brix_kxr_from_errno(EISDIR) == kXR_isDirectory);
    assert(brix_kxr_from_errno(ENAMETOOLONG) == kXR_ArgTooLong);
    assert(brix_kxr_from_errno(EIO) == kXR_IOError);
    assert(brix_kxr_from_errno(ENOMEM) == kXR_NoMemory);
    assert(brix_kxr_from_errno(ENOBUFS) == kXR_NoMemory);
    assert(brix_kxr_from_errno(ENOSPC) == kXR_NoSpace);
#ifdef EDQUOT
    assert(brix_kxr_from_errno(EDQUOT) == kXR_overQuota);
#endif
    assert(brix_kxr_from_errno(ENOTSUP) == kXR_Unsupported);
    assert(brix_kxr_from_errno(ENOSYS) == kXR_Unsupported);
#ifdef EOPNOTSUPP
    assert(brix_kxr_from_errno(EOPNOTSUPP) == kXR_Unsupported);
#endif
    assert(brix_kxr_from_errno(EBADF) == kXR_FileNotOpen);
    assert(brix_kxr_from_errno(ETIMEDOUT) == kXR_ReqTimedOut);
#ifdef ETIME
    assert(brix_kxr_from_errno(ETIME) == kXR_TimerExpired);
#endif
    assert(brix_kxr_from_errno(ECANCELED) == kXR_Cancelled);
    assert(brix_kxr_from_errno(ETXTBSY) == kXR_inProgress);
#ifdef EBADRQC
    assert(brix_kxr_from_errno(EBADRQC) == kXR_InvalidRequest);
#endif
#ifdef ENOTBLK
    assert(brix_kxr_from_errno(ENOTBLK) == kXR_NotFile);
#endif
    assert(brix_kxr_from_errno(ENODEV) == kXR_FSError);
    assert(brix_kxr_from_errno(EFAULT) == kXR_ServerError);
    assert(brix_kxr_from_errno(EDOM) == kXR_ChkSumErr);
    assert(brix_kxr_from_errno(EILSEQ) == kXR_SigVerErr);
    assert(brix_kxr_from_errno(ERANGE) == kXR_DecryptErr);
#ifdef EUSERS
    assert(brix_kxr_from_errno(EUSERS) == kXR_Overloaded);
#endif
#ifdef ENOATTR
    assert(brix_kxr_from_errno(ENOATTR) == kXR_AttrNotFound);
#elif defined(ENODATA)
    assert(brix_kxr_from_errno(ENODATA) == kXR_AttrNotFound);
#endif
#ifdef EPROTOTYPE
    assert(brix_kxr_from_errno(EPROTOTYPE) == kXR_TLSRequired);
#endif
    assert(brix_kxr_from_errno(EADDRNOTAVAIL) == kXR_noReplicas);
#ifdef EAUTH
    assert(brix_kxr_from_errno(EAUTH) == kXR_AuthFailed);
#endif
#ifdef EIDRM
    assert(brix_kxr_from_errno(EIDRM) == kXR_Impossible);
#endif
    assert(brix_kxr_from_errno(ENOTTY) == kXR_Conflict);
#ifdef ETOOMANYREFS
    assert(brix_kxr_from_errno(ETOOMANYREFS) == kXR_TooManyErrs);
#endif

    /* ERR-036/046: many-to-one collapses are intentional. */
    assert(brix_kxr_from_errno(ENETUNREACH) == kXR_noserver);
    assert(brix_kxr_from_errno(EHOSTUNREACH) == kXR_noserver);
    assert(brix_kxr_from_errno(ECONNREFUSED) == kXR_noserver);
    assert(brix_kxr_from_errno(EPERM) == brix_kxr_from_errno(EACCES));

    /* phase-105: a read-only export is a server property, so it gets its own
     * wire code and must not be laundered into an authorization failure */
    assert(brix_kxr_from_errno(EROFS) == kXR_fsReadOnly);
    assert(brix_kxr_from_errno(EROFS) != kXR_NotAuthorized);
    assert(brix_kxr_from_errno(EACCES) != kXR_fsReadOnly);

    /* ERR-037: an unrecognised errno takes the generic filesystem arm. */
    assert(brix_kxr_from_errno(EPIPE) == kXR_FSError);
    assert(kXR_TimerExpired + 1 == kXR_ERRFENCE);

    /* forward/reverse symmetry: the reverse table's kXR_Unsupported → ENOSYS
     * entry roundtrips through the new forward cases */
    assert(brix_errno_from_kxr(kXR_Unsupported) == ENOSYS);
    assert(brix_kxr_from_errno(brix_errno_from_kxr(kXR_Unsupported))
           == kXR_Unsupported);

    /* the same symmetry for the read-only endpoint code, in both directions,
     * so a proxied kXR_fsReadOnly stays a read-only refusal end to end */
    assert(brix_errno_from_kxr(kXR_fsReadOnly) == EROFS);
    assert(brix_errno_from_kxr(kXR_fsReadOnly) != EACCES);
    assert(brix_kxr_from_errno(brix_errno_from_kxr(kXR_fsReadOnly))
           == kXR_fsReadOnly);
    assert(brix_errno_from_kxr(brix_kxr_from_errno(EROFS)) == EROFS);

    /* ERR-043: the common HTTP edge preserves the documented cross-plane
     * classes for the six canonical errno categories. */
    assert(brix_http_errno_to_status(ENOENT) == 404);
    assert(brix_http_errno_to_status(EACCES) == 403);
    assert(brix_http_errno_to_status(EROFS) == 403);
    assert(brix_http_errno_to_status(EINVAL) == 400);
    assert(brix_http_errno_to_status(EIO) == 500);
    assert(brix_http_errno_to_status(ENOMEM) == 507);
    assert(brix_http_errno_to_status(ENOBUFS) == 507);

    printf("test_error_mapping: ALL PASS\n");
    return 0;
}
