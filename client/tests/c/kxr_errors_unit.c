/* kxr_errors_unit.c — the reference kXR error codes added for audit §1 gap 5
 * (kXR_SigVerErr/DecryptErr/BadPayload/noReplicas/ReqTimedOut/TimerExpired):
 * their wire values, their name-table entries, their errno mapping, and their
 * retryable classification.
 *
 * These codes are sent by STOCK servers. Before this, a BriX client decoded
 * them as "Unknown", mapped them to no errno at all, and classified every one
 * of them as fatal — so a transient stock-side timeout aborted a transfer that
 * a retry would have completed.
 *
 * Build+run (from client/): part of `make test` (CLIENT_UNIT_TESTS). */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "brix.h"
#include "brix_ops.h"
#include "core/compat/kxr_names.h"
#include "core/compat/error_mapping.h"

static void test_wire_values(void)                    /* success */
{
    /* The gaps the audit identified in BriX's error table, filled with the
     * reference values. Spot-checked against the neighbours already present so
     * a transposed digit cannot slip through. */
    assert(kXR_SigVerErr    == 3022);
    assert(kXR_DecryptErr   == 3023);
    assert(kXR_BadPayload   == 3026);
    assert(kXR_noReplicas   == 3029);
    assert(kXR_ReqTimedOut  == 3034);
    assert(kXR_TimerExpired == 3035);

    /* Neighbours must be untouched — these were already correct. */
    assert(kXR_overQuota    == 3021);
    assert(kXR_Overloaded   == 3024);
    assert(kXR_fsReadOnly   == 3025);
    assert(kXR_AttrNotFound == 3027);
    assert(kXR_TLSRequired  == 3028);
    assert(kXR_AuthFailed   == 3030);
    assert(kXR_TooManyErrs  == 3033);
}


static void test_names_resolve(void)                  /* success */
{
    /* Each new code must name itself rather than falling through to the
     * "Unknown" default — that default is what made a stock error message
     * unreadable in client diagnostics. */
    assert(strcmp(brix_kxr_error_name(kXR_SigVerErr),    "SigVerErr")    == 0);
    assert(strcmp(brix_kxr_error_name(kXR_DecryptErr),   "DecryptErr")   == 0);
    assert(strcmp(brix_kxr_error_name(kXR_BadPayload),   "BadPayload")   == 0);
    assert(strcmp(brix_kxr_error_name(kXR_noReplicas),   "noReplicas")   == 0);
    assert(strcmp(brix_kxr_error_name(kXR_ReqTimedOut),  "ReqTimedOut")  == 0);
    assert(strcmp(brix_kxr_error_name(kXR_TimerExpired), "TimerExpired") == 0);

    /* A code outside the vocabulary still reports Unknown (the fallback is
     * intentionally preserved, not removed). */
    assert(strcmp(brix_kxr_error_name(9999), "Unknown") == 0);
}


static void test_errno_mapping(void)                  /* success */
{
    /* The POSIX layers (FUSE / preload) hand the kernel -errno for a server
     * error; an unmapped code yields 0, which callers substitute for. */
    assert(brix_errno_from_kxr(kXR_SigVerErr)    == EACCES);
    assert(brix_errno_from_kxr(kXR_DecryptErr)   == EACCES);
    assert(brix_errno_from_kxr(kXR_BadPayload)   == EINVAL);
    assert(brix_errno_from_kxr(kXR_noReplicas)   == EHOSTUNREACH);
    assert(brix_errno_from_kxr(kXR_ReqTimedOut)  == ETIMEDOUT);
    assert(brix_errno_from_kxr(kXR_TimerExpired) == ETIMEDOUT);

    /* Pre-existing rows must not have shifted. */
    assert(brix_errno_from_kxr(kXR_NotFound)  == ENOENT);
    assert(brix_errno_from_kxr(kXR_noserver)  == EHOSTUNREACH);
    assert(brix_errno_from_kxr(9999)          == 0);
}


static void test_retryable_classification(void)       /* error-path behaviour */
{
    brix_status st;

    /* A signature/decrypt failure and a malformed payload are the server saying
     * "no" — re-issuing identical bytes gets the identical answer, so a
     * resilient loop MUST NOT spin on them. */
    brix_status_set(&st, kXR_SigVerErr, 0, "sig");
    assert(brix_status_retryable(&st) == 0);
    brix_status_set(&st, kXR_DecryptErr, 0, "decrypt");
    assert(brix_status_retryable(&st) == 0);
    brix_status_set(&st, kXR_BadPayload, 0, "payload");
    assert(brix_status_retryable(&st) == 0);

    /* The three transient codes MUST retry — that is the behaviour change: a
     * stock server's timeout or momentarily-unavailable replica used to abort
     * the whole transfer. */
    brix_status_set(&st, kXR_noReplicas, 0, "no replica");
    assert(brix_status_retryable(&st) == 1);
    brix_status_set(&st, kXR_ReqTimedOut, 0, "req timeout");
    assert(brix_status_retryable(&st) == 1);
    brix_status_set(&st, kXR_TimerExpired, 0, "timer");
    assert(brix_status_retryable(&st) == 1);

    /* Regression guard on the pre-existing classification. */
    brix_status_set(&st, kXR_NotFound, 0, "enoent");
    assert(brix_status_retryable(&st) == 0);
    brix_status_set(&st, kXR_Overloaded, 0, "busy");
    assert(brix_status_retryable(&st) == 1);
}


int
main(void)
{
    test_wire_values();
    test_names_resolve();
    test_errno_mapping();
    test_retryable_classification();
    printf("kxr_errors_unit: ALL PASS\n");
    return 0;
}
