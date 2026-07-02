/* Standalone unit test for src/core/compat/af_policy.h — gcc, no nginx. */
#include <assert.h>
#include <stdio.h>
#include "../src/core/compat/af_policy.h"

int main(void)
{
    assert(xrootd_af_policy_parse("auto", 4)  == XROOTD_AF_AUTO);
    assert(xrootd_af_policy_parse("inet", 4)  == XROOTD_AF_INET);
    assert(xrootd_af_policy_parse("inet6", 5) == XROOTD_AF_INET6);
    /* unknown / partial / wrong-length tokens reject */
    assert(xrootd_af_policy_parse("ipv4", 4)  == -1);
    assert(xrootd_af_policy_parse("inet", 3)  == -1);   /* "ine" */
    assert(xrootd_af_policy_parse("inet64", 6) == -1);
    assert(xrootd_af_policy_parse("", 0)      == -1);
    /* the enum values must equal the AF_* constants (assignable to ai_family) */
    assert(XROOTD_AF_AUTO  == AF_UNSPEC);
    assert(XROOTD_AF_INET  == AF_INET);
    assert(XROOTD_AF_INET6 == AF_INET6);
    printf("af_policy_unittest: all checks passed\n");
    return 0;
}
