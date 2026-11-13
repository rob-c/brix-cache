/* WHAT: Parse real remote conformance options without executing a remote run.
 * WHY: Resource ceilings and mutation authority must be settled before I/O.
 * HOW: Link the configured CLI closure and expose the resulting typed state;
 * only random-key generation has a finite success/failure seam. */
#include "apps/diag/xrd_conform_internal.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int __wrap_RAND_bytes(unsigned char *bytes, int count)
{
    if (getenv("BRIX_CONFORM_RNG_FAIL")) { return 0; }
    assert(count == 16); memset(bytes, 0xa5, (size_t) count); return 1;
}
int main(int argc, char **argv)
{
    xrd_conform_run run = {0};
    int rc = xrd_conform_parse_run(argc, argv, &run);
    printf("rc=%d\n", rc);
    if (rc) { return 0; }
    printf("profile=%s\nkey=%s\nwall=%u\nrequests=%u\nbytes=%llu\n",
        run.config.profile, run.config.run_key, run.config.wall_seconds,
        run.config.request_limit, (unsigned long long) run.config.byte_limit);
    printf("reference=%d\nfail=%d\nmutate=%d\ndisrupt=%d\ninterval=%u\ncycles=%u\n",
        run.config.reference_mode, run.config.fail_mode, run.config.allow_mutate,
        run.config.allow_disrupt, run.config.watch_interval_seconds, run.config.watch_cycles);
    printf("also=%zu\nnegative=%zu\nerror=%zu\nreadonly=%zu\nauth=%zu\ntls=%zu\n",
        run.also_count, run.negative_verify_count, run.error_fixture_count,
        run.readonly_fixture_count, run.auth_fixture_count, run.tls_fixture_count);
    printf("denied=%zu\nmutation=%zu\nopen=%zu\nlocate=%zu\ntoken=%zu\nline-limit=%u\n",
        run.denied_fixture_count, run.mutation_fixture_count, run.open_fixture_count,
        run.locate_fixture_count, run.token_fixture_count, run.http_request_line_limit);
    printf("cache=%s\ntpc=%s\n", run.cache_fixture_kind ? run.cache_fixture_kind : "",
        run.tpc_fixture_kind ? run.tpc_fixture_kind : "");
    return 0;
}
