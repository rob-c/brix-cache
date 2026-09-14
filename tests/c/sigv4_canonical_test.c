/* Run the actual S3 canonicalizer against fixture query bytes, without HTTP.
 * A separate short-output case checks the caller's fixed storage boundary. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "protocols/s3/auth_sigv4_verify_internal.h"

/* WHAT: Check short-output ownership. WHY: A larger scratch buffer must not
 * expand the caller's writable range. HOW: 1. Fill canaries. 2. Canonicalize
 * into eight bytes. 3. Require termination and unchanged surrounding bytes. */
static void
check_bounds(const char *query)
{
    struct {
        u_char before[16];
        u_char output[8];
        u_char after[16];
    } storage;
    size_t length;

    memset(&storage, 0xa5, sizeof(storage));
    length = build_canonical_qs((const u_char *) query, strlen(query), 1,
                                storage.output, sizeof(storage.output));
    assert(length < sizeof(storage.output));
    assert(storage.output[length] == '\0');
    for (size_t index = 0; index < sizeof(storage.before); index++) {
        assert(storage.before[index] == 0xa5);
        assert(storage.after[index] == 0xa5);
    }
}

/* WHAT: Emit canonical fixture bytes or check bounds. WHY: Compare real C
 * output against the existing Python signer. HOW: 1. Select one bounded
 * scenario. 2. Execute the production entry point and assert its length. */
int
main(int argc, char **argv)
{
    u_char output[4096];
    size_t length;

    assert(argc == 3);
    if (strcmp(argv[1], "bounds") == 0) {
        check_bounds(argv[2]);
        return 0;
    }
    assert(strcmp(argv[1], "canonical") == 0);
    length = build_canonical_qs((const u_char *) argv[2], strlen(argv[2]), 1,
                                output, sizeof(output));
    assert(length < sizeof(output));
    assert(length == strlen((const char *) output));
    assert(fwrite(output, 1, length, stdout) == length);
    return 0;
}
