/*
 * fuzz_oci_challenge.c — libFuzzer target for the WWW-Authenticate parser.
 *
 * WHAT: feeds arbitrary bytes to brix_oci_challenge_parse() as the VALUE of a
 *       401's WWW-Authenticate header and checks that a success leaves four
 *       NUL-terminated fields with a non-empty realm.
 *
 * WHY:  this is the one parser in the OCI plane that runs on bytes an
 *       *upstream* authored, before any of our own validation has a say
 *       (§0.7.5). Its output is spent immediately: the realm becomes the URL
 *       the token dance dials, the scope is echoed into that request's query.
 *       A field left unterminated, or a realm accepted empty, turns a hostile
 *       registry's header into our next outbound request.
 *
 * HOW:  the grammar is pure C with fixed-size outputs and no allocation, so
 *       the harness is the whole contract: parse, then read every field to
 *       its terminator so ASan sees any run past the end of a buffer that a
 *       truncating write would have left un-NUL'd.
 *
 * Build:
 *   cd tests/fuzz
 *   clang -O1 -g -fsanitize=fuzzer,address,undefined -I ../../shared \
 *       fuzz_oci_challenge.c ../../shared/oci/challenge.c -o fuzz_oci_challenge
 *   ./fuzz_oci_challenge -runs=200000 corpus_oci_challenge/
 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "oci/challenge.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    brix_oci_challenge_t  ch;
    char                 *value;
    int                   rc;

    if (size > 16 * 1024) {
        return 0;                     /* a header nginx would have refused */
    }

    value = (char *) malloc(size ? size : 1);
    if (value == NULL) {
        return 0;
    }
    memcpy(value, data, size);        /* deliberately NOT NUL-terminated */

    memset(&ch, 0x5A, sizeof(ch));    /* poison: a field read is a field set */
    rc = brix_oci_challenge_parse(value, size, &ch);

    if (rc == 0) {
        /* Every field is about to be spent on an outbound request, so every
         * field must be a C string, and the one the dance cannot do without
         * must be there. */
        assert(memchr(ch.realm, '\0', sizeof(ch.realm)) != NULL);
        assert(memchr(ch.service, '\0', sizeof(ch.service)) != NULL);
        assert(memchr(ch.scope, '\0', sizeof(ch.scope)) != NULL);
        assert(memchr(ch.error, '\0', sizeof(ch.error)) != NULL);
        assert(ch.realm[0] != '\0');
    }

    free(value);
    return 0;
}
