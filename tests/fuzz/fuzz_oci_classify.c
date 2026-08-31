/*
 * fuzz_oci_classify.c — libFuzzer target for the OCI `/v2/` route classifier.
 *
 * WHAT: feeds arbitrary bytes to brix_oci_classify() as a decoded request URI
 *       and asserts the invariants every consumer downstream relies on: a
 *       route that classifies carries spans that lie inside the input, a name
 *       that classifies re-validates, and a digest that classifies is exactly
 *       64 lowercase hex characters.
 *
 * WHY:  this classifier is the whole traversal defense for the OCI surface
 *       (§0.7.2). Every path the mirror and the registry later build —  cache
 *       key, store path, upstream URL — is assembled from the spans it hands
 *       back, and nothing further down sanitizes them again. A span that
 *       pointed one byte outside the URI, or a "name" that classified without
 *       satisfying the grammar, would be a path component under an attacker's
 *       control at every one of those sites at once.
 *
 * HOW:  the kernel is pure C over the shared grammars — no nginx types, no
 *       allocation, spans into the caller's buffer — so it links standalone
 *       beside the other parser kernels the way src/net/guard/ does. The input
 *       is copied into an exactly-sized heap block rather than a padded stack
 *       buffer so ASan traps a one-byte overread at either end; the copy is
 *       deliberately NOT NUL-terminated, because the contract says termination
 *       is not required and a kernel that quietly depends on one has a bug
 *       that only shows up on a request that fills the buffer.
 *
 * Build:
 *   cd tests/fuzz
 *   clang -O1 -g -fsanitize=fuzzer,address,undefined \
 *       -I ../../src/protocols/oci -I ../../shared \
 *       fuzz_oci_classify.c ../../src/protocols/oci/oci_classify.c \
 *       ../../shared/oci/name.c ../../shared/oci/digest.c \
 *       -lcrypto -o fuzz_oci_classify
 *   ./fuzz_oci_classify -runs=200000 -max_total_time=120 corpus_oci_classify/
 */
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "oci_classify.h"
#include "oci/name.h"

/* A span the classifier reported must lie wholly inside the URI it was given:
 * that is what makes "the spans point into the caller's buffer" a contract
 * rather than a hope. */
static void span_within(const char *p, size_t n, const char *base, size_t len)
{
    if (p == NULL) {
        assert(n == 0);
        return;
    }
    assert(p >= base && p <= base + len);
    assert(n <= (size_t) (base + len - p));
}

static void hex_matches_alg(const brix_oci_digest_t *d)
{
    size_t i, n = brix_oci_alg_hexlen(d->alg);

    assert(n > 0 && strlen(d->hex) == n);
    for (i = 0; i < n; i++) {
        assert((d->hex[i] >= '0' && d->hex[i] <= '9')
               || (d->hex[i] >= 'a' && d->hex[i] <= 'f'));
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    brix_oci_req_t  req;
    char           *uri;
    int             rc;

    if (size > 64 * 1024) {
        return 0;                     /* a URI nginx would have refused first */
    }

    uri = (char *) malloc(size ? size : 1);
    if (uri == NULL) {
        return 0;
    }
    memcpy(uri, data, size);

    memset(&req, 0xA5, sizeof(req));  /* poison: nothing may be read unset */
    rc = brix_oci_classify(uri, size, &req);

    if (rc != 0) {
        /* A refusal must name what to emit — an unset code would surface as a
         * blank error body, which no registry client can act on. */
        assert(req.cls == BRIX_OCI_REQ_BAD);
        assert(req.err != BRIX_OCI_ERR_NONE);
        free(uri);
        return 0;
    }

    assert(req.cls != BRIX_OCI_REQ_BAD);
    assert(brix_oci_class_str(req.cls) != NULL);

    span_within(req.name, req.name_len, uri, size);
    span_within(req.ref, req.ref_len, uri, size);
    span_within(req.session, req.session_len, uri, size);

    if (req.cls != BRIX_OCI_REQ_API_ROOT) {
        /* The name is about to become path components: it must satisfy the
         * grammar on a second, independent pass. */
        assert(req.name_len > 0);
        assert(brix_oci_name_valid(req.name, req.name_len) == 0);
        assert(req.name_components == brix_oci_name_components(req.name,
                                                               req.name_len));
        assert(req.name_components >= 1);
        assert(memchr(req.name, '/', req.name_len) != NULL
               || req.name_components == 1);
    }

    if (req.cls == BRIX_OCI_REQ_BLOB
        || (req.cls == BRIX_OCI_REQ_MANIFEST && req.ref_is_digest))
    {
        hex_matches_alg(&req.digest);
    }

    if (req.cls == BRIX_OCI_REQ_UPLOAD_SESSION) {
        assert(req.session_len > 0 && req.session_len <= BRIX_OCI_SESSION_MAX);
        assert(memchr(req.session, '/', req.session_len) == NULL);
    }

    free(uri);
    return 0;
}
