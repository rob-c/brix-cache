/*
 * test_opaque_schema.c — standalone unit for the D-2 opt-in opaque schema gate
 * (src/protocols/root/path/opaque_validate.c, brix_opaque_schema_check). Drives
 * the SHIPPED namespace-vocabulary + typed-key logic directly over NUL-
 * terminated opaque strings (no ngx, no wire):
 *
 *   success  — a well-formed opaque of known namespaces + a typed oss.asize
 *              passes, and the empty / NULL opaque is vacuously OK;
 *   type     — a typed key with a non-integer value is rejected as BAD_TYPE and
 *              the offending key is reported, while a valid integer passes;
 *   security — a key in no recognized namespace is rejected as UNKNOWN_KEY (the
 *              junk-parameter / typo'd-namespace vector), and the parser is not
 *              fooled by a bare "xrd" masquerading as the "xrd." namespace.
 *
 * ngx-free: compiles opaque_validate.c against libc only, mirroring the core.
 */
#include "protocols/root/path/opaque_validate.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static int
check(const char *opaque, char *key, size_t key_len)
{
    return brix_opaque_schema_check(opaque, key, key_len);
}

int
main(void)
{
    char key[64];

    /* success: known namespaces + a typed oss.asize + a bare key all pass. */
    assert(check("oss.asize=1048576&tpc.src=root://h//p&authz=abc", key,
                 sizeof(key)) == BRIX_OPAQUE_SCHEMA_OK);
    assert(check("xrd.appname=xrdcp&xrdcl.unzip=a.root&scitag.flow=17&cms.space=x",
                 key, sizeof(key)) == BRIX_OPAQUE_SCHEMA_OK);

    /* success: the empty / NULL / leading-'?' opaque is vacuously OK, and an
     * empty pair from a stray separator is tolerated. */
    assert(check("", key, sizeof(key)) == BRIX_OPAQUE_SCHEMA_OK);
    assert(check(NULL, key, sizeof(key)) == BRIX_OPAQUE_SCHEMA_OK);
    assert(check("?oss.asize=8", key, sizeof(key)) == BRIX_OPAQUE_SCHEMA_OK);
    assert(check("oss.asize=8&&tpc.key=k&", key, sizeof(key))
           == BRIX_OPAQUE_SCHEMA_OK);

    /* type: oss.asize must be an unsigned decimal integer; a word, a signed
     * value, a float, and an empty value are all BAD_TYPE and name the key. */
    key[0] = 'x';
    assert(check("oss.asize=abc", key, sizeof(key))
           == BRIX_OPAQUE_SCHEMA_BAD_TYPE);
    assert(strcmp(key, "oss.asize") == 0);
    assert(check("tpc.src=root://h//p&oss.asize=-5", key, sizeof(key))
           == BRIX_OPAQUE_SCHEMA_BAD_TYPE);
    assert(check("oss.asize=1.5", key, sizeof(key))
           == BRIX_OPAQUE_SCHEMA_BAD_TYPE);
    assert(check("oss.asize=", key, sizeof(key))
           == BRIX_OPAQUE_SCHEMA_BAD_TYPE);
    /* the same key with a clean integer passes — the type is the only gate. */
    assert(check("oss.asize=0", key, sizeof(key)) == BRIX_OPAQUE_SCHEMA_OK);

    /* security: a key in no recognized namespace is rejected and named — the
     * junk/injection-parameter and typo'd-namespace vector. */
    assert(check("bogus.key=1", key, sizeof(key))
           == BRIX_OPAQUE_SCHEMA_UNKNOWN_KEY);
    assert(strcmp(key, "bogus.key") == 0);
    assert(check("oss.asize=8&evil=1", key, sizeof(key))
           == BRIX_OPAQUE_SCHEMA_UNKNOWN_KEY);
    assert(strcmp(key, "evil") == 0);

    /* security: a bare "xrd" (no dot) must NOT satisfy the "xrd." namespace, and
     * "authz2" must NOT be accepted for the bare "authz" key. */
    assert(check("xrd=1", key, sizeof(key))
           == BRIX_OPAQUE_SCHEMA_UNKNOWN_KEY);
    assert(check("authz2=x", key, sizeof(key))
           == BRIX_OPAQUE_SCHEMA_UNKNOWN_KEY);

    /* the reported key is truncated to the buffer but always NUL-terminated. */
    char small[4];
    assert(check("longnamespacejunk=1", small, sizeof(small))
           == BRIX_OPAQUE_SCHEMA_UNKNOWN_KEY);
    assert(strlen(small) == 3);

    printf("test_opaque_schema: all assertions passed\n");
    return 0;
}
