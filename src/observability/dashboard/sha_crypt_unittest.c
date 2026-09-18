/*
 * sha_crypt_unittest.c — standalone unit test for the SHA-crypt kernel.
 *
 *   cc -std=c11 -Wall -Wextra -Werror -I src/observability/dashboard \
 *      src/observability/dashboard/sha_crypt.c \
 *      src/observability/dashboard/sha_crypt_unittest.c -lcrypto \
 *      -o /tmp/sha_crypt_ut && /tmp/sha_crypt_ut
 *
 * Exit 0 = all checks pass ("all checks passed" on stdout).  Pins: the four
 * reference vectors of the SHA-crypt specification (default and custom
 * rounds, both methods) so the output is byte-identical to glibc crypt(3);
 * that a malformed setting, an unsupported method and a short buffer fail
 * closed; and that a wrong password never reproduces the stored hash.
 */
#include "sha_crypt.h"

#include <stdio.h>
#include <string.h>

static int fails;

static void
check(const char *what, int ok)
{
    if (!ok) {
        printf("FAIL %s\n", what);
        fails++;
    }
}

static const struct {
    const char *key;
    const char *hash;
} vectors[] = {
    { "Hello world!",
      "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5" },
    { "Hello world!",
      "$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA" },
    { "Hello world!",
      "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1" },
    { "Hello world!",
      "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v." },
};

static void
test_reference_vectors(void)
{
    char   out[BRIX_SHA_CRYPT_MAX];
    size_t i;

    for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
        check("vector handled", brix_sha_crypt_handles(vectors[i].hash));
        check("vector computes",
              brix_sha_crypt(vectors[i].key, vectors[i].hash, out,
                             sizeof(out)) == 0);
        check("vector byte-identical", strcmp(out, vectors[i].hash) == 0);
    }
}

static void
test_malformed_settings_fail_closed(void)
{
    char out[BRIX_SHA_CRYPT_MAX];
    char small[8];

    check("$1$ not handled", !brix_sha_crypt_handles("$1$xx$yy"));
    check("plain not handled", !brix_sha_crypt_handles("secret"));
    check("empty not handled", !brix_sha_crypt_handles(""));
    check("NULL not handled", !brix_sha_crypt_handles(NULL));
    check("$1$ refused", brix_sha_crypt("pw", "$1$xx$yy", out, sizeof(out)) != 0);
    check("bad rounds refused",
          brix_sha_crypt("pw", "$6$rounds=abc$salt$", out, sizeof(out)) != 0);
    check("short buffer refused",
          brix_sha_crypt("pw", "$6$saltstring$", small, sizeof(small)) != 0);
    check("NULL key refused",
          brix_sha_crypt(NULL, "$6$saltstring$", out, sizeof(out)) != 0);
}

static void
test_wrong_password_never_matches(void)
{
    char out[BRIX_SHA_CRYPT_MAX];

    check("wrong password computes",
          brix_sha_crypt("Hello world?", vectors[2].hash, out, sizeof(out)) == 0);
    check("wrong password differs", strcmp(out, vectors[2].hash) != 0);
    check("same prefix kept", strncmp(out, "$6$saltstring$", 14) == 0);
    check("empty password differs",
          brix_sha_crypt("", vectors[0].hash, out, sizeof(out)) == 0
          && strcmp(out, vectors[0].hash) != 0);
}

int
main(void)
{
    test_reference_vectors();
    test_malformed_settings_fail_closed();
    test_wrong_password_never_matches();
    if (fails) {
        printf("%d check(s) failed\n", fails);
        return 1;
    }
    puts("all checks passed");
    return 0;
}
