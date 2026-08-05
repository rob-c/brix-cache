/*
 * web_proxy_pem_unit.c — brix_web_proxy_pem(): the davs/https mutual-TLS client
 * certificate resolver (conn.c). It picks the X.509 proxy PEM the HTTP client
 * presents to a GSI origin (Finding 2 of the XrdHttp+GSI delegation matrix,
 * docs/09-developer-guide/gsi-delegation-xrdhttp-fullmatrix.md).
 *
 * WHAT: resolves $X509_USER_PROXY, else /tmp/x509up_u<euid>, and returns the
 *       path ONLY when the file is readable (else NULL).
 *
 * Ritual (3 per CLAUDE.md):
 *   SUCCESS         — $X509_USER_PROXY → a readable file → that exact path.
 *   ERROR           — $X509_USER_PROXY → a missing file → NULL (fail closed: no
 *                     cert is presented rather than a bogus path that would fail
 *                     the TLS cert-load with a confusing error).
 *   SECURITY-NEG    — an explicit, readable $X509_USER_PROXY always wins over the
 *                     /tmp/x509up_u<euid> default, so a stray default proxy can
 *                     never silently substitute a different identity; and a NULL/
 *                     zero-length buffer yields NULL, never a stack read.
 */

#include "brix.h"   /* brix_web_proxy_pem (via brix_net.h) */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
write_file(const char *path, const char *contents)
{
    FILE *f = fopen(path, "wb");
    assert(f != NULL);
    fputs(contents, f);
    fclose(f);
}

int
main(void)
{
    char        buf[512];
    const char *got;
    char        proxy_path[256];
    char        missing_path[256];

    snprintf(proxy_path, sizeof(proxy_path),
             "/tmp/brix_web_proxy_unit_%u.pem", (unsigned) getpid());
    snprintf(missing_path, sizeof(missing_path),
             "/tmp/brix_web_proxy_unit_%u_absent.pem", (unsigned) getpid());
    (void) unlink(proxy_path);
    (void) unlink(missing_path);

    /* 1. SUCCESS: an explicit, readable proxy resolves to exactly its path. */
    write_file(proxy_path, "-----BEGIN CERTIFICATE-----\nstub\n"
                           "-----END CERTIFICATE-----\n");
    assert(setenv("X509_USER_PROXY", proxy_path, 1) == 0);
    got = brix_web_proxy_pem(buf, sizeof(buf));
    assert(got == buf);
    assert(strcmp(got, proxy_path) == 0);

    /* 2. ERROR: an explicit but UNREADABLE proxy → NULL. Fail closed: the client
     *    presents no certificate rather than a path that cannot be loaded. */
    assert(setenv("X509_USER_PROXY", missing_path, 1) == 0);
    got = brix_web_proxy_pem(buf, sizeof(buf));
    assert(got == NULL);

    /* 3a. SECURITY-NEG: the explicit env proxy takes precedence over the
     *     /tmp/x509up_u<euid> default even when that default also exists — an
     *     unrelated default proxy can never override the user's chosen identity. */
    {
        char        deflt[256];
        int         made_default = 0;

        snprintf(deflt, sizeof(deflt), "/tmp/x509up_u%u", (unsigned) geteuid());
        if (access(deflt, R_OK) != 0) {
            write_file(deflt, "-----BEGIN CERTIFICATE-----\ndefault\n"
                              "-----END CERTIFICATE-----\n");
            made_default = 1;
        }
        assert(setenv("X509_USER_PROXY", proxy_path, 1) == 0);
        got = brix_web_proxy_pem(buf, sizeof(buf));
        assert(got != NULL);
        assert(strcmp(got, proxy_path) == 0);   /* env wins, not the default */
        if (made_default) {
            (void) unlink(deflt);
        }
    }

    /* 3b. SECURITY-NEG: a NULL / zero-length output buffer yields NULL, never a
     *     read of uninitialised stack. */
    assert(brix_web_proxy_pem(NULL, sizeof(buf)) == NULL);
    assert(brix_web_proxy_pem(buf, 0) == NULL);

    (void) unlink(proxy_path);
    printf("web_proxy_pem_unit: all checks passed\n");
    return 0;
}
