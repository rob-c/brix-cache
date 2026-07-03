/*
 * xrdgsitest.c — GSI handshake self-test against an XRootD server.
 *
 * WHAT: `xrdgsitest [opts] root[s]://host[:port]` — force GSI auth, perform the
 *       full handshake/login, and narrate the result (caps, the auth choice, TLS,
 *       and the proxy/VOMS the client presented). Exit 0 only if GSI authenticated.
 * WHY:  Users debugging "why won't my GSI proxy work?" want a single command that
 *       isolates the credential + handshake from any data transfer — the diagnostic
 *       aid the stock xrdgsitest provides, here libXrdCl/libXrdSec*-free.
 * HOW:  Thin composition: set auth_force="gsi", brix_connect, then brix_explain_conn
 *       (which already narrates auth + invokes the §15.2 credential introspection).
 *
 * Clean-room: composes the public libbrix API only.
 */
#include "brix.h"
#include "core/compat/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void
usage(void)
{
    fprintf(stderr,
        "usage: xrdgsitest [opts] root[s]://host[:port]\n"
        "  forces GSI auth and reports whether the handshake authenticated.\n"
        "  opts: --tls --notlsok --noverifyhost\n"
        "  uses $X509_USER_PROXY / $X509_CERT_DIR as usual.\n");
}

int
main(int argc, char **argv)
{
    brix_url    u;
    brix_conn   c;
    brix_status st;
    brix_opts   o;
    const char *url = NULL;
    int         i;

    memset(&o, 0, sizeof(o));
    o.verify_host = 1;
    o.auth_force = "gsi";   /* this is the whole point of the tool */
    brix_crypto_init();

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-' && a[1] != '\0' && strcmp(a, "-") != 0) {
            if (brix_opts_parse_arg(&o, argc, argv, &i)) { continue; }
            if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(); return 0; }
            else { fprintf(stderr, "xrdgsitest: unknown option '%s'\n", a); usage(); return 50; }
        } else if (url == NULL) {
            url = a;
        } else {
            fprintf(stderr, "xrdgsitest: too many arguments\n");
            return 50;
        }
    }
    if (url == NULL) {
        usage();
        return 50;
    }

    brix_status_clear(&st);
    if (brix_endpoint_parse(url, &u, &st) != 0) {
        fprintf(stderr, "xrdgsitest: %s\n", st.msg);
        return 50;
    }
    if (brix_connect_resilient(&c, &u, &o, &st) != 0) {
        fprintf(stderr, "xrdgsitest: GSI handshake failed: %s\n", st.msg);
        return brix_shellcode(&st);
    }

    brix_explain_conn(&c, &o, stdout);

    /* The gate: GSI must actually be the protocol that authenticated. */
    {
        int ok = (c.diag.chosen_auth != NULL
                  && strcmp(c.diag.chosen_auth, "gsi") == 0);
        printf("Result: GSI %s\n", ok ? "OK" : "NOT used (fell back / anon)");
        brix_close(&c);
        return ok ? 0 : 53;
    }
}
