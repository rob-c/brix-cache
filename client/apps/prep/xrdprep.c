/*
 * xrdprep.c — issue a kXR_prepare (stage/cancel/evict/…) for one or more paths.
 *
 * WHAT: `xrdprep [-s|-c|-w|-f|-e] [-p PRTY] host[:port] <path>...` — a scriptable
 *       subset of `xrdfs prepare`. -s stage, -c cancel, -w write-mode, -f fresh,
 *       -e evict, -p priority (0-3).
 * WHY:  A thin front-end over the client library's brix_prepare. libXrdCl-free.
 * HOW:  brix_endpoint_parse → brix_connect → brix_prepare(options, optionX, prty).
 */
#include "brix.h"
#include "core/compat/crypto.h"
#include "core/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XRDPREP_MAX_PATHS 64

int
main(int argc, char **argv)
{
    brix_conn    c;
    brix_status  st;
    char         reply[1024];
    const char  *endpoint = NULL;
    const char  *paths[XRDPREP_MAX_PATHS];
    int          options = 0, optionX = 0, prty = 0, np = 0, i;

    /* --help / --version before the main loop (not on shared parser). */
    if (argc >= 2) {
        if (strcmp(argv[1], "--version") == 0) {
            printf("xrdprep (BriX-Cache client) %s\n", brix_client_version());
            return 0;
        }
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            printf("usage: %s [-s|-c|-w|-f|-e] [-p prty] host[:port] <path>...\n"
                   "  -s stage  -c cancel  -w write-mode  -f fresh  -e evict\n"
                   "  -p <prty>  priority 0-3 (default 0)\n"
                   BRIX_USAGE_FOOTER("xrdprep"),
                   argv[0]);
            return 0;
        }
    }

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-s") == 0)      { options |= kXR_stage; }
        else if (strcmp(a, "-c") == 0) { options |= kXR_cancel; }
        else if (strcmp(a, "-w") == 0) { options |= kXR_wmode; }
        else if (strcmp(a, "-f") == 0) { options |= kXR_fresh; }
        else if (strcmp(a, "-e") == 0) { optionX |= kXR_evict; }
        else if (strcmp(a, "-p") == 0 && i + 1 < argc) { prty = atoi(argv[++i]); }
        else if (endpoint == NULL)     { endpoint = a; }
        else if (np < XRDPREP_MAX_PATHS) { paths[np++] = a; }
    }
    if (endpoint == NULL || np == 0) {
        fprintf(stderr,
                "usage: %s [-s|-c|-w|-f|-e] [-p prty] host[:port] <path>...\n",
                argv[0]);
        return 50;
    }

    {
        int rc = brix_cli_connect(endpoint, NULL, &c, argv[0], &st);
        if (rc != 0) {
            return rc;
        }
    }
    if (brix_prepare(&c, paths, np, options, optionX, prty,
                     reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "%s: %s\n", argv[0], st.msg);
        brix_close(&c);
        return brix_shellcode(&st);
    }
    brix_close(&c);
    if (reply[0] != '\0') {
        printf("%s\n", reply);
    }
    return 0;
}
