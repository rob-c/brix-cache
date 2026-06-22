/*
 * xrdprep.c — issue a kXR_prepare (stage/cancel/evict/…) for one or more paths.
 *
 * WHAT: `xrdprep [-s|-c|-w|-f|-e] [-p PRTY] host[:port] <path>...` — a scriptable
 *       subset of `xrdfs prepare`. -s stage, -c cancel, -w write-mode, -f fresh,
 *       -e evict, -p priority (0-3).
 * WHY:  A thin front-end over the client library's xrdc_prepare. libXrdCl-free.
 * HOW:  xrdc_endpoint_parse → xrdc_connect → xrdc_prepare(options, optionX, prty).
 */
#include "xrdc.h"
#include "compat/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define XRDPREP_MAX_PATHS 64

int
main(int argc, char **argv)
{
    xrdc_conn    c;
    xrdc_status  st;
    char         reply[1024];
    const char  *endpoint = NULL;
    const char  *paths[XRDPREP_MAX_PATHS];
    int          options = 0, optionX = 0, prty = 0, np = 0, i;

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
        int rc = xrdc_cli_connect(endpoint, NULL, &c, argv[0], &st);
        if (rc != 0) {
            return rc;
        }
    }
    if (xrdc_prepare(&c, paths, np, options, optionX, prty,
                     reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "%s: %s\n", argv[0], st.msg);
        xrdc_close(&c);
        return xrdc_shellcode(&st);
    }
    xrdc_close(&c);
    if (reply[0] != '\0') {
        printf("%s\n", reply);
    }
    return 0;
}
