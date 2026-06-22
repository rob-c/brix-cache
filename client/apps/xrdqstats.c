/*
 * xrdqstats.c — query and print a server's monitoring/config/space info.
 *
 * WHAT: `xrdqstats [-c KEY | -s PATH] host[:port]` — default kXR_QStats; -c →
 *       kXR_Qconfig <KEY>; -s → kXR_Qspace <PATH>. Prints the server's text reply.
 * WHY:  A scriptable front-end over the client library's kXR_query. libXrdCl-free.
 * HOW:  xrdc_endpoint_parse → xrdc_connect → xrdc_query(infotype, args).
 */
#include "xrdc.h"
#include "compat/crypto.h"

#include <stdio.h>
#include <string.h>

int
main(int argc, char **argv)
{
    xrdc_conn   c;
    xrdc_status st;
    char        reply[4096];
    const char *endpoint = NULL, *args = "";
    int         infotype = kXR_QStats, i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            infotype = kXR_Qconfig; args = argv[++i];
        } else if (strcmp(argv[i], "-s") == 0 && i + 1 < argc) {
            infotype = kXR_Qspace; args = argv[++i];
        } else {
            endpoint = argv[i];
        }
    }
    if (endpoint == NULL) {
        fprintf(stderr, "usage: %s [-c config-key | -s path] host[:port]\n", argv[0]);
        return 50;
    }

    {
        int rc = xrdc_cli_connect(endpoint, NULL, &c, argv[0], &st);
        if (rc != 0) {
            return rc;
        }
    }
    if (xrdc_query(&c, infotype, args, reply, sizeof(reply), &st) != 0) {
        fprintf(stderr, "%s: %s\n", argv[0], st.msg);
        xrdc_close(&c);
        return xrdc_shellcode(&st);
    }
    xrdc_close(&c);
    printf("%s\n", reply);
    return 0;
}
