/*
 * cli_cksum.c — shared front-end for the local-or-root:// checksum CLIs.
 *
 * WHAT: xrdc_cli_cksum_main() is the whole body of the xrdcrc32c / xrdcrc64 /
 *       xrdadler32 tools: given a program name, a wire algorithm name and the
 *       matching local-digest enum, it checksums either a LOCAL file (streamed
 *       through xrdc_cksum_fd) or a root:// file (kXR_query/kXR_Qcksum via
 *       xrdc_query_cksum) and prints "<hex> <path>".
 * WHY:  The three checksum tools were byte-identical except for one algorithm
 *       string + enum; this collapses them to a ~6-line main() each, so a new
 *       algorithm tool is a one-liner and the dispatch logic lives in one place.
 * HOW:  strstr("://") selects the root:// path (parse URL, require root/roots,
 *       connect, query) vs the local path (open O_RDONLY, xrdc_cksum_fd). Exit
 *       codes mirror the historical behaviour: XRDC_EXIT_USAGE on argument/parse/
 *       open errors, xrdc_shellcode(st) on connect/query/digest failures.
 */
#include "xrdc.h"
#include "compat/crypto.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
xrdc_cli_cksum_main(const char *prog, const char *algo_name,
                    xrdc_cksum_algo algo, const char *arg)
{
    xrdc_status st;
    char        hex[129];

    if (arg == NULL) {
        fprintf(stderr, "usage: %s <local-path | root://host[:port]//path>\n",
                prog);
        return XRDC_EXIT_USAGE;
    }
    xrootd_crypto_init();
    xrdc_status_clear(&st);

    if (strstr(arg, "://") != NULL) {
        xrdc_url  u;
        xrdc_conn c;

        if (xrdc_url_parse(arg, &u, &st) != 0
            || (u.scheme != XRDC_SCHEME_ROOT && u.scheme != XRDC_SCHEME_ROOTS)) {
            fprintf(stderr, "%s: %s\n", prog, st.msg);
            return XRDC_EXIT_USAGE;
        }
        if (xrdc_connect(&c, &u, NULL, &st) != 0) {
            fprintf(stderr, "%s: connect: %s\n", prog, st.msg);
            return xrdc_shellcode(&st);
        }
        if (xrdc_query_cksum(&c, u.path, algo_name, hex, sizeof(hex), &st) != 0) {
            fprintf(stderr, "%s: %s\n", prog, st.msg);
            xrdc_close(&c);
            return xrdc_shellcode(&st);
        }
        xrdc_close(&c);
        printf("%s %s\n", hex, u.path);
        return 0;
    }

    {
        int fd = open(arg, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "%s: open %s failed\n", prog, arg);
            return XRDC_EXIT_USAGE;
        }
        if (xrdc_cksum_fd(fd, algo, hex, sizeof(hex), &st) != 0) {
            fprintf(stderr, "%s: %s\n", prog, st.msg);
            close(fd);
            return xrdc_shellcode(&st);
        }
        close(fd);
        printf("%s %s\n", hex, arg);
        return 0;
    }
}
