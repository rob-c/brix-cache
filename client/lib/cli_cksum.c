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
 *       codes mirror the stock tools byte-for-byte: argument/URL-parse errors are
 *       XRDC_EXIT_USAGE; any failure to PRODUCE a checksum (connect, query, local
 *       open, or digest) returns the caller's `err_exit` (xrdadler32 → 1,
 *       xrdcrc32c → 3, xrdcrc64 → 1) rather than the XrdCl-style shellcode, which
 *       diverged from stock (54=NotFound) and tripped scripts that branch on $?.
 */
#include "xrdc.h"
#include "compat/crypto.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
xrdc_cli_cksum_main(const char *prog, const char *algo_name,
                    xrdc_cksum_algo algo, const char *arg, int err_exit)
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
            return err_exit;
        }
        if (xrdc_query_cksum(&c, u.path, algo_name, hex, sizeof(hex), &st) != 0) {
            fprintf(stderr, "%s: %s\n", prog, st.msg);
            xrdc_close(&c);
            return err_exit;
        }
        xrdc_close(&c);
        printf("%s %s\n", hex, u.path);
        return 0;
    }

    {
        int fd = open(arg, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "%s: open %s failed\n", prog, arg);
            return err_exit;
        }
        if (xrdc_cksum_fd(fd, algo, hex, sizeof(hex), &st) != 0) {
            fprintf(stderr, "%s: %s\n", prog, st.msg);
            close(fd);
            return err_exit;
        }
        close(fd);
        printf("%s %s\n", hex, arg);
        return 0;
    }
}
