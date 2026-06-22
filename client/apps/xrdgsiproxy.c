/*
 * xrdgsiproxy.c — create / inspect / destroy an X.509 GSI proxy.
 *
 * WHAT: `xrdgsiproxy init [-valid H[:M]] [-cert F] [-key F] [-out F] [-bits N]`,
 *       `xrdgsiproxy info [-file F]`, `xrdgsiproxy destroy [-file F]`.
 * WHY:  Users need a proxy before any GSI xrdcp/xrdfs; pure local OpenSSL via the
 *       client library (lib/proxy.c). libXrdCl/XrdCrypto-free.
 * HOW:  Thin arg parse → xrdc_proxy_create/info/destroy.
 */
#include "xrdc.h"
#include "compat/crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
parse_valid(const char *s)
{
    /* "HH:MM" → hours (rounded up on minutes); a bare integer → hours. */
    const char *colon = strchr(s, ':');
    if (colon != NULL) {
        int h = atoi(s);
        int m = atoi(colon + 1);
        int hours = h + (m > 0 ? 1 : 0);
        return hours > 0 ? hours : 12;
    }
    return atoi(s) > 0 ? atoi(s) : 12;
}

static void
usage(void)
{
    fprintf(stderr,
        "usage: xrdgsiproxy <init|info|destroy> [opts]\n"
        "  init    [-valid H[:M]] [-cert FILE] [-key FILE] [-out FILE] [-bits N]\n"
        "  info    [-file FILE]\n"
        "  destroy [-file FILE]\n");
}

int
main(int argc, char **argv)
{
    xrdc_status     st;
    const char     *cmd;
    int             i, rc;

    if (argc < 2) { usage(); return 50; }
    cmd = argv[1];
    xrootd_crypto_init();
    xrdc_status_clear(&st);

    if (strcmp(cmd, "init") == 0) {
        xrdc_proxy_opts o;
        memset(&o, 0, sizeof(o));
        for (i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-valid") == 0 && i + 1 < argc) { o.valid_hours = parse_valid(argv[++i]); }
            else if (strcmp(argv[i], "-cert") == 0 && i + 1 < argc) { o.user_cert = argv[++i]; }
            else if (strcmp(argv[i], "-key") == 0 && i + 1 < argc)  { o.user_key = argv[++i]; }
            else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc)  { o.out_path = argv[++i]; }
            else if (strcmp(argv[i], "-bits") == 0 && i + 1 < argc) { o.bits = atoi(argv[++i]); }
            else { usage(); return 50; }
        }
        rc = xrdc_proxy_create(&o, &st);
        if (rc != 0) {
            fprintf(stderr, "xrdgsiproxy: init: %s\n", st.msg);
            return xrdc_shellcode(&st);
        }
        return xrdc_proxy_info(o.out_path, stdout, &st);  /* echo what we made */
    }

    if (strcmp(cmd, "info") == 0 || strcmp(cmd, "destroy") == 0) {
        const char *file = NULL;
        for (i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-file") == 0 && i + 1 < argc) { file = argv[++i]; }
            else { usage(); return 50; }
        }
        rc = (strcmp(cmd, "info") == 0)
             ? xrdc_proxy_info(file, stdout, &st)
             : xrdc_proxy_destroy(file, &st);
        if (rc != 0) {
            fprintf(stderr, "xrdgsiproxy: %s: %s\n", cmd, st.msg);
            return xrdc_shellcode(&st);
        }
        return 0;
    }

    usage();
    return 50;
}
