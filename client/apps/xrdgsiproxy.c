/*
 * xrdgsiproxy.c — create / inspect / destroy an X.509 GSI proxy.
 *
 * WHAT: `xrdgsiproxy init [-valid H[:M]] [-cert F] [-key F] [-out F] [-bits N]`,
 *       `xrdgsiproxy info [-file F]`, `xrdgsiproxy destroy [-file F]`.
 * WHY:  Users need a proxy before any GSI xrdcp/xrdfs; pure local OpenSSL via the
 *       client library (lib/proxy.c). libXrdCl/XrdCrypto-free.
 * HOW:  Thin arg parse → brix_proxy_create/info/destroy.
 */
#include "brix.h"
#include "core/compat/crypto.h"

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
    brix_status     st;
    const char     *cmd;
    int             i, rc;

    if (argc < 2) { usage(); return 50; }
    cmd = argv[1];
    brix_crypto_init();
    brix_status_clear(&st);

    if (strcmp(cmd, "init") == 0) {
        brix_proxy_opts o;
        memset(&o, 0, sizeof(o));
        for (i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-valid") == 0 && i + 1 < argc) { o.valid_hours = parse_valid(argv[++i]); }
            else if (strcmp(argv[i], "-cert") == 0 && i + 1 < argc) { o.user_cert = argv[++i]; }
            else if (strcmp(argv[i], "-key") == 0 && i + 1 < argc)  { o.user_key = argv[++i]; }
            else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc)  { o.out_path = argv[++i]; }
            else if (strcmp(argv[i], "-bits") == 0 && i + 1 < argc) { o.bits = atoi(argv[++i]); }
            else { usage(); return 50; }
        }
        rc = brix_proxy_create(&o, &st);
        if (rc != 0) {
            fprintf(stderr, "xrdgsiproxy: init: %s\n", st.msg);
            return brix_shellcode(&st);
        }
        return brix_proxy_info(o.out_path, stdout, &st);  /* echo what we made */
    }

    if (strcmp(cmd, "info") == 0 || strcmp(cmd, "destroy") == 0) {
        const char *file = NULL;
        int         is_info = (strcmp(cmd, "info") == 0);
        for (i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-file") == 0 && i + 1 < argc) { file = argv[++i]; }
            else { usage(); return 50; }
        }
        rc = is_info ? brix_proxy_info(file, stdout, &st)
                     : brix_proxy_destroy(file, &st);
        if (rc == 0) {
            return 0;
        }
        /* `info` is tolerant of an absent proxy, mirroring stock xrdgsiproxy:
         * emit a plain "not found" notice and exit 1 rather than escalating a
         * missing file to a hard usage error. Any other failure (e.g. a present
         * but unparseable proxy) still surfaces via the normal error path. */
        if (is_info && st.kxr == XRDC_ENOENT) {
            printf("%s\n", st.msg);
            return 1;
        }
        fprintf(stderr, "xrdgsiproxy: %s: %s\n", cmd, st.msg);
        return brix_shellcode(&st);
    }

    usage();
    return 50;
}
