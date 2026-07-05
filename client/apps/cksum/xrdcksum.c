/*
 * xrdcksum.c — multi-call front-end for the checksum tool family.
 *
 * WHAT: One binary serving xrdcrc32c / xrdcrc64 / xrdadler32 / xrdckverify /
 *       xrdcinfo (via argv[0] symlinks, stock-name compatible) and the
 *       subcommand form `xrdcksum <crc32c|crc64|adler32|verify|info> …`.
 * WHY:  Five installed binaries collapse into one link target — one binary to
 *       audit and ship; per-tool behavior, options and exit codes are
 *       unchanged (the checksum personalities keep their stock error exits:
 *       xrdcrc32c=3, xrdcrc64/xrdadler32=1).
 * HOW:  basename(argv[0]) picks the personality; the bare `xrdcksum` name
 *       shifts argv by one and dispatches on the subcommand so each
 *       personality still sees its own name at argv[0]. Checksum
 *       personalities delegate to brix_cli_cksum_main() exactly as the old
 *       thin wrappers did; verify/info call the renamed tool mains.
 */
#include "brix.h"

#include <stdio.h>
#include <string.h>

int brix_xrdckverify_main(int argc, char **argv);
int brix_xrdcinfo_main(int argc, char **argv);

typedef struct {
    const char *name;        /* argv[0] basename / subcommand         */
    const char *algo_name;   /* brix_cli_cksum_main() algorithm label */
    int         algo;        /* XRDC_CK_* enum                        */
    int         err_exit;    /* the stock tool's failure exit code    */
} cksum_tool;

static const cksum_tool CKSUM_TOOLS[] = {
    { "xrdcrc32c",  "crc32c",  XRDC_CK_CRC32C,  3 },
    { "crc32c",     "crc32c",  XRDC_CK_CRC32C,  3 },
    { "xrdcrc64",   "crc64",   XRDC_CK_CRC64,   1 },
    { "crc64",      "crc64",   XRDC_CK_CRC64,   1 },
    { "xrdadler32", "adler32", XRDC_CK_ADLER32, 1 },
    { "adler32",    "adler32", XRDC_CK_ADLER32, 1 },
};

static const char *
tool_basename(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash != NULL ? slash + 1 : path;
}

/* Run the personality named `name`; -1 = no such personality. */
static int
dispatch(const char *name, int argc, char **argv)
{
    size_t i;

    for (i = 0; i < sizeof(CKSUM_TOOLS) / sizeof(CKSUM_TOOLS[0]); i++) {
        const cksum_tool *t = &CKSUM_TOOLS[i];

        if (strcmp(name, t->name) == 0) {
            return brix_cli_cksum_main(argv[0], t->algo_name, t->algo,
                                       argc == 2 ? argv[1] : NULL,
                                       t->err_exit);
        }
    }
    if (strcmp(name, "xrdckverify") == 0 || strcmp(name, "verify") == 0) {
        return brix_xrdckverify_main(argc, argv);
    }
    if (strcmp(name, "xrdcinfo") == 0 || strcmp(name, "info") == 0) {
        return brix_xrdcinfo_main(argc, argv);
    }
    return -1;
}

int
main(int argc, char **argv)
{
    int rc;

    rc = dispatch(tool_basename(argv[0]), argc, argv);
    if (rc >= 0) {
        return rc;
    }
    /* bare `xrdcksum <sub> …`: shift so the personality sees its own name */
    if (argc >= 2) {
        rc = dispatch(argv[1], argc - 1, argv + 1);
        if (rc >= 0) {
            return rc;
        }
    }
    fprintf(stderr,
        "usage: xrdcksum <crc32c|crc64|adler32|verify|info> [args...]\n"
        "       (or invoke via the xrdcrc32c/xrdcrc64/xrdadler32/"
        "xrdckverify/xrdcinfo symlinks)\n");
    return 50;
}
