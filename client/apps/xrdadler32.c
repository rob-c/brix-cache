/*
 * xrdadler32.c — Adler32 of a local file or a root:// file.
 *
 * WHAT: `xrdadler32 <local-path | root://host[:port]//path>` prints "<hex> <path>".
 * WHY:  The checksum HEP tools historically use; a thin front-end over the shared
 *       checksum-tool template (zlib adler32 locally; kXR_Qcksum on the server).
 *       libXrdCl-free, mirroring xrdcrc32c / xrdcrc64.
 * HOW:  Delegates to xrdc_cli_cksum_main(); see lib/cli_cksum.c.
 */
#include "xrdc.h"

int
main(int argc, char **argv)
{
    return xrdc_cli_cksum_main(argv[0], "adler32", XRDC_CK_ADLER32,
                               argc == 2 ? argv[1] : NULL);
}
