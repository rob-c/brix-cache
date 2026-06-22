/*
 * xrdcrc64.c — CRC-64/XZ of a local file or a root:// file.
 *
 * WHAT: `xrdcrc64 <local-path | root://host[:port]//path>` prints "<hex> <path>".
 *       The digest is CRC-64/XZ (this gateway's canonical "crc64"); for the AWS
 *       CRC-64/NVME variant request "crc64nvme" over the wire instead.
 * WHY:  A thin front-end over the shared checksum-tool template — libXrdCl-free,
 *       mirroring xrdcrc32c / xrdadler32.
 * HOW:  Delegates to xrdc_cli_cksum_main(); see lib/cli_cksum.c.
 */
#include "xrdc.h"

int
main(int argc, char **argv)
{
    return xrdc_cli_cksum_main(argv[0], "crc64", XRDC_CK_CRC64,
                               argc == 2 ? argv[1] : NULL);
}
