/*
 * xrdcrc32c.c — CRC32c of a local file or a root:// file.
 *
 * WHAT: `xrdcrc32c <local-path | root://host[:port]//path>` prints "<hex> <path>".
 * WHY:  A thin front-end over the shared checksum-tool template (the same CRC32c
 *       the server, pgread/pgwrite, and `xrdcp --cksum` use) — libXrdCl-free.
 * HOW:  Delegates to xrdc_cli_cksum_main(); see lib/cli_cksum.c.
 */
#include "xrdc.h"

int
main(int argc, char **argv)
{
    /* err_exit=3 mirrors stock xrdcrc32c (local-only): its open() of the target
     * fails with Fatal()→exit(3); we match that code on any access failure. */
    return xrdc_cli_cksum_main(argv[0], "crc32c", XRDC_CK_CRC32C,
                               argc == 2 ? argv[1] : NULL, 3);
}
