/*
 * xrdckverify.c — verify a file on disk against its recorded checksum.
 *
 * WHAT: `xrdckverify [--cache|--storage|--auto] [--algo <name>] [-q] <file>`
 *       recomputes a local file's checksum and compares it to the value already
 *       recorded for that file — in a normal storage endpoint's
 *       "user.XrdCks.<alg>" xattr (or "<file>.cks" sidecar), or a proxy cache's
 *       "<file>.cinfo" / "<file>.meta" record.
 * WHY:  A single offline command to detect at-rest corruption of a cached or
 *       stored file, using the same checksum engine the server runs.
 * HOW:  Thin front-end over xrdc_cks_verify_file() (lib/cks_verify.c).
 *
 * exit: 0 ok · 1 mismatch (corruption) · 2 no recorded checksum / unsupported
 *       algorithm · 3 I/O or access error.
 */
#include "xrdc.h"

#include <stdio.h>
#include <string.h>

static int
usage(const char *prog, int rc)
{
    fprintf(stderr,
        "usage: %s [--cache|--storage|--auto] [--algo <name>] [-q] <file>\n"
        "  Verify a local file against its recorded checksum.\n"
        "    --storage  read the user.XrdCks.<alg> xattr (+ <file>.cks sidecar)\n"
        "    --cache    read the proxy-cache <file>.cinfo / <file>.meta digest\n"
        "    --auto     consult both (default)\n"
        "    --algo N   verify only algorithm N (adler32, crc32c, crc64, "
        "crc64nvme, md5)\n"
        "    -q         quiet: print only on mismatch or error\n"
        "  exit: 0 ok, 1 mismatch, 2 no recorded checksum, 3 error\n",
        prog);
    return rc;
}

int
main(int argc, char **argv)
{
    xrdc_ckv_mode   mode = XRDC_CKV_AUTO;
    const char     *algo = NULL;
    const char     *file = NULL;
    int             quiet = 0;
    int             i;
    xrdc_ckv_report rep;
    xrdc_ckv_result r;
    xrdc_status     st;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "--cache") == 0) {
            mode = XRDC_CKV_CACHE;
        } else if (strcmp(a, "--storage") == 0) {
            mode = XRDC_CKV_STORAGE;
        } else if (strcmp(a, "--auto") == 0) {
            mode = XRDC_CKV_AUTO;
        } else if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0) {
            quiet = 1;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            return usage(argv[0], 0);
        } else if (strcmp(a, "--algo") == 0) {
            if (++i >= argc) {
                return usage(argv[0], 2);
            }
            algo = argv[i];
        } else if (a[0] == '-') {
            fprintf(stderr, "%s: unknown option '%s'\n", argv[0], a);
            return usage(argv[0], 2);
        } else if (file == NULL) {
            file = a;
        } else {
            fprintf(stderr, "%s: only one file may be given\n", argv[0]);
            return usage(argv[0], 2);
        }
    }
    if (file == NULL) {
        return usage(argv[0], 2);
    }

    xrdc_status_clear(&st);
    r = xrdc_cks_verify_file(file, algo, mode, &rep, &st);

    switch (r) {
    case XRDC_CKV_OK:
        if (!quiet) {
            printf("OK %s %s %s (%s)\n", file, rep.algo, rep.recorded, rep.source);
        }
        return 0;
    case XRDC_CKV_MISMATCH:
        printf("MISMATCH %s %s recorded=%s computed=%s (%s)\n",
               file, rep.algo, rep.recorded, rep.computed, rep.source);
        return 1;
    case XRDC_CKV_NO_RECORD:
    case XRDC_CKV_UNSUPPORTED:
        fprintf(stderr, "%s: %s\n", file,
                st.msg[0] ? st.msg : "no recorded checksum");
        return 2;
    default:
        fprintf(stderr, "%s: %s\n", file, st.msg[0] ? st.msg : "error");
        return 3;
    }
}
