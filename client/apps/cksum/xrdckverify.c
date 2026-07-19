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
 * HOW:  Thin front-end over brix_cks_verify_file() (lib/cks_verify.c).
 *
 * exit: 0 ok · 1 mismatch (corruption) · 2 no recorded checksum / unsupported
 *       algorithm · 3 I/O or access error.
 */
#include "brix.h"
#include "core/version.h"
#include "core/progname.h"

#include <stdio.h>
#include <string.h>

static int
usage_fp(FILE *out, const char *prog, int rc)
{
    fprintf(out,
        "usage: %s [--cache|--storage|--auto] [--algo <name>] [-q] <file>\n"
        "  Verify a local file against its recorded checksum.\n"
        "    --storage  read the user.XrdCks.<alg> xattr (+ <file>.cks sidecar)\n"
        "    --cache    read the proxy-cache <file>.cinfo / <file>.meta digest\n"
        "    --auto     consult both (default)\n"
        "    --algo N   verify only algorithm N (adler32, crc32c, crc64, "
        "crc64nvme, md5)\n"
        "    -q         quiet: print only on mismatch or error\n"
        "  exit: 0 ok, 1 mismatch, 2 no recorded checksum, 3 error\n",
        brix_prog_base(prog));
    brix_usage_footer(out, prog);
    return rc;
}

static int
usage(const char *prog, int rc)
{
    return usage_fp(stderr, prog, rc);
}

/* ---- Handle the pre-parse informational flags (--version / --help) ----
 *
 * WHAT: Detects the two positional-first informational flags accepted before
 *       normal option parsing. If argv[1] is "--version" it prints the version
 *       banner; if it is "--help" or "-h" it prints usage to stdout. Returns 1
 *       when such a flag was handled (writing the process exit code into
 *       *exit_code), or 0 when no early flag was present and parsing continues.
 *
 * WHY:  These two flags short-circuit before the option loop so that a bare
 *       "--version"/"--help" as the first argument never requires a file
 *       operand; keeping them in one helper leaves the orchestrator flat and
 *       drops branch count out of the main function.
 *
 * HOW:  1. Require at least one argument after argv[0]; otherwise return 0.
 *       2. On "--version", print the banner and set exit_code 0, return 1.
 *       3. On "--help"/"-h", print usage to stdout with exit_code 0, return 1.
 *       4. Otherwise return 0 so the caller runs the full option loop.
 */
static int
ckv_handle_early_flags(int argc, char **argv, int *exit_code)
{
    if (argc < 2) {
        return 0;
    }
    if (strcmp(argv[1], "--version") == 0) {
        printf("%s (BriX-Cache client) %s\n", brix_prog_base(argv[0]),
               brix_client_version());
        *exit_code = 0;
        return 1;
    }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        *exit_code = usage_fp(stdout, argv[0], 0);
        return 1;
    }
    return 0;
}

/* ---- Parse the option/operand vector into the verify request fields ----
 *
 * WHAT: Walks argv filling *mode, *algo, *file and *quiet from the recognised
 *       options (--cache/--storage/--auto, --algo <name>, -q/--quiet,
 *       -h/--help) and the single file operand. Returns 1 when the caller must
 *       exit immediately with the code written into *exit_code (help request,
 *       bad option, missing --algo value, extra operand, or missing file), or
 *       0 when parsing succeeded and *file is set.
 *
 * WHY:  Isolating the whole option loop keeps every early-exit usage() path and
 *       the loop's branch fan-out out of the main function, so the orchestrator
 *       reads as a short linear sequence.
 *
 * HOW:  1. Iterate argv[1..argc); match each mode/quiet/help/algo option.
 *       2. For --algo, consume the following token or fail with code 2.
 *       3. Reject unknown "-"-prefixed options and a second file operand.
 *       4. After the loop, require a file operand; missing → usage code 2.
 *       5. Return 0 only on a clean parse with *file assigned.
 */
static int
ckv_parse_args(int argc, char **argv, brix_ckv_mode *mode,
               const char **algo, const char **file, int *quiet,
               int *exit_code)
{
    int i;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "--cache") == 0) {
            *mode = XRDC_CKV_CACHE;
        } else if (strcmp(a, "--storage") == 0) {
            *mode = XRDC_CKV_STORAGE;
        } else if (strcmp(a, "--auto") == 0) {
            *mode = XRDC_CKV_AUTO;
        } else if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0) {
            *quiet = 1;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            *exit_code = usage(argv[0], 0);
            return 1;
        } else if (strcmp(a, "--algo") == 0) {
            if (++i >= argc) {
                *exit_code = usage(argv[0], 2);
                return 1;
            }
            *algo = argv[i];
        } else if (a[0] == '-') {
            fprintf(stderr, "%s: unknown option '%s'\n", argv[0], a);
            *exit_code = usage(argv[0], 2);
            return 1;
        } else if (*file == NULL) {
            *file = a;
        } else {
            fprintf(stderr, "%s: only one file may be given\n", argv[0]);
            *exit_code = usage(argv[0], 2);
            return 1;
        }
    }
    if (*file == NULL) {
        *exit_code = usage(argv[0], 2);
        return 1;
    }
    return 0;
}

/* ---- Translate a verify result into stdout/stderr output and exit code ----
 *
 * WHAT: Renders the outcome of brix_cks_verify_file() and returns the process
 *       exit code: 0 (OK, one line unless quiet), 1 (MISMATCH, always printed),
 *       2 (no recorded checksum / unsupported algorithm), or 3 (I/O or access
 *       error). Diagnostic text falls back to a fixed message when st has none.
 *
 * WHY:  Keeping the result-to-output mapping in one pure-at-the-edges helper
 *       preserves the exact exit-code contract in a single reviewable place and
 *       removes the switch's branch weight from the main function.
 *
 * HOW:  1. Switch on the verify result code.
 *       2. OK prints the recorded digest line unless quiet; return 0.
 *       3. MISMATCH always prints recorded vs computed; return 1.
 *       4. NO_RECORD/UNSUPPORTED report st.msg or a default; return 2.
 *       5. Any other result reports st.msg or "error"; return 3.
 */
static int
ckv_report_result(brix_ckv_result r, const char *file,
                  const brix_ckv_report *rep, const brix_status *st, int quiet)
{
    switch (r) {
    case XRDC_CKV_OK:
        if (!quiet) {
            printf("OK %s %s %s (%s)\n", file, rep->algo, rep->recorded,
                   rep->source);
        }
        return 0;
    case XRDC_CKV_MISMATCH:
        printf("MISMATCH %s %s recorded=%s computed=%s (%s)\n",
               file, rep->algo, rep->recorded, rep->computed, rep->source);
        return 1;
    case XRDC_CKV_NO_RECORD:
    case XRDC_CKV_UNSUPPORTED:
        fprintf(stderr, "%s: %s\n", file,
                st->msg[0] ? st->msg : "no recorded checksum");
        return 2;
    default:
        fprintf(stderr, "%s: %s\n", file, st->msg[0] ? st->msg : "error");
        return 3;
    }
}

/* ---- Real main; dispatched from the xrdcksum multi-call binary ----
 *
 * WHAT: Front-end for `xrdckverify`: parses options, runs the shared verify
 *       engine over one file, and returns its exit code (0 ok, 1 mismatch,
 *       2 no recorded checksum / unsupported, 3 error).
 *
 * WHY:  A thin orchestrator over brix_cks_verify_file() (lib/cks_verify.c) so
 *       the CLI owns only argument handling and output formatting.
 *
 * HOW:  1. Handle the pre-parse --version/--help flags, exiting if matched.
 *       2. Parse the option/operand vector, exiting on any usage error.
 *       3. Clear status and run brix_cks_verify_file() on the file.
 *       4. Map the verify result to output and exit code.
 */
int
brix_xrdckverify_main(int argc, char **argv)
{
    brix_ckv_mode   mode = XRDC_CKV_AUTO;
    const char     *algo = NULL;
    const char     *file = NULL;
    int             quiet = 0;
    int             exit_code = 0;
    brix_ckv_report rep;
    brix_ckv_result r;
    brix_status     st;

    if (ckv_handle_early_flags(argc, argv, &exit_code)) {
        return exit_code;
    }

    if (ckv_parse_args(argc, argv, &mode, &algo, &file, &quiet, &exit_code)) {
        return exit_code;
    }

    brix_status_clear(&st);
    r = brix_cks_verify_file(file, algo, mode, &rep, &st);

    return ckv_report_result(r, file, &rep, &st, quiet);
}
