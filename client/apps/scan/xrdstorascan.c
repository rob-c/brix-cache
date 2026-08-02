/*
 * xrdstorascan.c — backend-aware storage admin tool (clean-room C, libXrdCl-free).
 *
 * WHAT: the dispatcher + shared helpers for the storage-scan feature set. The
 *       per-mode implementations live in sibling TUs:
 *         verify <url>   storascan_verify.c — end-to-end single-file integrity
 *                        (A1): pull the bytes, recompute the checksum, compare
 *                        to the server's kXR_Qcksum.
 *         bench  <url>   storascan_bench.c  — gateway performance test (B1):
 *                        sweep block size × parallelism, report throughput +
 *                        IOPS + latency p50/p95/p99.
 *         dump|verify|fill|compare|inspect|health|inventory|drift <dash-url>
 *                        storascan_scan.c   — server-side scan over the
 *                        /brix/api/v1/scan admin endpoint.
 * WHY:  give sysadmins a one-command trust check for a single object and a
 *       realistic, object-store-shaped throughput/latency probe of their gateway.
 * HOW:  this TU owns argv routing (`main`) plus the connect/usage/opt helpers
 *       every subcommand shares (see storascan_internal.h); the subcommands own
 *       the actual I/O, and the pure statistics/verdict core lives in
 *       storascan_core.c. No libXrdCl, no goto.
 *       (see docs/superpowers/specs/2026-06-29-client-backend-sysadmin-tooling-design.md)
 */
#include "storascan_internal.h"
#include "storascan_core.h"
#include "brix.h"
#include "brix_net.h"
#include "brix_ops.h"
#include "core/version.h"
#include "core/progname.h"

#include <stdio.h>
#include <string.h>

/*
 * usage_fp — print xrdstorascan usage to the given stream.
 * WHY: --help (WS-2) must go to stdout; no-arg / unknown-mode goes to stderr.
 *      Returns rc so callers can write `return usage_fp(stderr, prog, SX_USAGE)`.
 */
static int
usage_fp(FILE *out, const char *prog, int rc)
{
    fprintf(out,
        "usage: %s <mode> <url> [options]\n"
        "\n"
        "  verify <url> [--algo NAME] [-q]\n"
        "      End-to-end verify ONE file: download it, recompute the checksum,\n"
        "      compare to the server's recorded value. (--algo default adler32)\n"
        "      exit: 0 match, 1 mismatch, 2 no recorded checksum, 3 error\n"
        "\n"
        "  bench <url> [--op read] [--block SZ[,SZ...]] [--parallel N[,N...]]\n"
        "              [--duration S | --count N] [--pattern seq|random] [--json]\n"
        "      Throughput/latency sweep against the gateway. SZ accepts K/M/G.\n"
        "      defaults: --block 1M,4M --parallel 1,8 --duration 5 --pattern seq\n"
        "\n"
        "  dump|verify|fill|compare <dashboard-url> [--path P] [--algo A]\n"
        "              [--password PW] [--insecure] [--json|--summary]\n"
        "      Server-side scan over the /brix/api/v1/scan admin endpoint:\n"
        "      dump/backfill/verify checksums-at-rest across a subtree. URL is the\n"
        "      http(s):// dashboard base; auth via --password or $XRDSTORASCAN_PASSWORD.\n"
        "      verify/compare exit 1 when a mismatch (bit-rot) is found.\n"
        "\n"
        "  (inspect / inventory / drift / health require later server phases.)\n",
        prog);
    brix_usage_footer(out, prog);
    return rc;
}

int
usage(const char *prog, int rc)
{
    return usage_fp(stderr, prog, rc);
}

/* ---- shared ---------------------------------------------------------------- */

/*
 * opt_take — match argv[*i] against a value-taking option and consume it.
 * WHY: every subcommand's arg loop repeats the same "flag + next-arg" pattern;
 *      one matcher keeps each parse loop under the complexity gate.
 * HOW: exact-match the flag name AND require a following value; on match the
 *      value is stored in *out and *i is advanced past it. A flag without a
 *      value returns 0, so callers fall through to their unknown-option path
 *      (usage/SX_USAGE) exactly as before.
 */
int
opt_take(const char *name, int argc, char **argv, int *i, const char **out)
{
    if (strcmp(argv[*i], name) != 0 || *i + 1 >= argc) {
        return 0;
    }
    *i += 1;
    *out = argv[*i];
    return 1;
}

/* Parse + connect to the endpoint in `url`. 0 on success (c/u filled), else a
 * shell exit code already reported to stderr. */
int
storascan_connect(const char *url, brix_url *u, brix_conn *c, brix_status *st)
{
    brix_status_clear(st);
    if (brix_endpoint_parse(url, u, st) != 0) {
        fprintf(stderr, "xrdstorascan: %s\n", st->msg);
        return SX_USAGE;
    }
    if (u->path[0] == '\0' || strcmp(u->path, "/") == 0) {
        fprintf(stderr, "xrdstorascan: a file path is required in the URL\n");
        return SX_USAGE;
    }
    if (brix_connect(c, u, NULL, st) != 0) {
        fprintf(stderr, "xrdstorascan: connect %s:%d: %s\n",
                u->host, u->port, st->msg);
        return brix_shellcode(st);
    }
    return SX_OK;
}

int
main(int argc, char **argv)
{
    const char *prog = brix_prog_base(argv[0]);   /* self-ID from argv[0] */

    if (argc < 2) {
        return usage(prog, SX_USAGE);
    }
    /* `verify` routes by URL scheme: an http(s):// dashboard URL → the
     * server-engine verify; a root:// URL → the client-side end-to-end check. */
    if (strcmp(argv[1], "verify") == 0) {
        if (argc >= 3 && (strncmp(argv[2], "http://", 7) == 0
                          || strncmp(argv[2], "https://", 8) == 0))
        {
            return cmd_scan("verify", argc - 2, argv + 2, prog);
        }
        return cmd_verify(argc - 2, argv + 2, prog);
    }
    if (strcmp(argv[1], "bench") == 0) {
        return cmd_bench(argc - 2, argv + 2, prog);
    }
    {
        /* Server-engine scan modes routed straight to cmd_scan. */
        static const char *const scan_modes[] = {
            "dump", "fill", "compare", "inspect", "health", "inventory",
            "drift", NULL
        };
        int m;

        for (m = 0; scan_modes[m] != NULL; m++) {
            if (strcmp(argv[1], scan_modes[m]) == 0) {
                return cmd_scan(argv[1], argc - 2, argv + 2, prog);
            }
        }
    }
    if (strcmp(argv[1], "--version") == 0) {
        printf("%s (BriX-Cache client) %s\n", prog,
               brix_client_version());
        return SX_OK;
    }
    if (strcmp(argv[1], "--help") == 0) {
        return usage_fp(stdout, prog, SX_OK);    /* --help → stdout (WS-2) */
    }
    if (strcmp(argv[1], "-h") == 0) {
        return usage(prog, SX_OK);               /* -h → stderr (C1) */
    }
    fprintf(stderr, "xrdstorascan: unknown mode '%s'\n", argv[1]);
    return usage(prog, SX_USAGE);
}
