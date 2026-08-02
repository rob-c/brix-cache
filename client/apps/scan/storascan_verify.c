/*
 * storascan_verify.c — xrdstorascan `verify` subcommand (A1, client-side).
 *
 * WHAT: end-to-end single-file integrity check — pull the bytes over the wire,
 *       recompute the checksum, compare to the server's recorded kXR_Qcksum.
 * WHY:  catches at-rest *or* in-transit corruption of one object with a single
 *       command; split from xrdstorascan.c to keep each subcommand file within
 *       the Phase-38 size budget.
 * HOW:  thin orchestration over libbrix (connect/open/read/query) + the pure
 *       compare verdict in storascan_core.c. No libXrdCl, no goto.
 */
#include "storascan_core.h"
#include "storascan_internal.h"
#include "brix.h"
#include "brix_net.h"
#include "brix_ops.h"
#include "core/progname.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Stream the whole remote file into a private anonymous temp fd. Returns the fd
 * (already unlinked, caller closes) or -1 with *st set. */
static int
verify_download_tmp(brix_conn *c, const char *path, brix_status *st)
{
    char     tmpl[] = "/tmp/xrdstorascan.XXXXXX";
    int      fd;
    brix_file f;
    int64_t  off = 0;
    char    *buf;

    fd = mkstemp(tmpl);
    if (fd < 0) {
        brix_status_set(st, XRDC_ESOCK, 0, "mkstemp failed");
        return -1;
    }
    (void) unlink(tmpl);    /* anonymous fd — no symlink/planted-file race */

    if (brix_file_open_read(c, path, &f, st) != 0) {
        close(fd);
        return -1;
    }
    buf = (char *) malloc(1u << 20);
    if (buf == NULL) {
        brix_file_close(c, &f, st);
        close(fd);
        brix_status_set(st, XRDC_ESOCK, 0, "out of memory");
        return -1;
    }
    for (;;) {
        ssize_t n = brix_file_read(c, &f, off, buf, 1u << 20, st);
        if (n < 0) {
            free(buf);
            brix_file_close(c, &f, st);
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        if (write(fd, buf, (size_t) n) != n) {
            free(buf);
            brix_file_close(c, &f, st);
            close(fd);
            brix_status_set(st, XRDC_ESOCK, 0, "temp write failed");
            return -1;
        }
        off += n;
    }
    free(buf);
    (void) brix_file_close(c, &f, st);
    return fd;
}

/*
 * verify_help — print the verify subcommand usage to stdout (WS-2).
 * WHY: --help as the first subcommand arg must exit cleanly to stdout;
 *      avoids falling through to the unknown-option path (exit 64, stderr).
 * HOW: one printf of the frozen usage text; returns SX_OK for the caller.
 */
static int
verify_help(const char *prog)
{
    printf("usage: %s verify <url> [--algo NAME] [-q]\n"
           "    End-to-end verify ONE file: download it, recompute the\n"
           "    checksum, compare to the server's recorded value.\n"
           "    (--algo default adler32)\n"
           "    exit: 0 match, 1 mismatch, 2 no recorded checksum, 3 error\n",
           prog);
    brix_usage_footer(stdout, prog);
    return SX_OK;
}

/*
 * verify_parse_args — decode `verify` options into url/algo/quiet.
 * WHY: keeps cmd_verify a linear pipeline (parse → connect → compare).
 * HOW: --algo takes a value, -q/--quiet sets quiet, exactly one positional
 *      URL; anything else (or a missing URL) prints usage → SX_USAGE.
 */
static int
verify_parse_args(int argc, char **argv, const char **url,
                  const char **algo, int *quiet, const char *prog)
{
    int i;

    for (i = 0; i < argc; i++) {
        const char *a = argv[i];
        if (opt_take("--algo", argc, argv, &i, algo)) {
            continue;
        }
        if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0) {
            *quiet = 1;
        } else if (a[0] == '-') {
            return usage(prog, SX_USAGE);
        } else if (*url == NULL) {
            *url = a;
        } else {
            return usage(prog, SX_USAGE);
        }
    }
    if (*url == NULL) {
        return usage(prog, SX_USAGE);
    }
    return SX_OK;
}

/*
 * verify_compute_wire_hex — recompute the checksum from bytes over the wire.
 * WHY: the download+rewind+digest block is a self-contained step of the
 *      verify pipeline; isolating it keeps cmd_verify under the gate.
 * HOW: stream the file into an anonymous temp fd, rewind, digest it with the
 *      requested algorithm; errors are reported to stderr here and mapped to
 *      the shell exit code the caller returns (caller still owns brix_close).
 */
static int
verify_compute_wire_hex(brix_conn *c, const char *path,
                        brix_cksum_algo algo, char *hex, size_t hexsz)
{
    brix_status st;
    int         tmpfd;

    brix_status_clear(&st);
    tmpfd = verify_download_tmp(c, path, &st);
    if (tmpfd < 0) {
        fprintf(stderr, "xrdstorascan: download %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    if (lseek(tmpfd, 0, SEEK_SET) < 0 ||
        brix_cksum_fd(tmpfd, algo, hex, hexsz, &st) != 0) {
        fprintf(stderr, "xrdstorascan: checksum %s: %s\n", path, st.msg);
        close(tmpfd);
        return SX_ERROR;
    }
    close(tmpfd);
    return SX_OK;
}

int
cmd_verify(int argc, char **argv, const char *prog)
{
    const char     *url = NULL;
    const char     *algo = "adler32";
    int             quiet = 0;
    brix_url        u;
    brix_conn       c;
    brix_status     st;
    brix_cksum_algo algo_enum;
    char            server_hex[STORASCAN_HEX_MAX];
    char            computed_hex[STORASCAN_HEX_MAX];
    int             rc;
    storascan_cks_status verdict;

    if (argc >= 1 && strcmp(argv[0], "--help") == 0) {
        return verify_help(prog);
    }
    rc = verify_parse_args(argc, argv, &url, &algo, &quiet, prog);
    if (rc != SX_OK) {
        return rc;
    }
    if (brix_cksum_algo_parse(algo, &algo_enum) != 0) {
        fprintf(stderr, "xrdstorascan: unsupported algorithm '%s'\n", algo);
        return SX_USAGE;
    }

    rc = storascan_connect(url, &u, &c, &st);
    if (rc != SX_OK) {
        return rc;
    }

    /* Reference value: the server's recorded checksum. */
    if (brix_query_cksum(&c, u.path, algo, server_hex, sizeof(server_hex), &st) != 0) {
        fprintf(stderr, "xrdstorascan: %s %s: %s\n", "query checksum", u.path, st.msg);
        brix_close(&c);
        return brix_shellcode(&st);
    }

    /* Recompute from the bytes pulled over the wire. */
    rc = verify_compute_wire_hex(&c, u.path, algo_enum,
                                 computed_hex, sizeof(computed_hex));
    brix_close(&c);
    if (rc != SX_OK) {
        return rc;
    }

    verdict = storascan_cks_compare(computed_hex, server_hex);
    switch (verdict) {
    case STORASCAN_CKS_MATCH:
        if (!quiet) {
            printf("OK %s %s %s\n", u.path, algo, computed_hex);
        }
        return SX_OK;
    case STORASCAN_CKS_MISMATCH:
        fprintf(stderr, "MISMATCH %s %s: wire=%s recorded=%s\n",
                u.path, algo, computed_hex, server_hex);
        return SX_MISMATCH;
    case STORASCAN_CKS_MISSING:
    default:
        fprintf(stderr, "NO-RECORD %s %s: server reported no checksum\n",
                u.path, algo);
        return SX_NORECORD;
    }
}
