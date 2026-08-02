/*
 * xrdckcheck.c - xrdcksum "check" subcommand: verify a checksum manifest against a tree.
 * Phase-38 split of xrdcktree.c; behavior-identical. See cktree_internal.h.
 */
#include "brix.h"
#include "brix_ops.h"
#include "cktree_internal.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- xrdcksum check ---- */

/* usage_check — print usage and return rc. */
static int
usage_check(const char *prog, int rc)
{
    fprintf(stderr,
        "usage: %s <manifest> <root> [--algo NAME]\n"
        "  Verify every file listed in a tree manifest against its stored digest.\n"
        "    manifest   path to manifest file produced by `xrdcksum tree`\n"
        "    root       local directory or root:// URL that was checksummed\n"
        "    --algo N   digest algorithm (default: infer from hex length)\n"
        "  Without --algo, digests are assumed: adler32 (8 hex), crc64 (16 hex),\n"
        "  md5 (32 hex); use --algo for crc32c, zcrc32, crc64nvme manifests.\n"
        "  For each line prints 'OK <rel>' or 'FAILED <rel>'.\n"
        "  exit: 0 all OK, 1 any mismatch, 2 errors (parse/I/O); 2 (errors)\n"
        "        takes precedence over 1 (mismatch) when both occur\n",
        prog);
    return rc;
}

/* ckcheck_ctx — per-run state threaded through manifest verification. */
typedef struct {
    const char      *prog;        /* argv[0] for messages */
    const char      *root;        /* local root dir (is_remote == 0) */
    const char      *root_path;   /* remote URL path (is_remote == 1) */
    brix_conn       *c;           /* open remote connection, or NULL */
    int              is_remote;
    const char      *algo_str;    /* --algo value, or NULL (infer per line) */
    brix_cksum_algo  algo;        /* parsed --algo (valid iff algo_str set) */
    int             *errors;
    int             *mismatches;
} ckcheck_ctx;

/* ckcheck_parse_args — decode the `xrdcksum check` command line.
 *
 * WHAT: Validate argc and parse the optional --algo flag; on any usage error
 *       (or -h) set *rc to the exit code and return -1; return 0 to proceed
 *       (manifest = argv[1], root = argv[2]).
 * WHY:  Keeps the option ladder out of the main flow.
 * HOW:  argv[1]/argv[2] are positional; scan from argv[3]; --algo consumes
 *       and validates the next argument via brix_cksum_algo_parse. */
static int
ckcheck_parse_args(int argc, char **argv, const char **algo_str,
                   brix_cksum_algo *algo, int *rc)
{
    int i;

    *algo_str = NULL;
    if (argc < 3) {
        *rc = usage_check(argv[0], XRDC_EXIT_USAGE);
        return -1;
    }
    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--algo") == 0) {
            if (++i >= argc) {
                *rc = usage_check(argv[0], XRDC_EXIT_USAGE);
                return -1;
            }
            *algo_str = argv[i];
            if (brix_cksum_algo_parse(*algo_str, algo) != 0) {
                fprintf(stderr, "%s: unknown algorithm '%s'\n",
                        argv[0], *algo_str);
                *rc = XRDC_EXIT_USAGE;
                return -1;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            *rc = usage_check(argv[0], 0);
            return -1;
        } else {
            fprintf(stderr, "%s: unexpected argument '%s'\n", argv[0], argv[i]);
            *rc = usage_check(argv[0], XRDC_EXIT_USAGE);
            return -1;
        }
    }
    return 0;
}

/* ckcheck_connect — parse the remote root URL and open the one connection.
 *
 * WHAT: Fill *u from `root`, enforce root/roots scheme, and connect *c.
 *       Return 0 on success, -1 after printing the error.
 * WHY:  One connection is reused across every manifest line; setup failures
 *       must abort the whole run before any line is processed.
 * HOW:  brix_url_parse + scheme check → brix_connect; messages match the
 *       historical output exactly. */
static int
ckcheck_connect(const char *prog, const char *root, brix_url *u, brix_conn *c)
{
    brix_status st;

    brix_status_clear(&st);
    if (brix_url_parse(root, u, &st) != 0
        || (u->scheme != XRDC_SCHEME_ROOT
            && u->scheme != XRDC_SCHEME_ROOTS)) {
        fprintf(stderr, "%s: bad root URL: %s\n",
                prog, st.msg[0] ? st.msg : "parse error");
        return -1;
    }
    if (brix_connect(c, u, NULL, &st) != 0) {
        fprintf(stderr, "%s: connect: %s\n", prog, st.msg);
        return -1;
    }
    return 0;
}

/* ckcheck_report_malformed — warn about a manifest line that failed to parse.
 *
 * WHAT: Strip the trailing newline/CR from `line` (in place) and print the
 *       malformed-line message.
 * WHY:  A clean single-line error message; the caller counts the error.
 * HOW:  Trim terminator bytes from the end, then fprintf. */
static void
ckcheck_report_malformed(const char *prog, char *line)
{
    size_t ll = strlen(line);

    while (ll > 0 && (line[ll - 1] == '\n' || line[ll - 1] == '\r')) {
        line[--ll] = '\0';
    }
    fprintf(stderr, "%s: malformed manifest line: %s\n", prog, line);
}

/* ckcheck_line_algo — resolve the digest algorithm for one manifest line.
 *
 * WHAT: Set *out_algo / *out_name for the line: --algo when given, otherwise
 *       inferred from the hex digest length.  Return 0 on success, -1 after
 *       printing the unrecognised-length error (caller counts it).
 * WHY:  Manifests do not record the algorithm; the historical inference is
 *       part of the CLI contract and must stay EXACT: adler32 = 8 hex chars,
 *       crc64 (CRC-64/XZ) = 16, md5 = 32.  crc32c and zcrc32 also produce
 *       8 hex chars and are indistinguishable by length — they require
 *       --algo.  CRITICAL (INVARIANT 9): crc64 and crc64nvme are DIFFERENT
 *       polynomials; 16 hex maps to crc64 ONLY, and crc64nvme manifests must
 *       use --algo.  Never merge or "normalize" the two.
 * HOW:  --algo short-circuit, else switch on strlen(hex). */
static int
ckcheck_line_algo(const ckcheck_ctx *cx, const char *hex, const char *rel,
                  brix_cksum_algo *out_algo, const char **out_name)
{
    size_t hexlen;

    if (cx->algo_str != NULL) {
        *out_algo = cx->algo;
        *out_name = cx->algo_str;
        return 0;
    }
    hexlen = strlen(hex);
    switch (hexlen) {
    case  8: *out_algo = XRDC_CK_ADLER32; *out_name = "adler32"; return 0;
    case 16: *out_algo = XRDC_CK_CRC64;   *out_name = "crc64";   return 0;
    case 32: *out_algo = XRDC_CK_MD5;     *out_name = "md5";     return 0;
    default:
        fprintf(stderr, "%s: unrecognised hex length %zu for '%s'\n",
                cx->prog, hexlen, rel);
        return -1;
    }
}

/* ckcheck_digest_local — compute the actual digest of a local file.
 *
 * WHAT: Open cx->root/rel and compute its checksum into got (TREE_HEX_MAX
 *       bytes).  Return 0 on success, -1 after printing the error.
 * WHY:  The local half of per-line verification; every failure is one
 *       stderr line and one counted error at the call site.
 * HOW:  Overflow-checked ckt_path_join → open O_RDONLY → brix_cksum_fd. */
static int
ckcheck_digest_local(const ckcheck_ctx *cx, const char *rel,
                     brix_cksum_algo algo, char *got)
{
    char        lpath[XRDC_PATH_MAX];
    brix_status st;
    int         fd;

    if (ckt_path_join(cx->root, rel, lpath, sizeof(lpath)) != 0) {
        fprintf(stderr, "%s: path too long: %s/%s\n",
                cx->prog, cx->root, rel);
        return -1;
    }
    fd = open(lpath, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: open %s: %s\n",
                cx->prog, lpath, strerror(errno));
        return -1;
    }
    brix_status_clear(&st);
    if (brix_cksum_fd(fd, algo, got, TREE_HEX_MAX, &st) != 0) {
        fprintf(stderr, "%s: %s: %s\n", cx->prog, lpath,
                st.msg[0] ? st.msg : "checksum error");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/* ckcheck_digest_remote — query the server for a remote file's digest.
 *
 * WHAT: Build root_path + "/" + rel and ask the server (over the reused
 *       connection) for its digest into got (TREE_HEX_MAX bytes).  Return 0
 *       on success, -1 after printing the error.
 * WHY:  The remote half of per-line verification; the server computes, we
 *       compare.
 * HOW:  Overflow-checked snprintf → brix_query_cksum with the per-line
 *       algorithm name. */
static int
ckcheck_digest_remote(const ckcheck_ctx *cx, const char *rel,
                      const char *algo_name, char *got)
{
    char        rpath[XRDC_PATH_MAX];
    brix_status st;
    int         n;

    n = snprintf(rpath, sizeof(rpath), "%s/%s", cx->root_path, rel);
    if (n <= 0 || (size_t) n >= sizeof(rpath)) {
        fprintf(stderr, "%s: path too long: %s/%s\n",
                cx->prog, cx->root_path, rel);
        return -1;
    }
    brix_status_clear(&st);
    if (brix_query_cksum(cx->c, rpath, algo_name,
                         got, TREE_HEX_MAX, &st) != 0) {
        fprintf(stderr, "%s: query_cksum %s: %s\n", cx->prog, rpath,
                st.msg[0] ? st.msg : "query error");
        return -1;
    }
    return 0;
}

/* ckcheck_process_line — verify one manifest line and print its verdict.
 *
 * WHAT: Parse "<hex>  <rel>" via brix_ckmf_parse_line, resolve the line's
 *       algorithm, obtain the actual digest (local compute or remote query),
 *       and print "OK <rel>" or "FAILED <rel>".
 * WHY:  One line = one independent verification; every failure mode counts
 *       an error and moves on so a single bad record never aborts the run.
 * HOW:  brix_ckmf_parse_line is the sole gate on the check path (hostile
 *       manifests cannot escape the root) → ckcheck_line_algo →
 *       ckcheck_digest_local/_remote → case-insensitive compare. */
static void
ckcheck_process_line(const ckcheck_ctx *cx, char *line)
{
    char             hex[TREE_HEX_MAX];
    char             rel[XRDC_PATH_MAX];
    char             got[TREE_HEX_MAX];
    brix_cksum_algo  line_algo;
    const char      *line_algo_name;
    int              drc;

    if (brix_ckmf_parse_line(line, hex, sizeof(hex),
                             rel, sizeof(rel)) != 0) {
        ckcheck_report_malformed(cx->prog, line);
        (*cx->errors)++;
        return;
    }
    if (ckcheck_line_algo(cx, hex, rel, &line_algo, &line_algo_name) != 0) {
        (*cx->errors)++;
        return;
    }

    got[0] = '\0';
    if (!cx->is_remote) {
        drc = ckcheck_digest_local(cx, rel, line_algo, got);
    } else {
        drc = ckcheck_digest_remote(cx, rel, line_algo_name, got);
    }
    if (drc != 0) {
        (*cx->errors)++;
        return;
    }

    if (strcasecmp(hex, got) == 0) {
        printf("OK %s\n", rel);
    } else {
        printf("FAILED %s\n", rel);
        (*cx->mismatches)++;
    }
}

/*
 * brix_xrdckcheck_main — xrdcksum check: manifest verification.
 *
 * WHAT: Parse a manifest produced by `xrdcksum tree` and verify each recorded
 *       digest against the actual file content, local or remote.
 * WHY:  Periodic at-rest integrity checks without regenerating the full manifest;
 *       a single run covers the whole tree with one output line per file.
 * HOW:  Parse args (ckcheck_parse_args); open the manifest; for a remote root
 *       open one connection reused across all files (ckcheck_connect); verify
 *       every line with ckcheck_process_line (which owns algorithm inference —
 *       adler32=8 hex, crc64=16, md5=32 — and the OK/FAILED verdicts).
 *       Exit 0 all-OK, 1 any mismatch, 2 on any parse/I/O error.
 */
int
brix_xrdckcheck_main(int argc, char **argv)
{
    const char      *algo_str   = NULL;
    brix_cksum_algo  algo       = XRDC_CK_ADLER32;  /* valid iff algo_str set */
    FILE            *mf;
    char             line[XRDC_PATH_MAX + TREE_HEX_MAX + 8];
    int              mismatches = 0;
    int              errors     = 0;
    int              rc         = 0;
    brix_url         u;
    brix_conn        c;
    ckcheck_ctx      cx;

    if (ckcheck_parse_args(argc, argv, &algo_str, &algo, &rc) != 0) {
        return rc;
    }

    mf = fopen(argv[1], "r");
    if (mf == NULL) {
        fprintf(stderr, "%s: cannot open manifest '%s': %s\n",
                argv[0], argv[1], strerror(errno));
        return 2;
    }

    cx.prog       = argv[0];
    cx.root       = argv[2];
    cx.root_path  = NULL;
    cx.c          = NULL;
    cx.is_remote  = ckt_is_root_url(argv[2]);
    cx.algo_str   = algo_str;
    cx.algo       = algo;
    cx.errors     = &errors;
    cx.mismatches = &mismatches;

    if (cx.is_remote) {
        if (ckcheck_connect(argv[0], argv[2], &u, &c) != 0) {
            fclose(mf);
            return XRDC_EXIT_USAGE;
        }
        cx.root_path = u.path;
        cx.c         = &c;
    }

    while (fgets(line, sizeof(line), mf) != NULL) {
        ckcheck_process_line(&cx, line);
    }

    fclose(mf);
    if (cx.c != NULL) {
        brix_close(&c);
    }

    if (errors > 0) {
        return 2;
    }
    return mismatches > 0 ? 1 : 0;
}
