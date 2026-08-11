/*
 * xrdfs_meta.c - stat / locate / cache / space queries
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"


/* WHAT: Evaluates one stock `stat -q` query string ("IsDir|Offline",
 *       "IsReadable&IsDir", …) against a stat flags word. Returns 1 (holds),
 *       0 (does not hold), or -1 (unknown flag name — usage error).
 * WHY:  stock xrdfs contract, pinned live against xrdfs 5.6.9: '&' requires
 *       every named flag, '|' is satisfied by any; evaluation is a linear
 *       left-to-right fold with no precedence. Exit codes at the caller:
 *       0 holds, 55 fails, 50 unknown flag.
 * HOW:  walk '&'/'|'-separated tokens; map each name through the stock
 *       vocabulary table to its kXR bit; fold presence with the separator
 *       that PRECEDED the token. */
static int
stat_query_eval(const char *query, int flags)
{
    static const struct { const char *name; int bit; } vocab[] = {
        { "XBitSet",     kXR_xset     },
        { "IsDir",       kXR_isDir    },
        { "Other",       kXR_other    },
        { "Offline",     kXR_offline  },
        { "POSCPending", kXR_poscpend },
        { "IsReadable",  kXR_readable },
        { "IsWriteable", kXR_writable },
        { NULL,          0            },
    };
    const char *cursor = query;
    int         holds = -1;               /* -1 = first token pending */
    char        sep = 0;

    while (*cursor != '\0') {
        char   token[24];
        size_t token_len = 0;
        int    bit = -1, present, k;

        while (*cursor != '\0' && *cursor != '&' && *cursor != '|') {
            if (token_len + 1 < sizeof(token)) {
                token[token_len++] = *cursor;
            }
            cursor++;
        }
        token[token_len] = '\0';

        for (k = 0; vocab[k].name != NULL; k++) {
            if (strcmp(token, vocab[k].name) == 0) {
                bit = vocab[k].bit;
                break;
            }
        }
        if (bit < 0) {
            return -1;
        }

        present = (flags & bit) != 0;
        if (holds < 0) {
            holds = present;
        } else if (sep == '&') {
            holds = holds && present;
        } else {
            holds = holds || present;
        }

        if (*cursor != '\0') {
            sep = *cursor;
            cursor++;
        }
    }

    return holds < 0 ? -1 : holds;
}

/* First pass over argv: -j/--json and -q <query> (order-independent; -q
 * applies to every operand regardless of position). */
static void
stat_parse_flags(int argc, char **argv, int *json, const char **query)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            *json = 1;
        } else if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            *query = argv[++i];
        }
    }
}

/* Stat one operand: build_path → brix_stat → print → evaluate -q.  Returns 0
 * when the path stats clean (and satisfies -q when given), 55 when the -q
 * query does not hold, -1 on an unknown -q flag (caller aborts with 50), else
 * the per-path report code.  On error nothing goes to stdout for the path so
 * partial JSON is never emitted. */
static int
stat_one_path(brix_conn *c, const char *cwd, const char *arg, int json,
              const char *query)
{
    brix_status   st;
    brix_statinfo si;
    char          path[XRDC_PATH_MAX];

    build_path(cwd, arg, path, sizeof(path));

    brix_status_clear(&st);
    if (brix_stat(c, path, &si, &st) != 0) {
        return xrdfs_report_err("stat", path, &st, 0, c);
    }
    if (json) { json_statinfo(path, &si); } else { print_statinfo(path, &si); }

    if (query != NULL) {
        int q = stat_query_eval(query, si.flags);

        if (q < 0) {
            fprintf(stderr, "xrdfs: stat: unknown -q flag in '%s' "
                    "(XBitSet, IsDir, Other, Offline, POSCPending, "
                    "IsReadable, IsWriteable)\n", query);
            return -1;
        }
        if (q == 0) {
            return 55;                /* stock: query not satisfied */
        }
    }
    return 0;
}

/* WHAT: stat [-j] [-q query] <path> [path ...] — print metadata for every
 *       named path in human or JSON format (one JSON object per path).
 *       Returns 0 when all paths stat cleanly (and, with -q, every path
 *       satisfies the flag query), 55 when a path fails the query, else the
 *       first failure's exit code.
 * WHY:  -j enables machine-readable output for scripting and pipeline use.
 *       -q is the stock flag-query contract (parity audit §7.12): shell
 *       scripts branch on "is this a directory / offline / writable" without
 *       parsing output. Multiple operands used to silently act on the LAST
 *       path only (feature-parity audit §9.2); every operand now gets its own
 *       stat, and a failure is reported without hiding the remaining paths'
 *       output.
 * HOW:  stat_parse_flags gathers the flags; the operand pass runs
 *       stat_one_path per path, remembering the first failing exit code
 *       (unknown -q flag aborts the whole command with 50). */
int
do_stat(brix_conn *c, const char *cwd, int argc, char **argv)
{
    const char *query = NULL;
    int         json = 0, worst = 0, npaths = 0, i;

    stat_parse_flags(argc, argv, &json, &query);
    for (i = 1; i < argc; i++) {
        int rc;

        if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) {
            continue;
        }
        if (strcmp(argv[i], "-q") == 0 && i + 1 < argc) {
            i++;                          /* skip the query value operand */
            continue;
        }
        npaths++;
        rc = stat_one_path(c, cwd, argv[i], json, query);
        if (rc < 0) {
            return 50;                    /* unknown -q flag: usage error */
        }
        if (rc != 0 && worst == 0) {
            worst = rc;
        }
    }
    if (npaths == 0) {
        fprintf(stderr, "usage: stat [-j] [-q query] <path> [path ...]\n");
        return 50;
    }
    return worst;
}



/* deep-locate walk state: connection + wire options + failure latch. */
typedef struct {
    brix_conn *conn;
    unsigned   options;
    int        failures;
} locate_deep_ctx;

/* WHAT: walk_dir visitor for locate -d — locates every non-directory entry
 *       and prints "<path>: <reply>"; failures are reported and counted, the
 *       walk continues. Always returns 0 (never aborts the walk).
 * WHY:  stock deep-locate reports the locations of every FILE under the tree;
 *       one dead entry must not hide the rest.
 * HOW:  skip directories (their children are visited anyway); locate with the
 *       caller's wire options; print or report per entry. */
static int
locate_deep_visit(const char *full, const brix_dirent *e, int depth, void *u)
{
    locate_deep_ctx *dc = (locate_deep_ctx *) u;
    brix_status      st;
    char             reply[1024];

    (void) depth;
    if (e->have_stat && (e->st.flags & kXR_isDir)) {
        return 0;
    }
    brix_status_clear(&st);
    if (brix_locate_opts(dc->conn, full, dc->options, reply, sizeof(reply),
                         &st) != 0) {
        (void) xrdfs_report_err("locate", full, &st, 0, dc->conn);
        dc->failures++;
        return 0;
    }
    printf("%s: %s\n", full, reply);
    return 0;
}

/* Fold the locate flag surface into wire option bits.  Returns 0 with *arg
 * set, or 50 after printing usage (unknown flag / missing path). */
static int
locate_parse_opts(int argc, char **argv, unsigned *options, int *deep,
                  const char **arg)
{
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-r") == 0) {
            *options |= kXR_refresh;
        } else if (strcmp(argv[i], "-n") == 0) {
            *options |= kXR_nowait;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "-h") == 0) {
            *options |= kXR_prefname;
        } else if (strcmp(argv[i], "-d") == 0) {
            *deep = 1;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "-p") == 0) {
            /* accepted for stock CLI compatibility; see WHY above */
        } else if (argv[i][0] == '-') {
            break;                        /* unknown flag: usage below */
        } else {
            *arg = argv[i];
        }
    }
    if (i < argc || *arg == NULL) {
        fprintf(stderr,
                "usage: locate [-n] [-r] [-d] [-m|-h] [-i] [-p] <path>\n");
        return 50;
    }
    return 0;
}

/* locate -d on a directory: walk the tree, locating every file.  Returns the
 * command exit code, or -1 when the target is a plain file (caller falls
 * through to the single-path locate — stock behaviour). */
static int
locate_deep(brix_conn *c, const char *path, unsigned options)
{
    brix_status   st;
    brix_statinfo si;

    brix_status_clear(&st);
    if (brix_stat(c, path, &si, &st) != 0) {
        return xrdfs_report_err("locate", path, &st, 0, c);
    }
    if (!(si.flags & kXR_isDir)) {
        return -1;                        /* plain file: single locate */
    }
    {
        locate_deep_ctx dc = { c, options, 0 };

        brix_status_clear(&st);
        if (walk_dir(c, path, 0, locate_deep_visit, &dc, &st) < 0) {
            return xrdfs_report_err("locate -d", path, &st, 0, c);
        }
        return dc.failures ? 54 : 0;
    }
}

/* WHAT: locate [-n] [-r] [-d] [-m|-h] [-i] [-p] <path> — resolve a path to
 *       its serving endpoint(s); -d recurses, locating every file under a
 *       directory. Returns 0 on success, else the first failure's exit code.
 * WHY:  stock xrdfs flag surface (parity audit §7.12 — options were hardcoded
 *       to 0): -r sets kXR_refresh (BriX flushes + bypasses the loc/redirect
 *       caches, §2.7), -n sets kXR_nowait (immediate possibly-incomplete
 *       answer; stock servers honor it), -m/-h set kXR_prefname (DNS names
 *       over IPs — already this server's default). -i (no name resolution)
 *       and -p (no tried= opaque) are accepted for stock CLI compatibility:
 *       this client already never resolves names in locate replies and never
 *       sends tried= on a first attempt, so both are satisfied by default.
 * HOW:  locate_parse_opts folds flags into wire option bits; -d routes
 *       through locate_deep (a directory walks via walk_dir with
 *       locate_deep_visit; anything else falls through to the single
 *       locate). */
int
do_locate(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], reply[1024];
    const char *arg = NULL;
    unsigned    options = 0;
    int         deep = 0, rc;

    rc = locate_parse_opts(argc, argv, &options, &deep, &arg);
    if (rc != 0) {
        return rc;
    }
    build_path(cwd, arg, path, sizeof(path));

    if (deep) {
        rc = locate_deep(c, path, options);
        if (rc >= 0) {
            return rc;
        }
        /* -d on a plain file falls through to the single locate */
    }

    brix_status_clear(&st);
    if (brix_locate_opts(c, path, options, reply, sizeof(reply), &st) != 0) {
        return xrdfs_report_err("locate", path, &st, 0, c);
    }
    printf("%s\n", reply);
    return 0;
}



/* WHAT: cache {evict|fevict} <path> — the stock operator cache-eviction
 *       command (parity audit §4.11/§7.12): asks the server to drop the
 *       path's cached copy. Returns 0 on success, else the failure's code.
 * WHY:  drop-in with stock xrdfs: the command travels as kXR_set
 *       "cache <verb> <path>" (pinned live against 5.6.9). On BriX both
 *       spellings evict; the in-use refusal that distinguishes stock's evict
 *       from fevict is a documented divergence.
 * HOW:  validate the sub-verb, build the confined path, send the kXR_set
 *       command via brix_set_cmd, print any reply text. */
int
do_cache(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], payload[XRDC_PATH_MAX + 32];
    char        reply[256];

    if (argc < 3
        || (strcmp(argv[1], "evict") != 0 && strcmp(argv[1], "fevict") != 0)) {
        fprintf(stderr, "usage: cache {evict | fevict} <path>\n");
        return 50;
    }
    build_path(cwd, argv[2], path, sizeof(path));
    snprintf(payload, sizeof(payload), "cache %s %s", argv[1], path);

    brix_status_clear(&st);
    if (brix_set_cmd(c, payload, reply, sizeof(reply), &st) != 0) {
        return xrdfs_report_err("cache", path, &st, 1, c);
    }
    if (reply[0] != '\0') {
        printf("%s\n", reply);
    }
    return 0;
}

/* WHAT: spaceinfo [path] — the stock xrdfs report: Path/Total/Free/Used/
 *       Largest free chunk, one per line, labels padded to column 21 (byte
 *       shape captured live from stock 5.6.9). Returns 0 / mapped code.
 * WHY:  §7.12 — BriX had no spaceinfo verb at all; stock scripts parse this
 *       exact layout. The numbers come from kXR_Qspace's oss.* keys
 *       (space/free/used/maxf), the same source stock reads.
 * HOW:  query Qspace on the (cwd-resolved) path, pull the four keys out of
 *       the &-separated reply, print stock's five lines. */
int
do_spaceinfo(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], reply[1024];
    const char *keys[4] = { "oss.space=", "oss.free=", "oss.used=",
                            "oss.maxf=" };
    const char *labels[4] = { "Total:", "Free:", "Used:",
                              "Largest free chunk:" };
    long long   vals[4];
    int         k;

    build_path(cwd, argc >= 2 ? argv[1] : "/", path, sizeof(path));
    brix_status_clear(&st);
    if (brix_query(c, kXR_Qspace, path, reply, sizeof(reply), &st) != 0) {
        return xrdfs_report_err("spaceinfo", path, &st, 0, c);
    }
    for (k = 0; k < 4; k++) {
        const char *hit = strstr(reply, keys[k]);

        if (hit == NULL) {
            fprintf(stderr, "xrdfs: spaceinfo: server reply lacks %s\n",
                    keys[k]);
            return 54;
        }
        vals[k] = atoll(hit + strlen(keys[k]));
    }
    printf("%-20s%s\n", "Path:", path);
    for (k = 0; k < 4; k++) {
        printf("%-20s%lld\n", labels[k], vals[k]);
    }
    return 0;
}


int
do_statvfs(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], reply[1024];

    build_path(cwd, argc >= 2 ? argv[1] : "/", path, sizeof(path));
    brix_status_clear(&st);
    if (brix_statvfs(c, path, reply, sizeof(reply), &st) != 0) {
        return xrdfs_report_err("statvfs", path, &st, 0, c);
    }
    printf("%s\n", reply);
    return 0;
}


/* df [-h] [path] — friendly disk-space report over kXR_Qspace (the server's oss.*
 * capacity record). Default path "/". -h humanizes the byte columns. Falls back to
 * printing the raw reply verbatim when the shape is unrecognized (never crashes).
 * Cluster-wide aggregation (per-holder rows) is out of scope here — use `xrdmapc`. */
int
do_df(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX], reply[4096];
    int64_t     total, avail, used, largest;
    int         human = 0, i;
    const char *arg = NULL;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--human") == 0) { human = 1; }
        else { arg = argv[i]; }
    }
    build_path(cwd, arg != NULL ? arg : "/", path, sizeof(path));

    brix_status_clear(&st);
    if (brix_query(c, kXR_Qspace, path, reply, sizeof(reply), &st) != 0) {
        return xrdfs_report_err("df", path, &st, 0, c);
    }
    if (df_parse_space(reply, &total, &avail, &used, &largest) != 0) {
        printf("%s\n", reply);   /* unknown shape: honest raw passthrough */
        return 0;
    }
    {
        char ts[32], us[32], as[32], ls[32], pctbuf[8];
        fmt_size(total   >= 0 ? total   : 0, ts, sizeof(ts), human);
        fmt_size(used    >= 0 ? used    : 0, us, sizeof(us), human);
        fmt_size(avail   >= 0 ? avail   : 0, as, sizeof(as), human);
        fmt_size(largest >= 0 ? largest : 0, ls, sizeof(ls), human);
        if (total > 0 && used >= 0) {
            snprintf(pctbuf, sizeof(pctbuf), "%d%%", (int) ((used * 100) / total));
        } else {
            snprintf(pctbuf, sizeof(pctbuf), "-");
        }
        printf("%-12s %-12s %-12s %-6s %-12s %s\n",
               "Size", "Used", "Avail", "Use%", "Largest", "Path");
        printf("%-12s %-12s %-12s %-6s %-12s %s\n", ts, us, as, pctbuf, ls, path);
    }
    return 0;
}

