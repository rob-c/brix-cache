/*
 * xrd.c - (kept) routing + shared helpers
 * Phase-38 split of xrd.c; behavior-identical.
 */
#include "xrd_internal.h"
#include "core/version.h"
#include "core/progname.h"  /* brix_prog_*(): argv[0]-derived identity + exec prefix */
#include "cli/suggest.h"    /* brix_suggest(): did-you-mean at unknown-command sites */
#include "cli/cli_hint.h"   /* brix_cli_hint(): TTY-gated hint output */

const char *FS_VERBS[] = {
    "ls", "stat", "mkdir", "rm", "rmdir", "mv", "chmod", "touch", "ln", "readlink",
    "truncate", "cat", "head", "tail", "wc", "grep", "hexdump", "dd", "upload",
    "download", "cmp", "cksum", "xattr", "readv", "writev", "du", "df", "tree",
    "find", "locate", "query", "statvfs", "prepare", "stage", "evict", "explain", NULL
};

const char *XRD_CAP_KEYS[] = {
    "chksum", "readv", "tpc", "tpcdlg", "xrdfs.ext",
    "version", "role", "sitename", "pgread", NULL
};


int
is_fs_verb(const char *s)
{
    int i;
    for (i = 0; FS_VERBS[i] != NULL; i++) {
        if (strcmp(FS_VERBS[i], s) == 0) { return 1; }
    }
    return 0;
}


/*
 * usage_fp — print xrd usage to the given stream.
 * WHY: --help (WS-2) goes to stdout; no-arg / unknown-command goes to stderr.
 */
static void
usage_fp(FILE *out, const char *prog)
{
    fprintf(out,
        "usage: %s <command> [args]\n"
        "  the unified XRootD/WLCG toolkit front-end (~/.xrdrc aliases work everywhere)\n\n"
        "  transfer:\n"
        "    xrd cp [opts] <src>... <dst>     copy (-> xrdcp; supports -r -j --sync --from ...)\n"
        "    xrd get <url> [localdst]         download a file (default dst: cwd)\n"
        "    xrd put <localfile> <url>        upload a file\n"
        "    xrd upload   [rate=R] <localfile|-> <url>  rate-limited upload (bs=/-f)\n"
        "    xrd download [rate=R] <url> [localdst|-]   rate-limited download (bs=/-f)\n"
        "    xrd sync <srcdir> <dstdir>       recursive mirror (-> xrdcp -r --sync)\n\n"
        "  filesystem (-> xrdfs <endpoint> <verb>):\n"
        "    xrd ls|stat|du|df|tree|find|mkdir|rm|rmdir|mv|truncate <endpoint> [args]\n"
        "    xrd cat|head|tail|wc|grep|hexdump|dd|cmp|cksum|xattr <endpoint> [args]\n"
        "    xrd touch|chmod|ln|readlink|stage|evict <endpoint> [args]\n"
        "    xrd locate|query|statvfs|prepare|explain <endpoint> [args]\n"
        "      (ls/du/df -h; head/tail -c/-n; tail -f follows; grep -i/-n; ln [-s];\n"
        "       dd bs=/skip=/count=/rate=; upload bs=/rate=/-f)\n\n"
        "  diagnostics:\n"
        "    xrd diag <subcommand> [args]      (-> xrddiag: check/bench/watch/srr/tape/...)\n"
        "    xrd ping [-c N] <endpoint>       liveness + RTT probe\n"
        "    xrd certinfo <endpoint>          server host-cert validity + expiry\n"
        "    xrd clockskew <endpoint>         client<->server clock offset (token/GSI sanity)\n"
        "    xrd whoami <endpoint>            negotiated auth + presented identity\n"
        "    xrd caps <endpoint>              server role + kXR_Qconfig capability matrix\n"
        "    xrd replicas <url>               cluster holder + space map (-> xrdmapc)\n"
        "    xrd doctor [endpoint] [--rw] [--also URL]... [--insecure] [--json]\n"
        "       full endpoint health: creds/TLS/cert/clock/caps + a functional method\n"
        "       battery (--rw adds write tests; --also adds protocols; --json dumps all)\n"
        "    xrd login [--oidc-account N] [--read]  acquire/refresh a token and/or GSI proxy\n\n"
        "  backend storage (-> xrdstorascan; lists/verifies what the backend physically holds,\n"
        "                    incl. the Ceph/RADOS object catalog over librados):\n"
        "    xrd inventory <url> [--stats] [-o objs.tsv]   dump backend object paths (+ sizes)\n"
        "    xrd verify <url> [--wire]                     recompute + compare checksums\n"
        "    xrd drift <url>                               reconcile namespace vs catalog (orphans)\n"
        "    xrd inspect <url>                             one object's backend facts (key/type)\n\n"
        "  FUSE mount (needs the libfuse3-built driver):\n"
        "    xrd mount [--legacy] <endpoint> <mountpoint> [fuse-opts]   mount via xrootdfs (--legacy: simple driver)\n"
        "    xrd mount | xrd mounts            list active XRootD FUSE mounts\n"
        "    xrd unmount [-z] <mountpoint>     unmount (fusermount3/fusermount/umount)\n\n"
        "    xrd version | help\n",
        brix_prog_base(prog));
    brix_usage_footer(out, prog);
}

void
usage(const char *prog)
{
    usage_fp(stderr, prog);
}


/* try_exec_dir — execv `<dir>/<name>` if it exists and is executable (no-op on
 * a NULL dir or a too-long/absent path). Returns only on failure. */
static void
try_exec_dir(const char *dir, const char *name, char **argv)
{
    char path[PATH_MAX];

    if (dir != NULL
        && (size_t) snprintf(path, sizeof(path), "%s/%s", dir, name) < sizeof(path)
        && access(path, X_OK) == 0) {
        execv(path, argv);
    }
}

/*
 * Exec sibling `tool` (found next to this binary, else via $PATH), honouring the
 * co-install prefix: invoked as brix-xrd, prefer the brix-<tool> sibling and fall
 * back to the stock name (so the umbrella works whether or not the compat package
 * is installed). argv[0] is rewritten to the name actually exec'd so the child
 * self-identifies correctly. Does not return on success.
 */
void
exec_tool(const char *prefix, const char *tool, char **argv)
{
    char    self[PATH_MAX];
    char    dirbuf[PATH_MAX];
    char    prefixed[256];
    char   *dir = NULL;
    ssize_t n   = readlink("/proc/self/exe", self, sizeof(self) - 1);

    if (n > 0) {
        self[n] = '\0';
        snprintf(dirbuf, sizeof(dirbuf), "%s", self);
        dir = dirname(dirbuf);
    }
    /* Prefixed sibling first (brix-<tool>): next to this binary, then $PATH. */
    if (prefix != NULL && prefix[0] != '\0'
        && (size_t) snprintf(prefixed, sizeof(prefixed), "%s%s", prefix, tool)
               < sizeof(prefixed)) {
        argv[0] = prefixed;               /* child self-IDs as brix-<tool> */
        try_exec_dir(dir, prefixed, argv);
        execvp(prefixed, argv);
    }
    /* Stock name fallback: next to this binary, then $PATH. */
    argv[0] = (char *) tool;
    try_exec_dir(dir, tool, argv);
    execvp(tool, argv);
    fprintf(stderr, "xrd: cannot run %s: %s\n", tool, strerror(errno));
    _exit(127);
}


/* Map an fs-verb path-position arg to what xrdfs expects: a root:// URL (or an alias
 * resolving to one) becomes its path component (host/port must match `ehost:eport`);
 * anything else (a bare path or a flag) is passed through. Returns a malloc'd string,
 * or NULL with *mismatch=1 if the arg targets a different endpoint. */
char *
map_fs_arg(const char *arg, const char *ehost, int eport, int *mismatch)
{
    char        resolved[XRDC_PATH_MAX];
    brix_url    u;
    brix_status st;

    *mismatch = 0;
    brix_status_clear(&st);
    brix_alias_resolve(arg, resolved, sizeof(resolved));
    if (brix_url_parse(resolved, &u, &st) == 0
        && (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS)) {
        if (strcmp(u.host, ehost) != 0 || u.port != eport) {
            *mismatch = 1;
            return NULL;
        }
        return strdup(u.path[0] != '\0' ? u.path : "/");
    }
    return strdup(arg);   /* a bare path or a flag — verbatim */
}


/*
 * WHAT: `xrd version` / `--version` / `-V` — print the client version to stdout.
 * WHY:  table row for the version verb; keeps main() a pure dispatcher.
 * HOW:  printf + return 0; args beyond the verb are ignored (as before).
 */
static int
cmd_version(int argc, char **argv)
{
    (void) argc;
    printf("%s (BriX-Cache client) %s\n", brix_prog_base(argv[0]),
           brix_client_version());
    return 0;
}


/*
 * WHAT: `xrd -h` — usage to stderr, exit 0.
 * WHY:  spec C1: bare -h keeps the historical stderr stream (vs --help/stdout).
 * HOW:  usage() targets stderr; return 0.
 */
static int
cmd_usage_stderr(int argc, char **argv)
{
    (void) argc;
    usage(argv[0]);    /* -h → stderr (C1) */
    return 0;
}


/*
 * WHAT: `xrd --help` / `xrd help` — usage to stdout, exit 0.
 * WHY:  spec WS-2: explicit help requests print to stdout for pager/grep use.
 * HOW:  usage_fp(stdout); return 0.
 */
static int
cmd_help(int argc, char **argv)
{
    (void) argc;
    usage_fp(stdout, argv[0]);  /* --help/help → stdout (WS-2) */
    return 0;
}


/*
 * WHAT: `xrd cp|copy [args...]` -> exec `xrdcp [args...]`.
 * WHY:  cp is a thin alias; the copy engine lives in xrdcp.
 * HOW:  overwrite argv[1] with the tool name and exec from there.
 */
static int
cmd_cp(int argc, char **argv)
{
    const char *pfx = brix_prog_prefix(brix_prog_base(argv[0]));
    (void) argc;
    argv[1] = (char *) "xrdcp";
    exec_tool(pfx, "xrdcp", &argv[1]);
    return 127;   /* unreachable: exec_tool does not return */
}


/*
 * WHAT: `xrd get <url> [dst=.]` -> exec `xrdcp <url> <dst>`.
 * WHY:  convenience download verb with a cwd default destination.
 * HOW:  build a fixed 4-slot argv; missing dst becomes ".".
 */
static int
cmd_get(int argc, char **argv)
{
    const char *pfx = brix_prog_prefix(brix_prog_base(argv[0]));
    char *nv[5];
    int   k = 0;

    if (argc < 3) { fprintf(stderr, "xrd get: needs a <url>\n"); return 50; }
    nv[k++] = (char *) "xrdcp";
    nv[k++] = argv[2];
    nv[k++] = (argc >= 4) ? argv[3] : (char *) ".";
    nv[k] = NULL;
    exec_tool(pfx, "xrdcp", nv);
    return 127;   /* unreachable: exec_tool does not return */
}


/*
 * WHAT: `xrd put <localfile> <url>` -> exec `xrdcp <localfile> <url>`.
 * WHY:  convenience upload verb; both operands are mandatory.
 * HOW:  fixed 4-slot argv, then exec.
 */
static int
cmd_put(int argc, char **argv)
{
    const char *pfx = brix_prog_prefix(brix_prog_base(argv[0]));
    char *nv[4];

    if (argc < 4) { fprintf(stderr, "xrd put: needs <localfile> <url>\n"); return 50; }
    nv[0] = (char *) "xrdcp";
    nv[1] = argv[2];
    nv[2] = argv[3];
    nv[3] = NULL;
    exec_tool(pfx, "xrdcp", nv);
    return 127;   /* unreachable: exec_tool does not return */
}


/*
 * WHAT: `xrd diag ...` -> exec `xrddiag ...`.
 * WHY:  the diagnostics busybox owns the check/bench/watch/srr/tape family.
 * HOW:  overwrite argv[1] with the tool name and exec from there.
 */
static int
cmd_diag(int argc, char **argv)
{
    const char *pfx = brix_prog_prefix(brix_prog_base(argv[0]));
    (void) argc;
    argv[1] = (char *) "xrddiag";
    exec_tool(pfx, "xrddiag", &argv[1]);
    return 127;   /* unreachable: exec_tool does not return */
}


/*
 * WHAT: `xrd replicas <url>` -> exec `xrdmapc <url>` (cluster holder + space map).
 * WHY:  replica topology is xrdmapc's job; xrd only routes.
 * HOW:  overwrite argv[1] with the tool name and exec from there.
 */
static int
cmd_replicas(int argc, char **argv)
{
    const char *pfx = brix_prog_prefix(brix_prog_base(argv[0]));
    (void) argc;
    argv[1] = (char *) "xrdmapc";
    exec_tool(pfx, "xrdmapc", &argv[1]);
    return 127;   /* unreachable: exec_tool does not return */
}


/*
 * WHAT: `xrd sync <srcdir> <dstdir>` -> exec `xrdcp -r --sync <src> <dst>`
 *       (recursive mirror, skip same-size).
 * WHY:  sync is xrdcp recursion + the --sync skip filter; extra flags after the
 *       two operands pass through to xrdcp.
 * HOW:  malloc argc+3 slots; prepend the tool + fixed flags, copy the rest.
 */
static int
cmd_sync(int argc, char **argv)
{
    const char *pfx = brix_prog_prefix(brix_prog_base(argv[0]));
    char **nv;
    int    k = 0, j;

    if (argc < 4) {
        fprintf(stderr, "xrd sync: needs <srcdir> <dstdir>\n");
        return 50;
    }
    nv = (char **) malloc((size_t) (argc + 3) * sizeof(char *));
    if (nv == NULL) { fprintf(stderr, "xrd: out of memory\n"); return 51; }
    nv[k++] = (char *) "xrdcp";
    nv[k++] = (char *) "-r";
    nv[k++] = (char *) "--sync";
    for (j = 2; j < argc; j++) { nv[k++] = argv[j]; }
    nv[k] = NULL;
    exec_tool(pfx, "xrdcp", nv);
    return 127;   /* unreachable: exec_tool does not return */
}


/*
 * WHAT: `xrd mounts` — list active XRootD FUSE mounts.
 * WHY:  adapter row: xrd_list_mounts() takes no args, the table fn type does.
 * HOW:  ignore argc/argv (as before) and delegate.
 */
static int
cmd_mounts(int argc, char **argv)
{
    (void) argc; (void) argv;
    return xrd_list_mounts();
}


/*
 * WHAT: backend-storage list/verify (incl. the Ceph/RADOS object catalog) ->
 *       exec xrdstorascan. `inventory` dumps the objects the backend physically
 *       holds; `verify` recomputes + compares their checksums (Ceph: over
 *       libradosstriper-reassembled bytes); `drift` reconciles namespace vs
 *       catalog; `inspect` reports one object's backend facts.
 * WHY:  four verbs share one target tool; the subcommand stays at argv[1].
 * HOW:  rewrite argv[0] to the tool name and exec the whole vector.
 */
static int
cmd_storascan(int argc, char **argv)
{
    const char *pfx = brix_prog_prefix(brix_prog_base(argv[0]));
    (void) argc;
    argv[0] = (char *) "xrdstorascan";
    exec_tool(pfx, "xrdstorascan", argv);
    return 127;   /* unreachable: exec_tool does not return */
}


/*
 * xrd_dispatch_t — one named xrd subcommand: exact-match name -> handler.
 * Busybox-style table (same pattern as the xrdcksum/xrddiag applet families).
 * Non-flag names double as the did-you-mean suggestion corpus, so keep them in
 * the historical XRD_CMDS order; flag aliases ('-'-prefixed) sit at the end and
 * are skipped when building suggestions.
 */
typedef struct {
    const char *name;
    int       (*fn)(int argc, char **argv);
} xrd_dispatch_t;

static const xrd_dispatch_t XRD_DISPATCH[] = {
    { "cp",        cmd_cp        },
    { "copy",      cmd_cp        },
    { "get",       cmd_get       },
    { "put",       cmd_put       },
    { "sync",      cmd_sync      },
    { "ping",      xrd_ping      },   /* inline liveness + RTT probe */
    { "certinfo",  xrd_certinfo  },   /* endpoint diagnostics: inline composition */
    { "clockskew", xrd_clockskew },
    { "whoami",    xrd_whoami    },
    { "caps",      xrd_caps      },
    { "doctor",    xrd_doctor    },   /* cross-tool verbs (composition, no exec) */
    { "login",     xrd_login     },
    { "mount",     xrd_mount     },   /* FUSE3 driver + fusermount */
    { "mounts",    cmd_mounts    },
    { "unmount",   xrd_unmount   },
    { "umount",    xrd_unmount   },
    { "inventory", cmd_storascan },
    { "verify",    cmd_storascan },
    { "drift",     cmd_storascan },
    { "inspect",   cmd_storascan },
    { "version",   cmd_version   },
    { "help",      cmd_help      },
    { "diag",      cmd_diag      },
    { "replicas",  cmd_replicas  },
    { "--version", cmd_version   },
    { "-V",        cmd_version   },
    { "-h",        cmd_usage_stderr },
    { "--help",    cmd_help      },
    { NULL,        NULL          }
};


/*
 * fs_split_t — result of scanning an fs-verb arg vector for a root:// endpoint:
 * the parsed URL, the reassembled connect endpoint, and which argv slot bore it.
 */
typedef struct {
    brix_url u;
    char     endpoint[320];
    int      ep_idx;
} fs_split_t;


/*
 * WHAT: find the FIRST arg (argv[2..]) that resolves to a root:// URL; it fixes
 *       the connect endpoint (path depth doesn't matter — `root://h//` targets
 *       the root). Returns 1 with *sp filled, else 0.
 * WHY:  scanning (rather than assuming argv[2]) lets flags precede the endpoint,
 *       e.g. `xrd df -h root://h//` or `xrd ln -s root://h//tgt root://h//link`.
 * HOW:  alias-resolve + URL-parse each arg; on the first root/roots hit,
 *       rebuild `scheme://host:port` (bracketing IPv6 hosts) into sp->endpoint.
 */
static int
fs_find_endpoint(int argc, char **argv, fs_split_t *sp)
{
    char        resolved[XRDC_PATH_MAX];
    brix_status st;
    int         i;

    sp->ep_idx = -1;
    for (i = 2; i < argc; i++) {
        brix_status_clear(&st);
        brix_alias_resolve(argv[i], resolved, sizeof(resolved));
        if (brix_url_parse(resolved, &sp->u, &st) == 0
            && (sp->u.scheme == XRDC_SCHEME_ROOT
                || sp->u.scheme == XRDC_SCHEME_ROOTS)) {
            const char *scheme =
                (sp->u.scheme == XRDC_SCHEME_ROOTS) ? "roots" : "root";
            int         v6 = (strchr(sp->u.host, ':') != NULL);
            snprintf(sp->endpoint, sizeof(sp->endpoint), "%s://%s%s%s:%d", scheme,
                     v6 ? "[" : "", sp->u.host, v6 ? "]" : "", sp->u.port);
            sp->ep_idx = i;
            return 1;
        }
    }
    return 0;
}


/*
 * WHAT: append the mapped fs-verb args (argv[2..]) to nv starting at slot k.
 *       Returns the next free slot, or -1 (with the error printed) when an arg
 *       targets a different endpoint.
 * WHY:  map every arg — the endpoint-bearing URL and any further same-endpoint
 *       URL/alias become their path components; flags and bare paths pass
 *       through. So flags-before-endpoint and multi-path verbs (mv/ln) work.
 * HOW:  the endpoint slot emits an explicit path only when the URL carried one
 *       (a bare `root://h//`, path "/" or empty, leaves the verb to default);
 *       every other slot goes through map_fs_arg().
 */
static int
fs_map_split_args(char **nv, int k, int argc, char **argv, fs_split_t *sp)
{
    int i;

    for (i = 2; i < argc; i++) {
        int   mism = 0;
        char *m;
        if (i == sp->ep_idx) {
            if (sp->u.path[0] == '/' && sp->u.path[1] != '\0') {
                nv[k++] = strdup(sp->u.path);
            }
            continue;
        }
        m = map_fs_arg(argv[i], sp->u.host, sp->u.port, &mism);
        if (mism) {
            fprintf(stderr, "xrd %s: every path must be on the same endpoint "
                            "(%s)\n", argv[1], sp->endpoint);
            return -1;
        }
        nv[k++] = m;
    }
    return k;
}


/*
 * WHAT: filesystem verb -> exec `xrdfs <endpoint> <verb> [paths...]`.
 * WHY:  xrdfs separates the connect endpoint from the path, so when the target
 *       is a full root:// URL (or an alias that resolves to one) carrying a
 *       path, split it: `xrd stat root://h//d/f` -> `xrdfs root://h:port stat
 *       /d/f`. A bare host:port (or anything not a root:// URL) is passed
 *       through unchanged.
 * HOW:  fs_find_endpoint() scans for the endpoint URL; split mode maps every
 *       arg via fs_map_split_args(), pass-through mode copies args verbatim.
 */
static int
cmd_fs_verb(int argc, char **argv)
{
    const char *cmd = argv[1];
    const char *pfx = brix_prog_prefix(brix_prog_base(argv[0]));
    fs_split_t  sp;
    char      **nv;
    int         i, k = 0, split;

    if (argc < 3) {
        fprintf(stderr, "xrd %s: needs an <endpoint>\n", cmd);
        return 50;
    }
    split = fs_find_endpoint(argc, argv, &sp);
    nv = (char **) malloc((size_t) (argc + 3) * sizeof(char *));
    if (nv == NULL) { fprintf(stderr, "xrd: out of memory\n"); return 51; }
    nv[k++] = (char *) "xrdfs";
    if (split) {
        nv[k++] = sp.endpoint;         /* connect endpoint (host:port) */
        nv[k++] = (char *) cmd;        /* the verb */
        k = fs_map_split_args(nv, k, argc, argv, &sp);
        if (k < 0) {
            free(nv);
            return 50;
        }
    } else {
        nv[k++] = argv[2];             /* bare endpoint as given */
        nv[k++] = (char *) cmd;
        for (i = 3; i < argc; i++) {   /* paths/flags verbatim */
            nv[k++] = argv[i];
        }
    }
    nv[k] = NULL;
    exec_tool(pfx, "xrdfs", nv);
    return 127;   /* unreachable: exec_tool does not return */
}


/*
 * WHAT: emit a did-you-mean hint when the user typed an unrecognised xrd
 *       command; search both the named xrd dispatch table and FS_VERBS.
 * WHY:  spec WS-7: every unknown-command site must offer a suggestion when
 *       one exists within DL distance ≤ 2 (TTY-gated, C3 compliant).
 * HOW:  build a merged NULL-terminated names array — dispatch-table names in
 *       their historical order, skipping '-'-prefixed flag aliases, then
 *       FS_VERBS — and pass it to brix_suggest().
 */
static void
report_unknown_command(const char *cmd)
{
    const char *all_names[80];   /* FS_VERBS(36) + named commands(24) + pad */
    int         n = 0;
    int         i;
    const char *suggestion;

    for (i = 0; XRD_DISPATCH[i].name != NULL && n < 79; i++) {
        if (XRD_DISPATCH[i].name[0] != '-') {
            all_names[n++] = XRD_DISPATCH[i].name;
        }
    }
    for (i = 0; FS_VERBS[i] != NULL && n < 79; i++) {
        all_names[n++] = FS_VERBS[i];
    }
    all_names[n] = NULL;

    fprintf(stderr, "xrd: unknown command '%s'\n\n", cmd);
    suggestion = brix_suggest(cmd, all_names);
    if (suggestion != NULL) {
        brix_cli_hint("hint: did you mean '%s'?\n", suggestion);
    }
}


int
main(int argc, char **argv)
{
    const char *cmd;
    int         i;

    if (argc < 2) {
        usage(argv[0]);
        return 50;
    }
    cmd = argv[1];

    for (i = 0; XRD_DISPATCH[i].name != NULL; i++) {
        if (strcmp(XRD_DISPATCH[i].name, cmd) == 0) {
            return XRD_DISPATCH[i].fn(argc, argv);
        }
    }

    if (is_fs_verb(cmd)) {
        return cmd_fs_verb(argc, argv);
    }

    report_unknown_command(cmd);
    usage(argv[0]);
    return 50;
}
