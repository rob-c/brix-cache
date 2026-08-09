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
    brix_weburl wu;
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
    /* WebDAV/http operand on the same endpoint → its path component (so a
     * second URL operand, e.g. `xrd mv davs://h/a davs://h/b`, maps like root). */
    if (brix_weburl_parse(resolved, &wu) == 0 && !wu.is_s3) {
        if (strcmp(wu.host, ehost) != 0 || wu.port != eport) {
            *mismatch = 1;
            return NULL;
        }
        return strdup(wu.path[0] != '\0' ? wu.path : "/");
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
 * fs_split_t — result of scanning an fs-verb arg vector for a transport endpoint
 * (root:// or a WebDAV http/https/dav/davs URL): the reassembled connect endpoint,
 * its host/port/path (generic across schemes, so the mapper is scheme-agnostic),
 * and which argv slot bore it.
 */
typedef struct {
    char endpoint[320];
    char host[256];
    int  port;
    char path[XRDC_PATH_MAX];
    int  ep_idx;
} fs_split_t;


/* Map a WebDAV proto to its scheme word for the xrdfs connect endpoint; NULL for
 * s3/s3s, which xrdfs's WebDAV path does not serve (so those don't split). */
static const char *
web_scheme_name(brix_web_proto proto)
{
    switch (proto) {
    case XRDC_WEB_HTTPS: return "https";
    case XRDC_WEB_HTTP:  return "http";
    case XRDC_WEB_DAVS:  return "davs";
    case XRDC_WEB_DAV:   return "dav";
    default:             return NULL;   /* s3/s3s: unsupported by xrdfs WebDAV */
    }
}


/* Fill sp->{endpoint,host,port,path} for a resolved endpoint URL. Returns 1 when
 * `resolved` is a root:// or WebDAV endpoint xrdfs can connect to, else 0. */
static int
fs_fill_endpoint(const char *resolved, fs_split_t *sp)
{
    brix_url    u;
    brix_weburl wu;
    brix_status st;
    int         v6;

    brix_status_clear(&st);
    if (brix_url_parse(resolved, &u, &st) == 0
        && (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS)) {
        const char *scheme = (u.scheme == XRDC_SCHEME_ROOTS) ? "roots" : "root";
        v6 = (strchr(u.host, ':') != NULL);
        snprintf(sp->endpoint, sizeof(sp->endpoint), "%s://%s%s%s:%d", scheme,
                 v6 ? "[" : "", u.host, v6 ? "]" : "", u.port);
        snprintf(sp->host, sizeof(sp->host), "%s", u.host);
        sp->port = u.port;
        snprintf(sp->path, sizeof(sp->path), "%s", u.path);
        return 1;
    }
    if (brix_weburl_parse(resolved, &wu) == 0) {
        const char *scheme = web_scheme_name(wu.proto);
        if (scheme == NULL) {
            return 0;
        }
        v6 = (strchr(wu.host, ':') != NULL);
        snprintf(sp->endpoint, sizeof(sp->endpoint), "%s://%s%s%s:%d", scheme,
                 v6 ? "[" : "", wu.host, v6 ? "]" : "", wu.port);
        snprintf(sp->host, sizeof(sp->host), "%s", wu.host);
        sp->port = wu.port;
        snprintf(sp->path, sizeof(sp->path), "%s", wu.path);
        return 1;
    }
    return 0;
}


/*
 * WHAT: find the FIRST arg (argv[2..]) that resolves to a transport endpoint URL
 *       (root:// or WebDAV http/https/dav/davs); it fixes the connect endpoint
 *       (path depth doesn't matter — `root://h//`/`davs://h/` target the root).
 *       Returns 1 with *sp filled, else 0.
 * WHY:  scanning (rather than assuming argv[2]) lets flags precede the endpoint,
 *       e.g. `xrd df -h root://h//` or `xrd ln -s root://h//tgt root://h//link`;
 *       extending it to WebDAV lets the wrapper split those verbs over davs too.
 * HOW:  alias-resolve each arg, then fs_fill_endpoint() on the first hit.
 */
static int
fs_find_endpoint(int argc, char **argv, fs_split_t *sp)
{
    char resolved[XRDC_PATH_MAX];
    int  i;

    sp->ep_idx = -1;
    for (i = 2; i < argc; i++) {
        brix_alias_resolve(argv[i], resolved, sizeof(resolved));
        if (fs_fill_endpoint(resolved, sp)) {
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
            if (sp->path[0] == '/' && sp->path[1] != '\0') {
                nv[k++] = strdup(sp->path);
            }
            continue;
        }
        m = map_fs_arg(argv[i], sp->host, sp->port, &mism);
        if (mism) {
            fprintf(stderr, "xrd %s: every path must be on the same endpoint "
                            "(%s)\n", argv[1], sp->endpoint);
            return -1;
        }
        nv[k++] = m;
    }
    return k;
}

#define __XRD_C_COMPILED__
#include "_xrd_part2.c"
