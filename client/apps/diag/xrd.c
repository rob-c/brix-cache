/*
 * xrd.c - (kept) routing + shared helpers
 * Phase-38 split of xrd.c; behavior-identical.
 */
#include "xrd_internal.h"
#include "core/version.h"
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
usage_fp(FILE *out)
{
    fprintf(out,
        "usage: xrd <command> [args]\n"
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
        "    xrd version | help\n"
        BRIX_USAGE_FOOTER("xrd"));
}

void
usage(void)
{
    usage_fp(stderr);
}


/* Exec `tool` (found next to this binary, else via PATH) with argv. Does not return
 * on success. */
void
exec_tool(const char *tool, char **argv)
{
    char    self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);

    if (n > 0) {
        char  dirbuf[PATH_MAX];
        char  path[PATH_MAX];
        char *dir;
        self[n] = '\0';
        snprintf(dirbuf, sizeof(dirbuf), "%s", self);
        dir = dirname(dirbuf);
        if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, tool) < sizeof(path)
            && access(path, X_OK) == 0) {
            execv(path, argv);
        }
    }
    execvp(tool, argv);   /* fall back to $PATH */
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


int
main(int argc, char **argv)
{
    const char *cmd;

    if (argc < 2) {
        usage();
        return 50;
    }
    cmd = argv[1];

    if (strcmp(cmd, "--version") == 0 || strcmp(cmd, "version") == 0
        || strcmp(cmd, "-V") == 0) {
        printf("xrd (BriX-Cache client) %s\n", brix_client_version());
        return 0;
    }
    if (strcmp(cmd, "-h") == 0) {
        usage();           /* -h → stderr (C1) */
        return 0;
    }
    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "help") == 0) {
        usage_fp(stdout);  /* --help/help → stdout (WS-2) */
        return 0;
    }

    /* cp/copy -> xrdcp [args...] */
    if (strcmp(cmd, "cp") == 0 || strcmp(cmd, "copy") == 0) {
        argv[1] = (char *) "xrdcp";
        exec_tool("xrdcp", &argv[1]);
    }

    /* get <url> [dst=.] -> xrdcp <url> <dst> */
    if (strcmp(cmd, "get") == 0) {
        char *nv[5];
        int   k = 0;
        if (argc < 3) { fprintf(stderr, "xrd get: needs a <url>\n"); return 50; }
        nv[k++] = (char *) "xrdcp";
        nv[k++] = argv[2];
        nv[k++] = (argc >= 4) ? argv[3] : (char *) ".";
        nv[k] = NULL;
        exec_tool("xrdcp", nv);
    }

    /* put <localfile> <url> -> xrdcp <localfile> <url> */
    if (strcmp(cmd, "put") == 0) {
        char *nv[4];
        if (argc < 4) { fprintf(stderr, "xrd put: needs <localfile> <url>\n"); return 50; }
        nv[0] = (char *) "xrdcp";
        nv[1] = argv[2];
        nv[2] = argv[3];
        nv[3] = NULL;
        exec_tool("xrdcp", nv);
    }

    /* diag ... -> xrddiag ... */
    if (strcmp(cmd, "diag") == 0) {
        argv[1] = (char *) "xrddiag";
        exec_tool("xrddiag", &argv[1]);
    }

    /* replicas <url> -> xrdmapc <url> (cluster holder + space map). */
    if (strcmp(cmd, "replicas") == 0) {
        argv[1] = (char *) "xrdmapc";
        exec_tool("xrdmapc", &argv[1]);
    }

    /* sync <srcdir> <dstdir> -> xrdcp -r --sync <src> <dst> (recursive mirror, skip
     * same-size). Extra flags after the two operands pass through to xrdcp. */
    if (strcmp(cmd, "sync") == 0) {
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
        exec_tool("xrdcp", nv);
    }

    /* ping [-c N] <endpoint>: inline liveness + RTT probe. */
    if (strcmp(cmd, "ping") == 0) { return xrd_ping(argc, argv); }

    /* endpoint diagnostics: inline composition over libbrix. */
    if (strcmp(cmd, "certinfo") == 0)  { return xrd_certinfo(argc, argv); }
    if (strcmp(cmd, "clockskew") == 0) { return xrd_clockskew(argc, argv); }
    if (strcmp(cmd, "whoami") == 0)    { return xrd_whoami(argc, argv); }
    if (strcmp(cmd, "caps") == 0)      { return xrd_caps(argc, argv); }

    /* doctor / login: inline cross-tool verbs (composition, no exec). */
    if (strcmp(cmd, "doctor") == 0) { return xrd_doctor(argc, argv); }
    if (strcmp(cmd, "login") == 0)  { return xrd_login(argc, argv); }

    /* mount / mounts / unmount: drive the FUSE3 driver + fusermount, or list mounts. */
    if (strcmp(cmd, "mount") == 0) { return xrd_mount(argc, argv); }
    if (strcmp(cmd, "mounts") == 0) { return xrd_list_mounts(); }
    if (strcmp(cmd, "unmount") == 0 || strcmp(cmd, "umount") == 0) {
        return xrd_unmount(argc, argv);
    }

    /* backend-storage list/verify (incl. the Ceph/RADOS object catalog) ->
     * xrdstorascan. `inventory` dumps the objects the backend physically holds;
     * `verify` recomputes + compares their checksums (Ceph: over libradosstriper-
     * reassembled bytes); `drift` reconciles namespace vs catalog; `inspect`
     * reports one object's backend facts. The subcommand stays at argv[1]. */
    if (strcmp(cmd, "inventory") == 0 || strcmp(cmd, "verify") == 0
        || strcmp(cmd, "drift") == 0 || strcmp(cmd, "inspect") == 0)
    {
        argv[0] = (char *) "xrdstorascan";
        exec_tool("xrdstorascan", argv);
    }

    /* filesystem verb. xrdfs separates the connect endpoint from the path, so when
     * the target is a full root:// URL (or an alias that resolves to one) carrying a
     * path, split it: `xrd stat root://h//d/f` -> `xrdfs root://h:port stat /d/f`.
     * A bare host:port (or anything not a root:// URL) is passed through unchanged. */
    if (is_fs_verb(cmd)) {
        char        resolved[XRDC_PATH_MAX];
        char        endpoint[320];
        brix_url    u;
        brix_status st;
        char      **nv;
        int         i, k = 0, split = 0, ep_idx = -1;

        if (argc < 3) {
            fprintf(stderr, "xrd %s: needs an <endpoint>\n", cmd);
            return 50;
        }
        /* Find the FIRST arg that resolves to a root:// URL; it fixes the connect
         * endpoint (path depth doesn't matter — `root://h//` targets the root).
         * Scanning (rather than assuming argv[2]) lets flags precede the endpoint,
         * e.g. `xrd df -h root://h//` or `xrd ln -s root://h//tgt root://h//link`. */
        for (i = 2; i < argc; i++) {
            brix_status_clear(&st);
            brix_alias_resolve(argv[i], resolved, sizeof(resolved));
            if (brix_url_parse(resolved, &u, &st) == 0
                && (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS)) {
                const char *scheme = (u.scheme == XRDC_SCHEME_ROOTS) ? "roots" : "root";
                int         v6 = (strchr(u.host, ':') != NULL);
                snprintf(endpoint, sizeof(endpoint), "%s://%s%s%s:%d", scheme,
                         v6 ? "[" : "", u.host, v6 ? "]" : "", u.port);
                split  = 1;
                ep_idx = i;
                break;
            }
        }
        nv = (char **) malloc((size_t) (argc + 3) * sizeof(char *));
        if (nv == NULL) { fprintf(stderr, "xrd: out of memory\n"); return 51; }
        nv[k++] = (char *) "xrdfs";
        if (split) {
            nv[k++] = endpoint;        /* connect endpoint (host:port) */
            nv[k++] = (char *) cmd;    /* the verb */
            /* Map every arg: the endpoint-bearing URL and any further same-endpoint
             * URL/alias become their path components; flags and bare paths pass
             * through. So flags-before-endpoint and multi-path verbs (mv/ln) work. */
            for (i = 2; i < argc; i++) {
                int   mism = 0;
                char *m;
                if (i == ep_idx) {
                    /* Emit an explicit path only when the URL carried one; a bare
                     * `root://h//` (path "/" or empty) leaves the verb to default. */
                    if (u.path[0] == '/' && u.path[1] != '\0') {
                        nv[k++] = strdup(u.path);
                    }
                    continue;
                }
                m = map_fs_arg(argv[i], u.host, u.port, &mism);
                if (mism) {
                    fprintf(stderr, "xrd %s: every path must be on the same endpoint "
                                    "(%s)\n", cmd, endpoint);
                    free(nv);
                    return 50;
                }
                nv[k++] = m;
            }
        } else {
            nv[k++] = argv[2];         /* bare endpoint as given */
            nv[k++] = (char *) cmd;
            for (i = 3; i < argc; i++) {   /* paths/flags verbatim */
                nv[k++] = argv[i];
            }
        }
        nv[k] = NULL;
        exec_tool("xrdfs", nv);
    }

    {
        /*
         * WHAT: emit a did-you-mean hint when the user typed an unrecognised xrd
         *       command; search both the named xrd dispatch table and FS_VERBS.
         * WHY:  spec WS-7: every unknown-command site must offer a suggestion when
         *       one exists within DL distance ≤ 2 (TTY-gated, C3 compliant).
         * HOW:  build a merged NULL-terminated names array; pass to brix_suggest().
         */
        static const char *const XRD_CMDS[] = {
            "cp", "copy", "get", "put", "sync", "ping", "certinfo",
            "clockskew", "whoami", "caps", "doctor", "login", "mount",
            "mounts", "unmount", "umount", "inventory", "verify", "drift",
            "inspect", "version", "help", "diag", "replicas", NULL
        };
        const char          *all_names[80];   /* FS_VERBS(36) + XRD_CMDS(24) + pad */
        int                  n = 0;
        int                  i;
        const char          *suggestion;

        for (i = 0; XRD_CMDS[i] != NULL && n < 79; i++) {
            all_names[n++] = XRD_CMDS[i];
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
    usage();
    return 50;
}
