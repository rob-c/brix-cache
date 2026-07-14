/*
 * xrd_mount.c - extracted concern
 * Phase-38 split of xrd.c; behavior-identical.
 */
#include "xrd_internal.h"


/* `xrd login [--oidc-account N] [--read] [-v]` — acquire/refresh a bearer token
 * (oidc-agent) and/or a GSI proxy (xrdgsiproxy), then show the resulting posture.
 * Pure composition of brix_cred_autorefresh (best-effort: skips what isn't
 * configured). */
int
xrd_login(int argc, char **argv)
{
    const char *account = getenv("OIDC_ACCOUNT");
    int         want_write = 1;   /* login acquires write-capable creds by default */
    int         verbose = 0, i, n;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--oidc-account") == 0 && i + 1 < argc) {
            account = argv[++i];
        } else if (strcmp(argv[i], "--read") == 0) {
            want_write = 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = 1;
        } else {
            fprintf(stderr, "xrd login: unknown argument '%s'\n", argv[i]);
            return 50;
        }
    }
    brix_crypto_init();
    n = brix_cred_autorefresh(want_write, account, verbose, stderr);
    printf("xrd login: %d credential(s) acquired/refreshed\n", n);
    (void) brix_cred_diagnose(want_write, "  ", stdout);
    return 0;
}


/* `xrd ping [-c COUNT] <endpoint>` — connect once, then time COUNT (default 4) stat
 * round-trips to "/" and report min/avg/max RTT. A simple, dependency-free liveness +
 * latency probe (xrddiag has deeper net diagnostics). Exit nonzero on connect failure
 * or if every probe failed. */
int
xrd_ping(int argc, char **argv)
{
    const char *endpoint = NULL;
    int         count = 4, i, ok = 0;
    double      tmin = 1e30, tmax = 0.0, tsum = 0.0;
    brix_url    u;
    brix_opts   o;
    brix_conn   c;
    brix_status st;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) { count = atoi(argv[++i]); }
        else if (endpoint == NULL && argv[i][0] != '-') { endpoint = argv[i]; }
    }
    if (endpoint == NULL || count <= 0) {
        fprintf(stderr, "usage: xrd ping [-c COUNT] <endpoint>\n");
        return 50;
    }
    memset(&o, 0, sizeof(o));
    o.verify_host = 1;
    brix_crypto_init();
    brix_status_clear(&st);
    if (brix_endpoint_parse(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrd ping: %s\n", st.msg);
        return 50;
    }
    if (brix_connect(&c, &u, &o, &st) != 0) {
        fprintf(stderr, "xrd ping: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return brix_shellcode(&st);
    }
    printf("PING %s:%d  (%d stat round-trips to /)\n", u.host, u.port, count);
    for (i = 0; i < count; i++) {
        struct timespec t0, t1;
        brix_statinfo   si;
        brix_status     pst;
        double          ms;
        brix_status_clear(&pst);
        clock_gettime(CLOCK_MONOTONIC, &t0);
        if (brix_stat(&c, "/", &si, &pst) != 0) {
            printf("  seq %d: FAILED (%s)\n", i + 1, pst.msg);
            continue;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        ms = (double) (t1.tv_sec - t0.tv_sec) * 1000.0
           + (double) (t1.tv_nsec - t0.tv_nsec) / 1e6;
        printf("  seq %d: %.3f ms\n", i + 1, ms);
        ok++;
        tsum += ms;
        if (ms < tmin) { tmin = ms; }
        if (ms > tmax) { tmax = ms; }
    }
    brix_close(&c);
    if (ok == 0) {
        printf("%d probes, 0 successful\n", count);
        return 1;
    }
    printf("%d/%d ok  min/avg/max = %.3f/%.3f/%.3f ms\n",
           ok, count, tmin, tsum / ok, tmax);
    return 0;
}


/* ====================================================================== */
/* diagnostic verbs: certinfo / clockskew / whoami / caps (+ doctor JSON)  */
/* ====================================================================== */

/* kXR_Qconfig keys probed by `caps` and `doctor`. The module answers chksum/readv/
 * tpc/tpcdlg/xrdfs.ext meaningfully and echoes "<key>=0" for the rest; real XRootD
 * also answers version/role/sitename/pgread. */

/* Decode the server protocol flags into a short role label. */
const char *
xrd_role_str(uint32_t flags)
{
    if (flags & kXR_isManager) {
        return (flags & kXR_isServer) ? "supervisor" : "manager";
    }
    if (flags & kXR_isServer) { return "server"; }
    return "unknown";
}


/* `xrd whoami <endpoint>` — the negotiated auth protocol + the identity you are
 * presenting (local token subject / GSI proxy DN). Helps debug authz ("I have a
 * token but get 403 — what does the server see?"). */
int
xrd_whoami(int argc, char **argv)
{
    const char *endpoint = (argc >= 3 && argv[2][0] != '-') ? argv[2] : NULL;
    brix_url    u;
    brix_opts   o;
    brix_conn   c;
    brix_status st;
    char       *tok;
    char        pxp[1024];

    if (endpoint == NULL) { fprintf(stderr, "usage: xrd whoami <endpoint>\n"); return 50; }
    memset(&o, 0, sizeof(o)); o.verify_host = 1;
    brix_crypto_init();
    brix_status_clear(&st);
    if (brix_endpoint_parse(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrd whoami: %s\n", st.msg); return 50;
    }
    if (brix_connect(&c, &u, &o, &st) != 0) {
        fprintf(stderr, "xrd whoami: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return brix_shellcode(&st);
    }
    printf("endpoint:   %s:%d\n", u.host, u.port);
    printf("auth used:  %s\n", c.diag.chosen_auth != NULL ? c.diag.chosen_auth : "anonymous (no credential)");
    if (c.sec_list[0] != '\0') { printf("offered:    %s\n", c.sec_list); }
    printf("presenting:\n");
    tok = brix_token_discover();
    if (tok != NULL) { brix_token_explain(tok, stdout); free(tok); }
    else             { printf("  bearer token: none discovered\n"); }
    brix_proxy_default_path(pxp, sizeof(pxp));
    if (access(pxp, R_OK) == 0) { brix_gsi_cert_explain(pxp, stdout); }
    else                        { printf("  GSI proxy: none at %s\n", pxp); }
    brix_close(&c);
    return 0;
}


/* `xrd caps <endpoint>` — server role + kXR_Qconfig capability matrix. */
int
xrd_caps(int argc, char **argv)
{
    const char *endpoint = (argc >= 3 && argv[2][0] != '-') ? argv[2] : NULL;
    brix_url    u;
    brix_opts   o;
    brix_conn   c;
    brix_status st;
    xrd_probe   p;
    const char *ver = NULL, *cipher = NULL;
    int         i;

    if (endpoint == NULL) { fprintf(stderr, "usage: xrd caps <endpoint>\n"); return 50; }
    memset(&o, 0, sizeof(o)); o.verify_host = 1;
    memset(&p, 0, sizeof(p));
    brix_crypto_init();
    brix_status_clear(&st);
    if (brix_endpoint_parse(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrd caps: %s\n", st.msg); return 50;
    }
    if (brix_connect(&c, &u, &o, &st) != 0) {
        fprintf(stderr, "xrd caps: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return brix_shellcode(&st);
    }
    printf("server %s:%d  role=%s  tls=%s\n", u.host, u.port,
           xrd_role_str(c.server_flags),
           brix_tls_info(&c, &ver, &cipher) ? (ver ? ver : "yes") : "cleartext");
    printf("capabilities (kXR_Qconfig; 0 = unset/unsupported):\n");
    xrd_probe_caps(&c, &p);
    for (i = 0; i < p.ncaps; i++) {
        printf("  %-12s %s\n", p.caps[i].key, p.caps[i].val);
    }
    brix_close(&c);
    return 0;
}


/* Fork + exec `cmd_argv` (PATH-searched) and wait. Returns the child's exit code,
 * or 126 if it could not be exec'd (so callers can try a fallback tool), or -1 on
 * fork failure. */
int
run_cmd(char *const cmd_argv[])
{
    pid_t pid = fork();
    int   status;

    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        execvp(cmd_argv[0], cmd_argv);
        _exit(126);   /* distinct from any normal tool exit → "couldn't exec" */
    }
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
        /* retry */
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}


/* Decode mountinfo octal escapes (\040 space, \011 tab, \012 nl, \134 backslash)
 * from `in` into out[outsz]. */
void
mountinfo_unescape(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    while (*in != '\0' && o + 1 < outsz) {
        if (in[0] == '\\' && in[1] >= '0' && in[1] <= '7'
            && in[2] >= '0' && in[2] <= '7' && in[3] >= '0' && in[3] <= '7') {
            out[o++] = (char) ((in[1] - '0') * 64 + (in[2] - '0') * 8 + (in[3] - '0'));
            in += 4;
        } else {
            out[o++] = *in++;
        }
    }
    out[o] = '\0';
}


#ifdef __linux__
/* ---- Classify a mountinfo entry as an XRootD FUSE mount and name its driver ----
 *
 * WHAT: Given a mountinfo filesystem type and source, returns the driver label
 * ("legacy", "aio", or "fuse") when the entry is an XRootD FUSE mount, or NULL when
 * it is not one and should be skipped.
 *
 * WHY: The match/skip predicate and the driver-name decision are the two data-shaped
 * classification rules buried in the line loop; isolating them as one pure lookup
 * keeps the loop body flat and makes the matching rules independently reviewable.
 *
 * HOW:
 *   1. Reject anything that is neither a fuse.xrootdfs* type nor a plain fuse mount
 *      whose source string mentions "root" (a root:// endpoint) — return NULL.
 *   2. Map a "xrootdfs_legacy" type to "legacy", any other fuse.xrootdfs* to "aio",
 *      and the remaining accepted (plain fuse) case to "fuse".
 */
static const char *
xrd_mountinfo_driver(const char *fstype, const char *src)
{
    if (strncmp(fstype, "fuse.xrootdfs", 13) != 0
        && !(strncmp(fstype, "fuse", 4) == 0 && strstr(src, "root") != NULL)) {
        return NULL;
    }
    return (strstr(fstype, "xrootdfs_legacy") != NULL) ? "legacy"
         : (strncmp(fstype, "fuse.xrootdfs", 13) == 0) ? "aio"
         :                                               "fuse";
}


/* ---- Parse and, if it is an XRootD mount, print one /proc mountinfo line ----
 *
 * WHAT: Tokenizes a single mountinfo line (destructively, via strtok_r), and when it
 * describes an XRootD FUSE mount prints its "ENDPOINT  MOUNTPOINT  DRIVER" row,
 * emitting the column header once on the first printed row via *header. Non-matching
 * or malformed lines produce no output.
 *
 * WHY: The per-line parse is the whole of xrd_list_mounts' complexity; extracting it
 * turns the file loop into a flat read-a-line/emit-a-line sequence and gives the
 * field-splitting and unescape steps a single, testable owner.
 *
 * HOW:
 *   1. Split the line on spaces/newlines into up to 48 fields.
 *   2. Locate the "-" separator; bail on lines with too few fields before/after it.
 *   3. Read mountpoint (field 4), fstype (sep+1) and source (sep+2); classify via
 *      xrd_mountinfo_driver and return when it is not an XRootD mount.
 *   4. Unescape the mountpoint and source octal escapes, print the header once, then
 *      print the endpoint/mountpoint/driver row.
 */
static void
xrd_mountinfo_emit_line(char *line, int *header)
{
    char       *fields[48];
    int         nf = 0, sep = -1, i;
    char       *tok, *save;
    const char *mp, *fstype, *src, *driver;
    char        mpbuf[PATH_MAX], srcbuf[PATH_MAX];

    for (tok = strtok_r(line, " \n", &save); tok != NULL && nf < 48;
         tok = strtok_r(NULL, " \n", &save)) {
        fields[nf++] = tok;
    }
    for (i = 0; i < nf; i++) {
        if (strcmp(fields[i], "-") == 0) { sep = i; break; }
    }
    if (sep < 5 || sep + 2 >= nf) { return; }   /* malformed / too few fields */
    mp     = fields[4];
    fstype = fields[sep + 1];
    src    = fields[sep + 2];
    driver = xrd_mountinfo_driver(fstype, src);
    if (driver == NULL) { return; }
    mountinfo_unescape(mp, mpbuf, sizeof(mpbuf));
    mountinfo_unescape(src, srcbuf, sizeof(srcbuf));
    if (!*header) {
        printf("%-36s %-28s %s\n", "ENDPOINT", "MOUNTPOINT", "DRIVER");
        *header = 1;
    }
    printf("%-36s %-28s %s\n", srcbuf, mpbuf, driver);
}
#endif /* __linux__ */


/* `xrd mount` (no args) / `xrd mounts` / `xrd mount -l` — list active XRootD FUSE
 * mounts by parsing /proc/self/mountinfo (override with XRD_MOUNTINFO_PATH for tests).
 * Matches fuse.xrootdfs* filesystem types, plus any fuse mount whose source looks like
 * a root:// endpoint. Prints "ENDPOINT  MOUNTPOINT  DRIVER"; honest empty output (exit
 * 0) when nothing is mounted. Pure procfs parse — no network, no credentials. */
int
xrd_list_mounts(void)
{
#ifndef __linux__
    fprintf(stderr, "xrd mount: mount listing is only supported on Linux\n");
    return 0;
#else
    const char *path = getenv("XRD_MOUNTINFO_PATH");
    FILE       *fp = fopen(path != NULL ? path : "/proc/self/mountinfo", "r");
    char       *line = NULL;
    size_t      cap = 0;
    ssize_t     r;
    int         header = 0;

    if (fp == NULL) {
        fprintf(stderr, "xrd mount: cannot read mountinfo: %s\n", strerror(errno));
        return 1;
    }
    while ((r = getline(&line, &cap, fp)) >= 0) {
        (void) r;
        xrd_mountinfo_emit_line(line, &header);
    }
    free(line);
    fclose(fp);
    return 0;
#endif
}


/* ---- Parse `xrd mount`'s leading driver-selector / --list tokens ----
 *
 * WHAT: Scans the leading options of `xrd mount` (--legacy, --aio, -l/--list,
 * --driver <aio|legacy|resilient>), setting *legacy and *list and advancing *out_i to
 * the first non-selector token. Returns 0 on success, or 50 after printing a diagnostic
 * for an unknown --driver value.
 *
 * WHY: One unified `xrootdfs` binary carries both drivers and `--legacy` selects the
 * synchronous one at run time; the selector grammar is where xrd_mount's branching
 * concentrated. Isolating it leaves the orchestrator a flat sequence and keeps the
 * exact token handling (and its error/exit code) in one place.
 *
 * HOW:
 *   1. Starting at argv[2], consume selectors as long as they are the leading tokens.
 *   2. --legacy/--aio set *legacy; -l/--list set *list; --driver maps its argument
 *      (legacy → *legacy=1; aio/resilient → *legacy=0; anything else → error 50).
 *   3. Stop at the first token that is not a recognized selector and publish the
 *      resulting index via *out_i.
 */
static int
xrd_mount_parse_selectors(int argc, char **argv, int *legacy, int *list, int *out_i)
{
    int i = 2;

    while (i < argc) {
        if (strcmp(argv[i], "--legacy") == 0) { *legacy = 1; i++; }
        else if (strcmp(argv[i], "--aio") == 0) { *legacy = 0; i++; }
        else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
            *list = 1; i++;
        }
        else if (strcmp(argv[i], "--driver") == 0 && i + 1 < argc) {
            const char *d = argv[i + 1];
            if (strcmp(d, "legacy") == 0) { *legacy = 1; }
            else if (strcmp(d, "aio") == 0 || strcmp(d, "resilient") == 0) { *legacy = 0; }
            else {
                fprintf(stderr, "xrd mount: unknown driver '%s' (aio|legacy)\n", d);
                return 50;
            }
            i += 2;
        } else {
            break;
        }
    }
    *out_i = i;
    return 0;
}


/* ---- Build the driver argv for exec, in the driver's native order ----
 *
 * WHAT: Allocates and fills the NULL-terminated argv passed to `exec_tool`:
 * driver name, an optional "--legacy", the (alias-resolved) endpoint, then every
 * remaining forwarded token. Returns the malloc'd vector, or NULL on OOM. The
 * caller-owned `endpoint` buffer backs the resolved endpoint slot and must outlive
 * the returned vector.
 *
 * WHY: Assembling the forwarded vector — with the ~/.xrdrc alias expansion the driver
 * cannot do itself — is a distinct step from option parsing; separating it keeps each
 * concern small and the argv layout (`[opts] endpoint mountpoint [fuse-opts]`) explicit.
 *
 * HOW:
 *   1. Allocate argc-i+3 slots (driver, optional "--legacy", NULL terminator headroom).
 *   2. Emit the driver name, then "--legacy" when legacy mode is selected.
 *   3. If the first forwarded token is a non-option, resolve any alias into `endpoint`
 *      and emit it, consuming that token; a bare URL passes through verbatim.
 *   4. Copy the remaining tokens verbatim and NULL-terminate.
 */
static char **
xrd_mount_build_argv(int argc, char **argv, int i, const char *driver, int legacy,
                     char *endpoint, size_t endpoint_sz)
{
    char **nv = (char **) malloc((size_t) (argc - i + 3) * sizeof(char *));
    int    k = 0;

    if (nv == NULL) {
        return NULL;
    }
    nv[k++] = (char *) driver;
    if (legacy) {
        nv[k++] = (char *) "--legacy";
    }
    if (i < argc && argv[i][0] != '-') {
        brix_alias_resolve(argv[i], endpoint, endpoint_sz);
        nv[k++] = endpoint;
        i++;
    }
    for (; i < argc; i++) {
        nv[k++] = argv[i];
    }
    nv[k] = NULL;
    return nv;
}


/* `xrd mount [--legacy|--driver aio|legacy] [driver-opts] <endpoint> <mountpoint>
 * [fuse-opts]` — mount an XRootD export via the single FUSE3 driver `xrootdfs`.
 * Defaults to its resilient mode; --legacy is forwarded to xrootdfs to select its
 * synchronous mode. Everything after the
 * driver selector is forwarded verbatim in the driver's native arg order
 * (`[opts] endpoint mountpoint [fuse-opts]`). The driver backgrounds itself unless
 * a fuse -f/-d is passed. exec's the driver (does not return on success). */
int
xrd_mount(int argc, char **argv)
{
    const char *driver = "xrootdfs";
    int         i = 2, list = 0, legacy = 0, rc;
    char      **nv;
    char        endpoint[XRDC_PATH_MAX];

    rc = xrd_mount_parse_selectors(argc, argv, &legacy, &list, &i);
    if (rc != 0) {
        return rc;
    }
    /* No positional args (or an explicit --list) → list current XRootD mounts,
     * mirroring mount(8)'s no-arg behavior. */
    if (list || argc - i == 0) {
        return xrd_list_mounts();
    }
    if (argc - i < 2) {
        fprintf(stderr, "usage: xrd mount [--legacy] [driver-opts] <endpoint> "
                        "<mountpoint> [fuse-opts]\n"
                        "  e.g. xrd mount root://store//data /mnt/xrd -o ro\n");
        return 50;
    }
    nv = xrd_mount_build_argv(argc, argv, i, driver, legacy, endpoint, sizeof(endpoint));
    if (nv == NULL) {
        fprintf(stderr, "xrd: out of memory\n");
        return 51;
    }
    exec_tool(driver, nv);   /* does not return on success */
    return 127;              /* unreachable (exec_tool _exit's on failure) */
}


/* `xrd unmount [-z|--lazy] <mountpoint>` (alias: umount) — unmount a FUSE export,
 * preferring fusermount3 (fuse3), then fusermount, then umount. -z/--lazy maps to
 * the lazy-detach flag of whichever tool is used. */
int
xrd_unmount(int argc, char **argv)
{
    const char *mp = NULL;
    int         lazy = 0, i, rc;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-z") == 0 || strcmp(argv[i], "--lazy") == 0) {
            lazy = 1;
        } else if (mp == NULL && argv[i][0] != '-') {
            mp = argv[i];
        } else {
            fprintf(stderr, "xrd unmount: unexpected argument '%s'\n", argv[i]);
            return 50;
        }
    }
    if (mp == NULL) {
        fprintf(stderr, "usage: xrd unmount [-z] <mountpoint>\n");
        return 50;
    }
    {
        char *c[5]; int k = 0;
        c[k++] = (char *) "fusermount3"; c[k++] = (char *) "-u";
        if (lazy) { c[k++] = (char *) "-z"; }
        c[k++] = (char *) mp; c[k] = NULL;
        rc = run_cmd(c);
    }
    if (rc == 126) {   /* fusermount3 not present → fusermount */
        char *c[5]; int k = 0;
        c[k++] = (char *) "fusermount"; c[k++] = (char *) "-u";
        if (lazy) { c[k++] = (char *) "-z"; }
        c[k++] = (char *) mp; c[k] = NULL;
        rc = run_cmd(c);
    }
    if (rc == 126) {   /* neither fusermount → umount (-l = lazy) */
        char *c[4]; int k = 0;
        c[k++] = (char *) "umount";
        if (lazy) { c[k++] = (char *) "-l"; }
        c[k++] = (char *) mp; c[k] = NULL;
        rc = run_cmd(c);
    }
    if (rc == 126) {
        fprintf(stderr, "xrd unmount: no fusermount3/fusermount/umount found\n");
        return 127;
    }
    return (rc < 0) ? 1 : rc;
}
