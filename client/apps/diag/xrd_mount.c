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
        char       *fields[48];
        int         nf = 0, sep = -1, i;
        char       *tok, *save;
        const char *mp, *fstype, *src, *driver;
        char        mpbuf[PATH_MAX], srcbuf[PATH_MAX];

        (void) r;
        for (tok = strtok_r(line, " \n", &save); tok != NULL && nf < 48;
             tok = strtok_r(NULL, " \n", &save)) {
            fields[nf++] = tok;
        }
        for (i = 0; i < nf; i++) {
            if (strcmp(fields[i], "-") == 0) { sep = i; break; }
        }
        if (sep < 5 || sep + 2 >= nf) { continue; }   /* malformed / too few fields */
        mp     = fields[4];
        fstype = fields[sep + 1];
        src    = fields[sep + 2];
        if (strncmp(fstype, "fuse.xrootdfs", 13) != 0
            && !(strncmp(fstype, "fuse", 4) == 0 && strstr(src, "root") != NULL)) {
            continue;
        }
        driver = (strstr(fstype, "xrootdfs_legacy") != NULL) ? "legacy"
               : (strncmp(fstype, "fuse.xrootdfs", 13) == 0) ? "aio"
               :                                               "fuse";
        mountinfo_unescape(mp, mpbuf, sizeof(mpbuf));
        mountinfo_unescape(src, srcbuf, sizeof(srcbuf));
        if (!header) {
            printf("%-36s %-28s %s\n", "ENDPOINT", "MOUNTPOINT", "DRIVER");
            header = 1;
        }
        printf("%-36s %-28s %s\n", srcbuf, mpbuf, driver);
    }
    free(line);
    fclose(fp);
    return 0;
#endif
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
    /* One unified `xrootdfs` binary carries both drivers; `--legacy` selects the
     * synchronous one at run time (passed through to the driver). */
    const char *driver = "xrootdfs";
    int         i = 2, k = 0, list = 0, legacy = 0;
    char      **nv;
    char        endpoint[XRDC_PATH_MAX];

    /* Optional driver selector / --list, only as the leading token(s). */
    while (i < argc) {
        if (strcmp(argv[i], "--legacy") == 0) { legacy = 1; i++; }
        else if (strcmp(argv[i], "--aio") == 0) { legacy = 0; i++; }
        else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--list") == 0) {
            list = 1; i++;
        }
        else if (strcmp(argv[i], "--driver") == 0 && i + 1 < argc) {
            const char *d = argv[i + 1];
            if (strcmp(d, "legacy") == 0) { legacy = 1; }
            else if (strcmp(d, "aio") == 0 || strcmp(d, "resilient") == 0) { legacy = 0; }
            else {
                fprintf(stderr, "xrd mount: unknown driver '%s' (aio|legacy)\n", d);
                return 50;
            }
            i += 2;
        } else {
            break;
        }
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
    /* +3: driver name, an optional "--legacy", and the NULL terminator. */
    nv = (char **) malloc((size_t) (argc - i + 3) * sizeof(char *));
    if (nv == NULL) {
        fprintf(stderr, "xrd: out of memory\n");
        return 51;
    }
    nv[k++] = (char *) driver;
    if (legacy) {
        nv[k++] = (char *) "--legacy";
    }
    /* Resolve a ~/.xrdrc alias for the endpoint (the first forwarded non-option
     * token) so `xrd mount lab:/data /mnt` works like the rest of xrd; the driver
     * itself doesn't expand aliases. A bare URL passes through verbatim. */
    if (i < argc && argv[i][0] != '-') {
        brix_alias_resolve(argv[i], endpoint, sizeof(endpoint));
        nv[k++] = endpoint;
        i++;
    }
    for (; i < argc; i++) {
        nv[k++] = argv[i];
    }
    nv[k] = NULL;
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
