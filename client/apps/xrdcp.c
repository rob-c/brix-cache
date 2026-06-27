/*
 * xrdcp.c - (kept) routing + shared helpers
 * Phase-38 split of xrdcp.c; behavior-identical.
 */
#include "xrdcp_internal.h"

void
usage(void)
{
    fprintf(stderr,
        "usage: xrdcp [opts] <src>... <dst>\n"
        "  src/dst is root://host[:port]//path, a web URL, a local path, or '-'\n"
        "  web schemes (GET/PUT): davs:// http(s):// dav:// s3:// s3s://\n"
        "  web->web (e.g. davs://a/f s3://b/k) relays through a local temp file\n"
        "  multiple sources / a glob / --from <file> => <dst> is a directory\n"
        "  -f             overwrite an existing destination\n"
        "  -r             recursively copy a tree (root/davs/http/s3 <-> local, or web<->web)\n"
        "  -P             persist-on-successful-close (upload)\n"
        "  -s             silent\n"
        "  -v, -d         verbose / debug\n"
        "  --from <file>  read sources from a manifest (one per line; '-'=stdin)\n"
        "  --retry <n>    retry each failed transfer up to n times (backoff); 0 = fail fast\n"
        "  --no-retry     disable transport resilience: fail on the first fault\n"
        "  --max-stall <ms> reconnect/resume patience window (0 = fail fast)\n"
        "  --auto-refresh proactively renew an expired/near-expiry token (oidc-agent)\n"
        "                 or GSI proxy before transferring\n"
        "  --oidc-account <name>  oidc-agent account for --auto-refresh (or $OIDC_ACCOUNT)\n"
        "  -j, --jobs <n> copy up to n files concurrently (batch mode)\n"
        "  --sync         skip transfers whose destination already has the same size\n"
        "  --progress     show a transfer progress bar + ETA (auto on a TTY; single copy)\n"
        "  --verify       after the transfer, verify the checksum against the server (root://)\n"
        "  --tls          require in-protocol TLS (implied by roots://)\n"
        "  --notlsok      permit cleartext if the server offers no TLS (root:// only)\n"
        "  --noverifyhost skip TLS hostname check (chain verification stays on)\n"
        "  --auth <p>     force auth protocol: gsi | ztn | krb5 | sss | unix\n"
        "  --pgrw         use paged I/O (kXR_pgread/pgwrite) with per-page CRC32c\n"
        "  --cksum <t>[:source|:print|:<value>]  verify a checksum (adler32|crc32c|md5)\n"
        "  --compress <codec>  root:// inline compression (gzip|deflate|zstd|br|\n"
        "                      xz|bzip2): compress on download (read) and on\n"
        "                      upload (write); server opt-in, transparent, ignored\n"
        "                      if the server doesn't support it\n"
        "  --zip               store the local source as a STORE member of the\n"
        "                      destination ZIP archive (overwrites the archive)\n"
        "  --zip-append        like --zip but append to an existing archive\n"
        "  -S, --streams N   open N-1 secondary kXR_bind data streams\n"
        "  --tpc first|only|delegate   server-side third-party copy (remote->remote)\n"
        "  -T, --token <jwt>  WebDAV/HTTP bearer token (or $BEARER_TOKEN)\n"
        "  --s3-access <k>    S3 SigV4 access key id (or $AWS_ACCESS_KEY_ID)\n"
        "  --s3-secret <k>    S3 SigV4 secret key (or $AWS_SECRET_ACCESS_KEY)\n"
        "  --s3-region <r>    S3 SigV4 region (or $AWS_DEFAULT_REGION; default us-east-1)\n"
        "  --wire-trace[=N]  decode every frame to stderr (N>=2 adds a hexdump)\n"
        "  --timing       print per-opcode RTT at the end\n"
        "  -V             print version and exit\n"
        "  -h             this help\n");
}


/* Append a strdup'd copy of `s` to a growable string array. 0 / -1. */
int
str_append(char ***list, size_t *n, size_t *cap, const char *s)
{
    if (*n == *cap) {
        size_t  nc = *cap ? *cap * 2 : 16;
        char  **na = (char **) realloc(*list, nc * sizeof(char *));
        if (na == NULL) { return -1; }
        *list = na;
        *cap = nc;
    }
    (*list)[*n] = strdup(s);
    if ((*list)[*n] == NULL) { return -1; }
    (*n)++;
    return 0;
}


void
str_free(char **list, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) { free(list[i]); }
    free(list);
}


/* If `arg` names a ~/.xrdrc alias, fold its per-endpoint credentials into `o` — a
 * value already set (CLI flag or earlier alias) always wins. The opt pointers are
 * backed by static storage for the process lifetime. PII: creds are never logged. */
void
merge_alias_auth(const char *arg, xrdc_copy_opts *o)
{
    const char     *colon = strchr(arg, ':');
    char            name[256];
    size_t          nlen;
    xrdc_alias_info info;
    static char     s_bearer[8192], s_access[256], s_secret[256], s_region[64];

    if (colon == NULL) { return; }
    nlen = (size_t) (colon - arg);
    if (nlen == 0 || nlen >= sizeof(name)) { return; }
    if (colon[1] == '/' && colon[2] == '/') { return; }   /* scheme:// — not an alias */
    memcpy(name, arg, nlen);
    name[nlen] = '\0';
    if (!xrdc_alias_lookup(name, &info)) { return; }

    if (info.token_file_failed) {
        fprintf(stderr, "xrdcp: alias %s: token_file %s missing or empty\n",
                name, info.token_file);
    }
    if (o->bearer == NULL && info.bearer[0] != '\0') {
        snprintf(s_bearer, sizeof(s_bearer), "%s", info.bearer);
        o->bearer = s_bearer;
    }
    /* Fold the S3 access/secret as ONE unit so a mismatched key pair can never be
     * assembled from two different aliases. */
    if (o->s3_access == NULL && o->s3_secret == NULL
        && info.s3_access[0] != '\0' && info.s3_secret[0] != '\0') {
        snprintf(s_access, sizeof(s_access), "%s", info.s3_access);
        snprintf(s_secret, sizeof(s_secret), "%s", info.s3_secret);
        o->s3_access = s_access;
        o->s3_secret = s_secret;
    }
    if (o->s3_region == NULL && info.s3_region[0] != '\0') {
        snprintf(s_region, sizeof(s_region), "%s", info.s3_region);
        o->s3_region = s_region;
    }
    if (info.proxy[0] != '\0') {
        setenv("X509_USER_PROXY", info.proxy, 0);   /* 0 = don't clobber an existing env */
    }
}


/* Copy the basename of a path/URL (after the last '/', ignoring trailing slashes)
 * into out[sz]. out is empty if the input is all slashes. */
void
path_basename(const char *p, char *out, size_t sz)
{
    size_t len = strlen(p), start = 0, i, bl;
    while (len > 0 && p[len - 1] == '/') { len--; }   /* ignore trailing slashes */
    for (i = 0; i < len; i++) {
        if (p[i] == '/') { start = i + 1; }
    }
    bl = len - start;
    if (bl >= sz) { bl = sz - 1; }
    memcpy(out, p + start, bl);
    out[bl] = '\0';
}


/* Read a manifest (one source per line; '#' comments + blank lines skipped) and
 * append each entry to the source list. 0 / -1. */
int
read_manifest(const char *file, char ***list, size_t *n, size_t *cap)
{
    FILE *f = (strcmp(file, "-") == 0) ? stdin : fopen(file, "r");
    char  line[XRDC_PATH_MAX];

    if (f == NULL) {
        fprintf(stderr, "xrdcp: cannot open manifest %s: %s\n", file, strerror(errno));
        return -1;
    }
    while (fgets(line, sizeof(line), f) != NULL) {
        char *s = line, *e;
        while (*s == ' ' || *s == '\t') { s++; }
        e = s + strlen(s);
        while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) {
            *--e = '\0';
        }
        if (*s == '\0' || *s == '#') { continue; }
        if (str_append(list, n, cap, s) != 0) {
            if (f != stdin) { fclose(f); }
            return -1;
        }
    }
    if (f != stdin) { fclose(f); }
    return 0;
}


/* 1 if `s` is a root://-family URL (the only scheme we glob server-side). */
int
is_root_url(const char *s)
{
    return strncmp(s, "root://", 7) == 0 || strncmp(s, "roots://", 8) == 0
        || strncmp(s, "xroot://", 8) == 0 || strncmp(s, "xroots://", 9) == 0;
}


/* An s3/s3s endpoint authenticates with AWS SigV4 keys, NOT a GSI proxy or
 * bearer token — so the GSI/token credential pre-flight is irrelevant noise for
 * it. (case-insensitive: schemes may be upper-cased by the user) */
int
is_s3_url(const char *s)
{
    return strncasecmp(s, "s3://", 5) == 0 || strncasecmp(s, "s3s://", 6) == 0;
}


/* True when an endpoint uses the GSI-proxy / bearer-token credential family
 * (root:// or a non-s3 web URL). S3 SigV4 endpoints return 0 here. */
int
uses_cred_auth(const char *s)
{
    return is_root_url(s) || (xrdc_is_web_url(s) && !is_s3_url(s));
}


/* True when `p` names an existing local directory (a recursive-upload source). */
int
is_local_dir(const char *p)
{
    struct stat sb;
    return stat(p, &sb) == 0 && S_ISDIR(sb.st_mode);
}


/* Is `dst` an existing directory? 1=yes, 0=no, -1=can't determine (web/parse). */
int
dest_is_dir(const char *dst, const xrdc_opts *co)
{
    xrdc_url    u;
    xrdc_status st;
    if (xrdc_is_web_url(dst)) { return -1; }
    xrdc_status_clear(&st);
    if (xrdc_url_parse(dst, &u, &st) != 0) { return -1; }
    if (u.scheme == XRDC_SCHEME_LOCAL) {
        struct stat sb;
        return (stat(u.path, &sb) == 0 && S_ISDIR(sb.st_mode)) ? 1 : 0;
    }
    if (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS) {
        xrdc_conn     c;
        xrdc_statinfo si;
        int           isdir;
        if (xrdc_connect(&c, &u, co, &st) != 0) { return -1; }
        isdir = (xrdc_stat(&c, u.path, &si, &st) == 0 && (si.flags & kXR_isDir)) ? 1 : 0;
        xrdc_close(&c);
        return isdir;
    }
    return -1;
}


int
join_dest(const char *dstdir, const char *base, char *out, size_t sz)
{
    size_t      dl = strlen(dstdir);
    const char *sep = (dl > 0 && dstdir[dl - 1] == '/') ? "" : "/";
    return ((size_t) snprintf(out, sz, "%s%s%s", dstdir, sep, base) >= sz) ? -1 : 0;
}


/* True when both endpoints are web URLs (davs/http/s3) — a web->web transfer the
 * wire can't do directly, so xrdcp relays it through a local temp file. */
int
both_web(const char *src, const char *dst)
{
    return xrdc_is_web_url(src) && xrdc_is_web_url(dst);
}


/* Scheme keyword for a parsed web URL, for rebuilding per-file source URLs. */
const char *
web_scheme_str(xrdc_web_proto pr)
{
    switch (pr) {
    case XRDC_WEB_HTTPS: return "https";
    case XRDC_WEB_HTTP:  return "http";
    case XRDC_WEB_DAVS:  return "davs";
    case XRDC_WEB_DAV:   return "dav";
    case XRDC_WEB_S3S:   return "s3s";
    case XRDC_WEB_S3:    return "s3";
    }
    return "http";
}


/* Recursively download a WebDAV/HTTP collection into local directory `dstdir`,
 * preserving the tree: PROPFIND-list the files, then copy each to dstdir/<relpath>.
 * Reuses the public xrdc_copy per file (no copy-engine changes). Returns 0/1. */
/* 1 if a server-supplied relative path would escape the destination directory
 * (absolute, or contains a ".." component) — used to reject hostile listings. */
int
rel_is_unsafe(const char *rel)
{
    return rel[0] == '/' || strcmp(rel, "..") == 0
        || strncmp(rel, "../", 3) == 0 || strstr(rel, "/../") != NULL
        || (strlen(rel) >= 3 && strcmp(rel + strlen(rel) - 3, "/..") == 0);
}


/* Live progress state for a single transfer (label + timing). */

/* xrdc_copy progress callback: a throttled \r-updated stderr bar with rate + ETA. */
void
xrdcp_progress(void *arg, long long done, long long total)
{
    xrdcp_prog *p = (xrdcp_prog *) arg;
    uint64_t    now = xrdc_mono_ns();
    int         final = (total >= 0 && done >= total);
    double      secs, mb, rate;

    if (!final && (now - p->last_ns) < 200000000ULL) {
        return;   /* throttle intermediate updates to ~5 Hz */
    }
    p->last_ns = now;
    secs = (double) (now - p->start_ns) / 1e9;
    mb   = (double) done / 1048576.0;
    rate = (secs > 0.01) ? mb / secs : 0.0;
    if (total > 0) {
        int    pct = (int) ((done * 100) / total);
        double tmb = (double) total / 1048576.0;
        double eta = (rate > 0.01) ? (tmb - mb) / rate : 0.0;
        fprintf(stderr, "\r%-28s %3d%%  %.1f/%.1f MiB  %.1f MiB/s  ETA %3.0fs   ",
                p->label, pct, mb, tmb, rate, eta);
    } else {
        fprintf(stderr, "\r%-28s  %.1f MiB  %.1f MiB/s   ", p->label, mb, rate);
    }
    if (final) {
        fprintf(stderr, "\n");
    }
    fflush(stderr);
}


int
main(int argc, char **argv)
{
    xrdc_copy_opts opts;
    xrdc_opts      conn;
    xrdc_status    st;
    char         **pos = NULL, **srcs = NULL, **exp = NULL;
    size_t         npos = 0, poscap = 0, nsrc = 0, srccap = 0, nexp = 0, expcap = 0, i;
    const char    *from = NULL, *dst = NULL, *oidc_account = NULL;
    const char    *proxy = NULL;   /* --proxy: explicit X.509 proxy path override */
    int            retries = 0, jobs = 1, sync_mode = 0, force_progress = 0, verify = 0, rc = 0, oom = 0;
    int            auto_refresh = 0;   /* Phase 40 (b): --auto-refresh */
    /* C1: credential store built from CLI values after arg parsing; INERT until C2
     * threads it through the auth path.  NULL until xrdc_cli_cred_store_build runs;
     * freed on every exit path after construction. */
    struct xrdc_cred_store *cred_store = NULL;

    memset(&opts, 0, sizeof(opts));
    memset(&conn, 0, sizeof(conn));
    conn.verify_host = 1;

    /* Phase 44: XRDC_IO_URING env is the default (auto) for the local-disk
     * overlap ring; --io-uring overrides it below.  auto = 0 = memset default. */
    {
        const char *e = getenv("XRDC_IO_URING");
        if (e != NULL) {
            if (strcmp(e, "on") == 0)       { opts.io_uring = XRDC_IO_URING_ON; }
            else if (strcmp(e, "off") == 0) { opts.io_uring = XRDC_IO_URING_OFF; }
            else                            { opts.io_uring = XRDC_IO_URING_AUTO; }
        }
    }
    xrootd_crypto_init();   /* arm libxrdproto SHA-256/HMAC for GSI + sigver */
    xrdc_copy_install_signal_handlers();   /* Phase 40 (a): drop partial dest on
                                            * SIGINT/SIGTERM instead of leaving it */

    for (i = 1; i < (size_t) argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-' && a[1] != '\0' && strcmp(a, "-") != 0) {
            int oi = (int) i;   /* shared parser uses int*; bridge from size_t */
            if (xrdc_opts_parse_arg(&conn, argc, argv, &oi)) { i = (size_t) oi; continue; }
            if (strcmp(a, "-f") == 0)       { opts.force = 1; }
            else if (strcmp(a, "-r") == 0 || strcmp(a, "-R") == 0) { opts.recursive = 1; }
            else if (strcmp(a, "-P") == 0)  { opts.posc = 1; }
            else if (strcmp(a, "-s") == 0)  { opts.silent = 1; }
            else if (strcmp(a, "-v") == 0 || strcmp(a, "-d") == 0) { opts.verbose = 1; }
            else if (strcmp(a, "-N") == 0)  { /* no progress bar — already none */ }
            else if (strcmp(a, "--from") == 0 && i + 1 < (size_t) argc) { from = argv[++i]; }
            else if (strcmp(a, "--retry") == 0 && i + 1 < (size_t) argc) {
                retries = atoi(argv[++i]);
                if (retries <= 0) { retries = 0; opts.no_retry = 1; }  /* 0 ⇒ fail fast */
            }
            else if (strcmp(a, "--no-retry") == 0) { opts.no_retry = 1; }
            else if ((strcmp(a, "-j") == 0 || strcmp(a, "--jobs") == 0) && i + 1 < (size_t) argc) { jobs = atoi(argv[++i]); }
            else if (strcmp(a, "--sync") == 0) { sync_mode = 1; }
            else if (strcmp(a, "--progress") == 0) { force_progress = 1; }
            else if (strcmp(a, "--verify") == 0) { verify = 1; }
            else if (strcmp(a, "--auto-refresh") == 0) { auto_refresh = 1; }
            else if (strcmp(a, "--oidc-account") == 0 && i + 1 < (size_t) argc) { oidc_account = argv[++i]; }
            else if (strcmp(a, "--proxy") == 0 && i + 1 < (size_t) argc) { proxy = argv[++i]; }
            else if (strcmp(a, "--pgrw") == 0)  { opts.pgrw = 1; }
            else if (strcmp(a, "--cksum") == 0 && i + 1 < (size_t) argc) { opts.cksum = argv[++i]; }
            else if (strcmp(a, "--compress") == 0 && i + 1 < (size_t) argc) { opts.compress = argv[++i]; }
            else if (strcmp(a, "--zip") == 0)         { opts.zip = 1; }
            else if (strcmp(a, "--zip-append") == 0)  { opts.zip_append = 1; }
            else if ((strcmp(a, "-S") == 0 || strcmp(a, "--streams") == 0) && i + 1 < (size_t) argc) { opts.streams = atoi(argv[++i]); }
            else if (strcmp(a, "--max-stall") == 0 && i + 1 < (size_t) argc) {
                int v = atoi(argv[++i]);
                if (v > 0) { opts.max_stall_ms = v; opts.no_retry = 0; }
                else       { opts.no_retry = 1; }   /* 0/negative ⇒ fail fast */
            }
            else if (strncmp(a, "--io-uring=", 11) == 0) {
                const char *m = a + 11;
                opts.io_uring = (strcmp(m, "on") == 0)  ? XRDC_IO_URING_ON
                              : (strcmp(m, "off") == 0) ? XRDC_IO_URING_OFF
                                                        : XRDC_IO_URING_AUTO;
            }
            else if (strcmp(a, "--io-uring") == 0 && i + 1 < (size_t) argc) {
                const char *m = argv[++i];
                opts.io_uring = (strcmp(m, "on") == 0)  ? XRDC_IO_URING_ON
                              : (strcmp(m, "off") == 0) ? XRDC_IO_URING_OFF
                                                        : XRDC_IO_URING_AUTO;
            }
            else if (strcmp(a, "--tpc") == 0 && i + 1 < (size_t) argc) {
                const char *m = argv[++i];
                if (strcmp(m, "first") == 0)         { opts.tpc_mode = XRDC_TPC_FIRST; }
                else if (strcmp(m, "only") == 0)     { opts.tpc_mode = XRDC_TPC_ONLY; }
                else if (strcmp(m, "delegate") == 0) { opts.tpc_mode = XRDC_TPC_DELEGATE; }
                else { fprintf(stderr, "xrdcp: --tpc needs first|only|delegate\n"); usage(); return 50; }
            }
            else if (strcmp(a, "--tpc-token-mode") == 0 && i + 1 < (size_t) argc) { opts.tpc_token_mode = argv[++i]; }
            else if ((strcmp(a, "-T") == 0 || strcmp(a, "--token") == 0) && i + 1 < (size_t) argc) { opts.bearer = argv[++i]; }
            else if (strcmp(a, "--s3-access") == 0 && i + 1 < (size_t) argc) { opts.s3_access = argv[++i]; }
            else if (strcmp(a, "--s3-secret") == 0 && i + 1 < (size_t) argc) { opts.s3_secret = argv[++i]; }
            else if (strcmp(a, "--s3-region") == 0 && i + 1 < (size_t) argc) { opts.s3_region = argv[++i]; }
            else if (strcmp(a, "-V") == 0)  { printf("xrdcp (native, phase-37)\n"); return 0; }
            else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(); return 0; }
            else {
                fprintf(stderr, "xrdcp: unknown option '%s'\n", a);
                usage();
                return 50;
            }
        } else if (str_append(&pos, &npos, &poscap, a) != 0) {
            fprintf(stderr, "xrdcp: out of memory\n");
            return 51;
        }
    }

    /* --sync replaces destinations that differ, so the files it does copy must be
     * allowed to overwrite (skipped ones are left untouched by the size check). */
    if (sync_mode) {
        opts.force = 1;
    }
    /* --verify: post-transfer checksum against the server. An explicit --cksum wins. */
    if (verify && opts.cksum == NULL) {
        opts.cksum = "adler32:source";
    }

    /* Need a destination (the last positional) and at least one source. */
    if (npos < 1) {
        usage();
        str_free(pos, npos);
        return 50;
    }
    {
        static char dstbuf[XRDC_PATH_MAX];
        xrdc_alias_resolve(pos[npos - 1], dstbuf, sizeof(dstbuf));   /* ~/.xrdrc */
        dst = dstbuf;
    }
    for (i = 0; i + 1 < npos; i++) {
        if (str_append(&srcs, &nsrc, &srccap, pos[i]) != 0) { oom = 1; }
    }
    if (from != NULL && read_manifest(from, &srcs, &nsrc, &srccap) != 0) {
        str_free(pos, npos); str_free(srcs, nsrc);
        return 51;
    }
    if (oom) {
        fprintf(stderr, "xrdcp: out of memory\n");
        str_free(pos, npos); str_free(srcs, nsrc);
        return 51;
    }
    if (nsrc == 0) {
        fprintf(stderr, "xrdcp: no source given\n");
        usage();
        str_free(pos, npos);
        return 50;
    }

    /* Fold any ~/.xrdrc per-endpoint credentials (the dst + every source alias) into
     * opts so `xrdcp s3lab:/obj .` authenticates with no flags. */
    merge_alias_auth(pos[npos - 1], &opts);
    for (i = 0; i < nsrc; i++) {
        merge_alias_auth(srcs[i], &opts);
    }

    /* Expand globs (root:// + local) into the final source list. */
    for (i = 0; i < nsrc; i++) {
        if (expand_source(srcs[i], &conn, &exp, &nexp, &expcap) != 0) {
            fprintf(stderr, "xrdcp: out of memory\n");
            str_free(pos, npos); str_free(srcs, nsrc); str_free(exp, nexp);
            return 51;
        }
    }
    if (nexp == 0) {
        fprintf(stderr, "xrdcp: no sources after expansion\n");
        str_free(pos, npos); str_free(srcs, nsrc); str_free(exp, nexp);
        return 50;
    }

    /*
     * Phase 40 (c): credential pre-flight.  If a server endpoint is involved, warn
     * the user INSTANTLY about a locally-detectable auth problem (expired/near-
     * expiry bearer token or GSI proxy, or a read-only token on an upload) before
     * the transfer fails with a bare "permission denied".  Silent when creds look
     * fine; never aborts (the server stays authoritative).
     */
    {
        /* Only the GSI/token credential family is diagnosable here — an s3://
         * endpoint authenticates with AWS SigV4 keys, so it must not trip the
         * "GSI proxy expired" / "bearer token" pre-flight. */
        int dst_cred = uses_cred_auth(dst);
        int any_cred = dst_cred;
        for (i = 0; i < nexp && !any_cred; i++) {
            if (uses_cred_auth(exp[i])) { any_cred = 1; }
        }
        if (any_cred) {
            /* Phase 40 (b): if asked, proactively (re)acquire a stale token/proxy
             * BEFORE diagnosing — so a healthy refresh leaves nothing to warn. */
            if (auto_refresh) {
                (void) xrdc_cred_autorefresh(dst_cred, oidc_account,
                                             !opts.silent, stderr);
            }
            (void) xrdc_cred_diagnose(dst_cred, "xrdcp: ", stderr);
        }
    }

    /* C1: build the credential store from CLI values and attach it to the
     * connection options.  The store is INERT here — nothing reads conn.cred
     * yet; C2 will thread it through the auth/token handshake path.  Building
     * it now (before the transfer) means C2 only needs to consume conn.cred,
     * not rebuild it.  NULL/empty args fall back to per-handler env discovery. */
    cred_store = xrdc_cli_cred_store_build(proxy, opts.bearer, NULL,
                                            opts.s3_access, opts.s3_secret,
                                            oidc_account, auto_refresh);
    conn.cred = cred_store;

    xrdc_status_clear(&st);
    /* Recursive copy of a web (davs/http) collection: list it client-side and copy
     * each file (the wire has no recursive transfer op). root:// and local -r are
     * handled inside xrdc_copy, so only intercept web sources here. */
    if (opts.recursive) {
        int any_web = 0;
        for (i = 0; i < nexp; i++) {
            if (xrdc_is_web_url(exp[i])) { any_web = 1; }
        }
        if (any_web) {
            size_t bad = 0;
            for (i = 0; i < nexp; i++) {
                if (xrdc_is_web_url(exp[i])) {
                    if (recursive_web_download(exp[i], dst, &opts, &conn, retries) != 0) {
                        bad++;
                    }
                } else if (copy_one_with_retry(exp[i], dst, &opts, &conn, retries, &st) != 0) {
                    bad++;
                    fprintf(stderr, "xrdcp: %s: %s\n", exp[i], st.msg);
                    xrdc_cred_hint_for_status(&st, is_root_url(dst)
                                              || xrdc_is_web_url(dst), stderr);
                }
            }
            xrdc_cred_store_free(cred_store);
            str_free(pos, npos); str_free(srcs, nsrc); str_free(exp, nexp);
            return (bad == 0) ? 0 : 1;
        }
        /* Symmetric case: local directory tree(s) → a web (davs/http/s3)
         * collection. Walk each local dir, MKCOL + PUT; a plain local file with
         * -r to a web dst is just a single copy. */
        if (xrdc_is_web_url(dst)) {
            int has_dir = 0;
            for (i = 0; i < nexp; i++) {
                if (is_local_dir(exp[i])) { has_dir = 1; }
            }
            if (has_dir) {
                size_t bad = 0;
                for (i = 0; i < nexp; i++) {
                    if (is_local_dir(exp[i])) {
                        if (recursive_web_upload(exp[i], dst, &opts, &conn, retries) != 0) {
                            bad++;
                        }
                    } else if (copy_one_with_retry(exp[i], dst, &opts, &conn,
                                                   retries, &st) != 0) {
                        bad++;
                        fprintf(stderr, "xrdcp: %s: %s\n", exp[i], st.msg);
                    }
                }
                xrdc_cred_store_free(cred_store);
                str_free(pos, npos); str_free(srcs, nsrc); str_free(exp, nexp);
                return (bad == 0) ? 0 : 1;
            }
        }
    }
    if (nexp == 1 && from == NULL) {
        /* Classic single copy — dst may be a file, directory, or '-'. */
        char       label[XRDC_NAME_MAX];
        xrdcp_prog ps;
        int        one;
        /* Show a progress bar when asked (--progress) or on an interactive stderr,
         * but never to a piped stdout transfer ('-') and never when silent. */
        if ((force_progress || isatty(STDERR_FILENO)) && !opts.silent
            && !(exp[0][0] == '-' && exp[0][1] == '\0')) {
            path_basename(exp[0], label, sizeof(label));
            ps.label = (label[0] != '\0') ? label : "transfer";
            ps.start_ns = xrdc_mono_ns();
            ps.last_ns = 0;
            opts.progress = xrdcp_progress;
            opts.progress_arg = &ps;
        }
        one = transfer_one(exp[0], dst, &opts, &conn, retries, sync_mode, &st);
        if (one == 1 && !opts.silent) {
            fprintf(stderr, "xrdcp: %s up-to-date, skipped\n", dst);
        } else if (one < 0 && !opts.silent) {
            fprintf(stderr, "xrdcp: %s\n", st.msg);
            xrdc_cred_hint_for_status(&st, is_root_url(dst)
                                      || xrdc_is_web_url(dst), stderr);
        }
        rc = (one >= 0) ? 0 : xrdc_shellcode(&st);
    } else {
        /* Batch copy into a destination directory. */
        size_t ok = 0, skip = 0, fail = 0;
        if (dest_is_dir(dst, &conn) != 1) {
            fprintf(stderr, "xrdcp: destination must be an existing directory for "
                            "multi-source copy: %s\n", dst);
            xrdc_cred_store_free(cred_store);
            str_free(pos, npos); str_free(srcs, nsrc); str_free(exp, nexp);
            return 50;
        }
        if (jobs > (int) nexp) { jobs = (int) nexp; }
        if (jobs > 1) {
            batch_parallel(exp, nexp, dst, &opts, &conn, retries, sync_mode,
                           jobs, &ok, &skip, &fail);
        } else {
            for (i = 0; i < nexp; i++) {
                char dpath[XRDC_PATH_MAX];
                int  one = batch_copy_one(exp[i], dst, &opts, &conn, retries,
                                          sync_mode, dpath, sizeof(dpath), &st);
                if (one == 0) {
                    ok++;
                    if (!opts.silent) {
                        fprintf(stderr, "[%zu/%zu] %s -> %s\n",
                                ok + skip + fail, nexp, exp[i], dpath);
                    }
                } else if (one == 1) {
                    skip++;
                    if (!opts.silent) {
                        fprintf(stderr, "[%zu/%zu] %s (up-to-date)\n",
                                ok + skip + fail, nexp, exp[i]);
                    }
                } else {
                    fail++;
                    fprintf(stderr, "xrdcp: %s: %s\n", exp[i], st.msg);
                    xrdc_cred_hint_for_status(&st, is_root_url(dst)
                                              || xrdc_is_web_url(dst), stderr);
                }
            }
        }
        if (!opts.silent) {
            fprintf(stderr, "xrdcp: %zu copied, %zu skipped, %zu failed\n",
                    ok, skip, fail);
        }
        rc = (fail == 0) ? 0 : 1;
    }

    xrdc_cred_store_free(cred_store);
    str_free(pos, npos);
    str_free(srcs, nsrc);
    str_free(exp, nexp);
    return rc;
}
