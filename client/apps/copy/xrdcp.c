/*
 * xrdcp.c — xrdcp routing + shared helpers (Phase-38 keep-file).
 *
 * WHAT: main() plus the helpers every pipeline stage shares — usage text, the
 *       strdup-owned string-list primitives, alias/credential folding, the
 *       URL/path predicates, manifest reading, the progress callback, the
 *       credential preflight stage, and list cleanup.
 * WHY:  the parse pipeline (xrdcp_parse.c) and the transfer dispatch
 *       (xrdcp_dispatch.c) were split out to hold each TU within the Phase-38
 *       size budget; this file owns argv routing + the cross-stage helpers they
 *       both call. The pipeline state types live in xrdcp_internal.h.
 * HOW:  main threads one xrdcp_opts_t + xrdcp_lists_t through
 *       parse_and_validate_args → build_and_preflight_credentials →
 *       dispatch_transfer. No goto; early-return throughout.
 */
#include "xrdcp_internal.h"
#include "core/version.h"
#include "core/progname.h"  /* brix_prog_base(): argv[0]-derived identity + footer */

/*
 * usage_fp — print usage text to the given stream.
 * WHY: --help (spec WS-2) prints usage to stdout; no-arg / unknown-option
 *      errors still go to stderr.  A FILE* parameter keeps both paths
 *      sharing one text definition.
 */
void
usage_fp(FILE *out, const char *prog)
{
    fprintf(out,
        "usage: %s [opts] <src>... <dst>\n"
        "  src/dst is root://host[:port]//path, a web URL, a local path, or '-'\n"
        "  web schemes (GET/PUT): davs:// http(s):// dav:// s3:// s3s://\n"
        "  gridftp schemes: gsiftp:// (GSI proxy, delegated) ftp:// (anonymous)\n"
        "  web->web (e.g. davs://a/f s3://b/k) relays through a local temp file\n"
        "  multiple sources / a glob / --from <file> => <dst> is a directory\n"
        "  -f             overwrite an existing destination\n"
        "  -r             recursively copy a tree (root/davs/http/s3 <-> local, or web<->web)\n"
        "  -P, --posc     persist-on-successful-close (upload)\n"
        "  -s             silent\n"
        "  -v, -d, --verbose, --debug  verbose / debug\n"
        "  -N, --no-progress  suppress the progress bar even on a TTY\n"
        "  --from <file>  read sources from a manifest (one per line; '-'=stdin)\n"
        "  --journal <p>  record completed transfers; skip them on the next run\n"
        "  --resume       shorthand: --journal <manifest>.journal (needs --from)\n"
        "  --retry <n>    retry each failed transfer up to n times (backoff); 0 = fail fast\n"
        "  --no-retry     disable transport resilience: fail on the first fault\n"
        "  --max-stall <ms> reconnect/resume patience window (0 = fail fast)\n"
        "  --auto-refresh proactively renew an expired/near-expiry token (oidc-agent)\n"
        "                 or GSI proxy before transferring\n"
        "  --oidc-account <name>  oidc-agent account for --auto-refresh (or $OIDC_ACCOUNT)\n"
        "  -j, --jobs <n> copy up to n files concurrently (batch mode)\n"
        "  --sync         skip transfers whose destination already has the same size\n"
        "  --sync-check <m>  --sync comparison: size (default) | mtime | cksum[:algo]\n"
        "  -n, --dry-run  print what would be transferred/deleted; move no bytes\n"
        "  --exclude <pat> skip files matching this fnmatch pattern (repeatable)\n"
        "  --include <pat> only transfer files matching a pattern (repeatable)\n"
        "  --delete       with -r --sync: delete dest entries missing from the source\n"
        "  --remove-source  delete each source after its transfer succeeds (local/root://)\n"
        "  --progress     show a transfer progress bar + ETA (auto on a TTY; single copy)\n"
        "  --verify       after the transfer, verify the checksum against the server (root://)\n"
        "  --tls          require in-protocol TLS (implied by roots://)\n"
        "  --notlsok      permit cleartext if the server offers no TLS (root:// only)\n"
        "  --noverifyhost skip TLS hostname check (chain verification stays on)\n"
        "  -A, --allow-http  accepted for stock-xrdcp compatibility; http/davs URLs\n"
        "                 need no opt-in here, so the flag has nothing to enable\n"
        "  --auth <p>     force auth protocol: gsi | ztn | krb5 | sss | unix\n"
        "  --proxy <path> use <path> as the X.509 proxy certificate (overrides $X509_USER_PROXY)\n"
        "  --pgrw         use paged I/O (kXR_pgread/pgwrite) with per-page CRC32c\n"
        "  --io-uring on|off|auto  local-disk overlap ring; overrides $XRDC_IO_URING (default: auto)\n"
        "  --io-uring-direct  bypass the page cache on the ring (O_DIRECT tier); overrides $XRDC_IO_URING_DIRECT\n"
        "  --cksum <t>[:source|:print|:<value>]  verify a checksum (adler32|crc32c|md5;\n"
        "                    sha1|sha256|sha512 in :print/literal modes only)\n"
        "  --xattr           preserve user.* extended attributes across a\n"
        "                    root://<->local copy (best-effort; system./\n"
        "                    security./trusted. names never cross)\n"
        "  -F, --coerce      set kXR_force on the remote destination open\n"
        "                    (stock: ignore file locking/usage rules)\n"
        "  --retry-policy P  what a retry does with the partial destination:\n"
        "                    force = restart from scratch (default),\n"
        "                    continue = resume at the partial's size\n"
        "  --rm-bad-cksum    accepted for stock compatibility: BriX always drops\n"
        "                    a cksum-mismatched destination (fail-closed default)\n"
        "  --compress <codec>  root:// inline compression (gzip|deflate|zstd|br|\n"
        "                      xz|bzip2): compress on download (read) and on\n"
        "                      upload (write); server opt-in, transparent, ignored\n"
        "                      if the server doesn't support it\n"
        "  --zip               store the local source as a STORE member of the\n"
        "                      destination ZIP archive (overwrites the archive)\n"
        "  --zip-append        like --zip but append to an existing archive\n"
        "  -S, --streams N   open N-1 secondary kXR_bind data streams\n"
        "  --parallel        TRUE concurrent striped download (one thread per\n"
        "                    stream, disjoint ranges); opt-in, no single-link\n"
        "                    resilient ride-out — the serial fan-out is the default\n"
        "  --sources N       extreme copy: download blocks from up to N replicas\n"
        "                    concurrently with block stealing (replicas from a\n"
        "                    metalink mirror list, locate discovery, or the\n"
        "                    source duplicated); N in 1..16, 1 = off\n"
        "  --no-metalink     copy a .meta4/.metalink source as a plain file\n"
        "                    (default: resolve it as a virtual redirector and\n"
        "                    fail over across its ranked mirrors)\n"
        "  -X, --xrate R     cap the transfer rate at R bytes/sec (k/m/g\n"
        "                    suffixes; serial path only)\n"
        "  --xrate-threshold R  fail the transfer if the average rate drops\n"
        "                    below R bytes/sec (3s grace)\n"
        "  --continue        resume a download at the existing partial\n"
        "                    destination's size (writes the destination in\n"
        "                    place; partials survive failures for the next\n"
        "                    --continue; excludes -f/--pgrw/--compress/--zip)\n"
        "  --tpc first|only|delegate   server-side third-party copy (remote->remote)\n"
        "  --tpc-token-mode <m>  bearer-token forwarding mode for --tpc (nginx-xrootd extension)\n"
        "  -T, --token <jwt>  WebDAV/HTTP bearer token (or $BEARER_TOKEN)\n"
        "  --s3-access <k>    S3 SigV4 access key id (or $AWS_ACCESS_KEY_ID)\n"
        "  --s3-secret <k>    S3 SigV4 secret key (or $AWS_SECRET_ACCESS_KEY)\n"
        "  --s3-region <r>    S3 SigV4 region (or $AWS_DEFAULT_REGION; default us-east-1)\n"
        "  --wire-trace[=N]  decode every frame to stderr (N>=2 adds a hexdump)\n"
        "  --timing       print per-opcode RTT at the end\n"
        "  -V, --version  print version and exit\n"
        "  -h, --help     this help\n",
        brix_prog_base(prog));
    brix_usage_footer(out, prog);
}

void
usage(const char *prog)
{
    usage_fp(stderr, prog);
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


/* Extract the alias name from `arg` (the part before the first ':') into name[sz].
 * Returns 1 if `arg` looks like an alias reference, 0 otherwise (no colon, empty or
 * oversized name, or a scheme:// URL). */
static int
alias_name_of(const char *arg, char *name, size_t sz)
{
    const char *colon = strchr(arg, ':');
    size_t      nlen;

    if (colon == NULL) { return 0; }
    nlen = (size_t) (colon - arg);
    if (nlen == 0 || nlen >= sz) { return 0; }
    if (colon[1] == '/' && colon[2] == '/') { return 0; }   /* scheme:// — not an alias */
    memcpy(name, arg, nlen);
    name[nlen] = '\0';
    return 1;
}


/* Fold the alias `info`'s per-endpoint credentials into `o` — a value already set
 * (CLI flag or earlier alias) always wins. The opt pointers are backed by static
 * storage for the process lifetime. PII: creds are never logged. */
static void
fold_alias_creds(const brix_alias_info *info, brix_copy_opts *o)
{
    static char s_bearer[8192], s_access[256], s_secret[256], s_region[64];

    if (o->bearer == NULL && info->bearer[0] != '\0') {
        snprintf(s_bearer, sizeof(s_bearer), "%s", info->bearer);
        o->bearer = s_bearer;
    }
    /* Fold the S3 access/secret as ONE unit so a mismatched key pair can never be
     * assembled from two different aliases. */
    if (o->s3_access == NULL && o->s3_secret == NULL
        && info->s3_access[0] != '\0' && info->s3_secret[0] != '\0') {
        snprintf(s_access, sizeof(s_access), "%s", info->s3_access);
        snprintf(s_secret, sizeof(s_secret), "%s", info->s3_secret);
        o->s3_access = s_access;
        o->s3_secret = s_secret;
    }
    if (o->s3_region == NULL && info->s3_region[0] != '\0') {
        snprintf(s_region, sizeof(s_region), "%s", info->s3_region);
        o->s3_region = s_region;
    }
    if (info->proxy[0] != '\0') {
        setenv("X509_USER_PROXY", info->proxy, 0);   /* 0 = don't clobber an existing env */
    }
}


/* If `arg` names a ~/.xrdrc alias, fold its per-endpoint credentials into `o` — a
 * value already set (CLI flag or earlier alias) always wins. The opt pointers are
 * backed by static storage for the process lifetime. PII: creds are never logged. */
void
merge_alias_auth(const char *arg, brix_copy_opts *o)
{
    char            name[256];
    brix_alias_info info;

    if (!alias_name_of(arg, name, sizeof(name))) { return; }
    if (!brix_alias_lookup(name, &info)) { return; }

    if (info.token_file_failed) {
        fprintf(stderr, "xrdcp: alias %s: token_file %s missing or empty\n",
                name, info.token_file);
    }
    fold_alias_creds(&info, o);
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


/* Trim leading/trailing whitespace (and CR/LF) from `line` in place and return a
 * pointer to the first non-blank char. The returned string is "" for a blank line. */
static char *
manifest_trim(char *line)
{
    char *s = line, *e;
    while (*s == ' ' || *s == '\t') { s++; }
    e = s + strlen(s);
    while (e > s && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t')) {
        *--e = '\0';
    }
    return s;
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
        char *s = manifest_trim(line);
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
    return is_root_url(s) || (brix_is_web_url(s) && !is_s3_url(s));
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
dest_is_dir(const char *dst, const brix_opts *co)
{
    brix_url    u;
    brix_status st;
    if (brix_is_web_url(dst)) { return -1; }
    brix_status_clear(&st);
    if (brix_url_parse(dst, &u, &st) != 0) { return -1; }
    if (u.scheme == XRDC_SCHEME_LOCAL) {
        struct stat sb;
        return (stat(u.path, &sb) == 0 && S_ISDIR(sb.st_mode)) ? 1 : 0;
    }
    if (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS) {
        brix_conn     c;
        brix_statinfo si;
        int           isdir;
        if (brix_connect(&c, &u, co, &st) != 0) { return -1; }
        isdir = (brix_stat(&c, u.path, &si, &st) == 0 && (si.flags & kXR_isDir)) ? 1 : 0;
        brix_close(&c);
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


/* Live progress state for a single transfer (label + timing). */

/* brix_copy progress callback: a throttled \r-updated stderr bar with rate + ETA. */
void
xrdcp_progress(void *arg, long long done, long long total)
{
    xrdcp_prog *p = (xrdcp_prog *) arg;
    uint64_t    now = brix_mono_ns();
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




/* Free every strdup-owned vector main threads through the pipeline. Called on
 * the credential-build error paths and (via main) on normal exit. */
static void
xrdcp_lists_free(xrdcp_lists_t *l)
{
    str_free(l->pos.items, l->pos.n);
    str_free(l->srcs.items, l->srcs.n);
    str_free(l->exp.items, l->exp.n);
    str_free(l->excl.items, l->excl.n);
    str_free(l->incl.items, l->incl.n);
}


static struct brix_cred_store *
build_and_preflight_credentials(xrdcp_opts_t *o, xrdcp_lists_t *l)
{
    brix_copy_opts *opts = o->copt;
    size_t          i;

    /* Fold any ~/.xrdrc per-endpoint credentials (the dst + every source alias) into
     * opts so `xrdcp s3lab:/obj .` authenticates with no flags. */
    merge_alias_auth(l->pos.items[l->pos.n - 1], opts);
    for (i = 0; i < l->srcs.n; i++) {
        merge_alias_auth(l->srcs.items[i], opts);
    }

    /* Expand globs (root:// + local) into the final source list. */
    for (i = 0; i < l->srcs.n; i++) {
        if (expand_source(l->srcs.items[i], o->conn,
                          &l->exp.items, &l->exp.n, &l->exp.cap) != 0) {
            fprintf(stderr, "xrdcp: out of memory\n");
            xrdcp_lists_free(l);
            return NULL;
        }
    }
    if (l->exp.n == 0) {
        fprintf(stderr, "xrdcp: no sources after expansion\n");
        xrdcp_lists_free(l);
        return NULL;
    }
    /* --remove-source supports local and root:// sources only: web/S3 sources
     * have no cheap post-transfer delete path and cannot be safely removed. */
    if (opts->remove_source) {
        for (i = 0; i < l->exp.n; i++) {
            if (brix_is_web_url(l->exp.items[i])) {
                fprintf(stderr, "xrdcp: --remove-source supports local and "
                                "root:// sources only\n");
                xrdcp_lists_free(l);
                return NULL;
            }
        }
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
        int dst_cred = uses_cred_auth(o->dst);
        int any_cred = dst_cred;
        for (i = 0; i < l->exp.n && !any_cred; i++) {
            if (uses_cred_auth(l->exp.items[i])) { any_cred = 1; }
        }
        if (any_cred) {
            /* Phase 40 (b): if asked, proactively (re)acquire a stale token/proxy
             * BEFORE diagnosing — so a healthy refresh leaves nothing to warn. */
            if (o->auto_refresh) {
                (void) brix_cred_autorefresh(dst_cred, o->oidc_account,
                                             !opts->silent, stderr);
            }
            (void) brix_cred_diagnose(dst_cred, "xrdcp: ", stderr);
        }
    }

    /* C1: build the credential store from CLI values and attach it to the
     * connection options.  The store is INERT here — nothing reads conn.cred
     * yet; C2 will thread it through the auth/token handshake path.  Building
     * it now (before the transfer) means C2 only needs to consume conn.cred,
     * not rebuild it.  NULL/empty args fall back to per-handler env discovery. */
    return brix_cli_cred_store_build(o->proxy, opts->bearer, NULL,
                                      opts->s3_access, opts->s3_secret,
                                      o->oidc_account, o->auto_refresh);
}


int
main(int argc, char **argv)
{
    brix_copy_opts opts;
    brix_opts      conn;
    xrdcp_opts_t   o;
    xrdcp_lists_t  l;
    int            rc = 0;

    memset(&opts, 0, sizeof(opts));
    brix_opts_init(&conn);   /* verify_host=1 + seed $XRDC_MAX_STALL_MS resilience */

    memset(&o, 0, sizeof(o));
    memset(&l, 0, sizeof(l));
    o.copt = &opts;
    o.conn = &conn;
    o.jobs = 1;   /* default: one file at a time (batch concurrency opt-in) */
    /* Phase 94: data sub-streams ON by default (server default is also ON).  An
     * upload spreads write chunks across these secondaries (parallel upload); a
     * server that does not service bound writes falls back to the primary safely.
     * `-S N` overrides (N<=1 disables).  Kept modest so tiny transfers pay only a
     * few extra TCP setups. */
    opts.streams = 4;

    brix_crypto_init();   /* arm libxrdproto SHA-256/HMAC for GSI + sigver */
    brix_copy_install_signal_handlers();   /* Phase 40 (a): drop partial dest on
                                            * SIGINT/SIGTERM instead of leaving it */

    /* Parse and validate command-line arguments. */
    rc = parse_and_validate_args(argc, argv, &o, &l);
    if (rc != 0) {
        xrdcp_lists_free(&l);
        if (rc == XRDCP_PARSE_EXIT_OK) {
            return 0;
        }
        return rc;
    }

    /* Export --proxy into $X509_USER_PROXY so the davs/https leg's client-cert
     * resolver (brix_web_proxy_pem) presents the same identity the root:// path
     * already gets explicitly — the flag documents "overrides $X509_USER_PROXY",
     * so it clobbers (overwrite=1) any inherited value. */
    if (o.proxy != NULL && o.proxy[0] != '\0') {
        setenv("X509_USER_PROXY", o.proxy, 1);
    }

    /* Build credential store with alias resolution, glob expansion, and pre-flight.
     * C1: the store is INERT until C2 threads it through the auth path; NULL until
     * brix_cli_cred_store_build runs; freed on every exit path after construction. */
    o.cred_store = build_and_preflight_credentials(&o, &l);
    if (o.cred_store == NULL) {
        /* Cleanup already done inside helper; arrays freed */
        return 50;
    }
    conn.cred = o.cred_store;


    /* Dispatch to the appropriate transfer mode (web recursive, single, or batch). */
    rc = dispatch_transfer(&o, &l);

    brix_cred_store_free(o.cred_store);
    xrdcp_lists_free(&l);
    return rc;
}
