/*
 * xrdcp.c - (kept) routing + shared helpers
 * Phase-38 split of xrdcp.c; behavior-identical.
 */
#include "xrdcp_internal.h"
#include "core/version.h"
#include "core/progname.h"  /* brix_prog_base(): argv[0]-derived identity + footer */

#define XRDCP_PARSE_EXIT_OK 100

/* A growable, strdup-owned string list (source/positional/exclude/include/
 * expanded-source vectors main threads through the pipeline). */
typedef struct {
    char  **items;
    size_t  n;
    size_t  cap;
} xrdcp_strlist;

/*
 * WHAT: The complete parsed-option + connection state main threads through the
 *       parse → credential → dispatch pipeline.
 * WHY:  These flags and pointers were passed loose (up to 29 parameters), which
 *       is unreviewable and trips the parameter gate. Bundling them keeps every
 *       pipeline helper at a reviewable arity with explicit, single-owner data
 *       flow; `copt`/`conn` point at main's stack objects, the rest are the
 *       parse outputs that live beyond `brix_copy_opts`.
 * HOW:  main zero-inits one instance, points `copt`/`conn` at its locals, and
 *       hands the address to each pipeline stage. Parse writes the scalars;
 *       later stages read them. Byte-frozen: same values, same order.
 */
typedef struct {
    brix_copy_opts *copt;          /* the parsed brix_copy_opts (main's local) */
    brix_opts      *conn;          /* the connection opts (main's local) */
    struct brix_cred_store *cred_store; /* built by the credential stage; INERT */
    const char     *from;          /* --from manifest path (NULL = none) */
    const char     *journal_path;  /* --journal <path> or derived from --resume */
    const char     *oidc_account;  /* --oidc-account (or $OIDC_ACCOUNT) */
    const char     *proxy;         /* --proxy X.509 proxy path override */
    const char     *dst;           /* resolved destination (last positional) */
    int             resume;        /* --resume: derive journal from --from */
    int             retries;       /* --retry <n> budget */
    int             jobs;          /* -j/--jobs concurrency */
    int             force_progress;/* --progress */
    int             no_progress;   /* -N/--no-progress */
    int             verify;        /* --verify */
    int             auto_refresh;  /* --auto-refresh */
    int             sync_mode;     /* --sync / --sync-check */
} xrdcp_opts_t;

/*
 * WHAT: The set of strdup-owned string vectors main owns for one invocation.
 * WHY:  The positional/source/expanded/exclude/include lists were passed as
 *       five (array,count,cap) triples — 15 loose parameters — through the same
 *       helpers. One struct keeps the pipeline signatures under the gate and
 *       makes ownership (main frees them all) explicit.
 * HOW:  main zero-inits it; parse fills `pos` (+ srcs via the manifest), the
 *       credential stage fills `exp`, and main frees every vector on exit.
 */
typedef struct {
    xrdcp_strlist pos;    /* positional args (sources + dst) */
    xrdcp_strlist srcs;   /* sources after manifest merge, pre-glob */
    xrdcp_strlist exp;    /* sources after glob expansion */
    xrdcp_strlist excl;   /* --exclude patterns */
    xrdcp_strlist incl;   /* --include patterns */
} xrdcp_lists_t;

/*
 * WHAT: Per-CLI-parse scratch: the option target (`o`), list target (`l`), and
 *       a sticky out-of-memory flag the str_append callsites set.
 * WHY:  The option-parser fan-out (basic/manifest/sync/auth/transport/remote)
 *       all need the same two targets plus a shared OOM latch; a small state
 *       struct keeps each parser helper at three parameters.
 * HOW:  parse_and_validate_args builds it once and passes its address to every
 *       xrdcp_parse_* helper; `oom` is checked after the argv loop.
 */
typedef struct {
    xrdcp_opts_t  *o;
    xrdcp_lists_t *l;
    int            oom;
} xrdcp_cli_state;

typedef struct {
    brix_copy_opts          *opts;
    brix_opts               *conn;
    struct brix_cred_store  *cred_store;
    char                   **exp;
    size_t                   nexp;
    const char              *dst;
    const char              *from;
    const char              *journal_path;
    int                      retries;
    int                      jobs;
    int                      sync_mode;
    int                      force_progress;
    int                      no_progress;
} xrdcp_transfer_ctx;

/* Running batch outcome counters + the reusable status buffer for one
 * sequential batch pass. Bundled so the per-item worker stays under the
 * parameter gate; `batch_parallel` (extern) still takes the three counters by
 * address (&t.ok/&t.skip/&t.fail), so the wire-visible tally is unchanged. */
typedef struct {
    size_t      ok;
    size_t      skip;
    size_t      fail;
    brix_status st;
} xrdcp_tally_t;

/*
 * usage_fp — print usage text to the given stream.
 * WHY: --help (spec WS-2) prints usage to stdout; no-arg / unknown-option
 *      errors still go to stderr.  A FILE* parameter keeps both paths
 *      sharing one text definition.
 */
static void
usage_fp(FILE *out, const char *prog)
{
    fprintf(out,
        "usage: %s [opts] <src>... <dst>\n"
        "  src/dst is root://host[:port]//path, a web URL, a local path, or '-'\n"
        "  web schemes (GET/PUT): davs:// http(s):// dav:// s3:// s3s://\n"
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
        "  --auth <p>     force auth protocol: gsi | ztn | krb5 | sss | unix\n"
        "  --proxy <path> use <path> as the X.509 proxy certificate (overrides $X509_USER_PROXY)\n"
        "  --pgrw         use paged I/O (kXR_pgread/pgwrite) with per-page CRC32c\n"
        "  --io-uring on|off|auto  local-disk overlap ring; overrides $XRDC_IO_URING (default: auto)\n"
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


/* True when both endpoints are web URLs (davs/http/s3) — a web->web transfer the
 * wire can't do directly, so xrdcp relays it through a local temp file. */
int
both_web(const char *src, const char *dst)
{
    return brix_is_web_url(src) && brix_is_web_url(dst);
}


/* Scheme keyword for a parsed web URL, for rebuilding per-file source URLs. */
const char *
web_scheme_str(brix_web_proto pr)
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
 * Reuses the public brix_copy per file (no copy-engine changes). Returns 0/1. */
/* 1 if a server-supplied relative path would escape the destination directory
 * (absolute, or contains a ".." component) — used to reject hostile listings. */
int
rel_is_unsafe(const char *rel)
{
    return brix_rel_is_unsafe(rel);
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


/* ========================================================================
 * WHAT: Validate argument combinations and build source/destination lists
 * WHY:  Many flag combinations are invalid (--delete requires -r+--sync,
 *       --delete conflicts with --remove-source, --verify implies --cksum, etc.)
 * HOW:  Check constraints, derive implicit settings, build srcs list from pos
 *       and --from manifest, derive journal path from --resume+--from
 * PARAMS: All the parsed values from parse_and_validate_args
 * RETURNS: 0 on success, 50 on usage error, 51 on OOM
 * ======================================================================== */
static int
xrdcp_validate_flag_matrix(brix_copy_opts *opts, int sync_mode, int verify)
{
    /* --sync replaces destinations that differ, so the files it does copy must be
     * allowed to overwrite (skipped ones are left untouched by the size check). */
    if (sync_mode) {
        opts->force = 1;
    }
    opts->sync = sync_mode;   /* recursive walkers read o->sync (+ sync_cmp/algo) */
    
    /* --delete (mirror: make the destination match the source) and
     * --remove-source (move: delete each source once its transfer succeeds) are
     * contradictory.  Run together they destroy BOTH trees: on an upload the
     * per-file source unlink runs before the mirror-delete pass, which then sees
     * the now-missing local files and purges the freshly-uploaded remote copies.
     * Reject the pair before any bytes (or unlinks) move. */
    if (opts->sync_delete && opts->remove_source) {
        fprintf(stderr, "xrdcp: --delete and --remove-source are contradictory "
                        "(mirror vs move)\n");
        return 50;
    }
    
    /* --delete requires -r and --sync: without a recursive pass there is no
     * listing to diff against; without --sync the extra-deletion semantics are
     * ill-defined (we might delete a destination the caller wanted to keep). */
    if (opts->sync_delete && !(opts->recursive && sync_mode)) {
        fprintf(stderr, "xrdcp: --delete requires -r and --sync\n");
        return 50;
    }
    
    /* --verify: post-transfer checksum against the server. An explicit --cksum wins. */
    if (verify && opts->cksum == NULL) {
        opts->cksum = "adler32:source";
    }

    return 0;
}


static int
xrdcp_collect_sources(const xrdcp_strlist *pos, const char *from,
                      xrdcp_strlist *srcs)
{
    size_t i;
    int    oom = 0;

    for (i = 0; i + 1 < pos->n; i++) {
        if (str_append(&srcs->items, &srcs->n, &srcs->cap, pos->items[i]) != 0) {
            oom = 1;
        }
    }
    if (from != NULL
        && read_manifest(from, &srcs->items, &srcs->n, &srcs->cap) != 0) {
        return 51;
    }
    if (oom) {
        fprintf(stderr, "xrdcp: out of memory\n");
        return 51;
    }

    return 0;
}


static int
xrdcp_finalize_journal(xrdcp_opts_t *o)
{
    static char jbuf[XRDC_PATH_MAX];

    if (!o->resume || o->journal_path != NULL) {
        return 0;
    }
    if (o->from == NULL || strcmp(o->from, "-") == 0) {
        fprintf(stderr, "xrdcp: --resume needs --from <file> (not stdin) "
                        "or an explicit --journal <path>\n");
        return 50;
    }
    if ((size_t) snprintf(jbuf, sizeof(jbuf), "%s.journal", o->from)
            >= sizeof(jbuf)) {
        fprintf(stderr, "xrdcp: journal path too long\n");
        return 50;
    }
    o->journal_path = jbuf;
    return 0;
}


/*
 * WHAT: Fold the resilience posture (--max-stall / --no-retry / $XRDC_MAX_STALL_MS)
 *       from the shared brix_opts (o->conn) into the brix_copy_opts (o->copt).
 * WHY:  Those knobs are parsed/seeded into brix_opts by brix_opts_parse_arg and
 *       brix_opts_init, but the copy pump's give-up window is read from
 *       brix_copy_opts via copy_stall_ms().  Without this bridge the documented
 *       flag/env were silently no-ops for the transfer window — a hostile-network
 *       operator who set --max-stall to bound a slow-drip stall still got the 60 s
 *       default, so a tripped-deadline read would re-handshake for a full minute.
 * HOW:  no_retry (explicit fail-fast) dominates; otherwise a positive window is
 *       copied across.  conn is the sole parse target, so this is the one place
 *       the posture is mirrored — copt is never written by a flag handler directly.
 */
static void
finalize_resilience_posture(xrdcp_opts_t *o)
{
    if (o->conn->no_retry) {
        o->copt->no_retry = 1;
    } else if (o->conn->max_stall_ms > 0) {
        o->copt->max_stall_ms = o->conn->max_stall_ms;
    }
}


static int
validate_and_finalize_args(xrdcp_opts_t *o, xrdcp_lists_t *l, const char *prog)
{
    static char dstbuf[XRDC_PATH_MAX];
    int rc;

    finalize_resilience_posture(o);

    rc = xrdcp_validate_flag_matrix(o->copt, o->sync_mode, o->verify);
    if (rc != 0) {
        return rc;
    }

    /* Need a destination (the last positional) and at least one source. */
    if (l->pos.n < 1) {
        usage(prog);
        return 50;
    }
    brix_alias_resolve(l->pos.items[l->pos.n - 1], dstbuf, sizeof(dstbuf)); /* ~/.xrdrc */
    o->dst = dstbuf;

    rc = xrdcp_collect_sources(&l->pos, o->from, &l->srcs);
    if (rc != 0) {
        return rc;
    }

    /* --resume shorthand: derive journal path from the manifest path.  Must come
     * before nsrc==0 so the specific error fires even when there are no sources. */
    rc = xrdcp_finalize_journal(o);
    if (rc != 0) {
        return rc;
    }
    if (l->srcs.n == 0) {
        fprintf(stderr, "xrdcp: no source given\n");
        usage(prog);
        return 50;
    }

    return 0;
}


static int
xrdcp_parse_basic_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char     *a = argv[*i];
    brix_copy_opts *o = s->o->copt;

    (void) argc;
    if (strcmp(a, "-f") == 0) { o->force = 1; return 1; }
    if (strcmp(a, "-r") == 0 || strcmp(a, "-R") == 0) {
        o->recursive = 1;
        return 1;
    }
    if (strcmp(a, "-P") == 0 || strcmp(a, "--posc") == 0) {
        o->posc = 1;
        return 1;
    }
    if (strcmp(a, "-s") == 0) { o->silent = 1; return 1; }
    if (strcmp(a, "-v") == 0 || strcmp(a, "-d") == 0
        || strcmp(a, "--verbose") == 0 || strcmp(a, "--debug") == 0) {
        o->verbose = 1;
        return 1;
    }
    if (strcmp(a, "-N") == 0 || strcmp(a, "--no-progress") == 0) {
        s->o->no_progress = 1;
        return 1;
    }
    if (strcmp(a, "--dry-run") == 0 || strcmp(a, "-n") == 0) {
        o->dry_run = 1;
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_manifest_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char   *a = argv[*i];
    xrdcp_opts_t *o = s->o;

    if (strcmp(a, "--from") == 0 && *i + 1 < (size_t) argc) {
        o->from = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--journal") == 0 && *i + 1 < (size_t) argc) {
        o->journal_path = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--resume") == 0) { o->resume = 1; return 1; }
    if (strcmp(a, "--retry") == 0 && *i + 1 < (size_t) argc) {
        o->retries = atoi(argv[++(*i)]);
        if (o->retries <= 0) {
            o->retries = 0;
            o->copt->no_retry = 1;
        }
        return 1;
    }
    if (strcmp(a, "--no-retry") == 0) { o->copt->no_retry = 1; return 1; }
    if ((strcmp(a, "-j") == 0 || strcmp(a, "--jobs") == 0)
        && *i + 1 < (size_t) argc) {
        o->jobs = atoi(argv[++(*i)]);
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_sync_check(brix_copy_opts *opts, const char *mode, const char *prog)
{
    if (strcmp(mode, "size") == 0) {
        opts->sync_cmp = XRDC_SYNC_SIZE;
        return 1;
    }
    if (strcmp(mode, "mtime") == 0) {
        opts->sync_cmp = XRDC_SYNC_MTIME;
        return 1;
    }
    if (strncmp(mode, "cksum", 5) == 0
        && (mode[5] == '\0' || mode[5] == ':')) {
        opts->sync_cmp = XRDC_SYNC_CKSUM;
        opts->sync_cksum_algo = (mode[5] == ':' && mode[6] != '\0')
                                ? mode + 6 : "adler32";
        return 1;
    }
    fprintf(stderr, "xrdcp: --sync-check needs size|mtime|cksum[:algo]\n");
    usage(prog);
    return 50;
}


static int
xrdcp_parse_pattern_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char *a = argv[*i];

    if (strcmp(a, "--exclude") == 0 && *i + 1 < (size_t) argc) {
        if (str_append(&s->l->excl.items, &s->l->excl.n, &s->l->excl.cap,
                       argv[++(*i)]) != 0) { s->oom = 1; }
        return 1;
    }
    if (strcmp(a, "--include") == 0 && *i + 1 < (size_t) argc) {
        if (str_append(&s->l->incl.items, &s->l->incl.n, &s->l->incl.cap,
                       argv[++(*i)]) != 0) { s->oom = 1; }
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_sync_filter_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char *a = argv[*i];

    if (strcmp(a, "--sync") == 0) { s->o->sync_mode = 1; return 1; }
    if (strcmp(a, "--sync-check") == 0 && *i + 1 < (size_t) argc) {
        int rc = xrdcp_parse_sync_check(s->o->copt, argv[++(*i)], argv[0]);
        s->o->sync_mode = 1;
        return rc;
    }
    if (xrdcp_parse_pattern_option(s, argc, argv, i)) { return 1; }
    if (strcmp(a, "--delete") == 0) { s->o->copt->sync_delete = 1; return 1; }
    if (strcmp(a, "--remove-source") == 0) { s->o->copt->remove_source = 1; return 1; }
    return 0;
}


static int
xrdcp_parse_auth_data_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char   *a = argv[*i];
    xrdcp_opts_t *o = s->o;

    if (strcmp(a, "--progress") == 0) { o->force_progress = 1; return 1; }
    if (strcmp(a, "--verify") == 0) { o->verify = 1; return 1; }
    if (strcmp(a, "--auto-refresh") == 0) { o->auto_refresh = 1; return 1; }
    if (strcmp(a, "--oidc-account") == 0 && *i + 1 < (size_t) argc) {
        o->oidc_account = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--proxy") == 0 && *i + 1 < (size_t) argc) {
        o->proxy = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--pgrw") == 0) { o->copt->pgrw = 1; return 1; }
    if (strcmp(a, "--cksum") == 0 && *i + 1 < (size_t) argc) {
        o->copt->cksum = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--compress") == 0 && *i + 1 < (size_t) argc) {
        o->copt->compress = argv[++(*i)];
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_transport_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char     *a = argv[*i];
    brix_copy_opts *o = s->o->copt;

    if (strcmp(a, "--zip") == 0) { o->zip = 1; return 1; }
    if (strcmp(a, "--zip-append") == 0) { o->zip_append = 1; return 1; }
    if ((strcmp(a, "-S") == 0 || strcmp(a, "--streams") == 0)
        && *i + 1 < (size_t) argc) {
        o->streams = atoi(argv[++(*i)]);
        return 1;
    }
    /* --max-stall / --no-retry are parsed by brix_opts_parse_arg into the shared
     * brix_opts (s->o->conn) — which runs first in xrdcp_parse_option — and are
     * folded into copt by finalize_resilience_posture().  Do NOT duplicate the
     * flag here: a second handler is unreachable dead code and a second source of
     * truth for the give-up window. */
    if (strncmp(a, "--io-uring=", 11) == 0) {
        int v = brix_cli_parse_io_uring(a + 11);
        if (v < 0) {
            fprintf(stderr, "xrdcp: --io-uring: invalid mode '%s' (use on|off|auto)\n",
                    a + 11);
            usage(argv[0]);
            return 50;
        }
        o->io_uring = v;
        return 1;
    }
    if (strcmp(a, "--io-uring") == 0 && *i + 1 < (size_t) argc) {
        const char *m = argv[++(*i)];
        int v = brix_cli_parse_io_uring(m);
        if (v < 0) {
            fprintf(stderr, "xrdcp: --io-uring: invalid mode '%s' (use on|off|auto)\n",
                    m);
            usage(argv[0]);
            return 50;
        }
        o->io_uring = v;
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_tpc_mode(brix_copy_opts *opts, const char *mode, const char *prog)
{
    if (strcmp(mode, "first") == 0) {
        opts->tpc_mode = XRDC_TPC_FIRST;
        return 1;
    }
    if (strcmp(mode, "only") == 0) {
        opts->tpc_mode = XRDC_TPC_ONLY;
        return 1;
    }
    if (strcmp(mode, "delegate") == 0) {
        opts->tpc_mode = XRDC_TPC_DELEGATE;
        return 1;
    }
    fprintf(stderr, "xrdcp: --tpc needs first|only|delegate\n");
    usage(prog);
    return 50;
}


static int
xrdcp_parse_remote_auth_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    const char     *a = argv[*i];
    brix_copy_opts *o = s->o->copt;

    if (strcmp(a, "--tpc") == 0 && *i + 1 < (size_t) argc) {
        return xrdcp_parse_tpc_mode(o, argv[++(*i)], argv[0]);
    }
    if (strcmp(a, "--tpc-token-mode") == 0 && *i + 1 < (size_t) argc) {
        o->tpc_token_mode = argv[++(*i)];
        return 1;
    }
    if ((strcmp(a, "-T") == 0 || strcmp(a, "--token") == 0)
        && *i + 1 < (size_t) argc) {
        o->bearer = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--s3-access") == 0 && *i + 1 < (size_t) argc) {
        o->s3_access = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--s3-secret") == 0 && *i + 1 < (size_t) argc) {
        o->s3_secret = argv[++(*i)];
        return 1;
    }
    if (strcmp(a, "--s3-region") == 0 && *i + 1 < (size_t) argc) {
        o->s3_region = argv[++(*i)];
        return 1;
    }
    return 0;
}


static int
xrdcp_parse_option(xrdcp_cli_state *s, int argc, char **argv, size_t *i)
{
    int oi = (int) *i;
    int pr = brix_opts_parse_arg(s->o->conn, argc, argv, &oi);
    int rc;

    if (pr == 2) { usage_fp(stdout, argv[0]); return 2; }
    if (pr) { *i = (size_t) oi; return 1; }
    rc = xrdcp_parse_basic_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_manifest_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_sync_filter_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_auth_data_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_transport_option(s, argc, argv, i);
    if (rc) { return rc; }
    rc = xrdcp_parse_remote_auth_option(s, argc, argv, i);
    if (rc) { return rc; }
    if (strcmp(argv[*i], "-V") == 0) {
        printf("%s (BriX-Cache client) %s\n", brix_prog_base(argv[0]),
               brix_client_version());
        return 2;
    }
    if (strcmp(argv[*i], "-h") == 0) { usage(argv[0]); return 2; }

    fprintf(stderr, "xrdcp: unknown option '%s'\n", argv[*i]);
    usage(argv[0]);
    return 50;
}


/*
 * WHAT: Parse and validate command-line arguments.
 *
 * WHY:  The main() function is CCN 187 (527 lines). Extracting the argument
 *       parsing and validation logic reduces complexity and improves testability.
 *
 * HOW:  Parse all CLI flags into the provided structures, validate flag
 *       interactions (--sync implies --force, --delete requires -r + --sync,
 *       etc.), build positional/exclusion/inclusion lists, and derive defaults.
 *       Returns 0 on success, 50 on usage error, 51 on OOM.
 */
static int
parse_and_validate_args(int argc, char **argv, xrdcp_opts_t *o, xrdcp_lists_t *l)
{
    size_t          i;
    xrdcp_cli_state state;

    memset(&state, 0, sizeof(state));
    state.o = o;
    state.l = l;

    /* Phase 44: XRDC_IO_URING env is the default (auto) for the local-disk
     * overlap ring; --io-uring overrides it below.  auto = 0 = memset default. */
    {
        const char *e = getenv("XRDC_IO_URING");
        if (e != NULL) {
            if (strcmp(e, "on") == 0)       { o->copt->io_uring = XRDC_IO_URING_ON; }
            else if (strcmp(e, "off") == 0) { o->copt->io_uring = XRDC_IO_URING_OFF; }
            else                            { o->copt->io_uring = XRDC_IO_URING_AUTO; }
        }
    }

    for (i = 1; i < (size_t) argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-' && a[1] != '\0' && strcmp(a, "-") != 0) {
            int parsed = xrdcp_parse_option(&state, argc, argv, &i);
            if (parsed == 2) { return XRDCP_PARSE_EXIT_OK; }
            if (parsed == 50) { return 50; }
        } else if (str_append(&l->pos.items, &l->pos.n, &l->pos.cap, a) != 0) {
            fprintf(stderr, "xrdcp: out of memory\n");
            return 51;
        }
    }
    if (state.oom) {
        fprintf(stderr, "xrdcp: out of memory\n");
        return 51;
    }

    o->copt->excludes   = (const char *const *) l->excl.items;
    o->copt->n_excludes = l->excl.n;
    o->copt->includes   = (const char *const *) l->incl.items;
    o->copt->n_includes = l->incl.n;

    return validate_and_finalize_args(o, l, argv[0]);
}


/*
 * WHAT: Build credential store after alias resolution, glob expansion, and pre-flight.
 *
 * WHY:  Credential store construction requires expanded sources to determine auth
 *       needs, plus pre-flight validation to warn about expired/read-only credentials.
 *
 * HOW:  Merge ~/.xrdrc alias credentials, expand globs, validate --remove-source
 *       compatibility with web sources, run credential pre-flight (auto-refresh +
 *       diagnose), then build the credential store. Returns store on success,
 *       NULL on error (with cleanup of passed-in arrays).
 */
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


static void
xrdcp_hint_failed_source(const char *src, const char *dst, const brix_status *st)
{
    brix_url    u_src;
    brix_status ps;

    brix_cred_hint_for_status_url(st, is_root_url(dst) || brix_is_web_url(dst),
                                  stderr, src);
    brix_status_clear(&ps);
    if (brix_url_parse(src, &u_src, &ps) == 0) {
        brix_hint_url_double_slash(st, &u_src);
    }
}


static int
xrdcp_dispatch_recursive_web_download(const xrdcp_transfer_ctx *ctx)
{
    brix_status st;
    size_t      i;
    size_t      bad = 0;

    brix_status_clear(&st);
    for (i = 0; i < ctx->nexp; i++) {
        if (brix_is_web_url(ctx->exp[i])) {
            if (recursive_web_download(ctx->exp[i], ctx->dst, ctx->opts,
                                       ctx->conn, ctx->retries) != 0) {
                bad++;
            }
        } else if (copy_one_with_retry(ctx->exp[i], ctx->dst, ctx->opts,
                                       ctx->conn, ctx->retries, &st) != 0) {
            bad++;
            fprintf(stderr, "xrdcp: %s: %s\n", ctx->exp[i], st.msg);
            xrdcp_hint_failed_source(ctx->exp[i], ctx->dst, &st);
        }
    }
    return (bad == 0) ? 0 : 1;
}


static int
xrdcp_dispatch_recursive_web_upload(const xrdcp_transfer_ctx *ctx)
{
    brix_status st;
    size_t      i;
    size_t      bad = 0;

    brix_status_clear(&st);
    if (ctx->opts->sync_delete) {
        fprintf(stderr, "xrdcp: --delete is not supported for web "
                        "destinations (ignored)\n");
    }
    for (i = 0; i < ctx->nexp; i++) {
        if (is_local_dir(ctx->exp[i])) {
            if (recursive_web_upload(ctx->exp[i], ctx->dst, ctx->opts,
                                     ctx->conn, ctx->retries) != 0) {
                bad++;
            }
        } else if (copy_one_with_retry(ctx->exp[i], ctx->dst, ctx->opts,
                                       ctx->conn, ctx->retries, &st) != 0) {
            bad++;
            fprintf(stderr, "xrdcp: %s: %s\n", ctx->exp[i], st.msg);
        }
    }
    return (bad == 0) ? 0 : 1;
}


static int
xrdcp_try_recursive_web(const xrdcp_transfer_ctx *ctx, int *handled)
{
    size_t i;
    int    any_web = 0;
    int    has_dir = 0;

    *handled = 0;
    if (!ctx->opts->recursive) {
        return 0;
    }
    for (i = 0; i < ctx->nexp; i++) {
        if (brix_is_web_url(ctx->exp[i])) { any_web = 1; }
        if (is_local_dir(ctx->exp[i])) { has_dir = 1; }
    }
    if (any_web) {
        *handled = 1;
        return xrdcp_dispatch_recursive_web_download(ctx);
    }
    if (brix_is_web_url(ctx->dst) && has_dir) {
        *handled = 1;
        return xrdcp_dispatch_recursive_web_upload(ctx);
    }
    return 0;
}


static void
xrdcp_enable_progress_if_needed(xrdcp_transfer_ctx *ctx, xrdcp_prog *ps,
                                char *label, size_t label_len)
{
    if (!((ctx->force_progress || (isatty(STDERR_FILENO) && !ctx->no_progress))
          && !ctx->opts->silent
          && !(ctx->exp[0][0] == '-' && ctx->exp[0][1] == '\0'))) {
        return;
    }

    path_basename(ctx->exp[0], label, label_len);
    ps->label = (label[0] != '\0') ? label : "transfer";
    ps->start_ns = brix_mono_ns();
    ps->last_ns = 0;
    ctx->opts->progress = xrdcp_progress;
    ctx->opts->progress_arg = ps;
}


static int
xrdcp_dispatch_single(xrdcp_transfer_ctx *ctx)
{
    brix_status st;
    char        label[XRDC_NAME_MAX];
    xrdcp_prog  ps;
    int         one;

    brix_status_clear(&st);
    xrdcp_enable_progress_if_needed(ctx, &ps, label, sizeof(label));
    one = transfer_one(ctx->exp[0], ctx->dst, ctx->opts, ctx->conn,
                       ctx->retries, ctx->sync_mode, &st);
    if (one == 1 && !ctx->opts->silent) {
        fprintf(stderr, "xrdcp: %s up-to-date, skipped\n", ctx->dst);
    } else if (one < 0 && !ctx->opts->silent) {
        fprintf(stderr, "xrdcp: %s\n", st.msg);
        xrdcp_hint_failed_source(ctx->exp[0], ctx->dst, &st);
    }
    return (one >= 0) ? 0 : brix_shellcode(&st);
}


static brix_journal *
xrdcp_open_batch_journal(const xrdcp_transfer_ctx *ctx, brix_status *st,
                         int *rc)
{
    *rc = 0;
    if (ctx->journal_path == NULL || ctx->opts->dry_run) {
        return NULL;
    }
    brix_status_clear(st);
    {
        brix_journal *jrn = brix_journal_open(ctx->journal_path, st);
        if (jrn == NULL) {
            fprintf(stderr, "xrdcp: %s\n", st->msg);
            *rc = 51;
        }
        return jrn;
    }
}


static void
xrdcp_batch_one(const xrdcp_transfer_ctx *ctx, brix_journal *jrn,
                xrdcp_tally_t *t, size_t idx)
{
    char dpath[XRDC_PATH_MAX];
    int  one;

    if (jrn != NULL && brix_journal_has(jrn, ctx->exp[idx])) {
        t->skip++;
        if (!ctx->opts->silent) {
            fprintf(stderr, "[%zu/%zu] %s (already transferred)\n",
                    t->ok + t->skip + t->fail, ctx->nexp, ctx->exp[idx]);
        }
        return;
    }
    one = batch_copy_one(ctx->exp[idx], ctx->dst, ctx->opts, ctx->conn,
                         ctx->retries, ctx->sync_mode, dpath, sizeof(dpath), &t->st);
    if (one == 0) {
        t->ok++;
        if (!ctx->opts->silent) {
            fprintf(stderr, "[%zu/%zu] %s -> %s\n",
                    t->ok + t->skip + t->fail, ctx->nexp, ctx->exp[idx], dpath);
        }
        if (jrn != NULL && !ctx->opts->dry_run) {
            (void) brix_journal_mark(jrn, ctx->exp[idx]);
        }
    } else if (one == 1) {
        t->skip++;
        if (!ctx->opts->silent) {
            fprintf(stderr, "[%zu/%zu] %s (up-to-date)\n",
                    t->ok + t->skip + t->fail, ctx->nexp, ctx->exp[idx]);
        }
    } else {
        t->fail++;
        fprintf(stderr, "xrdcp: %s: %s\n", ctx->exp[idx], t->st.msg);
        xrdcp_hint_failed_source(ctx->exp[idx], ctx->dst, &t->st);
    }
}


static int
xrdcp_dispatch_batch(xrdcp_transfer_ctx *ctx)
{
    xrdcp_tally_t t;
    brix_journal *jrn;
    size_t        i;
    int           rc;
    int           jobs = ctx->jobs;

    memset(&t, 0, sizeof(t));
    brix_status_clear(&t.st);
    if (dest_is_dir(ctx->dst, ctx->conn) != 1) {
        fprintf(stderr, "xrdcp: destination must be an existing directory for "
                        "multi-source copy: %s\n", ctx->dst);
        return 50;
    }
    jrn = xrdcp_open_batch_journal(ctx, &t.st, &rc);
    if (rc != 0) {
        return rc;
    }
    if (jobs > (int) ctx->nexp) { jobs = (int) ctx->nexp; }
    if (jobs > 1) {
        batch_parallel(ctx->exp, ctx->nexp, ctx->dst, ctx->opts, ctx->conn,
                       ctx->retries, ctx->sync_mode, jobs, jrn,
                       &t.ok, &t.skip, &t.fail);
    } else {
        for (i = 0; i < ctx->nexp; i++) {
            xrdcp_batch_one(ctx, jrn, &t, i);
        }
    }
    if (!ctx->opts->silent) {
        fprintf(stderr, "xrdcp: %zu copied, %zu skipped, %zu failed\n",
                t.ok, t.skip, t.fail);
    }
    return (t.fail == 0) ? 0 : 1;
}


/*
 * WHAT: Dispatch transfer based on mode (web recursive, single, or batch).
 *
 * WHY:  Main() had CCN 187 with complex mode routing. Extracting the dispatch
 *       logic (web recursive download/upload, single transfer with progress,
 *       batch sequential/parallel, journal lifecycle) reduces complexity.
 *
 * HOW:  Determine transfer mode from source types and flags. Route to:
 *       - Web recursive download/upload (davs/http collections)
 *       - Single transfer with progress bar (nexp==1)
 *       - Batch transfer with journal support (nexp>1)
 *       Returns 0 on success, 1 on partial failure, 50 on usage error, 51 on OOM.
 */
static int
dispatch_transfer(xrdcp_opts_t *o, xrdcp_lists_t *l)
{
    xrdcp_transfer_ctx ctx;
    int                handled;
    int                rc;

    ctx.opts = o->copt;
    ctx.conn = o->conn;
    ctx.cred_store = o->cred_store;
    ctx.exp = l->exp.items;
    ctx.nexp = l->exp.n;
    ctx.dst = o->dst;
    ctx.from = o->from;
    ctx.journal_path = o->journal_path;
    ctx.retries = o->retries;
    ctx.jobs = o->jobs;
    ctx.sync_mode = o->sync_mode;
    ctx.force_progress = o->force_progress;
    ctx.no_progress = o->no_progress;

    rc = xrdcp_try_recursive_web(&ctx, &handled);
    if (handled) {
        return rc;
    }
    if (l->exp.n == 1 && o->from == NULL) {
        return xrdcp_dispatch_single(&ctx);
    }

    return xrdcp_dispatch_batch(&ctx);
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
