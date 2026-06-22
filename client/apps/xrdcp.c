/*
 * xrdcp.c — native XRootD copy CLI.
 *
 * WHAT: `xrdcp [opts] SRC... DST` — copies between root:// (and davs/http(s)/s3 web
 *       schemes) and local files. Single `SRC DST` keeps the classic behaviour; with
 *       multiple sources, a glob, or a --from manifest, DST is a directory and every
 *       source is copied into it (with optional --retry).
 * WHY:  A libXrdCl-free xrdcp (phase-37) drivable by the harness via TEST_XRDCP_BIN,
 *       growing toward a "swiss-army-knife" data mover.
 * HOW:  Arg parse → expand globs/manifest into a source list → single copy or a batch
 *       loop over xrdc_copy(); exit with the copy's shell code (nonzero if any fail).
 *
 * Clean-room: option letters/semantics mirror the documented xrdcp (xrdcp.1).
 */
#include "xrdc.h"
#include "compat/crypto.h"   /* xrootd_crypto_init (libxrdproto SHA/HMAC kernels) */

#include <dirent.h>   /* local-tree walk for recursive web upload */
#include <errno.h>
#include <glob.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  /* strncasecmp() for case-insensitive scheme match */
#include <sys/stat.h>
#include <time.h>     /* nanosleep() for jittered retry backoff */
#include <unistd.h>

static void
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
        "  --retry <n>    retry each failed transfer up to n times (backoff)\n"
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
static int
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

static void
str_free(char **list, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) { free(list[i]); }
    free(list);
}

/* If `arg` names a ~/.xrdrc alias, fold its per-endpoint credentials into `o` — a
 * value already set (CLI flag or earlier alias) always wins. The opt pointers are
 * backed by static storage for the process lifetime. PII: creds are never logged. */
static void
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
static void
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
static int
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
static int
is_root_url(const char *s)
{
    return strncmp(s, "root://", 7) == 0 || strncmp(s, "roots://", 8) == 0
        || strncmp(s, "xroot://", 8) == 0 || strncmp(s, "xroots://", 9) == 0;
}

/* An s3/s3s endpoint authenticates with AWS SigV4 keys, NOT a GSI proxy or
 * bearer token — so the GSI/token credential pre-flight is irrelevant noise for
 * it. (case-insensitive: schemes may be upper-cased by the user) */
static int
is_s3_url(const char *s)
{
    return strncasecmp(s, "s3://", 5) == 0 || strncasecmp(s, "s3s://", 6) == 0;
}

/* True when an endpoint uses the GSI-proxy / bearer-token credential family
 * (root:// or a non-s3 web URL). S3 SigV4 endpoints return 0 here. */
static int
uses_cred_auth(const char *s)
{
    return is_root_url(s) || (xrdc_is_web_url(s) && !is_s3_url(s));
}

/* True when `p` names an existing local directory (a recursive-upload source). */
static int
is_local_dir(const char *p)
{
    struct stat sb;
    return stat(p, &sb) == 0 && S_ISDIR(sb.st_mode);
}

/* Expand one source into `out`: a root:// glob via xrdc_glob, a local glob via
 * glob(3), otherwise the literal. Returns 0; -1 only on a hard (alloc) failure.
 * A glob that matches nothing appends nothing and warns. */
/* Like xrdc_has_glob, but a '?' that introduces an opaque section
 * (root://...?key=val, e.g. ?xrdcl.unzip=member) is the opaque separator, not a
 * wildcard — so only the path before it is considered for globbing. */
static int
source_has_glob(const char *s)
{
    const char *q = strchr(s, '?');

    if (q != NULL && strchr(q, '=') != NULL) {
        size_t plen = (size_t) (q - s), i;
        for (i = 0; i < plen; i++) {
            if (s[i] == '*' || s[i] == '[' || s[i] == '?') {
                return 1;
            }
        }
        return 0;
    }
    return xrdc_has_glob(s);
}

static int
expand_source(const char *s_in, const xrdc_opts *co, char ***out, size_t *n, size_t *cap)
{
    char        rs[XRDC_PATH_MAX];
    const char *s;
    xrdc_alias_resolve(s_in, rs, sizeof(rs));   /* ~/.xrdrc: name:suffix -> URL */
    s = rs;
    if (!source_has_glob(s)) {
        return str_append(out, n, cap, s);
    }
    if (xrdc_is_web_url(s)) {
        return str_append(out, n, cap, s);   /* web globbing not supported; literal */
    }
    if (is_root_url(s)) {
        char      **m = NULL;
        size_t      nm = 0, i;
        xrdc_status st;
        xrdc_status_clear(&st);
        if (xrdc_glob(s, co, &m, &nm, &st) < 0) {
            if (st.kxr == XRDC_EUSAGE) {
                return str_append(out, n, cap, s);   /* genuinely not a glob → literal */
            }
            /* Hard failure (connect/dirlist/auth): surface it; don't silently fall
             * back to copying the literal '*' pattern as a filename. */
            fprintf(stderr, "xrdcp: glob %s: %s\n", s, st.msg);
            return 0;
        }
        if (nm == 0) {
            fprintf(stderr, "xrdcp: no matches for %s\n", s);
        }
        for (i = 0; i < nm; i++) {
            if (str_append(out, n, cap, m[i]) != 0) { xrdc_glob_free(m, nm); return -1; }
        }
        xrdc_glob_free(m, nm);
        return 0;
    }
    {
        glob_t g;
        int    rc = glob(s, 0, NULL, &g);
        if (rc == 0) {
            size_t i;
            for (i = 0; i < g.gl_pathc; i++) {
                if (str_append(out, n, cap, g.gl_pathv[i]) != 0) { globfree(&g); return -1; }
            }
            globfree(&g);
            return 0;
        }
        globfree(&g);
        fprintf(stderr, "xrdcp: no matches for %s\n", s);
        return 0;
    }
}

/* Is `dst` an existing directory? 1=yes, 0=no, -1=can't determine (web/parse). */
static int
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

static int
join_dest(const char *dstdir, const char *base, char *out, size_t sz)
{
    size_t      dl = strlen(dstdir);
    const char *sep = (dl > 0 && dstdir[dl - 1] == '/') ? "" : "/";
    return ((size_t) snprintf(out, sz, "%s%s%s", dstdir, sep, base) >= sz) ? -1 : 0;
}

/* True when both endpoints are web URLs (davs/http/s3) — a web->web transfer the
 * wire can't do directly, so xrdcp relays it through a local temp file. */
static int
both_web(const char *src, const char *dst)
{
    return xrdc_is_web_url(src) && xrdc_is_web_url(dst);
}

/* Relay a web->web copy through a private local temp file (download then upload).
 * Defined after copy_one_with_retry (which it calls for each leg). */
static int relay_web_to_web(const char *src, const char *dst, const xrdc_copy_opts *o,
                            const xrdc_opts *co, int retries, xrdc_status *st);

/* Copy one src->dst, retrying up to `retries` times with capped exponential backoff. */
static int
copy_one_with_retry(const char *src, const char *dst, const xrdc_copy_opts *o,
                    const xrdc_opts *co, int retries, xrdc_status *st)
{
    int attempt = 0;
    /* web->web has no direct wire path — stage through a local temp. Each relay
     * leg is web<->local (never web->web), so it re-enters here on the normal
     * path with no recursion. */
    if (both_web(src, dst)) {
        return relay_web_to_web(src, dst, o, co, retries, st);
    }
    for (;;) {
        xrdc_status_clear(st);
        if (xrdc_copy(src, dst, o, co, st) == 0) {
            return 0;
        }
        if (attempt >= retries) {
            return -1;
        }
        {
            int backoff = 1 << (attempt < 5 ? attempt : 5);   /* 1,2,4,8,16,32 -> cap */
            unsigned half_ms, wait_ms;
            struct timespec ts;
            if (backoff > 30) { backoff = 30; }
            /* Phase 40 (a): "equal jitter" — wait half the backoff plus a random
             * slice of the other half, so many clients/jobs retrying in lockstep
             * spread their attempts instead of stampeding the server together. */
            half_ms = (unsigned) backoff * 500u;          /* backoff/2 in ms */
            wait_ms = half_ms + xrdc_jitter_ms(half_ms + 1u);
            if (!o->silent) {
                fprintf(stderr, "xrdcp: %s failed (%s); retry %d/%d in %.1fs\n",
                        src, st->msg, attempt + 1, retries, wait_ms / 1000.0);
            }
            ts.tv_sec  = wait_ms / 1000u;
            ts.tv_nsec = (long) (wait_ms % 1000u) * 1000000L;
            (void) nanosleep(&ts, NULL);
        }
        attempt++;
    }
}

/* Size of a regular file at `url` (root:// or local). 0 and *size set if it exists
 * as a regular file; -1 otherwise (missing, a directory, web, or error). */
static int
entry_size(const char *url, const xrdc_opts *co, long long *size)
{
    xrdc_url    u;
    xrdc_status st;
    if (xrdc_is_web_url(url)) {
        return -1;   /* no cheap stat for web; --sync always copies web targets */
    }
    xrdc_status_clear(&st);
    if (xrdc_url_parse(url, &u, &st) != 0) {
        return -1;
    }
    if (u.scheme == XRDC_SCHEME_LOCAL) {
        struct stat sb;
        if (stat(u.path, &sb) != 0 || !S_ISREG(sb.st_mode)) { return -1; }
        *size = (long long) sb.st_size;
        return 0;
    }
    if (u.scheme == XRDC_SCHEME_ROOT || u.scheme == XRDC_SCHEME_ROOTS) {
        xrdc_conn     c;
        xrdc_statinfo si;
        int           ok;
        if (xrdc_connect(&c, &u, co, &st) != 0) { return -1; }
        ok = (xrdc_stat(&c, u.path, &si, &st) == 0 && !(si.flags & kXR_isDir));
        if (ok) { *size = (long long) si.size; }
        xrdc_close(&c);
        return ok ? 0 : -1;
    }
    return -1;
}

/* Transfer src -> dst. In --sync mode, skip when both ends exist with the same size.
 * Returns 0 (copied), 1 (skipped, up-to-date), or -1 (failed, st set). */
static int
transfer_one(const char *src, const char *dst, const xrdc_copy_opts *o,
             const xrdc_opts *co, int retries, int sync_mode, xrdc_status *st)
{
    if (sync_mode) {
        long long ssz = 0, dsz = 0;
        if (entry_size(src, co, &ssz) == 0 && entry_size(dst, co, &dsz) == 0
            && ssz == dsz) {
            return 1;   /* up-to-date — skip */
        }
    }
    return (copy_one_with_retry(src, dst, o, co, retries, st) == 0) ? 0 : -1;
}

/* Relay a web->web copy (e.g. davs://a/f -> s3://b/k) by staging through a private
 * local temp file: download src into it, then upload it to dst. The wire has no
 * direct web->web op and xrdc_http_upload needs a seekable/sized body, so a temp
 * is the only correct path. The temp is created 0600 via mkstemp in $TMPDIR and
 * unlinked on every return. Note the download leg rewrites the temp via its own
 * temp+rename (which lands 0644), so we re-tighten it to 0600 before the upload
 * leg, keeping the staged bytes private during the (longer) upload window. Each
 * leg is web<->local, so cancellation is only as prompt as a single web transfer
 * (a timeout/EINTR boundary), not instantaneous. */
static int
relay_web_to_web(const char *src, const char *dst, const xrdc_copy_opts *o,
                 const xrdc_opts *co, int retries, xrdc_status *st)
{
    const char    *tmpdir = getenv("TMPDIR");
    char           tmpl[XRDC_PATH_MAX];
    xrdc_copy_opts leg;
    int            fd, rc;

    if (tmpdir == NULL || tmpdir[0] == '\0') { tmpdir = "/tmp"; }
    if ((size_t) snprintf(tmpl, sizeof(tmpl), "%s/xrdcp-w2w-XXXXXX", tmpdir)
            >= sizeof(tmpl)) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "web->web: temp path too long");
        return -1;
    }
    fd = mkstemp(tmpl);
    if (fd < 0) {
        xrdc_status_set(st, XRDC_ESOCK, errno,
                        "web->web: mkstemp in %s: %s", tmpdir, strerror(errno));
        return -1;
    }
    close(fd);   /* the download leg reopens by path */

    if (!o->silent) {
        fprintf(stderr, "xrdcp: %s -> %s (web->web via local temp)\n", src, dst);
    }
    /* Leg 1: download src -> our private temp. Force-overwrite the empty mkstemp
     * file (it is ours) and never recurse. */
    leg = *o;
    leg.force = 1;
    leg.recursive = 0;
    rc = copy_one_with_retry(src, tmpl, &leg, co, retries, st);
    if (rc == 0) {
        /* The download's temp+rename left the staged file group/other-readable;
         * re-tighten before the upload so the bytes aren't world-readable in a
         * shared /tmp for the whole upload. */
        (void) chmod(tmpl, S_IRUSR | S_IWUSR);
        /* Leg 2: upload temp -> dst, honouring the user's real force/posc/creds. */
        leg = *o;
        leg.recursive = 0;
        rc = copy_one_with_retry(tmpl, dst, &leg, co, retries, st);
    }
    (void) unlink(tmpl);
    return rc;
}

/* Copy one batch item into dstdir as dstdir/<basename>. Returns 0 (copied),
 * 1 (skipped), or -1 (failed, st set); the destination is written to dpath. */
static int
batch_copy_one(const char *item, const char *dstdir, const xrdc_copy_opts *o,
               const xrdc_opts *co, int retries, int sync_mode, char *dpath,
               size_t dpsz, xrdc_status *st)
{
    char base[XRDC_NAME_MAX];
    path_basename(item, base, sizeof(base));
    if (base[0] == '\0') {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "cannot derive a filename from %s", item);
        return -1;
    }
    if (join_dest(dstdir, base, dpath, dpsz) != 0) {
        xrdc_status_set(st, XRDC_EUSAGE, 0, "destination path too long for %s", item);
        return -1;
    }
    return transfer_one(item, dpath, o, co, retries, sync_mode, st);
}

/* Shared state for the parallel batch worker pool. Each xrdc_copy() is fully
 * independent (its own connection + fds), so workers only contend on this counter
 * block + stderr, guarded by one mutex. */
typedef struct {
    char           **items;
    size_t           n;
    const char      *dst;
    const xrdc_copy_opts *o;
    const xrdc_opts *co;
    int              retries;
    int              sync_mode;
    size_t           next;   /* next item index to claim */
    size_t           ok;
    size_t           skip;
    size_t           fail;
    pthread_mutex_t  lock;
} batch_ctx;

static void *
batch_worker(void *arg)
{
    batch_ctx *b = (batch_ctx *) arg;
    for (;;) {
        size_t      idx;
        char        dpath[XRDC_PATH_MAX];
        xrdc_status st;
        int         rc;

        pthread_mutex_lock(&b->lock);
        idx = b->next++;
        pthread_mutex_unlock(&b->lock);
        if (idx >= b->n) {
            break;
        }
        xrdc_status_clear(&st);
        rc = batch_copy_one(b->items[idx], b->dst, b->o, b->co, b->retries,
                            b->sync_mode, dpath, sizeof(dpath), &st);
        pthread_mutex_lock(&b->lock);
        if (rc == 0) {
            b->ok++;
            if (!b->o->silent) {
                fprintf(stderr, "[%zu/%zu] %s -> %s\n", b->ok + b->skip + b->fail,
                        b->n, b->items[idx], dpath);
            }
        } else if (rc == 1) {
            b->skip++;
            if (!b->o->silent) {
                fprintf(stderr, "[%zu/%zu] %s (up-to-date)\n",
                        b->ok + b->skip + b->fail, b->n, b->items[idx]);
            }
        } else {
            b->fail++;
            fprintf(stderr, "xrdcp: %s: %s\n", b->items[idx], st.msg);
        }
        pthread_mutex_unlock(&b->lock);
    }
    return NULL;
}

/* Run the batch with `jobs` concurrent workers (jobs>=2). Fills ok/skip/fail counts. */
static void
batch_parallel(char **items, size_t n, const char *dst, const xrdc_copy_opts *o,
               const xrdc_opts *co, int retries, int sync_mode, int jobs,
               size_t *ok, size_t *skip, size_t *fail)
{
    batch_ctx  b;
    pthread_t *th;
    int        j, spawned = 0;

    memset(&b, 0, sizeof(b));
    b.items = items; b.n = n; b.dst = dst; b.o = o; b.co = co; b.retries = retries;
    b.sync_mode = sync_mode;
    pthread_mutex_init(&b.lock, NULL);
    th = (pthread_t *) malloc((size_t) jobs * sizeof(pthread_t));
    if (th == NULL) {
        /* Fall back to single-threaded drain on allocation failure. */
        batch_worker(&b);
    } else {
        for (j = 0; j < jobs; j++) {
            if (pthread_create(&th[j], NULL, batch_worker, &b) == 0) {
                spawned++;
            }
        }
        if (spawned == 0) {
            batch_worker(&b);   /* no thread started — drain inline */
        }
        for (j = 0; j < spawned; j++) {
            pthread_join(th[j], NULL);
        }
        free(th);
    }
    pthread_mutex_destroy(&b.lock);
    *ok = b.ok;
    *skip = b.skip;
    *fail = b.fail;
}

/* Scheme keyword for a parsed web URL, for rebuilding per-file source URLs. */
static const char *
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

/* mkdir -p of the directory component of `filepath` (errors other than EEXIST are
 * left for the subsequent open to report). */
static void
mkdirs_for(const char *filepath)
{
    char  tmp[XRDC_PATH_MAX];
    char *slash, *p;
    snprintf(tmp, sizeof(tmp), "%s", filepath);
    slash = strrchr(tmp, '/');
    if (slash == NULL || slash == tmp) {
        return;
    }
    *slash = '\0';
    for (p = tmp + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            (void) mkdir(tmp, 0755);
            *p = '/';
        }
    }
    (void) mkdir(tmp, 0755);
}

/* Recursively download a WebDAV/HTTP collection into local directory `dstdir`,
 * preserving the tree: PROPFIND-list the files, then copy each to dstdir/<relpath>.
 * Reuses the public xrdc_copy per file (no copy-engine changes). Returns 0/1. */
/* 1 if a server-supplied relative path would escape the destination directory
 * (absolute, or contains a ".." component) — used to reject hostile listings. */
static int
rel_is_unsafe(const char *rel)
{
    return rel[0] == '/' || strcmp(rel, "..") == 0
        || strncmp(rel, "../", 3) == 0 || strstr(rel, "/../") != NULL
        || (strlen(rel) >= 3 && strcmp(rel + strlen(rel) - 3, "/..") == 0);
}

/* MKCOL each ancestor collection of `rel` under `base` on web endpoint `du`
 * (davs/http only; S3 keys are flat → no-op). Idempotent, created top-down so a
 * deeper PUT never hits 409. 0 / -1 (st set). */
static int
mkcol_parents(const xrdc_weburl *du, const char *base, const char *rel,
              const char *bearer, const xrdc_opts *co, xrdc_status *st)
{
    char        acc[XRDC_PATH_MAX * 2];
    const char *slash;
    size_t      blen;

    if (du->is_s3) { return 0; }
    blen = (size_t) snprintf(acc, sizeof(acc), "%s", base);
    if (blen >= sizeof(acc)) { return -1; }
    for (slash = strchr(rel, '/'); slash != NULL; slash = strchr(slash + 1, '/')) {
        int w = snprintf(acc + blen, sizeof(acc) - blen, "/%.*s",
                         (int) (slash - rel), rel);
        if (w < 0 || blen + (size_t) w >= sizeof(acc)) { return -1; }
        if (xrdc_webdav_mkcol(du, acc, bearer, co ? co->verify_host : 1,
                              co ? co->ca_dir : NULL, st) != 0) {
            return -1;
        }
    }
    return 0;
}

/* Place one recursively-listed source file `srcurl` at `rel` under `dstroot`,
 * which may be a LOCAL directory (mkdir -p + copy) or a WEB collection (MKCOL the
 * parent collections + a web->web relay via copy_one_with_retry). Centralising the
 * destination side lets both the WebDAV and S3 recursive sources copy to a local
 * tree OR another web endpoint (web->web). 0 / -1 (st set). */
static int
recursive_place(const char *dstroot, const char *rel, const char *srcurl,
                const xrdc_copy_opts *fo, const xrdc_opts *co, int retries,
                xrdc_status *st)
{
    if (xrdc_is_web_url(dstroot)) {
        xrdc_weburl du;
        char        dbase[XRDC_PATH_MAX], dsturl[XRDC_PATH_MAX * 2 + 320];
        const char *dbearer;
        size_t      blen;
        if (xrdc_weburl_parse(dstroot, &du) != 0) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "bad web dst URL %s", dstroot);
            return -1;
        }
        snprintf(dbase, sizeof(dbase), "%s", du.path);
        blen = strlen(dbase);
        while (blen > 0 && dbase[blen - 1] == '/') { dbase[--blen] = '\0'; }
        dbearer = (fo != NULL && fo->bearer != NULL) ? fo->bearer
                                                     : getenv("BEARER_TOKEN");
        if (mkcol_parents(&du, dbase, rel, dbearer, co, st) != 0) {
            return -1;
        }
        if ((size_t) snprintf(dsturl, sizeof(dsturl), "%s://%s:%d%s/%s",
                              web_scheme_str(du.proto), du.host, du.port, dbase, rel)
                >= sizeof(dsturl)) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "web->web dst path too long");
            return -1;
        }
        return copy_one_with_retry(srcurl, dsturl, fo, co, retries, st);
    } else {
        char dstfile[XRDC_PATH_MAX];
        if ((size_t) snprintf(dstfile, sizeof(dstfile), "%s/%s", dstroot, rel)
                >= sizeof(dstfile)) {
            xrdc_status_set(st, XRDC_EUSAGE, 0, "dst path too long");
            return -1;
        }
        mkdirs_for(dstfile);
        return copy_one_with_retry(srcurl, dstfile, fo, co, retries, st);
    }
}

/* For a recursive copy whose destination is a web COLLECTION, MKCOL the base
 * collection once (idempotent) so the first per-file PUT doesn't 409. No-op for a
 * local destination or an S3 bucket (flat keys need no collections). */
static void
ensure_web_dst_base(const char *dstroot, const xrdc_copy_opts *fo,
                    const xrdc_opts *co)
{
    xrdc_weburl  du;
    char         dbase[XRDC_PATH_MAX];
    const char  *dbearer;
    size_t       blen;
    xrdc_status  st;

    if (!xrdc_is_web_url(dstroot) || xrdc_weburl_parse(dstroot, &du) != 0
        || du.is_s3) {
        return;
    }
    snprintf(dbase, sizeof(dbase), "%s", du.path);
    blen = strlen(dbase);
    while (blen > 0 && dbase[blen - 1] == '/') { dbase[--blen] = '\0'; }
    if (dbase[0] == '\0') { return; }   /* root collection needs no MKCOL */
    dbearer = (fo != NULL && fo->bearer != NULL) ? fo->bearer
                                                 : getenv("BEARER_TOKEN");
    xrdc_status_clear(&st);
    (void) xrdc_webdav_mkcol(&du, dbase, dbearer, co ? co->verify_host : 1,
                             co ? co->ca_dir : NULL, &st);   /* best-effort */
}

/* Recursively download an s3:// prefix into dstdir: ListObjectsV2 (paginated,
 * SigV4-signed) then copy each key to dstdir/<key-minus-prefix>, preserving the
 * tree. `fo` is a non-recursive opts copy carrying the S3 creds. Returns 0/1. */
static int
recursive_s3_download(const xrdc_weburl *u, const char *dstdir,
                      const xrdc_copy_opts *fo, const xrdc_opts *co, int retries)
{
    xrdc_status st;
    char      **keys = NULL;
    char        bucket[256], prefix[XRDC_PATH_MAX];
    const char *ak, *sk, *region, *scheme, *bsl;
    size_t      n = 0, i, plen, ok = 0, fail = 0;

    xrdc_status_clear(&st);
    ak     = fo->s3_access ? fo->s3_access : getenv("AWS_ACCESS_KEY_ID");
    sk     = fo->s3_secret ? fo->s3_secret : getenv("AWS_SECRET_ACCESS_KEY");
    region = fo->s3_region ? fo->s3_region : getenv("AWS_DEFAULT_REGION");
    if (xrdc_s3_list(u, ak, sk, region, co ? co->verify_host : 1,
                     co ? co->ca_dir : NULL, &keys, &n, &st) != 0) {
        fprintf(stderr, "xrdcp: s3 list: %s\n", st.msg);
        return 1;
    }
    /* split u->path "/bucket[/prefix]" into bucket + prefix (no trailing slash).
     * One guarded memcpy for the bucket covers both the no-slash and prefix cases
     * (xrdc_s3_list already validated the same split, but stay defensive). */
    bsl = strchr(u->path + 1, '/');
    {
        size_t bl = bsl ? (size_t) (bsl - (u->path + 1)) : strlen(u->path + 1);
        if (bl >= sizeof(bucket)) {
            fprintf(stderr, "xrdcp: s3 bucket name too long\n");
            xrdc_strv_free(keys, n);
            return 1;
        }
        memcpy(bucket, u->path + 1, bl);
        bucket[bl] = '\0';
        if (bsl != NULL) {
            snprintf(prefix, sizeof(prefix), "%s", bsl + 1);
        } else {
            prefix[0] = '\0';
        }
    }
    plen = strlen(prefix);
    while (plen > 0 && prefix[plen - 1] == '/') { prefix[--plen] = '\0'; }
    scheme = web_scheme_str(u->proto);
    ensure_web_dst_base(dstdir, fo, co);   /* s3->web: create the dst collection */

    for (i = 0; i < n; i++) {
        const char *key = keys[i];
        const char *rel;
        char        relbuf[XRDC_NAME_MAX];
        char        srcurl[XRDC_PATH_MAX + 320];
        xrdc_status cst;

        if (plen == 0) {
            rel = key;
        } else if (strncmp(key, prefix, plen) == 0 && (key[plen] == '/' || key[plen] == '\0')) {
            rel = key + plen + (key[plen] == '/' ? 1 : 0);
        } else {
            path_basename(key, relbuf, sizeof(relbuf));   /* fallback: flatten */
            rel = relbuf;
        }
        if (*rel == '\0') {
            continue;
        }
        if (rel_is_unsafe(rel)) {
            fprintf(stderr, "xrdcp: refusing unsafe key from server: %s\n", key);
            fail++;
            continue;
        }
        if ((size_t) snprintf(srcurl, sizeof(srcurl), "%s://%s:%d/%s/%s",
                              scheme, u->host, u->port, bucket, key) >= sizeof(srcurl)) {
            fail++;
            continue;
        }
        /* dstdir may be a local dir OR a web collection (recursive s3->web). */
        xrdc_status_clear(&cst);
        if (recursive_place(dstdir, rel, srcurl, fo, co, retries, &cst) == 0) {
            ok++;
            if (!fo->silent) {
                fprintf(stderr, "[%zu/%zu] %s -> %s/%s\n", ok + fail, n, srcurl, dstdir, rel);
            }
        } else {
            fail++;
            fprintf(stderr, "xrdcp: %s: %s\n", srcurl, cst.msg);
        }
    }
    xrdc_strv_free(keys, n);
    if (!fo->silent) {
        fprintf(stderr, "xrdcp: %zu copied, %zu failed (recursive s3)\n", ok, fail);
    }
    return (fail == 0) ? 0 : 1;
}

static int
recursive_web_download(const char *src, const char *dstdir, const xrdc_copy_opts *o,
                       const xrdc_opts *co, int retries)
{
    xrdc_weburl    u;
    xrdc_status    st;
    xrdc_copy_opts fo;
    char         **paths = NULL;
    char           prefix[XRDC_PATH_MAX];
    const char    *bearer, *scheme;
    size_t         n = 0, i, plen, ok = 0, fail = 0;

    /* Each listed file is a plain (non-recursive) copy; clear the -r flag so the
     * per-file xrdc_copy doesn't bounce off the "no recursive web" guard. */
    fo = *o;
    fo.recursive = 0;
    xrdc_status_clear(&st);
    if (xrdc_weburl_parse(src, &u) != 0) {
        fprintf(stderr, "xrdcp: bad web URL %s\n", src);
        return 1;
    }
    if (u.is_s3) {
        return recursive_s3_download(&u, dstdir, &fo, co, retries);
    }
    bearer = (o != NULL && o->bearer != NULL) ? o->bearer : getenv("BEARER_TOKEN");
    if (xrdc_webdav_list(&u, bearer, co ? co->verify_host : 1,
                         co ? co->ca_dir : NULL, &paths, &n, &st) != 0) {
        fprintf(stderr, "xrdcp: list %s: %s\n", src, st.msg);
        return 1;
    }
    snprintf(prefix, sizeof(prefix), "%s", u.path);
    plen = strlen(prefix);
    while (plen > 1 && prefix[plen - 1] == '/') { prefix[--plen] = '\0'; }
    scheme = web_scheme_str(u.proto);
    ensure_web_dst_base(dstdir, &fo, co);   /* web->web: create the dst collection */

    for (i = 0; i < n; i++) {
        const char *path = paths[i];
        const char *rel;
        char        relbuf[XRDC_NAME_MAX];
        char        srcurl[XRDC_PATH_MAX + 320];
        xrdc_status cst;

        if (strncmp(path, prefix, plen) == 0 && (path[plen] == '/' || path[plen] == '\0')) {
            rel = path + plen + (path[plen] == '/' ? 1 : 0);
        } else {
            path_basename(path, relbuf, sizeof(relbuf));   /* fallback: flatten */
            rel = relbuf;
        }
        if (*rel == '\0') {
            continue;
        }
        /* Security: a hostile server must not traverse out of dstdir via the href. */
        if (rel_is_unsafe(rel)) {
            fprintf(stderr, "xrdcp: refusing unsafe path from server: %s\n", path);
            fail++;
            continue;
        }
        if ((size_t) snprintf(srcurl, sizeof(srcurl), "%s://%s:%d%s",
                              scheme, u.host, u.port, path) >= sizeof(srcurl)) {
            fail++;
            continue;
        }
        /* dstdir may be a local dir OR a web collection (recursive web->web). */
        xrdc_status_clear(&cst);
        if (recursive_place(dstdir, rel, srcurl, &fo, co, retries, &cst) == 0) {
            ok++;
            if (o == NULL || !o->silent) {
                fprintf(stderr, "[%zu/%zu] %s -> %s/%s\n", ok + fail, n, srcurl, dstdir, rel);
            }
        } else {
            fail++;
            fprintf(stderr, "xrdcp: %s: %s\n", srcurl, cst.msg);
        }
    }
    xrdc_strv_free(paths, n);
    if (o == NULL || !o->silent) {
        fprintf(stderr, "xrdcp: %zu copied, %zu failed (recursive web)\n", ok, fail);
    }
    return (fail == 0) ? 0 : 1;
}

/* Shared state for one recursive web-upload walk (local tree → web collection).
 * `base` is the dst URL's path with trailing slashes trimmed ("" for the root);
 * the bucket/collection root, into which the source directory's CONTENTS go
 * (symmetric with recursive download). */
typedef struct {
    const xrdc_weburl    *u;        /* dst endpoint (host/port/tls/is_s3) */
    const char           *base;     /* dst path, trailing '/' trimmed */
    const char           *scheme;   /* web_scheme_str(u->proto) */
    const char           *bearer;   /* WebDAV Authorization, NULL ⇒ anon */
    const xrdc_copy_opts *fo;       /* per-file opts (recursive cleared) */
    const xrdc_opts      *co;       /* connection opts (verify/ca_dir) */
    int                   retries;
    size_t                ok;
    size_t                fail;
} web_upload_ctx;

/* Build "<base>/<rel>" (or "/<rel>" when base is the root "") into out.
 * 0 on success, -1 if it would not fit. */
static int
web_join(const char *base, const char *rel, char *out, size_t outsz)
{
    int w = snprintf(out, outsz, "%s/%s", base, rel);
    return (w < 0 || (size_t) w >= outsz) ? -1 : 0;
}

/* Recursively walk a local directory, MKCOL'ing each WebDAV collection (davs/http
 * only — S3 keys are flat) and PUT'ing each regular file. `rel` is the path of the
 * current directory relative to the upload root ("" at the top). Symlinks and
 * special files are skipped (only real dirs + regular files are uploaded). */
static void
web_upload_walk(web_upload_ctx *c, const char *localdir, const char *rel)
{
    DIR           *d = opendir(localdir);
    struct dirent *de;

    if (d == NULL) {
        fprintf(stderr, "xrdcp: cannot open %s: %s\n", localdir, strerror(errno));
        c->fail++;
        return;
    }
    while ((de = readdir(d)) != NULL) {
        char        childlocal[XRDC_PATH_MAX];
        char        childrel[XRDC_PATH_MAX];
        struct stat sb;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
            continue;
        }
        if ((size_t) snprintf(childlocal, sizeof(childlocal), "%s/%s",
                              localdir, de->d_name) >= sizeof(childlocal)
            || (rel[0] == '\0'
                    ? (size_t) snprintf(childrel, sizeof(childrel), "%s", de->d_name)
                    : (size_t) snprintf(childrel, sizeof(childrel), "%s/%s",
                                        rel, de->d_name)) >= sizeof(childrel)) {
            fprintf(stderr, "xrdcp: path too long under %s\n", localdir);
            c->fail++;
            continue;
        }
        if (lstat(childlocal, &sb) != 0) {
            fprintf(stderr, "xrdcp: stat %s: %s\n", childlocal, strerror(errno));
            c->fail++;
            continue;
        }
        if (S_ISDIR(sb.st_mode)) {
            /* Create the remote collection (top-down) before descending so the
             * child PUTs/MKCOLs don't hit 409 Conflict. S3 has no real dirs. */
            if (!c->u->is_s3) {
                char        rpath[XRDC_PATH_MAX * 2];
                xrdc_status mst;
                xrdc_status_clear(&mst);
                if (web_join(c->base, childrel, rpath, sizeof(rpath)) != 0
                    || xrdc_webdav_mkcol(c->u, rpath, c->bearer,
                                         c->co ? c->co->verify_host : 1,
                                         c->co ? c->co->ca_dir : NULL, &mst) != 0) {
                    fprintf(stderr, "xrdcp: mkcol %s: %s\n", childrel, mst.msg);
                    c->fail++;
                    continue;   /* skip this subtree — its files would 409 */
                }
            }
            web_upload_walk(c, childlocal, childrel);
        } else if (S_ISREG(sb.st_mode)) {
            char        rurl[XRDC_PATH_MAX * 2 + 320];
            char        rpath[XRDC_PATH_MAX * 2];
            xrdc_status cst;
            if (web_join(c->base, childrel, rpath, sizeof(rpath)) != 0
                || (size_t) snprintf(rurl, sizeof(rurl), "%s://%s:%d%s",
                                     c->scheme, c->u->host, c->u->port, rpath)
                       >= sizeof(rurl)) {
                fprintf(stderr, "xrdcp: remote path too long for %s\n", childrel);
                c->fail++;
                continue;
            }
            xrdc_status_clear(&cst);
            if (copy_one_with_retry(childlocal, rurl, c->fo, c->co, c->retries,
                                    &cst) == 0) {
                c->ok++;
                if (c->fo == NULL || !c->fo->silent) {
                    fprintf(stderr, "[%zu] %s -> %s\n", c->ok + c->fail,
                            childlocal, rurl);
                }
            } else {
                c->fail++;
                fprintf(stderr, "xrdcp: %s: %s\n", rurl, cst.msg);
            }
        }
        /* else: symlink / fifo / device — skip (not uploaded) */
    }
    closedir(d);
}

/* Recursively upload a local directory's CONTENTS into a web (davs/http/s3)
 * collection: `xrdcp -r ./dir davs://h/coll/` → coll/<files-under-dir>. The wire
 * has no recursive transfer op, so walk locally + MKCOL + per-file PUT. Returns
 * 0 if every file uploaded, 1 otherwise. */
static int
recursive_web_upload(const char *localdir, const char *dst, const xrdc_copy_opts *o,
                     const xrdc_opts *co, int retries)
{
    xrdc_weburl     u;
    xrdc_copy_opts  fo;
    char            base[XRDC_PATH_MAX];
    web_upload_ctx  c;
    size_t          blen;

    if (xrdc_weburl_parse(dst, &u) != 0) {
        fprintf(stderr, "xrdcp: bad web URL %s\n", dst);
        return 1;
    }
    /* Each file is a plain (non-recursive) copy so xrdc_copy's "no recursive web"
     * guard doesn't trip. */
    fo = *o;
    fo.recursive = 0;

    snprintf(base, sizeof(base), "%s", u.path);
    blen = strlen(base);
    while (blen > 0 && base[blen - 1] == '/') { base[--blen] = '\0'; }

    c.u       = &u;
    c.base    = base;
    c.scheme  = web_scheme_str(u.proto);
    c.bearer  = (o != NULL && o->bearer != NULL) ? o->bearer : getenv("BEARER_TOKEN");
    c.fo      = &fo;
    c.co      = co;
    c.retries = retries;
    c.ok      = 0;
    c.fail    = 0;

    /* Ensure the destination collection itself exists (idempotent). Root ("")
     * and S3 buckets need no MKCOL. */
    if (!u.is_s3 && base[0] != '\0') {
        xrdc_status mst;
        xrdc_status_clear(&mst);
        if (xrdc_webdav_mkcol(&u, base, c.bearer, co ? co->verify_host : 1,
                              co ? co->ca_dir : NULL, &mst) != 0) {
            fprintf(stderr, "xrdcp: mkcol %s: %s\n", base, mst.msg);
            /* proceed anyway — PUTs will surface any real problem */
        }
    }

    web_upload_walk(&c, localdir, "");
    if (o == NULL || !o->silent) {
        fprintf(stderr, "xrdcp: %zu copied, %zu failed (recursive web upload)\n",
                c.ok, c.fail);
    }
    return (c.fail == 0) ? 0 : 1;
}

/* Live progress state for a single transfer (label + timing). */
typedef struct {
    const char *label;
    uint64_t    start_ns;
    uint64_t    last_ns;
} xrdcp_prog;

/* xrdc_copy progress callback: a throttled \r-updated stderr bar with rate + ETA. */
static void
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
    int            retries = 0, jobs = 1, sync_mode = 0, force_progress = 0, verify = 0, rc = 0, oom = 0;
    int            auto_refresh = 0;   /* Phase 40 (b): --auto-refresh */

    memset(&opts, 0, sizeof(opts));
    memset(&conn, 0, sizeof(conn));
    conn.verify_host = 1;
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
            else if (strcmp(a, "--retry") == 0 && i + 1 < (size_t) argc) { retries = atoi(argv[++i]); }
            else if ((strcmp(a, "-j") == 0 || strcmp(a, "--jobs") == 0) && i + 1 < (size_t) argc) { jobs = atoi(argv[++i]); }
            else if (strcmp(a, "--sync") == 0) { sync_mode = 1; }
            else if (strcmp(a, "--progress") == 0) { force_progress = 1; }
            else if (strcmp(a, "--verify") == 0) { verify = 1; }
            else if (strcmp(a, "--auto-refresh") == 0) { auto_refresh = 1; }
            else if (strcmp(a, "--oidc-account") == 0 && i + 1 < (size_t) argc) { oidc_account = argv[++i]; }
            else if (strcmp(a, "--pgrw") == 0)  { opts.pgrw = 1; }
            else if (strcmp(a, "--cksum") == 0 && i + 1 < (size_t) argc) { opts.cksum = argv[++i]; }
            else if (strcmp(a, "--compress") == 0 && i + 1 < (size_t) argc) { opts.compress = argv[++i]; }
            else if (strcmp(a, "--zip") == 0)         { opts.zip = 1; }
            else if (strcmp(a, "--zip-append") == 0)  { opts.zip_append = 1; }
            else if ((strcmp(a, "-S") == 0 || strcmp(a, "--streams") == 0) && i + 1 < (size_t) argc) { opts.streams = atoi(argv[++i]); }
            else if (strcmp(a, "--max-stall") == 0 && i + 1 < (size_t) argc) { opts.max_stall_ms = atoi(argv[++i]); }
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

    str_free(pos, npos);
    str_free(srcs, nsrc);
    str_free(exp, nexp);
    return rc;
}
