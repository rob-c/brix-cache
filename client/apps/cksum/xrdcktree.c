/* xrdcktree.c — recursive checksum manifests and manifest verification.
 *
 * WHAT: `xrdcksum tree <root> [--algo NAME] [-o FILE]` produces a sha256sum-style
 *       manifest of all regular files under a local directory or a root:// tree.
 *       `xrdcksum check <manifest> <root>` verifies every recorded digest against
 *       the same-side data — local files with brix_cksum_fd, remote files with one
 *       reused connection and brix_query_cksum.
 * WHY:  End-to-end audit: a site can generate a manifest during ingest and replay
 *       check periodically to catch at-rest corruption or unauthorised modification,
 *       both locally and over root://.
 * HOW:  Local tree: POSIX opendir/readdir recursion (lstat; skip symlinks + dots;
 *       overflow-checked path joins; mirrors copy_tree_upload discipline).  Remote
 *       tree: brix_tree_walk visitor (dirs skipped; path stripped to rel by removing
 *       the root's path prefix + one slash).  Manifest format "<hex>  <rel>\n"
 *       (two spaces) is sha256sum -c compatible; brix_ckmf_parse_line is the sole
 *       gate on the check path so hostile manifests cannot escape the root. */
#include "brix.h"
#include "brix_ops.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   /* strcasecmp */
#include <sys/stat.h>
#include <unistd.h>

/* Maximum hex digest length: 128 chars + NUL (SHA-512 would be 128; adler32=8). */
#define TREE_HEX_MAX  129
/* Manifest output buffer: two-space separator + NUL. */
#define TREE_LINE_MAX (TREE_HEX_MAX + 2 + XRDC_PATH_MAX)

/* ---- shared helpers ---- */

/* is_root_url — detect XRootD URLs.
 *
 * WHAT: Return 1 if `s` looks like a root:// or roots:// URL, 0 otherwise.
 * WHY:  Tree and check distinguish local paths from remote URLs; this simple
 *       heuristic (presence of "://") works for all XRootD URLs and avoids
 *       parsing overhead in the common local-path case.
 * HOW:  Check for "://" substring; any URL scheme (root://, roots://, etc.)
 *       will match. */
static int
is_root_url(const char *s)
{
    return strstr(s, "://") != NULL;
}

/* path_join — safely concatenate a directory and filename.
 *
 * WHAT: Join dir + "/" + name into out[outsz]; return -1 on overflow, 0 on
 *       success. Avoids double-slash if dir already ends with /.
 * WHY:  Walking trees requires joining paths safely without stack overflow;
 *       mirrors copy_tree_upload discipline to stay overflow-consistent.
 * HOW:  Check dir's trailing slash; call snprintf with the appropriate format;
 *       validate output against outsz. */
static int
path_join(const char *dir, const char *name, char *out, size_t outsz)
{
    size_t dl = strlen(dir);
    int    n;

    if (dl > 0 && dir[dl - 1] == '/') {
        n = snprintf(out, outsz, "%s%s", dir, name);
    } else {
        n = snprintf(out, outsz, "%s/%s", dir, name);
    }
    return (n > 0 && (size_t) n < outsz) ? 0 : -1;
}

/* rel_join — safely concatenate a relative path prefix and name.
 *
 * WHAT: Join prefix + "/" + name into out[outsz]; prefix may be empty string.
 *       Return -1 on overflow, 0 on success.
 * WHY:  Building relative paths during tree walks (from tree root); handles
 *       the empty-prefix edge case (top-level files have rel="filename").
 * HOW:  Omit "/" separator when prefix is empty; otherwise snprintf with both;
 *       validate output size. */
static int
rel_join(const char *prefix, const char *name, char *out, size_t outsz)
{
    int n;

    if (prefix[0] == '\0') {
        n = snprintf(out, outsz, "%s", name);
    } else {
        n = snprintf(out, outsz, "%s/%s", prefix, name);
    }
    return (n > 0 && (size_t) n < outsz) ? 0 : -1;
}

/* rel_has_newline — detect a manifest-forgeable name.
 *
 * WHAT: Return 1 if `rel` contains a '\n' or '\r', 0 otherwise.
 * WHY:  The manifest format is one "<hex>  <rel>\n" record per line, parsed
 *       line-by-line on the check side.  A file whose name embeds a newline (or
 *       CR) would forge an extra record — smuggling a second "<hex>  <path>"
 *       into the manifest and corrupting the whole verification.  Such names are
 *       skipped-and-warned (counted as an error) rather than written.
 * HOW:  Linear scan for the two line-terminator bytes. */
static int
rel_has_newline(const char *rel)
{
    return strchr(rel, '\n') != NULL || strchr(rel, '\r') != NULL;
}

/* ---- shared local-tree walk ---- */

/* cktree_file_fn — per-regular-file callback for cktree_walk.
 *
 * WHAT: Invoked for every regular file found during the walk with the full
 *       local path and the root-relative path.
 * WHY:  Separates the traversal mechanics (one shared walker) from what is
 *       done per file; per-file failures are the callback's business (count
 *       and return 0 to keep walking).
 * HOW:  Return 0 to continue the walk; nonzero aborts it structurally. */
typedef int (*cktree_file_fn)(const char *lpath, const char *rel, void *u);

/* entry_is_dot — recognise the "." and ".." directory entries.
 *
 * WHAT: Return 1 if `name` is exactly "." or "..", 0 otherwise.
 * WHY:  Every readdir loop must skip these two to avoid infinite recursion;
 *       naming the test keeps the walker's loop readable.
 * HOW:  Byte comparison without strcmp calls (hot loop). */
static int
entry_is_dot(const char *name)
{
    return name[0] == '.'
           && (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

/* cktree_walk — recursive POSIX opendir/readdir walk with per-file callback.
 *
 * WHAT: Visit every regular file under `lpath`, invoking cb(full, rel, u)
 *       for each one.
 * WHY:  Mirrors copy_tree_upload discipline: lstat (not stat), skip symlinks,
 *       skip dot-entries, overflow-check every path join before use.  Shared
 *       walker so callers only supply per-file behaviour.
 * HOW:  opendir → readdir loop → lstat → classify → recurse or callback.
 *       Returns 0 to continue, -1 on an unrecoverable structural error (path
 *       overflow or opendir failure on the root).  Structural errors are
 *       counted in *errors; per-file errors are the callback's business. */
static int
cktree_walk(const char *lpath, const char *rel,
            cktree_file_fn cb, void *u, int *errors)
{
    DIR           *d;
    struct dirent *de;

    d = opendir(lpath);
    if (d == NULL) {
        fprintf(stderr, "xrdcksum tree: opendir %s: %s\n",
                lpath, strerror(errno));
        (*errors)++;
        /* Root opendir failure is fatal to the subtree but callers continue. */
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        char        relc[XRDC_PATH_MAX];
        char        lc[XRDC_PATH_MAX];
        struct stat sb;

        if (entry_is_dot(de->d_name)) {
            continue;
        }
        if (path_join(lpath, de->d_name, lc, sizeof(lc)) != 0
            || rel_join(rel, de->d_name, relc, sizeof(relc)) != 0) {
            fprintf(stderr,
                    "xrdcksum tree: path too long under %s\n", lpath);
            (*errors)++;   /* a skipped file is an error, not clean output */
            closedir(d);
            return -1;
        }
        /* lstat so a symlink inside the tree is never followed outward. */
        if (lstat(lc, &sb) != 0) {
            continue;   /* vanished between readdir and lstat — skip silently */
        }
        if (S_ISLNK(sb.st_mode)) {
            continue;   /* skip symlinks (loop-safety; mirrors -r copy default) */
        }
        if (S_ISDIR(sb.st_mode)) {
            if (cktree_walk(lc, relc, cb, u, errors) != 0) {
                closedir(d);
                return -1;
            }
        } else if (S_ISREG(sb.st_mode)) {
            if (cb(lc, relc, u) != 0) {
                closedir(d);
                return -1;
            }
        }
        /* other file types (block/char/fifo/socket) are silently skipped */
    }
    closedir(d);
    return 0;
}

/* ---- xrdcksum tree (local walk) ---- */

/* tree_ctx — shared state threaded through the recursive local walk. */
typedef struct {
    FILE            *out;          /* output stream (stdout or -o file) */
    const char      *algo_name;    /* e.g. "adler32" */
    brix_cksum_algo  algo;         /* enum */
    int             *errors;       /* pointer to per-run error counter */
} tree_ctx;

/* tree_emit_file — cktree_walk callback: checksum one file, emit its record.
 *
 * WHAT: Compute the checksum of the regular file at `lpath` and write
 *       "<hex>  <rel>\n" to ctx->out.
 * WHY:  The per-file half of `xrdcksum tree`'s local walk — the walker owns
 *       traversal, this owns digest + manifest emission.
 * HOW:  open O_RDONLY → brix_cksum_fd → refuse newline/CR-bearing names
 *       (manifest-forgery guard) → fprintf.  Per-file errors go to stderr,
 *       bump ctx->errors, and return 0 so the walk continues. */
static int
tree_emit_file(const char *lpath, const char *rel, void *u)
{
    tree_ctx   *ctx = (tree_ctx *) u;
    char        hex[TREE_HEX_MAX];
    brix_status st;
    int         fd;

    brix_status_clear(&st);
    fd = open(lpath, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "xrdcksum tree: open %s: %s\n",
                lpath, strerror(errno));
        (*ctx->errors)++;
        return 0;
    }
    if (brix_cksum_fd(fd, ctx->algo, hex, sizeof(hex), &st) != 0) {
        fprintf(stderr, "xrdcksum tree: %s: %s\n", lpath,
                st.msg[0] ? st.msg : "checksum error");
        close(fd);
        (*ctx->errors)++;
        return 0;
    }
    close(fd);
    /* Refuse to emit a record for a newline/CR-bearing name: it would
     * forge an extra manifest line.  Skip-and-warn (counted). */
    if (rel_has_newline(rel)) {
        fprintf(stderr, "xrdcksum tree: %s: name contains newline/CR, "
                "skipping\n", lpath);
        (*ctx->errors)++;
        return 0;
    }
    fprintf(ctx->out, "%s  %s\n", hex, rel);
    return 0;
}

/* ---- xrdcksum tree (remote walk visitor) ---- */

/* remote_tree_ctx — state for the brix_tree_walk visitor. */
typedef struct {
    brix_conn       *c;
    FILE            *out;
    const char      *algo_name;
    const char      *root_path;    /* the root URL path; rel = path[prefix_len+1..] */
    size_t           root_path_len;
    int             *errors;
} remote_tree_ctx;

/* remote_tree_visitor — brix_walk_fn callback for remote tree walks.
 *
 * WHAT: Called by brix_tree_walk for every entry under the root path.
 * WHY:  Skip directories (no checksum); query the server for each file.
 * HOW:  Strip the root path prefix (+ one slash) from the full path to get rel;
 *       call brix_query_cksum; emit "<hex>  <rel>\n". Per-file errors: stderr,
 *       errors counter, continue (return 0 so the walk proceeds). */
static int
remote_tree_visitor(const char *path, const brix_dirent *e, int depth,
                    void *u)
{
    remote_tree_ctx *ctx = (remote_tree_ctx *) u;
    const char      *rel;
    char             hex[TREE_HEX_MAX];
    brix_status      st;

    (void) depth;

    /* Skip directories — the walker descends automatically. */
    if (e->have_stat && (e->st.flags & kXR_isDir)) {
        return 0;
    }
    /* Derive rel from the full path by stripping the root prefix + one slash.
     * root_path "/foo/bar" → paths are "/foo/bar/sub/f.root" → rel = "sub/f.root".
     * Guard: if the path does not start with root_path, skip (should not happen). */
    if (strncmp(path, ctx->root_path, ctx->root_path_len) != 0
        || path[ctx->root_path_len] != '/') {
        fprintf(stderr,
                "xrdcksum tree: unexpected path %s outside root %s\n",
                path, ctx->root_path);
        (*ctx->errors)++;
        return 0;
    }
    rel = path + ctx->root_path_len + 1;

    /* A newline/CR in the derived rel would forge an extra manifest line — skip
     * it and count the error rather than corrupt the manifest. */
    if (rel_has_newline(rel)) {
        fprintf(stderr, "xrdcksum tree: %s: name contains newline/CR, skipping\n",
                path);
        (*ctx->errors)++;
        return 0;
    }

    brix_status_clear(&st);
    if (brix_query_cksum(ctx->c, path, ctx->algo_name,
                         hex, sizeof(hex), &st) != 0) {
        fprintf(stderr, "xrdcksum tree: %s: %s\n", path,
                st.msg[0] ? st.msg : "query_cksum error");
        (*ctx->errors)++;
        return 0;
    }
    fprintf(ctx->out, "%s  %s\n", hex, rel);
    return 0;
}

/* ---- brix_xrdcktree_main ---- */

/* usage_tree — print usage and return rc. */
static int
usage_tree(const char *prog, int rc)
{
    fprintf(stderr,
        "usage: %s <root> [--algo NAME] [-o FILE]\n"
        "  Produce a sha256sum-style checksum manifest for all regular files\n"
        "  under a local directory or a root:// tree.\n"
        "    --algo N   digest algorithm (default: adler32)\n"
        "    -o FILE    write manifest to FILE (default: stdout)\n"
        "  exit: 0 clean, 2 any per-file errors\n",
        prog);
    return rc;
}

/* cktree_opts — parsed command line for `xrdcksum tree`. */
typedef struct {
    const char *root;       /* positional: local dir or root:// URL */
    const char *algo_str;   /* --algo (default "adler32") */
    const char *outpath;    /* -o FILE, or NULL for stdout */
} cktree_opts;

/* cktree_parse_args — decode the `xrdcksum tree` command line.
 *
 * WHAT: Fill *o from argv; on any usage error (or -h) set *rc to the exit
 *       code and return -1; return 0 to proceed.
 * WHY:  Keeps the option ladder out of the main flow so the main reads as
 *       parse → plan → run → report.
 * HOW:  Linear argv scan; --algo/-o consume the next argument; first
 *       non-option is the root; anything else is a usage error. */
static int
cktree_parse_args(int argc, char **argv, cktree_opts *o, int *rc)
{
    int i;

    o->root     = NULL;
    o->algo_str = "adler32";
    o->outpath  = NULL;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "--algo") == 0) {
            if (++i >= argc) {
                *rc = usage_tree(argv[0], XRDC_EXIT_USAGE);
                return -1;
            }
            o->algo_str = argv[i];
        } else if (strcmp(a, "-o") == 0) {
            if (++i >= argc) {
                *rc = usage_tree(argv[0], XRDC_EXIT_USAGE);
                return -1;
            }
            o->outpath = argv[i];
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            *rc = usage_tree(argv[0], 0);
            return -1;
        } else if (a[0] == '-') {
            fprintf(stderr, "%s: unknown option '%s'\n", argv[0], a);
            *rc = usage_tree(argv[0], XRDC_EXIT_USAGE);
            return -1;
        } else if (o->root == NULL) {
            o->root = a;
        } else {
            fprintf(stderr, "%s: unexpected argument '%s'\n", argv[0], a);
            *rc = usage_tree(argv[0], XRDC_EXIT_USAGE);
            return -1;
        }
    }
    if (o->root == NULL) {
        *rc = usage_tree(argv[0], XRDC_EXIT_USAGE);
        return -1;
    }
    return 0;
}

/* cktree_run_local — generate the manifest for a local directory tree.
 *
 * WHAT: Walk o->root with cktree_walk/tree_emit_file, writing records to out.
 * WHY:  The local half of `xrdcksum tree`, isolated so the main only routes.
 * HOW:  Build the tree_ctx and run the walk; a structural failure (root
 *       opendir / path overflow) must land in the exit code — a partial
 *       manifest is not clean — so ensure at least one counted error. */
static void
cktree_run_local(const cktree_opts *o, brix_cksum_algo algo,
                 FILE *out, int *errors)
{
    tree_ctx ctx;

    ctx.out       = out;
    ctx.algo_name = o->algo_str;
    ctx.algo      = algo;
    ctx.errors    = errors;
    if (cktree_walk(o->root, "", tree_emit_file, &ctx, errors) != 0
        && *errors == 0) {
        (*errors)++;
    }
}

/* cktree_run_remote — generate the manifest for a root:// tree.
 *
 * WHAT: Parse the URL, connect once, and drive brix_tree_walk with
 *       remote_tree_visitor.  Returns 0 when the run completed (per-file and
 *       walk errors are counted in *errors), or a nonzero exit code when the
 *       URL/connect failed before any work started.
 * WHY:  The remote half of `xrdcksum tree`; keeps connection lifecycle and
 *       prefix computation out of the main.
 * HOW:  brix_url_parse + scheme check → brix_connect → strip trailing slashes
 *       from the root path so `tree root://h//dir/` yields the same rel
 *       prefixes as `.../dir` (a bare "/" export root collapses to a
 *       zero-length prefix, keeping that case working) → walk → close. */
static int
cktree_run_remote(const char *prog, const cktree_opts *o,
                  FILE *out, int *errors)
{
    brix_url        u;
    brix_conn       c;
    remote_tree_ctx ctx;
    brix_status     st;
    size_t          rlen;
    int             wrc;

    brix_status_clear(&st);
    if (brix_url_parse(o->root, &u, &st) != 0
        || (u.scheme != XRDC_SCHEME_ROOT
            && u.scheme != XRDC_SCHEME_ROOTS)) {
        fprintf(stderr, "%s: %s\n", prog,
                st.msg[0] ? st.msg : "bad URL");
        return XRDC_EXIT_USAGE;
    }
    if (brix_connect(&c, &u, NULL, &st) != 0) {
        fprintf(stderr, "%s: connect: %s\n", prog, st.msg);
        return XRDC_EXIT_USAGE;
    }
    ctx.c         = &c;
    ctx.out       = out;
    ctx.algo_name = o->algo_str;
    ctx.root_path = u.path;
    rlen = strlen(u.path);
    while (rlen > 0 && u.path[rlen - 1] == '/') {
        rlen--;
    }
    ctx.root_path_len = rlen;
    ctx.errors        = errors;

    wrc = brix_tree_walk(&c, u.path, remote_tree_visitor, &ctx, &st);
    if (wrc < 0) {
        fprintf(stderr, "%s: walk error: %s\n", prog,
                st.msg[0] ? st.msg : "tree walk failed");
        (*errors)++;
    }
    brix_close(&c);
    return 0;
}

/*
 * brix_xrdcktree_main — xrdcksum tree: recursive checksum manifest generator.
 *
 * WHAT: Walk a local directory tree or a root:// tree, compute each regular
 *       file's checksum, and emit one "<hex>  <rel>\n" line per file.
 * WHY:  Produces audit manifests compatible with sha256sum -c for ingestion
 *       verification and at-rest integrity checks.
 * HOW:  Parse args (cktree_parse_args); detect local vs remote by "://";
 *       local → cktree_run_local; remote → cktree_run_remote.  -o opens the
 *       output file; stdout is the default.  Exit 0 clean, 2 if any errors
 *       occurred.
 */
int
brix_xrdcktree_main(int argc, char **argv)
{
    cktree_opts     o;
    brix_cksum_algo algo;
    FILE           *out    = stdout;
    int             errors = 0;
    int             rc     = 0;

    if (cktree_parse_args(argc, argv, &o, &rc) != 0) {
        return rc;
    }
    if (brix_cksum_algo_parse(o.algo_str, &algo) != 0) {
        fprintf(stderr, "%s: unknown algorithm '%s'\n", argv[0], o.algo_str);
        return XRDC_EXIT_USAGE;
    }
    if (o.outpath != NULL) {
        out = fopen(o.outpath, "w");
        if (out == NULL) {
            fprintf(stderr, "%s: cannot open '%s': %s\n",
                    argv[0], o.outpath, strerror(errno));
            return XRDC_EXIT_USAGE;
        }
    }

    if (!is_root_url(o.root)) {
        cktree_run_local(&o, algo, out, &errors);
    } else {
        rc = cktree_run_remote(argv[0], &o, out, &errors);
        if (rc != 0) {
            if (out != stdout) {
                fclose(out);
            }
            return rc;
        }
    }

    if (out != stdout) {
        fclose(out);
    }
    return errors > 0 ? 2 : 0;
}

/* ---- xrdcksum check ---- */

/* usage_check — print usage and return rc. */
static int
usage_check(const char *prog, int rc)
{
    fprintf(stderr,
        "usage: %s <manifest> <root> [--algo NAME]\n"
        "  Verify every file listed in a tree manifest against its stored digest.\n"
        "    manifest   path to manifest file produced by `xrdcksum tree`\n"
        "    root       local directory or root:// URL that was checksummed\n"
        "    --algo N   digest algorithm (default: infer from hex length)\n"
        "  Without --algo, digests are assumed: adler32 (8 hex), crc64 (16 hex),\n"
        "  md5 (32 hex); use --algo for crc32c, zcrc32, crc64nvme manifests.\n"
        "  For each line prints 'OK <rel>' or 'FAILED <rel>'.\n"
        "  exit: 0 all OK, 1 any mismatch, 2 errors (parse/I/O); 2 (errors)\n"
        "        takes precedence over 1 (mismatch) when both occur\n",
        prog);
    return rc;
}

/* ckcheck_ctx — per-run state threaded through manifest verification. */
typedef struct {
    const char      *prog;        /* argv[0] for messages */
    const char      *root;        /* local root dir (is_remote == 0) */
    const char      *root_path;   /* remote URL path (is_remote == 1) */
    brix_conn       *c;           /* open remote connection, or NULL */
    int              is_remote;
    const char      *algo_str;    /* --algo value, or NULL (infer per line) */
    brix_cksum_algo  algo;        /* parsed --algo (valid iff algo_str set) */
    int             *errors;
    int             *mismatches;
} ckcheck_ctx;

/* ckcheck_parse_args — decode the `xrdcksum check` command line.
 *
 * WHAT: Validate argc and parse the optional --algo flag; on any usage error
 *       (or -h) set *rc to the exit code and return -1; return 0 to proceed
 *       (manifest = argv[1], root = argv[2]).
 * WHY:  Keeps the option ladder out of the main flow.
 * HOW:  argv[1]/argv[2] are positional; scan from argv[3]; --algo consumes
 *       and validates the next argument via brix_cksum_algo_parse. */
static int
ckcheck_parse_args(int argc, char **argv, const char **algo_str,
                   brix_cksum_algo *algo, int *rc)
{
    int i;

    *algo_str = NULL;
    if (argc < 3) {
        *rc = usage_check(argv[0], XRDC_EXIT_USAGE);
        return -1;
    }
    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--algo") == 0) {
            if (++i >= argc) {
                *rc = usage_check(argv[0], XRDC_EXIT_USAGE);
                return -1;
            }
            *algo_str = argv[i];
            if (brix_cksum_algo_parse(*algo_str, algo) != 0) {
                fprintf(stderr, "%s: unknown algorithm '%s'\n",
                        argv[0], *algo_str);
                *rc = XRDC_EXIT_USAGE;
                return -1;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            *rc = usage_check(argv[0], 0);
            return -1;
        } else {
            fprintf(stderr, "%s: unexpected argument '%s'\n", argv[0], argv[i]);
            *rc = usage_check(argv[0], XRDC_EXIT_USAGE);
            return -1;
        }
    }
    return 0;
}

/* ckcheck_connect — parse the remote root URL and open the one connection.
 *
 * WHAT: Fill *u from `root`, enforce root/roots scheme, and connect *c.
 *       Return 0 on success, -1 after printing the error.
 * WHY:  One connection is reused across every manifest line; setup failures
 *       must abort the whole run before any line is processed.
 * HOW:  brix_url_parse + scheme check → brix_connect; messages match the
 *       historical output exactly. */
static int
ckcheck_connect(const char *prog, const char *root, brix_url *u, brix_conn *c)
{
    brix_status st;

    brix_status_clear(&st);
    if (brix_url_parse(root, u, &st) != 0
        || (u->scheme != XRDC_SCHEME_ROOT
            && u->scheme != XRDC_SCHEME_ROOTS)) {
        fprintf(stderr, "%s: bad root URL: %s\n",
                prog, st.msg[0] ? st.msg : "parse error");
        return -1;
    }
    if (brix_connect(c, u, NULL, &st) != 0) {
        fprintf(stderr, "%s: connect: %s\n", prog, st.msg);
        return -1;
    }
    return 0;
}

/* ckcheck_report_malformed — warn about a manifest line that failed to parse.
 *
 * WHAT: Strip the trailing newline/CR from `line` (in place) and print the
 *       malformed-line message.
 * WHY:  A clean single-line error message; the caller counts the error.
 * HOW:  Trim terminator bytes from the end, then fprintf. */
static void
ckcheck_report_malformed(const char *prog, char *line)
{
    size_t ll = strlen(line);

    while (ll > 0 && (line[ll - 1] == '\n' || line[ll - 1] == '\r')) {
        line[--ll] = '\0';
    }
    fprintf(stderr, "%s: malformed manifest line: %s\n", prog, line);
}

/* ckcheck_line_algo — resolve the digest algorithm for one manifest line.
 *
 * WHAT: Set *out_algo/*out_name for the line: --algo when given, otherwise
 *       inferred from the hex digest length.  Return 0 on success, -1 after
 *       printing the unrecognised-length error (caller counts it).
 * WHY:  Manifests do not record the algorithm; the historical inference is
 *       part of the CLI contract and must stay EXACT: adler32 = 8 hex chars,
 *       crc64 (CRC-64/XZ) = 16, md5 = 32.  crc32c and zcrc32 also produce
 *       8 hex chars and are indistinguishable by length — they require
 *       --algo.  CRITICAL (INVARIANT 9): crc64 and crc64nvme are DIFFERENT
 *       polynomials; 16 hex maps to crc64 ONLY, and crc64nvme manifests must
 *       use --algo.  Never merge or "normalize" the two.
 * HOW:  --algo short-circuit, else switch on strlen(hex). */
static int
ckcheck_line_algo(const ckcheck_ctx *cx, const char *hex, const char *rel,
                  brix_cksum_algo *out_algo, const char **out_name)
{
    size_t hexlen;

    if (cx->algo_str != NULL) {
        *out_algo = cx->algo;
        *out_name = cx->algo_str;
        return 0;
    }
    hexlen = strlen(hex);
    switch (hexlen) {
    case  8: *out_algo = XRDC_CK_ADLER32; *out_name = "adler32"; return 0;
    case 16: *out_algo = XRDC_CK_CRC64;   *out_name = "crc64";   return 0;
    case 32: *out_algo = XRDC_CK_MD5;     *out_name = "md5";     return 0;
    default:
        fprintf(stderr, "%s: unrecognised hex length %zu for '%s'\n",
                cx->prog, hexlen, rel);
        return -1;
    }
}

/* ckcheck_digest_local — compute the actual digest of a local file.
 *
 * WHAT: Open cx->root/rel and compute its checksum into got (TREE_HEX_MAX
 *       bytes).  Return 0 on success, -1 after printing the error.
 * WHY:  The local half of per-line verification; every failure is one
 *       stderr line and one counted error at the call site.
 * HOW:  Overflow-checked path_join → open O_RDONLY → brix_cksum_fd. */
static int
ckcheck_digest_local(const ckcheck_ctx *cx, const char *rel,
                     brix_cksum_algo algo, char *got)
{
    char        lpath[XRDC_PATH_MAX];
    brix_status st;
    int         fd;

    if (path_join(cx->root, rel, lpath, sizeof(lpath)) != 0) {
        fprintf(stderr, "%s: path too long: %s/%s\n",
                cx->prog, cx->root, rel);
        return -1;
    }
    fd = open(lpath, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: open %s: %s\n",
                cx->prog, lpath, strerror(errno));
        return -1;
    }
    brix_status_clear(&st);
    if (brix_cksum_fd(fd, algo, got, TREE_HEX_MAX, &st) != 0) {
        fprintf(stderr, "%s: %s: %s\n", cx->prog, lpath,
                st.msg[0] ? st.msg : "checksum error");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

/* ckcheck_digest_remote — query the server for a remote file's digest.
 *
 * WHAT: Build root_path + "/" + rel and ask the server (over the reused
 *       connection) for its digest into got (TREE_HEX_MAX bytes).  Return 0
 *       on success, -1 after printing the error.
 * WHY:  The remote half of per-line verification; the server computes, we
 *       compare.
 * HOW:  Overflow-checked snprintf → brix_query_cksum with the per-line
 *       algorithm name. */
static int
ckcheck_digest_remote(const ckcheck_ctx *cx, const char *rel,
                      const char *algo_name, char *got)
{
    char        rpath[XRDC_PATH_MAX];
    brix_status st;
    int         n;

    n = snprintf(rpath, sizeof(rpath), "%s/%s", cx->root_path, rel);
    if (n <= 0 || (size_t) n >= sizeof(rpath)) {
        fprintf(stderr, "%s: path too long: %s/%s\n",
                cx->prog, cx->root_path, rel);
        return -1;
    }
    brix_status_clear(&st);
    if (brix_query_cksum(cx->c, rpath, algo_name,
                         got, TREE_HEX_MAX, &st) != 0) {
        fprintf(stderr, "%s: query_cksum %s: %s\n", cx->prog, rpath,
                st.msg[0] ? st.msg : "query error");
        return -1;
    }
    return 0;
}

/* ckcheck_process_line — verify one manifest line and print its verdict.
 *
 * WHAT: Parse "<hex>  <rel>" via brix_ckmf_parse_line, resolve the line's
 *       algorithm, obtain the actual digest (local compute or remote query),
 *       and print "OK <rel>" or "FAILED <rel>".
 * WHY:  One line = one independent verification; every failure mode counts
 *       an error and moves on so a single bad record never aborts the run.
 * HOW:  brix_ckmf_parse_line is the sole gate on the check path (hostile
 *       manifests cannot escape the root) → ckcheck_line_algo →
 *       ckcheck_digest_local/_remote → case-insensitive compare. */
static void
ckcheck_process_line(const ckcheck_ctx *cx, char *line)
{
    char             hex[TREE_HEX_MAX];
    char             rel[XRDC_PATH_MAX];
    char             got[TREE_HEX_MAX];
    brix_cksum_algo  line_algo;
    const char      *line_algo_name;
    int              drc;

    if (brix_ckmf_parse_line(line, hex, sizeof(hex),
                             rel, sizeof(rel)) != 0) {
        ckcheck_report_malformed(cx->prog, line);
        (*cx->errors)++;
        return;
    }
    if (ckcheck_line_algo(cx, hex, rel, &line_algo, &line_algo_name) != 0) {
        (*cx->errors)++;
        return;
    }

    got[0] = '\0';
    if (!cx->is_remote) {
        drc = ckcheck_digest_local(cx, rel, line_algo, got);
    } else {
        drc = ckcheck_digest_remote(cx, rel, line_algo_name, got);
    }
    if (drc != 0) {
        (*cx->errors)++;
        return;
    }

    if (strcasecmp(hex, got) == 0) {
        printf("OK %s\n", rel);
    } else {
        printf("FAILED %s\n", rel);
        (*cx->mismatches)++;
    }
}

/*
 * brix_xrdckcheck_main — xrdcksum check: manifest verification.
 *
 * WHAT: Parse a manifest produced by `xrdcksum tree` and verify each recorded
 *       digest against the actual file content, local or remote.
 * WHY:  Periodic at-rest integrity checks without regenerating the full manifest;
 *       a single run covers the whole tree with one output line per file.
 * HOW:  Parse args (ckcheck_parse_args); open the manifest; for a remote root
 *       open one connection reused across all files (ckcheck_connect); verify
 *       every line with ckcheck_process_line (which owns algorithm inference —
 *       adler32=8 hex, crc64=16, md5=32 — and the OK/FAILED verdicts).
 *       Exit 0 all-OK, 1 any mismatch, 2 on any parse/I/O error.
 */
int
brix_xrdckcheck_main(int argc, char **argv)
{
    const char      *algo_str   = NULL;
    brix_cksum_algo  algo       = XRDC_CK_ADLER32;  /* valid iff algo_str set */
    FILE            *mf;
    char             line[XRDC_PATH_MAX + TREE_HEX_MAX + 8];
    int              mismatches = 0;
    int              errors     = 0;
    int              rc         = 0;
    brix_url         u;
    brix_conn        c;
    ckcheck_ctx      cx;

    if (ckcheck_parse_args(argc, argv, &algo_str, &algo, &rc) != 0) {
        return rc;
    }

    mf = fopen(argv[1], "r");
    if (mf == NULL) {
        fprintf(stderr, "%s: cannot open manifest '%s': %s\n",
                argv[0], argv[1], strerror(errno));
        return 2;
    }

    cx.prog       = argv[0];
    cx.root       = argv[2];
    cx.root_path  = NULL;
    cx.c          = NULL;
    cx.is_remote  = is_root_url(argv[2]);
    cx.algo_str   = algo_str;
    cx.algo       = algo;
    cx.errors     = &errors;
    cx.mismatches = &mismatches;

    if (cx.is_remote) {
        if (ckcheck_connect(argv[0], argv[2], &u, &c) != 0) {
            fclose(mf);
            return XRDC_EXIT_USAGE;
        }
        cx.root_path = u.path;
        cx.c         = &c;
    }

    while (fgets(line, sizeof(line), mf) != NULL) {
        ckcheck_process_line(&cx, line);
    }

    fclose(mf);
    if (cx.c != NULL) {
        brix_close(&c);
    }

    if (errors > 0) {
        return 2;
    }
    return mismatches > 0 ? 1 : 0;
}
