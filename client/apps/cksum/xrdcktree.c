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

/* ---- xrdcksum tree (local walk) ---- */

/* tree_ctx — shared state threaded through the recursive local walk. */
typedef struct {
    FILE            *out;          /* output stream (stdout or -o file) */
    const char      *algo_name;    /* e.g. "adler32" */
    brix_cksum_algo  algo;         /* enum */
    int             *errors;       /* pointer to per-run error counter */
} tree_ctx;

/* walk_local_tree — recursive POSIX opendir/readdir walk.
 *
 * WHAT: Visit every regular file under `lpath`, computing its checksum and
 *       emitting "<hex>  <rel>\n" to ctx->out.
 * WHY:  Mirrors copy_tree_upload discipline: lstat (not stat), skip symlinks,
 *       skip dot-entries, overflow-check every path join before use.
 * HOW:  opendir → readdir loop → lstat → classify → recurse or checksum.
 *       Returns 0 to continue, -1 on an unrecoverable structural error (path
 *       overflow or opendir failure on the root). Per-file errors are counted
 *       and continue. */
static int
walk_local_tree(const char *lpath, const char *rel, tree_ctx *ctx)
{
    DIR           *d;
    struct dirent *de;

    d = opendir(lpath);
    if (d == NULL) {
        fprintf(stderr, "xrdcksum tree: opendir %s: %s\n",
                lpath, strerror(errno));
        (*ctx->errors)++;
        /* Root opendir failure is fatal to the subtree but callers continue. */
        return -1;
    }
    while ((de = readdir(d)) != NULL) {
        char        relc[XRDC_PATH_MAX];
        char        lc[XRDC_PATH_MAX];
        struct stat sb;

        /* Skip "." and ".." */
        if (de->d_name[0] == '.'
            && (de->d_name[1] == '\0'
                || (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
            continue;
        }
        if (path_join(lpath, de->d_name, lc, sizeof(lc)) != 0
            || rel_join(rel, de->d_name, relc, sizeof(relc)) != 0) {
            fprintf(stderr,
                    "xrdcksum tree: path too long under %s\n", lpath);
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
            if (walk_local_tree(lc, relc, ctx) != 0) {
                closedir(d);
                return -1;
            }
        } else if (S_ISREG(sb.st_mode)) {
            char       hex[TREE_HEX_MAX];
            brix_status st;
            int        fd;

            brix_status_clear(&st);
            fd = open(lc, O_RDONLY);
            if (fd < 0) {
                fprintf(stderr, "xrdcksum tree: open %s: %s\n",
                        lc, strerror(errno));
                (*ctx->errors)++;
                continue;
            }
            if (brix_cksum_fd(fd, ctx->algo, hex, sizeof(hex), &st) != 0) {
                fprintf(stderr, "xrdcksum tree: %s: %s\n", lc,
                        st.msg[0] ? st.msg : "checksum error");
                close(fd);
                (*ctx->errors)++;
                continue;
            }
            close(fd);
            fprintf(ctx->out, "%s  %s\n", hex, relc);
        }
        /* other file types (block/char/fifo/socket) are silently skipped */
    }
    closedir(d);
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

/*
 * brix_xrdcktree_main — xrdcksum tree: recursive checksum manifest generator.
 *
 * WHAT: Walk a local directory tree or a root:// tree, compute each regular
 *       file's checksum, and emit one "<hex>  <rel>\n" line per file.
 * WHY:  Produces audit manifests compatible with sha256sum -c for ingestion
 *       verification and at-rest integrity checks.
 * HOW:  Parse args; detect local vs remote by "://"; local → walk_local_tree;
 *       remote → brix_tree_walk with remote_tree_visitor.  -o opens the output
 *       file; stdout is the default.  Exit 0 clean, 2 if any errors occurred.
 */
int
brix_xrdcktree_main(int argc, char **argv)
{
    const char      *root     = NULL;
    const char      *algo_str = "adler32";
    const char      *outpath  = NULL;
    brix_cksum_algo  algo;
    brix_status      st;
    FILE            *out      = stdout;
    int              errors   = 0;
    int              i;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "--algo") == 0) {
            if (++i >= argc) {
                return usage_tree(argv[0], XRDC_EXIT_USAGE);
            }
            algo_str = argv[i];
        } else if (strcmp(a, "-o") == 0) {
            if (++i >= argc) {
                return usage_tree(argv[0], XRDC_EXIT_USAGE);
            }
            outpath = argv[i];
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            return usage_tree(argv[0], 0);
        } else if (a[0] == '-') {
            fprintf(stderr, "%s: unknown option '%s'\n", argv[0], a);
            return usage_tree(argv[0], XRDC_EXIT_USAGE);
        } else if (root == NULL) {
            root = a;
        } else {
            fprintf(stderr, "%s: unexpected argument '%s'\n", argv[0], a);
            return usage_tree(argv[0], XRDC_EXIT_USAGE);
        }
    }
    if (root == NULL) {
        return usage_tree(argv[0], XRDC_EXIT_USAGE);
    }
    brix_status_clear(&st);
    if (brix_cksum_algo_parse(algo_str, &algo) != 0) {
        fprintf(stderr, "%s: unknown algorithm '%s'\n", argv[0], algo_str);
        return XRDC_EXIT_USAGE;
    }
    if (outpath != NULL) {
        out = fopen(outpath, "w");
        if (out == NULL) {
            fprintf(stderr, "%s: cannot open '%s': %s\n",
                    argv[0], outpath, strerror(errno));
            return XRDC_EXIT_USAGE;
        }
    }

    if (!is_root_url(root)) {
        /* Local directory walk. */
        tree_ctx ctx;
        ctx.out       = out;
        ctx.algo_name = algo_str;
        ctx.algo      = algo;
        ctx.errors    = &errors;
        (void) walk_local_tree(root, "", &ctx);
    } else {
        /* Remote root:// tree walk. */
        brix_url  u;
        brix_conn c;
        remote_tree_ctx ctx;
        int             wrc;

        if (brix_url_parse(root, &u, &st) != 0
            || (u.scheme != XRDC_SCHEME_ROOT
                && u.scheme != XRDC_SCHEME_ROOTS)) {
            fprintf(stderr, "%s: %s\n", argv[0],
                    st.msg[0] ? st.msg : "bad URL");
            if (out != stdout) {
                fclose(out);
            }
            return XRDC_EXIT_USAGE;
        }
        if (brix_connect(&c, &u, NULL, &st) != 0) {
            fprintf(stderr, "%s: connect: %s\n", argv[0], st.msg);
            if (out != stdout) {
                fclose(out);
            }
            return XRDC_EXIT_USAGE;
        }
        ctx.c            = &c;
        ctx.out          = out;
        ctx.algo_name    = algo_str;
        ctx.root_path    = u.path;
        ctx.root_path_len = strlen(u.path);
        ctx.errors       = &errors;

        wrc = brix_tree_walk(&c, u.path, remote_tree_visitor, &ctx, &st);
        if (wrc < 0) {
            fprintf(stderr, "%s: walk error: %s\n", argv[0],
                    st.msg[0] ? st.msg : "tree walk failed");
            errors++;
        }
        brix_close(&c);
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
        "  exit: 0 all OK, 1 any mismatch, 2 errors (parse/I/O)\n",
        prog);
    return rc;
}

/* strcasecmp_hex — case-insensitive comparison of two NUL-terminated hex
 * strings; returns 0 when equal, nonzero otherwise. */
static int
strcasecmp_hex(const char *a, const char *b)
{
    while (*a && *b) {
        if (tolower((unsigned char) *a) != tolower((unsigned char) *b)) {
            return 1;
        }
        a++;
        b++;
    }
    return (*a != '\0' || *b != '\0') ? 1 : 0;
}

/*
 * brix_xrdckcheck_main — xrdcksum check: manifest verification.
 *
 * WHAT: Parse a manifest produced by `xrdcksum tree` and verify each recorded
 *       digest against the actual file content, local or remote.
 * WHY:  Periodic at-rest integrity checks without regenerating the full manifest;
 *       a single run covers the whole tree with one output line per file.
 * HOW:  Parse args; for each manifest line call brix_ckmf_parse_line (malformed →
 *       stderr + errors++). With --algo NAME, use it for both compute and query;
 *       without --algo, infer the algorithm from the hex length (adler32=8,
 *       crc32c=8, zcrc32=8, crc64=16, md5=32). For local root: open each rel
 *       path under root, call brix_cksum_fd.  For remote root: open one connection,
 *       reuse it across all files, call brix_query_cksum.  Compare case-insensitively;
 *       print OK/FAILED.  Exit 0 all-OK, 1 any mismatch, 2 on any parse/I/O error.
 */
int
brix_xrdckcheck_main(int argc, char **argv)
{
    const char      *manifest_path;
    const char      *root;
    const char      *algo_str = NULL;
    brix_cksum_algo  algo;
    FILE            *mf;
    char             line[XRDC_PATH_MAX + TREE_HEX_MAX + 8];
    char             hex[TREE_HEX_MAX];
    char             rel[XRDC_PATH_MAX];
    char             got[TREE_HEX_MAX];
    int              mismatches = 0;
    int              errors     = 0;
    int              is_remote  = 0;
    brix_url         u;
    brix_conn        c;
    brix_status      st;
    int              conn_open  = 0;
    int              i;

    if (argc < 3) {
        return usage_check(argv[0], XRDC_EXIT_USAGE);
    }
    manifest_path = argv[1];
    root          = argv[2];

    /* Parse optional --algo flag. */
    for (i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--algo") == 0) {
            if (++i >= argc) {
                return usage_check(argv[0], XRDC_EXIT_USAGE);
            }
            algo_str = argv[i];
            brix_status_clear(&st);
            if (brix_cksum_algo_parse(algo_str, &algo) != 0) {
                fprintf(stderr, "%s: unknown algorithm '%s'\n",
                        argv[0], algo_str);
                return XRDC_EXIT_USAGE;
            }
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            return usage_check(argv[0], 0);
        } else {
            fprintf(stderr, "%s: unexpected argument '%s'\n", argv[0], argv[i]);
            return usage_check(argv[0], XRDC_EXIT_USAGE);
        }
    }

    mf = fopen(manifest_path, "r");
    if (mf == NULL) {
        fprintf(stderr, "%s: cannot open manifest '%s': %s\n",
                argv[0], manifest_path, strerror(errno));
        return 2;
    }

    is_remote = is_root_url(root);
    brix_status_clear(&st);

    if (is_remote) {
        if (brix_url_parse(root, &u, &st) != 0
            || (u.scheme != XRDC_SCHEME_ROOT
                && u.scheme != XRDC_SCHEME_ROOTS)) {
            fprintf(stderr, "%s: bad root URL: %s\n",
                    argv[0], st.msg[0] ? st.msg : "parse error");
            fclose(mf);
            return XRDC_EXIT_USAGE;
        }
        if (brix_connect(&c, &u, NULL, &st) != 0) {
            fprintf(stderr, "%s: connect: %s\n", argv[0], st.msg);
            fclose(mf);
            return XRDC_EXIT_USAGE;
        }
        conn_open = 1;
    }

    while (fgets(line, sizeof(line), mf) != NULL) {
        brix_cksum_algo  line_algo;
        const char      *line_algo_name;
        size_t           hexlen;

        if (brix_ckmf_parse_line(line, hex, sizeof(hex),
                                 rel, sizeof(rel)) != 0) {
            /* Strip trailing newline for a clean error message. */
            size_t ll = strlen(line);
            while (ll > 0 && (line[ll - 1] == '\n' || line[ll - 1] == '\r')) {
                line[--ll] = '\0';
            }
            fprintf(stderr, "%s: malformed manifest line: %s\n",
                    argv[0], line);
            errors++;
            continue;
        }

        /* Determine the algorithm: use --algo if given, else infer from hex length.
         * Without --algo: adler32=8, crc64=16, md5=32.
         * For 8-char digests we default to adler32 (the tree default). */
        if (algo_str != NULL) {
            line_algo = algo;
            line_algo_name = algo_str;
        } else {
            hexlen = strlen(hex);
            switch (hexlen) {
            case  8: line_algo = XRDC_CK_ADLER32; line_algo_name = "adler32"; break;
            case 16: line_algo = XRDC_CK_CRC64;   line_algo_name = "crc64";   break;
            case 32: line_algo = XRDC_CK_MD5;     line_algo_name = "md5";     break;
            default:
                fprintf(stderr, "%s: unrecognised hex length %zu for '%s'\n",
                        argv[0], hexlen, rel);
                errors++;
                continue;
            }
        }

        brix_status_clear(&st);
        got[0] = '\0';

        if (!is_remote) {
            /* Local: open root/rel and compute. */
            char lpath[XRDC_PATH_MAX];
            int  fd;

            if (path_join(root, rel, lpath, sizeof(lpath)) != 0) {
                fprintf(stderr, "%s: path too long: %s/%s\n",
                        argv[0], root, rel);
                errors++;
                continue;
            }
            fd = open(lpath, O_RDONLY);
            if (fd < 0) {
                fprintf(stderr, "%s: open %s: %s\n",
                        argv[0], lpath, strerror(errno));
                errors++;
                continue;
            }
            if (brix_cksum_fd(fd, line_algo, got, sizeof(got), &st) != 0) {
                fprintf(stderr, "%s: %s: %s\n", argv[0], lpath,
                        st.msg[0] ? st.msg : "checksum error");
                close(fd);
                errors++;
                continue;
            }
            close(fd);
        } else {
            /* Remote: build full path = root_path + "/" + rel */
            char rpath[XRDC_PATH_MAX];
            int  n;

            n = snprintf(rpath, sizeof(rpath), "%s/%s", u.path, rel);
            if (n <= 0 || (size_t) n >= sizeof(rpath)) {
                fprintf(stderr, "%s: path too long: %s/%s\n",
                        argv[0], u.path, rel);
                errors++;
                continue;
            }
            if (brix_query_cksum(&c, rpath, line_algo_name,
                                 got, sizeof(got), &st) != 0) {
                fprintf(stderr, "%s: query_cksum %s: %s\n", argv[0], rpath,
                        st.msg[0] ? st.msg : "query error");
                errors++;
                continue;
            }
        }

        if (strcasecmp_hex(hex, got) == 0) {
            printf("OK %s\n", rel);
        } else {
            printf("FAILED %s\n", rel);
            mismatches++;
        }
    }

    fclose(mf);
    if (conn_open) {
        brix_close(&c);
    }

    if (errors > 0) {
        return 2;
    }
    return mismatches > 0 ? 1 : 0;
}
