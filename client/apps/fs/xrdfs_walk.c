/*
 * xrdfs_walk.c - extracted concern
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"


/* Per-entry callback for walk_dir; return nonzero to abort the whole walk. */

/* Recursively walk the remote tree under `path` (depth-first, pre-order), invoking
 * `visit` for every entry. Directories are descended up to XRDFS_MAXDEPTH. 0 / -1. */
int
walk_dir(brix_conn *c, const char *path, int depth, xrdfs_visit visit, void *u,
         brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, i;

    if (brix_dirlist(c, path, 1 /*want_stat*/, &ents, &n, st) != 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        char full[XRDC_PATH_MAX];
        if (is_dot(ents[i].name) || join_path(path, ents[i].name, full, sizeof(full)) != 0) {
            continue;
        }
        if (visit(full, &ents[i], depth, u) != 0) {
            free(ents);
            return 1;
        }
        if (ents[i].have_stat && (ents[i].st.flags & kXR_isDir)
            && depth + 1 < XRDFS_MAXDEPTH) {
            int rc = walk_dir(c, full, depth + 1, visit, u, st);
            if (rc != 0) {
                free(ents);
                return rc;
            }
        }
    }
    free(ents);
    return 0;
}


/* chmod -R */

/* walk_dir visitor: chmod each entry, counting (and reporting) per-entry failures
 * without aborting the walk. */
int
chmod_visit(const char *full, const brix_dirent *e, int depth, void *u)
{
    chmod_walk *w = (chmod_walk *) u;
    brix_status st;
    (void) e; (void) depth;
    brix_status_clear(&st);
    if (brix_chmod(w->c, full, w->mode, &st) != 0) {
        fprintf(stderr, "xrdfs: chmod %s: %s\n", full, st.msg);
        w->failures++;
    }
    return 0;   /* keep walking */
}


/* Recursively chmod every entry under `path` (the top path is chmod'd by the caller).
 * *failures accumulates per-entry errors; returns 0 / -1 (walk-level error, st set). */
int
chmod_recursive(brix_conn *c, const char *path, int mode, int *failures,
                brix_status *st)
{
    chmod_walk w;
    int        rc;
    w.c = c; w.mode = mode; w.failures = 0;
    rc = walk_dir(c, path, 0, chmod_visit, &w, st);
    *failures = w.failures;
    return (rc < 0) ? -1 : 0;
}


/* du */

/* WHAT: print one du result in human-readable or JSON format.
 * WHY:  deduplicates the output logic shared by the multi-path and
 *       default-path branches of do_du.
 * HOW:  JSON emits a single-line object WITHOUT a trailing newline; the caller
 *       (do_du) owns array framing and item separators so the combined output
 *       is always a top-level JSON array (single path → array of 1).  Human
 *       mode delegates to fmt_size and includes its own newline. */
static void
du_print(const char *path, const du_acc *a, int human, int json)
{
    if (json) {
        fputc('{', stdout);
        brix_json_kv_str(stdout, "path",  path,                 1);
        brix_json_kv_ll(stdout,  "bytes", (long long) a->bytes, 1);
        brix_json_kv_ll(stdout,  "files", (long long) a->files, 1);
        brix_json_kv_ll(stdout,  "dirs",  (long long) a->dirs,  0);
        fputc('}', stdout);   /* caller handles array separators + trailing newline */
    } else {
        char sz[32];
        fmt_size(a->bytes, sz, sizeof(sz), human);
        printf("%-10s %s  (%ld files, %ld dirs)\n", sz, path, a->files, a->dirs);
    }
}


int
du_visit(const char *full, const brix_dirent *e, int depth, void *u)
{
    du_acc *a = (du_acc *) u;
    (void) full;
    (void) depth;
    if (e->have_stat && (e->st.flags & kXR_isDir)) {
        a->dirs++;
    } else if (e->have_stat) {
        a->bytes += e->st.size;
        a->files++;
    }
    return 0;
}


/* WHAT: scan do_du's argv for the -h/--human and -j/--json flags.
 * WHY:  hoisting the option scan out of do_du keeps the command handler under
 *       the complexity cap; the scan is a pure classification with no I/O.
 * HOW:  walks argv from index 1, setting *human / *json on the recognized
 *       long/short spellings; any other token (positional path) is ignored
 *       here and consumed by do_du's own path loop. */
static void
du_parse_flags(int argc, char **argv, int *human, int *json)
{
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--human") == 0)      { *human = 1; }
        else if (strcmp(argv[i], "-j") == 0 || strcmp(argv[i], "--json") == 0) { *json  = 1; }
    }
}


/* WHAT: run du over one already-built path — walk, accumulate, print.
 * WHY:  do_du's positional-arg loop and its default-"." fallback share
 *       identical walk + error-report + JSON-separator + print logic; hoisting
 *       it removes the duplication and keeps do_du below the complexity cap.
 * HOW:  walk_dir accumulates into a fresh du_acc. On a walk-level error it
 *       reports to stderr and returns the nonzero shell code WITHOUT printing
 *       an item (the caller decides whether to continue or abort). On success
 *       it emits the JSON item separator when this is not the first item
 *       (*jfirst == 0), prints the object/line via du_print, clears *jfirst,
 *       and returns 0. *jfirst is only touched in JSON mode. */
static int
du_one_path(brix_conn *c, const char *path, int human, int json, int *jfirst)
{
    brix_status st;
    du_acc      a = { 0, 0, 0 };

    brix_status_clear(&st);
    if (walk_dir(c, path, 0, du_visit, &a, &st) != 0) {
        fprintf(stderr, "xrdfs: du %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    if (json && !*jfirst) { fputs(",\n", stdout); }
    du_print(path, &a, human, json);
    if (json) { *jfirst = 0; }
    return 0;
}


/* WHAT: du [-h] [-j] <path>... — recursive total size + file/dir counts.
 * WHY:  -j enables JSON output for scripting; -h humanizes byte counts.
 *       JSON output is always a top-level array so parsers can handle both
 *       single-path (array of 1) and multi-path invocations uniformly.
 * HOW:  flags are scanned first; if json, print "[" before any items.
 *       Each positional arg drives a du_one_path pass; du_print emits the
 *       object body (no trailing newline in JSON mode); do_du emits the
 *       comma-newline separator between items and the closing "]\n" at the
 *       end. A walk error on a positional path records the shell code (last
 *       error wins) and continues; a walk error on the default "." path
 *       closes the array and returns immediately, matching the original. */
int
do_du(brix_conn *c, const char *cwd, int argc, char **argv)
{
    int human = 0, json = 0, i, rc = 0, any = 0;
    int jfirst = 1;   /* tracks first JSON item for array framing */

    du_parse_flags(argc, argv, &human, &json);
    if (json) { fputs("[\n", stdout); }
    for (i = 1; i < argc; i++) {
        char path[XRDC_PATH_MAX];
        int  r;
        if (argv[i][0] == '-') { continue; }
        any = 1;
        build_path(cwd, argv[i], path, sizeof(path));
        r = du_one_path(c, path, human, json, &jfirst);
        if (r != 0) { rc = r; }
    }
    if (!any) {
        char path[XRDC_PATH_MAX];
        int  r;
        build_path(cwd, ".", path, sizeof(path));
        r = du_one_path(c, path, human, json, &jfirst);
        if (r != 0) {
            if (json) { fputs("\n]\n", stdout); }
            return r;
        }
    }
    if (json) { fputs("\n]\n", stdout); }
    return rc;
}


/* find */

int
find_visit(const char *full, const brix_dirent *e, int depth, void *u)
{
    const find_pred *p = (const find_pred *) u;
    int  is_dir = e->have_stat && (e->st.flags & kXR_isDir);
    (void) depth;

    if (p->type == 1 && is_dir) { return 0; }
    if (p->type == 2 && !is_dir) { return 0; }
    if (p->name_glob != NULL && fnmatch(p->name_glob, e->name, 0) != 0) { return 0; }
    if (p->size_sign != 0 && e->have_stat) {
        if (p->size_sign < 0 && !(e->st.size < p->size_val)) { return 0; }
        if (p->size_sign > 0 && !(e->st.size > p->size_val)) { return 0; }
    }
    printf("%s\n", full);
    return 0;
}


/* WHAT: parse a find -size argument (+N / -N / N) into sign + magnitude.
 * WHY:  isolating the sign/offset arithmetic keeps find_parse_args below the
 *       complexity cap; the +/- handling is otherwise a dense knot of nested
 *       ternaries.
 * HOW:  size_sign is +1 for "+N" (strictly greater), -1 for "-N" (strictly
 *       less), and +1 for a bare "N" (matching the original default). The
 *       magnitude is the decimal value after any leading sign character. */
static void
find_parse_size(const char *s, find_pred *p)
{
    p->size_sign = (s[0] == '+') ? 1 : (s[0] == '-') ? -1 : 1;
    p->size_val  = (int64_t) strtoll((s[0] == '+' || s[0] == '-') ? s + 1 : s,
                                     NULL, 10);
}


/* WHAT: parse find's argv into a find_pred and a starting path token.
 * WHY:  hoisting the option scan out of do_find keeps the command handler
 *       under the complexity cap; the scan is pure classification, no I/O.
 * HOW:  recognizes -name GLOB, -type f|d, and -size +N|-N (each requiring a
 *       following argument, consumed via ++i); -type maps 'd'->2, 'f'->1,
 *       anything else ->0; the first non-flag token becomes *start (a later
 *       positional overrides an earlier one, as in the original). */
static void
find_parse_args(int argc, char **argv, find_pred *p, const char **start)
{
    int i;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-name") == 0 && i + 1 < argc) {
            p->name_glob = argv[++i];
        } else if (strcmp(argv[i], "-type") == 0 && i + 1 < argc) {
            const char *t = argv[++i];
            p->type = (t[0] == 'd') ? 2 : (t[0] == 'f') ? 1 : 0;
        } else if (strcmp(argv[i], "-size") == 0 && i + 1 < argc) {
            find_parse_size(argv[++i], p);
        } else if (argv[i][0] != '-') {
            *start = argv[i];
        }
    }
}


/* find <path> [-name GLOB] [-type f|d] [-size +N|-N] — recursive predicate search. */
int
do_find(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    find_pred   p = { NULL, 0, 0, 0 };
    const char *start = ".";

    find_parse_args(argc, argv, &p, &start);
    build_path(cwd, start, path, sizeof(path));
    brix_status_clear(&st);
    if (walk_dir(c, path, 0, find_visit, &p, &st) != 0) {
        fprintf(stderr, "xrdfs: find %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    return 0;
}


/* tree */

/* WHAT: select, in directory order, the dirlist entries tree will render.
 * WHY:  separating the filter pass keeps tree_recurse under the complexity
 *       cap and isolates the dot / dirs-only skip rules from the render loop.
 * HOW:  writes the indices of kept entries into keep[] (which the caller sizes
 *       to n) in the original listing order, skipping "." / ".." and — when
 *       o->dirs_only is set — every non-directory. Returns the number of
 *       indices written. Pure: touches only keep[] and its return value. */
static int
tree_collect(const brix_dirent *ents, size_t n, const tree_opts *o, int *keep)
{
    size_t i;
    int    nk = 0;

    for (i = 0; i < n; i++) {
        int is_dir = ents[i].have_stat && (ents[i].st.flags & kXR_isDir);
        if (is_dot(ents[i].name)) { continue; }
        if (o->dirs_only && !is_dir) { continue; }
        keep[nk++] = (int) i;
    }
    return nk;
}


/* WHAT: print one tree entry and, when it is a descendable directory, recurse.
 * WHY:  pulling the render-loop body out of tree_recurse keeps the caller
 *       below the complexity cap while preserving the exact glyphs, counters,
 *       depth limit, and error propagation.
 * HOW:  prints the branch glyph (the corner "\\-- " for the last sibling,
 *       the tee "|-- " otherwise) then the entry name; bumps o->ndirs or
 *       o->nfiles. For a directory whose path joins cleanly and whose child
 *       depth stays under XRDFS_MAXDEPTH, it builds the continuation prefix
 *       (blanks after the last sibling, a pipe otherwise) and recurses.
 *       Returns 0 on success or -1 on a walk-level error with st already set
 *       by the recursive call. */
static int
tree_emit(brix_conn *c, const char *path, const char *prefix,
          brix_dirent *e, int last, int depth, tree_opts *o, brix_status *st)
{
    int  is_dir = e->have_stat && (e->st.flags & kXR_isDir);
    char full[XRDC_PATH_MAX];
    char child_prefix[512];

    printf("%s%s%s\n", prefix, last ? "\\-- " : "|-- ", e->name);
    if (is_dir) { o->ndirs++; } else { o->nfiles++; }
    if (is_dir && join_path(path, e->name, full, sizeof(full)) == 0
        && depth + 1 < XRDFS_MAXDEPTH) {
        snprintf(child_prefix, sizeof(child_prefix), "%s%s",
                 prefix, last ? "    " : "|   ");
        if (tree_recurse(c, full, child_prefix, depth + 1, o, st) != 0) {
            return -1;
        }
    }
    return 0;
}


int
tree_recurse(brix_conn *c, const char *path, const char *prefix, int depth,
             tree_opts *o, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0;
    int         *keep, nk, j;

    if (o->maxdepth >= 0 && depth > o->maxdepth) { return 0; }
    if (brix_dirlist(c, path, 1, &ents, &n, st) != 0) { return -1; }

    keep = (int *) malloc((n ? n : 1) * sizeof(int));
    if (keep == NULL) {
        free(ents);
        brix_status_set(st, XRDC_EPROTO, 0, "tree: out of memory");
        return -1;
    }
    nk = tree_collect(ents, n, o, keep);
    for (j = 0; j < nk; j++) {
        if (tree_emit(c, path, prefix, &ents[keep[j]], j == nk - 1,
                      depth, o, st) != 0) {
            free(keep);
            free(ents);
            return -1;
        }
    }
    free(keep);
    free(ents);
    return 0;
}


/* tree [-d] [-L N] [path] — visual directory tree. */
int
do_tree(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    tree_opts   o = { 0, 0, -1, 0 };
    const char *start = ".";
    int         i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dirs-only") == 0) {
            o.dirs_only = 1;
        } else if ((strcmp(argv[i], "-L") == 0 || strcmp(argv[i], "--depth") == 0)
                   && i + 1 < argc) {
            o.maxdepth = atoi(argv[++i]);
        } else if (argv[i][0] != '-') { start = argv[i]; }
    }
    build_path(cwd, start, path, sizeof(path));
    printf("%s\n", path);
    brix_status_clear(&st);
    if (tree_recurse(c, path, "", 0, &o, &st) != 0) {
        fprintf(stderr, "xrdfs: tree %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    printf("\n%ld directories, %ld files\n", o.ndirs, o.nfiles);
    return 0;
}


/* dispatch table                                                      */




const xrdfs_cmd *
find_command(const char *name)
{
    for (const xrdfs_cmd *cmd = COMMANDS; cmd->name != NULL; cmd++) {
        if (strcmp(cmd->name, name) == 0) {
            return cmd;
        }
    }
    return NULL;
}
