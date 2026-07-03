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


/* du [-h] <path>... — recursive total size + file/dir counts per argument. */
int
do_du(brix_conn *c, const char *cwd, int argc, char **argv)
{
    int human = 0, i, rc = 0, any = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0) { human = 1; }
    }
    for (i = 1; i < argc; i++) {
        char        path[XRDC_PATH_MAX], sz[32];
        brix_status st;
        du_acc      a = { 0, 0, 0 };
        if (argv[i][0] == '-') { continue; }
        any = 1;
        build_path(cwd, argv[i], path, sizeof(path));
        brix_status_clear(&st);
        if (walk_dir(c, path, 0, du_visit, &a, &st) != 0) {
            fprintf(stderr, "xrdfs: du %s: %s\n", path, st.msg);
            rc = brix_shellcode(&st);
            continue;
        }
        fmt_size(a.bytes, sz, sizeof(sz), human);
        printf("%-10s %s  (%ld files, %ld dirs)\n", sz, path, a.files, a.dirs);
    }
    if (!any) {
        char        path[XRDC_PATH_MAX], sz[32];
        brix_status st;
        du_acc      a = { 0, 0, 0 };
        build_path(cwd, ".", path, sizeof(path));
        brix_status_clear(&st);
        if (walk_dir(c, path, 0, du_visit, &a, &st) != 0) {
            fprintf(stderr, "xrdfs: du %s: %s\n", path, st.msg);
            return brix_shellcode(&st);
        }
        fmt_size(a.bytes, sz, sizeof(sz), human);
        printf("%-10s %s  (%ld files, %ld dirs)\n", sz, path, a.files, a.dirs);
    }
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


/* find <path> [-name GLOB] [-type f|d] [-size +N|-N] — recursive predicate search. */
int
do_find(brix_conn *c, const char *cwd, int argc, char **argv)
{
    brix_status st;
    char        path[XRDC_PATH_MAX];
    find_pred   p = { NULL, 0, 0, 0 };
    const char *start = ".";
    int         i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-name") == 0 && i + 1 < argc) {
            p.name_glob = argv[++i];
        } else if (strcmp(argv[i], "-type") == 0 && i + 1 < argc) {
            const char *t = argv[++i];
            p.type = (t[0] == 'd') ? 2 : (t[0] == 'f') ? 1 : 0;
        } else if (strcmp(argv[i], "-size") == 0 && i + 1 < argc) {
            const char *s = argv[++i];
            p.size_sign = (s[0] == '+') ? 1 : (s[0] == '-') ? -1 : 1;
            p.size_val  = (int64_t) strtoll((s[0] == '+' || s[0] == '-') ? s + 1 : s,
                                            NULL, 10);
        } else if (argv[i][0] != '-') {
            start = argv[i];
        }
    }
    build_path(cwd, start, path, sizeof(path));
    brix_status_clear(&st);
    if (walk_dir(c, path, 0, find_visit, &p, &st) != 0) {
        fprintf(stderr, "xrdfs: find %s: %s\n", path, st.msg);
        return brix_shellcode(&st);
    }
    return 0;
}


/* tree */

int
tree_recurse(brix_conn *c, const char *path, const char *prefix, int depth,
             tree_opts *o, brix_status *st)
{
    brix_dirent *ents = NULL;
    size_t       n = 0, i;
    int         *keep, nk = 0, j;

    if (o->maxdepth >= 0 && depth > o->maxdepth) { return 0; }
    if (brix_dirlist(c, path, 1, &ents, &n, st) != 0) { return -1; }

    keep = (int *) malloc((n ? n : 1) * sizeof(int));
    if (keep == NULL) {
        free(ents);
        brix_status_set(st, XRDC_EPROTO, 0, "tree: out of memory");
        return -1;
    }
    for (i = 0; i < n; i++) {
        int is_dir = ents[i].have_stat && (ents[i].st.flags & kXR_isDir);
        if (is_dot(ents[i].name)) { continue; }
        if (o->dirs_only && !is_dir) { continue; }
        keep[nk++] = (int) i;
    }
    for (j = 0; j < nk; j++) {
        brix_dirent *e = &ents[keep[j]];
        int   last   = (j == nk - 1);
        int   is_dir = e->have_stat && (e->st.flags & kXR_isDir);
        char  full[XRDC_PATH_MAX];
        char  child_prefix[512];

        printf("%s%s%s\n", prefix, last ? "\\-- " : "|-- ", e->name);
        if (is_dir) { o->ndirs++; } else { o->nfiles++; }
        if (is_dir && join_path(path, e->name, full, sizeof(full)) == 0
            && depth + 1 < XRDFS_MAXDEPTH) {
            snprintf(child_prefix, sizeof(child_prefix), "%s%s",
                     prefix, last ? "    " : "|   ");
            if (tree_recurse(c, full, child_prefix, depth + 1, o, st) != 0) {
                free(keep);
                free(ents);
                return -1;
            }
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
        if (strcmp(argv[i], "-d") == 0) { o.dirs_only = 1; }
        else if (strcmp(argv[i], "-L") == 0 && i + 1 < argc) { o.maxdepth = atoi(argv[++i]); }
        else if (argv[i][0] != '-') { start = argv[i]; }
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
