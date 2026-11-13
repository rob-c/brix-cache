/* Native tree walkers retain real filesystem effects and remote call ordering. */
#include "xfer/copy_internal.h"
#include <assert.h>

static int mode(const char *value) { return strcmp(getenv("BRIX_TREE_MODE"), value) == 0; }
static int fail(brix_status *st) { brix_status_set(st, kXR_NotAuthorized, 0, "refused"); return -1; }

int __wrap_brix_dirlist(brix_conn *c, const char *path, int want_stat,
    brix_dirent **entries, size_t *count, brix_status *st) {
    (void) c; assert(want_stat == 1);
    printf("LIST %s\n", path); *entries = NULL; *count = 0;
    if (mode("list-error")) { return fail(st); }
    FILE *input = fopen(getenv("BRIX_TREE_LIST"), "r"); assert(input);
    char name[XRDC_NAME_MAX]; int kind;
    while (fscanf(input, "%255s %d", name, &kind) == 2) {
        *entries = realloc(*entries, (*count + 1) * sizeof(**entries)); assert(*entries);
        brix_dirent *entry = &(*entries)[(*count)++]; memset(entry, 0, sizeof(*entry));
        snprintf(entry->name, sizeof(entry->name), "%s", name);
        entry->have_stat = kind != 3;
        entry->st.flags = kind == 1 ? kXR_isDir : (kind == 2 ? kXR_other : 0);
        entry->st.size = 7;
    }
    fclose(input);
    if (strstr(path, "/sub") != NULL) {
        free(*entries); *entries = calloc(1, sizeof(**entries)); assert(*entries);
        *count = 1; strcpy((*entries)[0].name, "nested");
        (*entries)[0].have_stat = 1; (*entries)[0].st.size = 7;
    }
    return 0;
}

int __wrap_copy_one_r2l(brix_conn *c, const char *remote, const char *local,
    int64_t expected, brix_status *st) {
    (void) c; printf("DOWNLOAD %s %s expected=%lld\n", remote, local, (long long) expected);
    if (mode("copy-error")) { return fail(st); }
    /* A hostile entry must never reach this transport boundary. */
    assert(strstr(local, "/../") == NULL && strstr(remote, "/../") == NULL);
    FILE *output = fopen(local, "w");
    if (!output) { return fail(st); }
    assert(fputs("payload", output) >= 0 && fclose(output) == 0);
    return 0;
}
int __wrap_copy_one_l2r(brix_conn *c, const char *local, const char *remote,
    const brix_copy_opts *options, brix_status *st) {
    (void) c; (void) options;
    printf("UPLOAD %s %s\n", local, remote);
    if (mode("copy-error")) { return fail(st); }
    return 0;
}
int __wrap_brix_rm(brix_conn *c, const char *path, brix_status *st) {
    (void) c; printf("REMOVE %s\n", path);
    assert(strstr(path, "/../") == NULL);
    return mode("delete-error") ? fail(st) : 0;
}
int __wrap_brix_rmdir(brix_conn *c, const char *path, brix_status *st) {
    (void) c; (void) st; printf("RMDIR %s\n", path); return 0;
}
int __wrap_brix_rmtree(brix_conn *c, const char *path, unsigned flags,
    brix_rmtree_report callback, void *argument, brix_status *st) {
    (void) c; assert(flags == 0 && callback == NULL && argument == NULL);
    printf("RMTREE %s\n", path); return mode("delete-error") ? fail(st) : 0;
}
int __wrap_brix_mkdir(brix_conn *c, const char *path, int permissions, int parents,
    brix_status *st) {
    (void) c; (void) st; assert(permissions == 0755 && parents == 1);
    printf("MKDIR %s\n", path); return 0;
}
int __wrap_brix_stat(brix_conn *c, const char *path, brix_statinfo *info,
    brix_status *st) {
    (void) c; printf("STAT %s\n", path);
    if (mode("stat-error")) { return fail(st); }
    memset(info, 0, sizeof(*info)); info->size = 7;
    info->flags = mode("stat-dir") ? kXR_isDir : 0;
    return 0;
}
int __wrap_brix_query_cksum(brix_conn *c, const char *path, const char *algo,
    char *hex, size_t cap, brix_status *st) {
    (void) c; (void) algo; printf("CHECKSUM %s\n", path);
    if (mode("query-error")) { return fail(st); }
    snprintf(hex, cap, "%s", mode("different") ? "00000000" : "0bdd02eb");
    return 0;
}

static int run_tree(const char *operation, copy_walk_ctx *walk) {
    if (strcmp(operation, "upload") == 0) { return copy_tree_upload(walk); }
    if (strcmp(operation, "mirror") == 0) {
        mirror_delete_remote(walk->c, walk->rpath, walk->lpath, walk->rel, walk->o);
        return 0;
    }
    return copy_tree_download(walk);
}
int main(int argc, char **argv) {
    assert(argc == 6);
    assert(setenv("BRIX_TREE_MODE", argv[2], 1) == 0);
    brix_conn connection = {0}; brix_status status; brix_copy_opts options = {0};
    const char *excludes[] = {"*.omit"};
    char oversized[XRDC_PATH_MAX]; memset(oversized, 'a', sizeof(oversized)-1);
    oversized[sizeof(oversized)-1] = 0;
    options.excludes = excludes; options.n_excludes = 1;
    options.dry_run = mode("dry") || mode("mirror-dry");
    options.sync = mode("sync") || mode("cksum") || mode("different")
                   || mode("bad-algo") || mode("query-error");
    options.sync_cmp = mode("sync") ? XRDC_SYNC_SIZE : XRDC_SYNC_CKSUM;
    options.sync_cksum_algo = mode("bad-algo") ? "invalid" : "adler32";
    options.sync_delete = mode("mirror") || mode("mirror-dry");
    options.remove_source = mode("remove");
    copy_walk_ctx walk = {&connection, "/remote", argv[3], "", &options, &status};
    if (mode("long-rel")) { walk.rel = oversized; }
    if (mode("long-remote")) { walk.rpath = oversized; }
    if (mode("long-local")) { walk.lpath = oversized; }
    brix_status_clear(&status);
    int rc = run_tree(argv[1], &walk);
    printf("RESULT %d %s\n", rc, status.msg); fflush(stdout);
    assert(rc == atoi(argv[4]));
    (void) argv[5];
    return 0;
}
