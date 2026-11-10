/* Exercise real recursive placement with scripted listing/transport boundaries. */
#include "xfer/copy_internal.h"
#include <assert.h>

static int
fault(const char *name)
{
    const char *selected = getenv("BRIX_COPY_FAULT");
    return selected != NULL && strcmp(selected, name) == 0;
}

static int
listing(char ***paths, size_t *count, brix_status *st)
{
    FILE *input;
    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    *paths = NULL;
    *count = 0;
    if (fault("list")) {
        brix_status_set(st, XRDC_EAUTH, 0, "listing denied");
        return -1;
    }
    input = fopen(getenv("BRIX_COPY_LIST"), "r");
    assert(input != NULL);
    while ((length = getline(&line, &capacity, input)) >= 0) {
        if (length > 0 && line[length - 1] == '\n') { line[--length] = 0; }
        *paths = realloc(*paths, (*count + 1) * sizeof(**paths));
        assert(*paths != NULL);
        (*paths)[(*count)++] = strdup(line);
    }
    free(line);
    assert(fclose(input) == 0);
    return 0;
}

int
__wrap_brix_webdav_list(const brix_weburl *u, const char *bearer, int verify,
                       const char *ca, const char *cert, char ***paths,
                       size_t *count, brix_status *st)
{
    (void) ca; (void) cert;
    printf("LIST %s %s verify=%d\n", u->path, bearer ? bearer : "anonymous", verify);
    return listing(paths, count, st);
}

int
__wrap_brix_s3_list(const brix_weburl *u, const char *ak, const char *sk,
                   const char *region, int verify, const char *ca,
                   char ***paths, size_t *count, brix_status *st)
{
    (void) ca;
    printf("S3LIST %s %s %s %s verify=%d\n", u->path, ak ? ak : "none",
           sk ? sk : "none", region ? region : "none", verify);
    return listing(paths, count, st);
}

int
__wrap_brix_webdav_mkcol(const brix_weburl *u, const char *path,
                        const char *bearer, int verify, const char *ca,
                        const char *cert, brix_status *st)
{
    (void) ca; (void) cert;
    assert(!u->is_s3);
    printf("MKCOL %s %s verify=%d\n", path, bearer ? bearer : "anonymous", verify);
    if (fault("mkcol")) {
        brix_status_set(st, XRDC_EAUTH, 0, "collection denied");
        return -1;
    }
    return 0;
}

int
__wrap_copy_web_leaf_retry(const char *src, const char *dst,
                           const brix_copy_opts *opts, const brix_opts *co,
                           brix_status *st)
{
    FILE *output;
    (void) co;
    assert(opts != NULL && opts->recursive == 0 && opts->dry_run == 0);
    printf("COPY %s -> %s\n", src, dst);
    if (fault("transfer")) {
        brix_status_set(st, XRDC_ESOCK, 0, "transfer refused");
        return -1;
    }
    if (brix_is_web_url(dst)) { return 0; }
    output = fopen(dst, "w");
    if (output == NULL) {
        brix_status_set(st, XRDC_ESOCK, errno, "cannot create destination");
        return -1;
    }
    assert(fputs(src, output) >= 0);
    assert(fclose(output) == 0);
    return 0;
}

int
main(int argc, char **argv)
{
    brix_copy_opts opts = {0};
    brix_opts connection = {0};
    brix_status st;
    const char *exclude[] = {"*.omit"};
    int rc;
    assert(argc == 5);
    opts.recursive = 1;
    opts.excludes = exclude;
    opts.n_excludes = 1;
    opts.dry_run = strcmp(argv[3], "dry") == 0;
    opts.silent = strcmp(argv[3], "silent") == 0;
    if (strcmp(argv[3], "credentials") == 0) {
        opts.bearer = "option-token";
        opts.s3_access = "option-access";
        opts.s3_secret = "option-secret";
        opts.s3_region = "option-region";
    }
    brix_status_clear(&st);
    rc = copy_web_recursive_download(argv[1], argv[2],
            strcmp(argv[3], "null") == 0 ? NULL : &opts,
            strcmp(argv[3], "null") == 0 ? NULL : &connection, &st);
    printf("RESULT %d %s\n", rc, st.msg);
    assert(rc == atoi(argv[4]));
    return 0;
}
