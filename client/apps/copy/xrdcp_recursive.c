/* xrdcp_recursive.c - CLI source expansion before copy-engine dispatch. */
#include "xrdcp_internal.h"

/* A '?' introducing an opaque query is not a glob metacharacter. */
int
source_has_glob(const char *s)
{
    const char *query = strchr(s, '?');
    size_t      i;
    size_t      path_len;

    if (query == NULL || strchr(query, '=') == NULL) {
        return brix_has_glob(s);
    }
    path_len = (size_t) (query - s);
    for (i = 0; i < path_len; i++) {
        if (s[i] == '*' || s[i] == '[' || s[i] == '?') {
            return 1;
        }
    }
    return 0;
}


static int
expand_root_glob(const char *source, const brix_opts *opts, char ***out,
                 size_t *count, size_t *capacity)
{
    char       **matches = NULL;
    size_t       match_count = 0;
    size_t       i;
    brix_status  status;

    brix_status_clear(&status);
    if (brix_glob(source, opts, &matches, &match_count, &status) < 0) {
        if (status.kxr == XRDC_EUSAGE) {
            return str_append(out, count, capacity, source);
        }
        fprintf(stderr, "xrdcp: glob %s: %s\n", source, status.msg);
        return 0;
    }
    if (match_count == 0) {
        fprintf(stderr, "xrdcp: no matches for %s\n", source);
    }
    for (i = 0; i < match_count; i++) {
        if (str_append(out, count, capacity, matches[i]) != 0) {
            brix_glob_free(matches, match_count);
            return -1;
        }
    }
    brix_glob_free(matches, match_count);
    return 0;
}


static int
expand_local_glob(const char *source, char ***out, size_t *count,
                  size_t *capacity)
{
    glob_t result;
    size_t i;
    int    rc;

    rc = glob(source, 0, NULL, &result);
    if (rc != 0) {
        globfree(&result);
        fprintf(stderr, "xrdcp: no matches for %s\n", source);
        return 0;
    }
    for (i = 0; i < result.gl_pathc; i++) {
        if (str_append(out, count, capacity, result.gl_pathv[i]) != 0) {
            globfree(&result);
            return -1;
        }
    }
    globfree(&result);
    return 0;
}


int
expand_source(const char *input, const brix_opts *opts, char ***out,
              size_t *count, size_t *capacity)
{
    char        resolved[XRDC_PATH_MAX];
    const char *source;

    brix_alias_resolve(input, resolved, sizeof(resolved));
    source = resolved;
    if (!source_has_glob(source) || brix_is_web_url(source)) {
        return str_append(out, count, capacity, source);
    }
    if (is_root_url(source)) {
        return expand_root_glob(source, opts, out, count, capacity);
    }
    return expand_local_glob(source, out, count, capacity);
}
