/* name.c — OCI repository-name + tag grammar.
 *
 * WHAT: the name.h contract — strict byte-grammar walks for names and tags.
 * WHY:  see name.h; this is the single implementation both surfaces trust.
 * HOW:  a component walker consuming alnum runs joined by separator runs
 *       (".", "_", "__", "-"+ — the spec's exact production), applied per
 *       slash-split component. Length caps are checked first so no walk ever
 *       runs unbounded.
 */
#include "oci/name.h"

static int lower_alnum(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

static int tag_body_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

/* One name component: [a-z0-9]+ (sep [a-z0-9]+)* where sep is ".", "_",
 * "__" or "-"+. Returns 0 valid / -1. */
static int component_valid(const char *s, size_t n) {
    size_t i = 0;

    if (n == 0 || !lower_alnum(s[0]))
        return -1;
    while (i < n) {
        /* alnum run */
        if (!lower_alnum(s[i]))
            return -1;
        while (i < n && lower_alnum(s[i]))
            i++;
        if (i == n)
            return 0;
        /* separator run: '.', '_', "__" or one-or-more '-' */
        if (s[i] == '.') {
            i++;
        } else if (s[i] == '_') {
            i++;
            if (i < n && s[i] == '_')
                i++;
        } else if (s[i] == '-') {
            while (i < n && s[i] == '-')
                i++;
        } else {
            return -1;
        }
        if (i == n)
            return -1;              /* trailing separator */
    }
    return 0;
}

int brix_oci_name_valid(const char *s, size_t n) {
    size_t start = 0, i;

    if (s == NULL || n == 0 || n > BRIX_OCI_NAME_MAX)
        return -1;
    for (i = 0; i <= n; i++) {
        if (i == n || s[i] == '/') {
            if (component_valid(s + start, i - start) != 0)
                return -1;
            start = i + 1;
        } else if (s[i] == '\0') {
            return -1;              /* embedded NUL never reaches a path */
        }
    }
    return 0;
}

int brix_oci_tag_valid(const char *s, size_t n) {
    size_t i;

    if (s == NULL || n == 0 || n > BRIX_OCI_TAG_MAX)
        return -1;
    if (!(tag_body_char(s[0]) && s[0] != '.' && s[0] != '-'))
        return -1;                  /* first char: [a-zA-Z0-9_] */
    for (i = 1; i < n; i++) {
        if (!tag_body_char(s[i]))
            return -1;
    }
    return 0;
}

int brix_oci_name_components(const char *s, size_t n) {
    int    count = 1;
    size_t i;

    for (i = 0; i < n; i++) {
        if (s[i] == '/')
            count++;
    }
    return count;
}
