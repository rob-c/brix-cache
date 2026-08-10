/*
 * copy_xattr.c — xrdcp --xattr: preserve extended attributes (§7.13).
 *
 * WHAT: brix_copy_preserve_xattrs() mirrors user-namespace extended
 *       attributes across a completed root://↔local copy: a download lists
 *       the source's kXR_fattr attributes and setxattr()s them onto the
 *       local destination; an upload lists the local user.* attributes and
 *       kXR_fattr-sets them on the remote destination.
 * WHY:  Stock xrdcp --xattr ("preserve extended attributes"); scientific
 *       workflows carry checksums/provenance in xattrs. Preservation is
 *       BEST-EFFORT exactly like stock: a failed attribute warns and the
 *       copy stays successful — attributes are auxiliary to the bytes.
 * HOW:  Direction from the URL schemes; names travel VERBATIM in both
 *       directions with two hard rules: (a) only user-namespace attributes
 *       ever transfer — system./security./trusted. names are skipped
 *       outright in BOTH directions, so a hostile remote name like
 *       "security.capability" can never be planted on a local file; (b) a
 *       remote name without a user. prefix lands locally under
 *       "user.<name>". Values are bounded by the fattr wire caps (64 KiB).
 */
#include "copy_internal.h"

#include <sys/xattr.h>

#define XATTR_VAL_MAX   (64u * 1024u)
#define XATTR_NAME_MAX_ 256

/* ---- May this attribute name cross the copy boundary? ----
 *
 * WHAT: 1 only for user-namespace names (with or without the "user."
 *       prefix spelled out); anything claiming another namespace is refused.
 *
 * WHY: system./security./trusted./btrfs. attributes change LOCAL KERNEL
 *      behavior (capabilities, ACLs) — a remote server must never be able to
 *      plant one via --xattr, and uploading them would leak host metadata.
 *
 * HOW: Explicit deny on a '.'-delimited first token that is a known kernel
 *      namespace other than user; bare names (no namespace) are allowed and
 *      later normalised under user. locally.
 */
static int
xattr_name_allowed(const char *name)
{
    if (name == NULL || name[0] == '\0'
        || strlen(name) >= XATTR_NAME_MAX_) {
        return 0;
    }
    if (strncmp(name, "user.", 5) == 0) {
        return 1;
    }
    if (strncmp(name, "system.", 7) == 0 || strncmp(name, "security.", 9) == 0
        || strncmp(name, "trusted.", 8) == 0) {
        return 0;
    }
    return strchr(name, '.') == NULL;   /* bare names ok; odd namespaces not */
}

/* ---- Download direction: remote fattr list → local setxattr ---- */
static void
xattr_pull(brix_conn *c, const char *rpath, const char *lpath, int silent)
{
    brix_status st;
    char        names[8192];
    size_t      nlen = 0, cursor = 0;

    brix_status_clear(&st);
    if (brix_fattr_list(c, rpath, names, sizeof(names), &nlen, &st) != 0) {
        return;   /* no attributes / unsupported: nothing to preserve */
    }
    if (nlen > sizeof(names)) {
        nlen = sizeof(names);
    }
    while (cursor < nlen) {
        const char *name = names + cursor;
        size_t      span = strnlen(name, nlen - cursor);
        char        localname[XATTR_NAME_MAX_ + 8];
        char       *val;
        size_t      vlen = 0;

        cursor += span + 1;
        if (span == 0 || !xattr_name_allowed(name)) {
            continue;
        }
        val = (char *) malloc(XATTR_VAL_MAX);
        if (val == NULL) {
            return;
        }
        brix_status_clear(&st);
        if (brix_fattr_get(c, rpath, name, val, XATTR_VAL_MAX, &vlen,
                           &st) == 0
            && vlen <= XATTR_VAL_MAX) {
            snprintf(localname, sizeof(localname),
                     strncmp(name, "user.", 5) == 0 ? "%s" : "user.%s", name);
            if (setxattr(lpath, localname, val, vlen, 0) != 0 && !silent) {
                fprintf(stderr, "xrdcp: --xattr: could not set %s on %s: %s\n",
                        localname, lpath, strerror(errno));
            }
        } else if (!silent) {
            fprintf(stderr, "xrdcp: --xattr: could not read %s from %s: %s\n",
                    name, rpath, st.msg);
        }
        free(val);
    }
}

/* ---- Upload direction: local user.* list → remote fattr set ---- */
static void
xattr_push(brix_conn *c, const char *lpath, const char *rpath, int silent)
{
    char    names[8192];
    ssize_t nlen = listxattr(lpath, names, sizeof(names));
    size_t  cursor = 0;

    if (nlen <= 0) {
        return;
    }
    while (cursor < (size_t) nlen) {
        const char *name = names + cursor;
        size_t      span = strnlen(name, (size_t) nlen - cursor);
        char       *val;
        ssize_t     vlen;

        cursor += span + 1;
        if (span == 0 || strncmp(name, "user.", 5) != 0
            || !xattr_name_allowed(name)) {
            continue;   /* only the user namespace ever leaves the host */
        }
        val = (char *) malloc(XATTR_VAL_MAX);
        if (val == NULL) {
            return;
        }
        vlen = getxattr(lpath, name, val, XATTR_VAL_MAX);
        if (vlen >= 0) {
            brix_status st;

            brix_status_clear(&st);
            if (brix_fattr_set(c, rpath, name, val, (size_t) vlen,
                               0 /* overwrite ok */, &st) != 0
                && !silent) {
                fprintf(stderr, "xrdcp: --xattr: could not set %s on %s: %s\n",
                        name, rpath, st.msg);
            }
        }
        free(val);
    }
}

/* ---- Preserve xattrs across one completed copy ----
 *
 * WHAT: Applies the direction-appropriate mirror for a root://↔local pair;
 *       other scheme pairs are silently out of scope (stock --xattr is a
 *       root-protocol feature). Never fails the copy: warnings only.
 *
 * WHY: Called by the transfer wrapper AFTER the bytes (and any --cksum
 *      verdict) succeeded — attributes describe a file that now exists.
 *
 * HOW: Parse both URLs; open one throwaway connection to the remote side
 *      (the data connection is already torn down by the time the wrapper
 *      runs); dispatch pull/push.
 */
void
brix_copy_preserve_xattrs(const char *src, const char *dst,
                          const brix_opts *co, int silent)
{
    brix_url    su, du;
    brix_status st;
    brix_conn   c;

    brix_status_clear(&st);
    if (brix_url_parse(src, &su, &st) != 0
        || brix_url_parse(dst, &du, &st) != 0) {
        return;
    }
    if ((su.scheme == XRDC_SCHEME_ROOT || su.scheme == XRDC_SCHEME_ROOTS)
        && du.scheme == XRDC_SCHEME_LOCAL) {
        if (brix_connect(&c, &su, co, &st) == 0) {
            xattr_pull(&c, su.path, du.path, silent);
            brix_close(&c);
        }
        return;
    }
    if (su.scheme == XRDC_SCHEME_LOCAL
        && (du.scheme == XRDC_SCHEME_ROOT || du.scheme == XRDC_SCHEME_ROOTS)) {
        if (brix_connect(&c, &du, co, &st) == 0) {
            xattr_push(&c, su.path, du.path, silent);
            brix_close(&c);
        }
    }
}
