/*
 * progname.h — runtime program-name identity for the client tools.
 *
 * WHAT: helpers that let one name-agnostic binary discover, at run time from
 *       argv[0], (a) its own display name, (b) whether it was invoked under the
 *       co-install "brix-" prefix, and (c) the name of a sibling tool to exec.
 *       Plus brix_usage_footer(), the runtime replacement for the old
 *       BRIX_USAGE_FOOTER() string-literal macro.
 * WHY:  the brix-cache-client-compat package installs the exact same binaries as
 *       brix-cache-client but under a "brix-" prefix (brix-xrdcp, brix-xrdfs …)
 *       so they co-install with the official xrootd tools.  A prefixed tool must
 *       print its own name — never the stock one — in usage/version/footer, and
 *       must dispatch multi-call personalities and exec sibling tools under the
 *       matching name.  Deriving everything from argv[0] keeps ONE binary (git /
 *       busybox model) with no second compile and no drift.
 * HOW:  header-only inline helpers (no new translation unit, so the build
 *       source-list is untouched).  basename is computed with strrchr rather
 *       than libgen basename(3) to avoid mutating the caller's string.
 */
#ifndef BRIX_CORE_PROGNAME_H
#define BRIX_CORE_PROGNAME_H

#include <stdio.h>
#include <string.h>

/* The co-install prefix carried by the brix-cache-client-compat tools. */
#define BRIX_COMPAT_PREFIX     "brix-"
#define BRIX_COMPAT_PREFIX_LEN 5

/*
 * brix_prog_base — basename of an argv[0]/path (pointer into the same string).
 * WHY: argv[0] may be a bare name ("brix-xrdcp") or a path ("./bin/brix-xrdcp");
 *      the display/identity logic wants just the final component.
 */
static inline const char *
brix_prog_base(const char *argv0)
{
    const char *slash;

    if (argv0 == NULL || *argv0 == '\0') {
        return "?";
    }
    slash = strrchr(argv0, '/');
    return slash != NULL ? slash + 1 : argv0;
}

/*
 * brix_prog_strip_compat — the basename with any leading "brix-" removed.
 * WHY: multi-call dispatchers (xrdcksum, xrddiag) pick a personality from
 *      basename(argv[0]); invoked as "brix-xrdadler32" they must still match the
 *      "xrdadler32" personality, so strip the co-install prefix before matching.
 */
static inline const char *
brix_prog_strip_compat(const char *base)
{
    if (strncmp(base, BRIX_COMPAT_PREFIX, BRIX_COMPAT_PREFIX_LEN) == 0) {
        return base + BRIX_COMPAT_PREFIX_LEN;
    }
    return base;
}

/*
 * brix_prog_prefix — "brix-" when the basename carries the co-install prefix,
 * else "".  WHY: an umbrella tool (xrd) must exec siblings under the same
 * flavour it was invoked as — "brix-xrd cp" -> "brix-xrdcp".
 */
static inline const char *
brix_prog_prefix(const char *base)
{
    return strncmp(base, BRIX_COMPAT_PREFIX, BRIX_COMPAT_PREFIX_LEN) == 0
               ? BRIX_COMPAT_PREFIX
               : "";
}

/*
 * brix_usage_footer — the two-line footer appended to every usage block.
 * WHY: replaces the old BRIX_USAGE_FOOTER(TOOL) string-literal macro so the
 *      "man <tool>" line names the tool AS INVOKED (brix-xrdcp under the compat
 *      package, xrdcp otherwise) rather than a baked-in stock literal.
 * HOW: prints basename(argv0); the middle dot (U+00B7) is the same UTF-8 byte
 *      sequence the old macro emitted.
 */
static inline void
brix_usage_footer(FILE *out, const char *argv0)
{
    fprintf(out,
        "config: ~/.xrdrc defines endpoint aliases and credentials "
            "(see brix-env(7))\n"
        "docs:   man %s   \xc2\xb7   exit codes are listed at the end of "
            "the man page\n",
        brix_prog_base(argv0));
}

#endif /* BRIX_CORE_PROGNAME_H */
