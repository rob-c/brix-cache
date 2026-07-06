/*
 * version.h — client build-version constant and usage-footer macro.
 *
 * WHAT: BRIX_CLIENT_VERSION is the canonical version string for all client
 *       tools.  It defaults to "dev" unless the build system injects a real
 *       tag via -DBRIX_CLIENT_VERSION=\"<tag>\".  brix_client_version() wraps
 *       the macro for use in C code.  BRIX_USAGE_FOOTER(TOOL) expands to the
 *       two-line footer appended to every usage text (spec §WS-2).
 * WHY:  Single source of truth: every tool prints the same version token and
 *       identical footer wording regardless of who generates the help text.
 * HOW:  client/Makefile appends -DBRIX_CLIENT_VERSION=\"$(BRIX_CLIENT_VERSION)\"
 *       to ALL_CFLAGS when the make variable is non-empty; otherwise the "dev"
 *       fallback ensures a build always links.
 */
#ifndef BRIX_CORE_VERSION_H
#define BRIX_CORE_VERSION_H

/*
 * BRIX_CLIENT_VERSION — injected at build time via
 *   -DBRIX_CLIENT_VERSION=\"<tag>\"
 * Falls back to "dev" for unversioned developer builds.
 */
#ifndef BRIX_CLIENT_VERSION
#define BRIX_CLIENT_VERSION "dev"
#endif

/*
 * BRIX_USAGE_FOOTER(TOOL) — two-line footer appended to every usage block.
 * TOOL must be a C string literal naming the tool (e.g. "xrdcp").
 * The middle dot (U+00B7) is encoded as \xc2\xb7 (UTF-8).
 */
#define BRIX_USAGE_FOOTER(TOOL)                                                 \
    "config: ~/.xrdrc defines endpoint aliases and credentials "                \
        "(see brix-env(7))\n"                                                   \
    "docs:   man " TOOL "   \xc2\xb7   exit codes are listed at the end of "   \
        "the man page\n"

/*
 * brix_client_version() — return the version string for this build.
 * WHY: inline wrapper lets callers reference the version as a const char *
 *      at any call site without repeating the macro.
 */
static inline const char *
brix_client_version(void)
{
    return BRIX_CLIENT_VERSION;
}

#endif /* BRIX_CORE_VERSION_H */
