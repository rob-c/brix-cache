/*
 * Unreachable startup boundaries for object-linked publish tests.
 *
 * The confined descriptor/open/resolution kernels are REAL. Some sanitizer
 * runtimes retain unrelated startup-only functions from their translation
 * units, so those functions' unused dependencies still need link symbols.
 * Abort rather than fabricate a canonical path or permit a broker shortcut.
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <stdlib.h>

/* WHAT: Trap an unexpected startup resolver call. WHY: Runtime fd confinement
 * is the unit's actual boundary. HOW: Ignore borrowed arguments and abort. */
int
brix_get_canonical_root(ngx_log_t *log, const ngx_str_t *root,
    char *canonical, size_t capacity)
{
    (void) log; (void) root; (void) canonical; (void) capacity;
    abort();
}

/* WHAT: Trap startup policy-rule resolution. WHY: Publish tests pass explicit
 * canonical roots. HOW: Abort if an unrelated retained function executes. */
int
brix_resolve_path_noexist(ngx_log_t *log, const ngx_str_t *root,
    const char *requested, char *resolved, size_t capacity)
{
    (void) log; (void) root; (void) requested; (void) resolved; (void) capacity;
    abort();
}

/* WHAT: Trap an unrelated directory-access branch. WHY: Broker dispatch has
 * its own explicit inactive fixture. HOW: Abort instead of granting access. */
int
brix_imp_enabled(void)
{
    abort();
}
