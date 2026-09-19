/*
 * src/core/compat/host_identity.c — see host_identity.h.
 */

/* gethostname(3) is a POSIX-2001 name, so <unistd.h> hides it under a strict
 * -std=c11: glibc withdraws _DEFAULT_SOURCE, and Darwin gates it on
 * __STRICT_ANSI__.  Declared HERE rather than left to the caller because the
 * module build passes -D_GNU_SOURCE and a harness that compiles this one file
 * on its own does not — tests/test_host_identity_unit.py does exactly that and
 * died on an implicit declaration.  Guarded so a caller that already chose a
 * level keeps it, and placed above every include because that is the only
 * point at which it still has any effect. */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "host_identity.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
brix_host_identity_valid(const char *name, size_t len)
{
    size_t i;

    if (name == NULL || len == 0 || len > BRIX_HOST_IDENTITY_MAX) {
        return 0;
    }
    for (i = 0; i < len; i++) {
        unsigned char ch = (unsigned char) name[i];
        int ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
                 || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-'
                 || ch == ':';
        if (!ok) {
            return 0;
        }
    }
    return 1;
}

/* The override, or NULL when unset / not a host name. */
static const char *
identity_from_env(void)
{
    const char *env = getenv("XRDNET_IDENTITY");

    if (env == NULL || !brix_host_identity_valid(env, strlen(env))) {
        return NULL;
    }
    return env;
}

const char *
brix_host_identity(void)
{
    static char  cached[BRIX_HOST_IDENTITY_MAX + 1];
    static int   resolved;              /* 0 → unset, 1 → cached[] valid */
    const char  *env;

    if (resolved) {
        return cached;
    }
    env = identity_from_env();
    if (env != NULL) {
        memcpy(cached, env, strlen(env) + 1);
    } else if (gethostname(cached, sizeof(cached)) != 0) {
        cached[0] = '\0';
    }
    cached[sizeof(cached) - 1] = '\0';
    resolved = 1;
    return cached;
}
