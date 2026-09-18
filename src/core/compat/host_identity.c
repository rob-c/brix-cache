/*
 * src/core/compat/host_identity.c — see host_identity.h.
 */
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
