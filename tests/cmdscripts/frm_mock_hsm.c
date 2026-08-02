/*
 * frm_mock_hsm.c — a mock HSM shared object for the frm:// library-native
 * ("lib" / "libhpss" / "libcta") adapter tests (tests/test_frm_lib_adapter.py).
 *
 * It is the vendor .so stand-in: the sd_frm "lib" adapter dlopen()s it and
 * dlsym()s the sd_frm_lib_abi.h symbols, then drives tape residency/recall/
 * migrate as in-process calls instead of forking a stage command. Tape is
 * simulated by a local directory whose path arrives in $BRIX_FRM_MOCK_TAPE.
 *
 * The tape directory is captured in a constructor at dlopen time (config parse,
 * in the master process where the real environment is intact) into a static that
 * fork inherits — nginx wipes a worker's environ to reclaim the process-title
 * arena, so a plain getenv() on the worker recall path would come back empty.
 *
 * purge is intentionally NOT exported, exercising the adapter's optional-symbol
 * path (a lib that binds only the three required verbs must still load).
 */

#include "sd_frm_lib_abi.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_tape[4096];

__attribute__((constructor))
static void
mock_hsm_init(void)
{
    const char *t = getenv("BRIX_FRM_MOCK_TAPE");

    if (t != NULL) {
        snprintf(g_tape, sizeof(g_tape), "%s", t);
    }
}

/* tape/<key>, dropping a single leading '/' so an LFN key nests under the tape
 * root rather than escaping it. */
static int
tape_path(const char *key, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s", g_tape, (key[0] == '/') ? key + 1 : key);

    return (n > 0 && (size_t) n < cap) ? 0 : -1;
}

/* mkdir -p of every parent directory of `path` (best effort). */
static void
mkparents(const char *path)
{
    char   buf[8192];
    size_t i;

    if (snprintf(buf, sizeof(buf), "%s", path) >= (int) sizeof(buf)) {
        return;
    }
    for (i = 1; buf[i] != '\0'; i++) {
        if (buf[i] == '/') {
            buf[i] = '\0';
            (void) mkdir(buf, 0755);
            buf[i] = '/';
        }
    }
}

static int
copyfile(const char *src, const char *dst)
{
    char    buf[65536];
    ssize_t n;
    int     in, out, rc = 0;

    in = open(src, O_RDONLY);
    if (in < 0) {
        return -1;
    }
    out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) {
        close(in);
        return -1;
    }
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(out, buf, (size_t) n) != n) {
            rc = -1;
            break;
        }
    }
    if (n < 0) {
        rc = -1;
    }
    close(in);
    close(out);
    return rc;
}

/* 0 = key is on tape (recallable); non-zero = absent (never fabricated). */
int
brix_frm_hsm_exists(const char *key)
{
    char        p[8192];
    struct stat sb;

    if (tape_path(key, p, sizeof(p)) != 0) {
        return 1;
    }
    return (stat(p, &sb) == 0 && S_ISREG(sb.st_mode)) ? 0 : 1;
}

/* Materialise tape/<key> into the adapter-provided online_path (parents already
 * created by the adapter); 0 = online. */
int
brix_frm_hsm_recall(const char *key, const char *online_path)
{
    char p[8192];

    if (tape_path(key, p, sizeof(p)) != 0) {
        return -1;
    }
    return copyfile(p, online_path);
}

/* Copy the online-buffer object back to tape/<key>; 0 = migrated. */
int
brix_frm_hsm_migrate(const char *key, const char *online_path)
{
    char p[8192];

    if (tape_path(key, p, sizeof(p)) != 0) {
        return -1;
    }
    mkparents(p);
    return copyfile(online_path, p);
}
