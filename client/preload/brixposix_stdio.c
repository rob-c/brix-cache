/*
 * brixposix_stdio.c — §7.8 stdio interposition for the POSIX preload shim.
 *
 * WHAT: fopen/freopen over the shim's shadow descriptors (the glibc fopen64 /
 *       freopen64 spellings forward here from lib/platform/linux/preload_lfs.c),
 *       so a program that reaches for FILE* instead of a raw fd still sees the
 *       remote namespace.
 * WHY:  The fd family alone leaves out most of the software this shim exists
 *       for.  Analysis code, config readers and every script language's file
 *       object go through fopen; without it the shim covered `dd` and not
 *       `awk`.
 * HOW:  The host's cookie stdio (glibc fopencookie, BSD funopen; the body is
 *       brixposix_stream_open in lib/platform/<host>/preload_stream.c): we
 *       hand back a REAL FILE* whose backing store is our shadow fd, and libc
 *       keeps doing the buffering, fgets, fscanf, ungetc and feof.  So this TU
 *       interposes exactly the entry points that CREATE a stream and touches
 *       nothing that reads one — no fake FILE*, no reimplemented buffering,
 *       and no risk of a stream we made being handed to a libc function we
 *       did not.
 *
 * The cookie's read/write/seek/close are the shim's OWN interposed
 * read/write/lseek/close, not the libc ones, which is what keeps this file
 * short and keeps it correct as the fd layer grows.
 */
#include "brixposix_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * The open called below is spelt BRIXPOSIX_WRAP(open): the shim's own wrapper
 * in brixposix_preload.c, whatever the host names it.  That is deliberate —
 * it is what lets a FILE* opened here read remote bytes without this file
 * knowing anything about the wire.
 */

/*
 * Translate an fopen mode to open(2) flags.
 *
 * Returns 0 on success.  A mode this shim cannot honour is REFUSED (-1) rather
 * than passed to the real fopen: the path is under the remote prefix, so a
 * fallback would open — or create — a LOCAL file wearing a remote path's name,
 * and the caller would read bytes that are not the ones it asked for.  A
 * refusal is legible; a silent local shadow is not.
 *
 *   "r"  read          -> supported
 *   "w"  truncate/create -> supported (the fd layer's write handle)
 *   "a"  append        -> refused: a remote write handle starts at offset 0
 *                        and there is no "seek to end" on it, so an append
 *                        would overwrite from the front.
 *   "+"  read+write    -> refused: one handle is read OR write, never both.
 */
static int
mode_to_flags(const char *mode, int *out)
{
    if (mode == NULL || mode[0] == '\0' || strchr(mode, '+') != NULL) {
        return -1;
    }
    if (mode[0] == 'r') {
        *out = O_RDONLY;
        return 0;
    }
    if (mode[0] == 'w') {
        *out = O_WRONLY | O_CREAT | O_TRUNC;
        return 0;
    }
    return -1;   /* 'a', and anything else glibc might grow */
}

/* Open `path` remotely if it is ours; *handled stays 0 when it is not. */
static FILE *
remote_fopen(const char *path, const char *mode, int *handled)
{
    char remote[XRDC_PATH_MAX];
    int  flags, fd;

    *handled = 0;
    if (path == NULL || !map_path(path, remote, sizeof(remote))) {
        return NULL;
    }
    *handled = 1;
    if (mode_to_flags(mode, &flags) != 0) {
        errno = ENOTSUP;
        return NULL;
    }
    fd = BRIXPOSIX_WRAP(open)(path, flags, 0644);   /* our open(): maps the path again */
    if (fd < 0) {
        return NULL;
    }
    return brixposix_stream_open(fd, mode);
}

FILE *
BRIXPOSIX_WRAP(fopen)(const char *path, const char *mode)
{
    int handled;
    FILE *fp;

    REAL(fopen);
    fp = remote_fopen(path, mode, &handled);
    if (handled) {
        return fp;
    }
    return real_fopen(path, mode);
}


/*
 * freopen's contract is "close `stream`, reopen it on `path`" — the CALLER
 * keeps its FILE*, and the classic use is redirecting stdout.  fopencookie
 * cannot rebind an existing stream, so a remote target is refused rather than
 * half-served: returning a different FILE* would leave every caller that
 * relies on the identity (`freopen(p, "r", stdin)`) reading the old stream.
 */
FILE *
BRIXPOSIX_WRAP(freopen)(const char *path, const char *mode, FILE *stream)
{
    char remote[XRDC_PATH_MAX];

    REAL(freopen);
    if (path != NULL && map_path(path, remote, sizeof(remote))) {
        errno = ENOTSUP;
        return NULL;
    }
    return real_freopen(path, mode, stream);
}
