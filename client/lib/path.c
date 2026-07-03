/*
 * path.c — client-side path helpers shared by the front-end tools.
 *
 * brix_path_resolve() canonicalises a (possibly relative) argument against a
 * current working directory, collapsing ".", "..", and duplicate slashes to an
 * absolute server path — the logic xrdfs's interactive shell and one-shot
 * subcommands used (build_path) and that xrdcp open-codes for its destinations.
 */
#include "brix.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

void
brix_path_resolve(const char *cwd, const char *arg, char *out, size_t outsz)
{
    char  raw[XRDC_PATH_MAX * 2];
    char *comps[256];
    int   nc = 0;
    char *tok, *save;
    size_t pos;
    int   i;

    if (arg[0] == '/') {
        snprintf(raw, sizeof(raw), "%s", arg);
    } else {
        snprintf(raw, sizeof(raw), "%s/%s",
                 (cwd[0] == '/' && cwd[1] == '\0') ? "" : cwd, arg);
    }

    for (tok = strtok_r(raw, "/", &save); tok != NULL && nc < 256;
         tok = strtok_r(NULL, "/", &save)) {
        if (strcmp(tok, ".") == 0) {
            continue;
        }
        if (strcmp(tok, "..") == 0) {
            if (nc > 0) { nc--; }
            continue;
        }
        comps[nc++] = tok;
    }

    if (nc == 0) {
        snprintf(out, outsz, "/");
        return;
    }
    pos = 0;
    for (i = 0; i < nc && pos + 1 < outsz; i++) {
        int w = snprintf(out + pos, outsz - pos, "/%s", comps[i]);
        if (w < 0) { break; }
        pos += (size_t) w;
    }
}

/*
 * brix_open_credfile — open a credential file for reading, refusing anything an
 * attacker could have planted or tampered with.
 *
 * WHAT: open `path` read-only and return a validated fd (caller closes), or -1.
 * WHY:  credentials default to predictable, world-writable locations
 *       (/tmp/bt_u<uid>, /tmp/x509up_u<uid>). A plain fopen/BIO_new_file there
 *       follows a symlink an attacker pre-planted under the victim's uid — leaking
 *       a secret the client then transmits — or reads an attacker-owned regular
 *       file, authenticating the victim as the attacker (confused deputy). This is
 *       the same hardening brix_sss_keytab_read already applies to keytabs.
 * HOW:  O_NOFOLLOW (no final-component symlink) | O_CLOEXEC; require a regular
 *       file owned by the effective uid; reject group/other WRITE always, and —
 *       for `secret` files (private keys / GSI proxies) — group/other READ too.
 *       `st` may be NULL for silent probing (returns -1 without setting an error).
 */
int
brix_open_credfile(const char *path, int secret, brix_status *st)
{
    struct stat sb;
    mode_t      bad;
    int         fd;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        brix_status_set(st, XRDC_EAUTH, errno, "open %s: %s",
                        path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        close(fd);
        brix_status_set(st, XRDC_EAUTH, 0, "%s is not a regular file", path);
        return -1;
    }
    if (sb.st_uid != geteuid()) {
        close(fd);
        brix_status_set(st, XRDC_EAUTH, 0,
                        "%s not owned by uid %u (refusing untrusted credential)",
                        path, (unsigned) geteuid());
        return -1;
    }
    bad = secret ? (S_IRWXG | S_IRWXO) : (S_IWGRP | S_IWOTH);
    if (sb.st_mode & bad) {
        close(fd);
        brix_status_set(st, XRDC_EAUTH, 0,
                        "%s has unsafe permissions (must be %s)",
                        path, secret ? "0600" : "non-writable by group/other");
        return -1;
    }
    return fd;
}
