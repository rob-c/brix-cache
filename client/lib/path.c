/*
 * path.c — client-side path helpers shared by the front-end tools.
 *
 * xrdc_path_resolve() canonicalises a (possibly relative) argument against a
 * current working directory, collapsing ".", "..", and duplicate slashes to an
 * absolute server path — the logic xrdfs's interactive shell and one-shot
 * subcommands used (build_path) and that xrdcp open-codes for its destinations.
 */
#include "xrdc.h"

#include <stdio.h>
#include <string.h>

void
xrdc_path_resolve(const char *cwd, const char *arg, char *out, size_t outsz)
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
