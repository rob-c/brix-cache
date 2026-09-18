/*
 * client/lib/platform/linux/mounts.c - the mount table for client tools
 *
 * WHAT: brix_plat_mounts_walk over /proc/self/mountinfo (or a test-supplied
 *       table path). The same parser as src/platform/linux/path_wrapper.c.
 * WHY:  `xrd mount` lists xrootdfs mounts without naming /proc itself.
 * HOW:  One destructive tokenizer per line; malformed lines are skipped.
 */

#include "platform/platform.h"

#if BRIX_PLATFORM_LINUX

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Decode the \ooo escapes mountinfo uses for spaces, tabs and backslashes. */
static void
mountinfo_unescape(const char *in, char *out, size_t cap)
{
    size_t o = 0;

    while (*in != '\0' && o + 1 < cap) {
        if (in[0] == '\\' && in[1] >= '0' && in[1] <= '7'
            && in[2] >= '0' && in[2] <= '7' && in[3] >= '0' && in[3] <= '7')
        {
            out[o++] = (char) (((in[1] - '0') << 6) | ((in[2] - '0') << 3)
                               | (in[3] - '0'));
            in += 4;
            continue;
        }
        out[o++] = *in++;
    }
    out[o] = '\0';
}

/* One mountinfo line -> (mountpoint, fstype, source) -> cb. Malformed lines
 * are skipped; the tokenizer is destructive on `line`. */
static int
mountinfo_emit_line(char *line, brix_plat_mount_cb cb, void *arg)
{
    char   *fields[48];
    int     nf = 0, sep = -1, i;
    char   *tok, *save;
    char    mp[4096], src[4096];

    for (tok = strtok_r(line, " \n", &save); tok != NULL && nf < 48;
         tok = strtok_r(NULL, " \n", &save))
    {
        fields[nf++] = tok;
    }
    for (i = 0; i < nf; i++) {
        if (strcmp(fields[i], "-") == 0) {
            sep = i;
            break;
        }
    }
    if (sep < 5 || sep + 2 >= nf) {
        return 0;
    }
    mountinfo_unescape(fields[4], mp, sizeof(mp));
    mountinfo_unescape(fields[sep + 2], src, sizeof(src));
    return cb(mp, fields[sep + 1], src, arg);
}

int
brix_plat_mounts_walk(const char *table_path, brix_plat_mount_cb cb, void *arg)
{
    FILE    *fp;
    char    *line = NULL;
    size_t   cap = 0;
    int      rc = 0;

    fp = fopen(table_path != NULL ? table_path : "/proc/self/mountinfo", "r"); /* vfs-seam-allow: NOT_STORAGE - PAL mount-table read */
    if (fp == NULL) {
        return -1;
    }
    while (rc == 0 && getline(&line, &cap, fp) >= 0) {
        rc = mountinfo_emit_line(line, cb, arg);
    }
    free(line);
    fclose(fp);
    return rc;
}

#endif /* BRIX_PLATFORM_LINUX */
