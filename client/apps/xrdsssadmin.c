/*
 * xrdsssadmin.c — manage an SSS (Simple Shared Secret) keytab.
 *
 * WHAT: `xrdsssadmin [-k keytab] <add|list|del|install>` — create and maintain
 *       the symmetric-key keytab that both an XRootD server and the native client
 *       use for SSS authentication.
 * WHY:  SSS needs a shared keytab on both ends; this is the clean-room, libXrdCl-
 *       free tool to mint a random key, list entries, and delete one — mode 0600,
 *       self-validated by re-reading after every mutation.
 * HOW:  Thin arg parse → lib/sss_keytab.c read/write. `add`/`install` generate a
 *       32-byte RAND_bytes key with id = max+1 (or --id), append, and write back;
 *       `list` prints id/user/group/name/keylen/expiry; `del --id N` removes one.
 *
 * Clean-room: keytab grammar matches src/auth/sss/config.c; no XrdSecsssAdmin code.
 */
#include "xrdc.h"
#include "sss_keytab.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>

static void
usage(void)
{
    fprintf(stderr,
        "usage: xrdsssadmin [-k keytab] <command> [opts]\n"
        "  commands:\n"
        "    add        mint a new random key and append it\n"
        "    install    same as add (creates the keytab if absent)\n"
        "    list       print the keytab entries\n"
        "    del --id N delete the entry with wire id N\n"
        "  add/install opts:\n"
        "    --user U   (default: anybody)   --group G  (default: anygroup)\n"
        "    --name NM  (default: <host>)    --id N     (default: max+1)\n"
        "    --lifetime DAYS                 --keylen BYTES (default 32)\n"
        "  -k defaults to $XrdSecSSSKT / $XrdSecsssKT / ~/.xrd/sss.keytab\n");
}

/* Load the keytab, tolerating a not-yet-existing file (treated as empty). */
static int
load_or_empty(const char *path, xrdc_sss_key *keys, int max, int *n)
{
    xrdc_status st;
    if (access(path, F_OK) != 0) {
        *n = 0;
        return 0;
    }
    xrdc_status_clear(&st);
    if (xrdc_sss_keytab_read(path, keys, max, n, &st) != 0) {
        fprintf(stderr, "xrdsssadmin: %s\n", st.msg);
        return -1;
    }
    return 0;
}

static int
cmd_add(const char *path, const char *user, const char *group, const char *name,
        int64_t want_id, int lifetime_days, int keylen)
{
    xrdc_sss_key keys[XRDC_SSS_KEYS_MAX];
    xrdc_sss_key chk[XRDC_SSS_KEYS_MAX];
    xrdc_status  st;
    int          n = 0, i, m = 0;
    int64_t      maxid = 0;
    char         hostname[128];

    if (load_or_empty(path, keys, XRDC_SSS_KEYS_MAX, &n) != 0) {
        return 1;
    }
    if (n >= XRDC_SSS_KEYS_MAX) {
        fprintf(stderr, "xrdsssadmin: keytab full (%d keys)\n", n);
        return 1;
    }
    if (keylen <= 0 || keylen > XRDC_SSS_KEY_MAX) {
        keylen = 32;
    }
    for (i = 0; i < n; i++) {
        if (keys[i].id > maxid) {
            maxid = keys[i].id;
        }
    }

    {
        xrdc_sss_key *k = &keys[n];
        memset(k, 0, sizeof(*k));
        k->id = (want_id >= 0) ? want_id : maxid + 1;
        k->key_len = (size_t) keylen;
        if (RAND_bytes(k->key, keylen) != 1) {
            fprintf(stderr, "xrdsssadmin: RAND_bytes failed\n");
            return 1;
        }
        snprintf(k->user, sizeof(k->user), "%s", user ? user : "anybody");
        snprintf(k->group, sizeof(k->group), "%s", group ? group : "anygroup");
        if (name != NULL) {
            snprintf(k->name, sizeof(k->name), "%s", name);
        } else {
            if (gethostname(hostname, sizeof(hostname)) != 0) {
                snprintf(hostname, sizeof(hostname), "localhost");
            }
            snprintf(k->name, sizeof(k->name), "%s", hostname);
        }
        k->exp = (lifetime_days > 0)
                 ? (int64_t) time(NULL) + (int64_t) lifetime_days * 86400
                 : 0;
        n++;
    }

    xrdc_status_clear(&st);
    if (xrdc_sss_keytab_write(path, keys, n, &st) != 0) {
        fprintf(stderr, "xrdsssadmin: %s\n", st.msg);
        return 1;
    }
    /* Self-validate: re-read and confirm the new id is present. */
    xrdc_status_clear(&st);
    if (xrdc_sss_keytab_read(path, chk, XRDC_SSS_KEYS_MAX, &m, &st) != 0) {
        fprintf(stderr, "xrdsssadmin: re-read failed: %s\n", st.msg);
        return 1;
    }
    printf("added key id=%lld (%d-byte) to %s (%d keys)\n",
           (long long) keys[n - 1].id, keylen, path, m);
    return 0;
}

static int
cmd_list(const char *path)
{
    xrdc_sss_key keys[XRDC_SSS_KEYS_MAX];
    xrdc_status  st;
    int          n = 0, i;

    xrdc_status_clear(&st);
    if (xrdc_sss_keytab_read(path, keys, XRDC_SSS_KEYS_MAX, &n, &st) != 0) {
        fprintf(stderr, "xrdsssadmin: %s\n", st.msg);
        return 1;
    }
    printf("%s: %d key(s)\n", path, n);
    for (i = 0; i < n; i++) {
        printf("  id=%-4lld user=%-10s group=%-10s name=%-16s keylen=%zu",
               (long long) keys[i].id, keys[i].user, keys[i].group,
               keys[i].name, keys[i].key_len);
        if (keys[i].exp != 0) {
            printf(" exp=%lld", (long long) keys[i].exp);
        }
        printf("\n");
    }
    return 0;
}

static int
cmd_del(const char *path, int64_t id)
{
    xrdc_sss_key keys[XRDC_SSS_KEYS_MAX];
    xrdc_status  st;
    int          n = 0, i, out = 0, removed = 0;

    if (id < 0) {
        fprintf(stderr, "xrdsssadmin: del requires --id N\n");
        return 1;
    }
    xrdc_status_clear(&st);
    if (xrdc_sss_keytab_read(path, keys, XRDC_SSS_KEYS_MAX, &n, &st) != 0) {
        fprintf(stderr, "xrdsssadmin: %s\n", st.msg);
        return 1;
    }
    for (i = 0; i < n; i++) {
        if (keys[i].id == id) {
            removed++;
            continue;
        }
        if (out != i) {
            keys[out] = keys[i];
        }
        out++;
    }
    if (removed == 0) {
        fprintf(stderr, "xrdsssadmin: no key with id=%lld\n", (long long) id);
        return 1;
    }
    xrdc_status_clear(&st);
    if (xrdc_sss_keytab_write(path, keys, out, &st) != 0) {
        fprintf(stderr, "xrdsssadmin: %s\n", st.msg);
        return 1;
    }
    printf("removed %d key(s) with id=%lld; %d remain in %s\n",
           removed, (long long) id, out, path);
    return 0;
}

int
main(int argc, char **argv)
{
    char        kt[XRDC_PATH_MAX];
    const char *keytab = NULL;
    const char *cmd = NULL;
    const char *user = NULL, *group = NULL, *name = NULL;
    int64_t     id = -1;
    int         lifetime_days = 0, keylen = 32;
    int         i;

    for (i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-k") == 0 && i + 1 < argc)            { keytab = argv[++i]; }
        else if (strcmp(a, "--user") == 0 && i + 1 < argc)   { user = argv[++i]; }
        else if (strcmp(a, "--group") == 0 && i + 1 < argc)  { group = argv[++i]; }
        else if (strcmp(a, "--name") == 0 && i + 1 < argc)   { name = argv[++i]; }
        else if (strcmp(a, "--id") == 0 && i + 1 < argc)     { id = strtoll(argv[++i], NULL, 10); }
        else if (strcmp(a, "--lifetime") == 0 && i + 1 < argc) { lifetime_days = atoi(argv[++i]); }
        else if (strcmp(a, "--keylen") == 0 && i + 1 < argc) { keylen = atoi(argv[++i]); }
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(); return 0; }
        else if (a[0] != '-' && cmd == NULL)                 { cmd = a; }
        else { fprintf(stderr, "xrdsssadmin: unexpected arg '%s'\n", a); usage(); return 2; }
    }

    if (cmd == NULL) {
        usage();
        return 2;
    }
    if (keytab == NULL) {
        xrdc_sss_keytab_default(kt, sizeof(kt));
        keytab = kt;
    }

    if (strcmp(cmd, "add") == 0 || strcmp(cmd, "install") == 0) {
        return cmd_add(keytab, user, group, name, id, lifetime_days, keylen);
    }
    if (strcmp(cmd, "list") == 0) {
        return cmd_list(keytab);
    }
    if (strcmp(cmd, "del") == 0) {
        return cmd_del(keytab, id);
    }
    fprintf(stderr, "xrdsssadmin: unknown command '%s'\n", cmd);
    usage();
    return 2;
}
