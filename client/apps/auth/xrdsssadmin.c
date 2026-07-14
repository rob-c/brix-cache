/*
 * xrdsssadmin.c — manage an SSS (Simple Shared Secret) keytab.
 *
 * WHAT: `xrdsssadmin-brix [-k keytab] <add|list|del|install>` — create and maintain
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
#include "brix.h"
#include "auth/sss/sss_keytab.h"
#include "core/version.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>

static void
usage_fp(FILE *out)
{
    fprintf(out,
        "usage: xrdsssadmin-brix [-k/--keytab keytab] <command> [opts]\n"
        "  commands:\n"
        "    add        mint a new random key and append it\n"
        "    install    same as add (creates the keytab if absent)\n"
        "    list       print the keytab entries\n"
        "    del --id N delete the entry with wire id N\n"
        "  add/install opts:\n"
        "    --user U   (default: anybody)   --group G  (default: anygroup)\n"
        "    --name NM  (default: <host>)    --id N     (default: max+1)\n"
        "    --lifetime DAYS                 --keylen BYTES (default 32)\n"
        "  -k, --keytab defaults to $XRDC_SSS_KEYTAB / $XrdSecSSSKT / $XrdSecsssKT /\n"
        "               ~/.xrd/sss.keytab\n"
        "  --version  print version and exit\n"
        BRIX_USAGE_FOOTER("xrdsssadmin-brix"));
}

static void
usage(void)
{
    usage_fp(stderr);
}

/* Load the keytab, tolerating a not-yet-existing file (treated as empty). */
static int
load_or_empty(const char *path, brix_sss_key *keys, int max, int *n)
{
    brix_status st;
    if (access(path, F_OK) != 0) {
        *n = 0;
        return 0;
    }
    brix_status_clear(&st);
    if (brix_sss_keytab_read(path, keys, max, n, &st) != 0) {
        fprintf(stderr, "xrdsssadmin-brix: %s\n", st.msg);
        return -1;
    }
    return 0;
}

/*
 * add_args_t — the parsed `add`/`install` request.
 *
 * WHAT:  bundles the six user-supplied fields of a key-add into one value.
 * WHY:   collapses cmd_add's 7-parameter signature (path + six knobs) to two
 *        (path + this struct), matching the coding-standard param-count gate
 *        while keeping every field's meaning and default behavior unchanged.
 * HOW:   populated once in main() from argv, then passed by const pointer to
 *        cmd_add(); NULL/<=0 sentinels still select the documented defaults.
 */
typedef struct {
    const char *user;          /* NULL → "anybody"           */
    const char *group;         /* NULL → "anygroup"          */
    const char *name;          /* NULL → local hostname      */
    int64_t     want_id;       /* <0   → max existing id + 1  */
    int         lifetime_days; /* <=0  → no expiry            */
    int         keylen;        /* <=0 or >max → 32 bytes      */
} add_args_t;

/*
 * add_fill_entry — populate one keytab slot from an add request.
 *
 * WHAT:  fills *k (id/key/user/group/name/exp) for a new key of keylen bytes.
 * WHY:   isolates the pure per-entry construction (defaults + RAND_bytes) from
 *        cmd_add's file I/O, keeping each function single-purpose and cutting
 *        the orchestrator's branch count.
 * HOW:   zero-init, resolve id/defaults, mint a random key; returns 0 on
 *        success or -1 if RAND_bytes fails (message already printed).
 */
static int
add_fill_entry(brix_sss_key *k, const add_args_t *a, int64_t maxid, int keylen)
{
    char hostname[128];

    memset(k, 0, sizeof(*k));
    k->id = (a->want_id >= 0) ? a->want_id : maxid + 1;
    k->key_len = (size_t) keylen;
    if (RAND_bytes(k->key, keylen) != 1) {
        fprintf(stderr, "xrdsssadmin-brix: RAND_bytes failed\n");
        return -1;
    }
    snprintf(k->user, sizeof(k->user), "%s", a->user ? a->user : "anybody");
    snprintf(k->group, sizeof(k->group), "%s", a->group ? a->group : "anygroup");
    if (a->name != NULL) {
        snprintf(k->name, sizeof(k->name), "%s", a->name);
    } else {
        if (gethostname(hostname, sizeof(hostname)) != 0) {
            snprintf(hostname, sizeof(hostname), "localhost");
        }
        snprintf(k->name, sizeof(k->name), "%s", hostname);
    }
    k->exp = (a->lifetime_days > 0)
             ? (int64_t) time(NULL) + (int64_t) a->lifetime_days * 86400
             : 0;
    return 0;
}

/*
 * cmd_add — mint and append a new random SSS key, then self-validate.
 *
 * WHAT:  loads the keytab, appends one freshly generated key, writes it back,
 *        and re-reads to confirm the mutation landed.
 * WHY:   the `add`/`install` subcommand; delegates per-entry construction to
 *        add_fill_entry so this function is just the load/append/write/verify
 *        orchestration.
 * HOW:   load-or-empty → capacity/keylen guards → compute max id → fill slot n
 *        → write → re-read; returns 0 on success, 1 on any error.
 */
static int
cmd_add(const char *path, const add_args_t *a)
{
    brix_sss_key keys[XRDC_SSS_KEYS_MAX];
    brix_sss_key chk[XRDC_SSS_KEYS_MAX];
    brix_status  st;
    int          n = 0, i, m = 0;
    int          keylen = a->keylen;
    int64_t      maxid = 0;

    if (load_or_empty(path, keys, XRDC_SSS_KEYS_MAX, &n) != 0) {
        return 1;
    }
    if (n >= XRDC_SSS_KEYS_MAX) {
        fprintf(stderr, "xrdsssadmin-brix: keytab full (%d keys)\n", n);
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

    if (add_fill_entry(&keys[n], a, maxid, keylen) != 0) {
        return 1;
    }
    n++;

    brix_status_clear(&st);
    if (brix_sss_keytab_write(path, keys, n, &st) != 0) {
        fprintf(stderr, "xrdsssadmin-brix: %s\n", st.msg);
        return 1;
    }
    /* Self-validate: re-read and confirm the new id is present. */
    brix_status_clear(&st);
    if (brix_sss_keytab_read(path, chk, XRDC_SSS_KEYS_MAX, &m, &st) != 0) {
        fprintf(stderr, "xrdsssadmin-brix: re-read failed: %s\n", st.msg);
        return 1;
    }
    printf("added key id=%lld (%d-byte) to %s (%d keys)\n",
           (long long) keys[n - 1].id, keylen, path, m);
    return 0;
}

static int
cmd_list(const char *path)
{
    brix_sss_key keys[XRDC_SSS_KEYS_MAX];
    brix_status  st;
    int          n = 0, i;

    brix_status_clear(&st);
    if (brix_sss_keytab_read(path, keys, XRDC_SSS_KEYS_MAX, &n, &st) != 0) {
        fprintf(stderr, "xrdsssadmin-brix: %s\n", st.msg);
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
    brix_sss_key keys[XRDC_SSS_KEYS_MAX];
    brix_status  st;
    int          n = 0, i, out = 0, removed = 0;

    if (id < 0) {
        fprintf(stderr, "xrdsssadmin-brix: del requires --id N\n");
        return 1;
    }
    brix_status_clear(&st);
    if (brix_sss_keytab_read(path, keys, XRDC_SSS_KEYS_MAX, &n, &st) != 0) {
        fprintf(stderr, "xrdsssadmin-brix: %s\n", st.msg);
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
        fprintf(stderr, "xrdsssadmin-brix: no key with id=%lld\n", (long long) id);
        return 1;
    }
    brix_status_clear(&st);
    if (brix_sss_keytab_write(path, keys, out, &st) != 0) {
        fprintf(stderr, "xrdsssadmin-brix: %s\n", st.msg);
        return 1;
    }
    printf("removed %d key(s) with id=%lld; %d remain in %s\n",
           removed, (long long) id, out, path);
    return 0;
}

/*
 * cli_opts_t — everything parsed off argv for one invocation.
 *
 * WHAT:  the subcommand name, the keytab path, and the add/del knobs (add_args
 *        fields plus the shared --id used by both `add` and `del`).
 * WHY:   lets the argv loop live in a single-purpose parser that fills this
 *        struct, so main() reduces to parse → resolve-keytab → dispatch.
 * HOW:   zero/default-initialised in main(), populated by parse_opts(), then
 *        read by the subcommand handlers.
 */
typedef struct {
    const char *cmd;    /* first non-flag positional; NULL if none */
    const char *keytab; /* -k/--keytab; NULL → resolved default    */
    add_args_t  add;    /* --user/--group/--name/--lifetime/--keylen */
    int64_t     id;     /* --id; shared by add (want_id) and del    */
} cli_opts_t;

/* Kind of value a value-taking flag consumes. */
typedef enum { OPT_STR, OPT_I32, OPT_I64 } opt_kind;

/*
 * opt_spec — one value-taking flag: its two accepted spellings and where its
 *            value lands in a cli_opts_t.
 *
 * WHAT:  descriptor row {long name, short/alias name, value kind, field offset}.
 * WHY:   expresses the flag ladder as data (coding-standard §8.6) so parse_opts
 *        is a single loop over the table instead of a per-flag if-chain.
 * HOW:   apply_opt() writes the parsed value at (char*)o + off according to
 *        kind; alt may be NULL when a flag has only one spelling.
 */
typedef struct {
    const char *name;
    const char *alt;
    opt_kind    kind;
    size_t      off;
} opt_spec;

static const opt_spec OPTS[] = {
    { "--keytab",   "-k", OPT_STR, offsetof(cli_opts_t, keytab)            },
    { "--user",     NULL, OPT_STR, offsetof(cli_opts_t, add.user)          },
    { "--group",    NULL, OPT_STR, offsetof(cli_opts_t, add.group)         },
    { "--name",     NULL, OPT_STR, offsetof(cli_opts_t, add.name)          },
    { "--id",       NULL, OPT_I64, offsetof(cli_opts_t, id)                },
    { "--lifetime", NULL, OPT_I32, offsetof(cli_opts_t, add.lifetime_days) },
    { "--keylen",   NULL, OPT_I32, offsetof(cli_opts_t, add.keylen)        },
};

/*
 * apply_opt — store one value-taking flag's argument into *o.
 *
 * WHAT:  parses val per s->kind and writes it at the struct field s->off.
 * WHY:   keeps the string/int/int64 conversion in one place so the parser loop
 *        stays flat and adding a flag is one table row.
 * HOW:   pointer-arithmetic to the target field, then the kind-appropriate
 *        conversion (identical strtoll/atoi calls as the original loop).
 */
static void
apply_opt(cli_opts_t *o, const opt_spec *s, const char *val)
{
    char *base = (char *) o;

    if (s->kind == OPT_STR) {
        *(const char **) (base + s->off) = val;
    } else if (s->kind == OPT_I64) {
        *(int64_t *) (base + s->off) = strtoll(val, NULL, 10);
    } else {
        *(int *) (base + s->off) = atoi(val);
    }
}

/*
 * match_opt — find the value-taking flag matching token a, if any.
 *
 * WHAT:  returns the OPTS row whose name or alt equals a, else NULL.
 * WHY:   isolates the table scan so parse_opts reads as flag/positional/error.
 * HOW:   linear scan comparing a against each row's two spellings.
 */
static const opt_spec *
match_opt(const char *a)
{
    size_t i;

    for (i = 0; i < sizeof(OPTS) / sizeof(OPTS[0]); i++) {
        if (strcmp(a, OPTS[i].name) == 0
            || (OPTS[i].alt != NULL && strcmp(a, OPTS[i].alt) == 0)) {
            return &OPTS[i];
        }
    }
    return NULL;
}

/*
 * parse_opts — walk argv into a cli_opts_t.
 *
 * WHAT:  fills *o from argv; returns 0 to continue, or a process exit code
 *        (0 for -h) when the caller should stop immediately.
 * WHY:   moves the option-scanning ladder out of main(), keeping the
 *        orchestrator flat; behavior (flags, arg-count checks, error text,
 *        exit codes) is identical to the original inline loop.
 * HOW:   for each token: a table-listed value flag with a following arg is
 *        applied via apply_opt; else -h prints usage and stops (exit 0); else
 *        the first bare word is the command; else usage + stop (exit 2). *stop
 *        is set non-zero when the returned code is a process exit code.
 */
static int
parse_opts(int argc, char **argv, cli_opts_t *o, int *stop)
{
    int i;

    *stop = 0;
    for (i = 1; i < argc; i++) {
        const char     *a = argv[i];
        const opt_spec *s = match_opt(a);

        if (s != NULL && i + 1 < argc) {
            apply_opt(o, s, argv[++i]);
        } else if (strcmp(a, "-h") == 0) {
            usage(); *stop = 1; return 0;  /* C1 */
        } else if (a[0] != '-' && o->cmd == NULL) {
            o->cmd = a;
        } else {
            fprintf(stderr, "xrdsssadmin-brix: unexpected arg '%s'\n", a);
            usage(); *stop = 1; return 2;
        }
    }
    return 0;
}

/*
 * dispatch_cmd — run the resolved subcommand.
 *
 * WHAT:  matches o->cmd against the {add,install,list,del} table and calls the
 *        corresponding handler with the resolved keytab path.
 * WHY:   replaces main()'s trailing if-ladder with a table-driven lookup so the
 *        orchestrator stays flat and new subcommands are one row.
 * HOW:   linear scan of a static-const descriptor table; on no match print the
 *        unknown-command error + usage and return 2 (unchanged behavior).
 */
static int
dispatch_cmd(const cli_opts_t *o, const char *keytab)
{
    add_args_t add = o->add;
    add.want_id = o->id;

    if (strcmp(o->cmd, "add") == 0 || strcmp(o->cmd, "install") == 0) {
        return cmd_add(keytab, &add);
    }
    if (strcmp(o->cmd, "list") == 0) {
        return cmd_list(keytab);
    }
    if (strcmp(o->cmd, "del") == 0) {
        return cmd_del(keytab, o->id);
    }
    fprintf(stderr, "xrdsssadmin-brix: unknown command '%s'\n", o->cmd);
    usage();
    return 2;
}

int
main(int argc, char **argv)
{
    char       kt[XRDC_PATH_MAX];
    cli_opts_t o = { NULL, NULL, { NULL, NULL, NULL, -1, 0, 32 }, -1 };
    int        rc, stop = 0;

    /* --help / --version before loop (not on shared parser). */
    if (argc >= 2) {
        if (strcmp(argv[1], "--version") == 0) {
            printf("xrdsssadmin-brix (BriX-Cache client) %s\n", brix_client_version());
            return 0;
        }
        if (strcmp(argv[1], "--help") == 0) {
            usage_fp(stdout);
            return 0;
        }
    }

    rc = parse_opts(argc, argv, &o, &stop);
    if (stop) {
        return rc;
    }

    if (o.cmd == NULL) {
        usage();
        return 2;
    }
    if (o.keytab == NULL) {
        brix_sss_keytab_default(kt, sizeof(kt));
        o.keytab = kt;
    }

    return dispatch_cmd(&o, o.keytab);
}
