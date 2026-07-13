/*
 * xrdgsiproxy.c — create / inspect / destroy an X.509 GSI proxy.
 *
 * WHAT: `xrdgsiproxy init [-valid H[:M]] [-cert F] [-key F] [-out F] [-bits N]`,
 *       `xrdgsiproxy info [-file F]`, `xrdgsiproxy destroy [-file F]`.
 * WHY:  Users need a proxy before any GSI xrdcp/xrdfs; pure local OpenSSL via the
 *       client library (lib/proxy.c). libXrdCl/XrdCrypto-free.
 * HOW:  Thin arg parse → subcommand table (init/info/destroy) → per-cmd helper
 *       → brix_proxy_create/info/destroy.
 */
#include "brix.h"
#include "core/compat/crypto.h"
#include "core/version.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int
parse_valid(const char *s)
{
    /* "HH:MM" → hours (rounded up on minutes); a bare integer → hours. */
    const char *colon = strchr(s, ':');
    if (colon != NULL) {
        int h = atoi(s);
        int m = atoi(colon + 1);
        int hours = h + (m > 0 ? 1 : 0);
        return hours > 0 ? hours : 12;
    }
    return atoi(s) > 0 ? atoi(s) : 12;
}

static void
usage_fp(FILE *out)
{
    fprintf(out,
        "usage: xrdgsiproxy <init|info|destroy> [opts]\n"
        "  init    [-valid/--valid H[:M]] [-cert/--cert FILE] [-key/--key FILE]\n"
        "          [-out/--out FILE] [-bits/--bits N]\n"
        "  info    [-file/--file FILE]\n"
        "  destroy [-file/--file FILE]\n"
        BRIX_USAGE_FOOTER("xrdgsiproxy"));
}

static void
usage(void)
{
    usage_fp(stderr);
}

/* Cursor over the argument vector shared by every option parser. */
typedef struct {
    char **argv;
    int    argc;
    int    i;
} arg_cursor;

/*
 * WHAT: Match the argument at the cursor against a long/short option pair and,
 *       on a hit, capture the following argument into *out.
 * WHY:  Every subcommand parses options as identical `-x`/`--x VALUE` pairs; a
 *       single matcher removes the repeated four-term boolean ladder that drove
 *       main's complexity while keeping the exact accepted spellings.
 * HOW:  On a spelling match with a value available, advance the cursor past the
 *       value, store it, and return 1; otherwise leave state untouched, return 0.
 */
static int
opt_take_value(arg_cursor *ac, const char *short_name, const char *long_name,
               const char **out)
{
    char *cur = ac->argv[ac->i];

    if ((strcmp(cur, short_name) == 0 || strcmp(cur, long_name) == 0)
        && ac->i + 1 < ac->argc)
    {
        *out = ac->argv[++ac->i];
        return 1;
    }
    return 0;
}

/*
 * WHAT: Parse the `init` option vector into a zeroed brix_proxy_opts.
 * WHY:  Isolates init's five-option grammar (valid/cert/key/out/bits) from the
 *       dispatch flow; -valid and -bits need numeric conversion, the rest are
 *       raw argv pointers, matching the original per-flag behavior exactly.
 * HOW:  Walk argv[2..]; each flag is an option pair captured via opt_take_value
 *       into a scratch string then applied. Any unmatched token → 0 (usage).
 */
static int
init_parse_opts(int argc, char **argv, brix_proxy_opts *o)
{
    arg_cursor  ac = { argv, argc, 0 };
    const char *val;

    memset(o, 0, sizeof(*o));

    for (ac.i = 2; ac.i < argc; ac.i++) {
        val = NULL;
        if (opt_take_value(&ac, "-valid", "--valid", &val)) {
            o->valid_hours = parse_valid(val);
        } else if (opt_take_value(&ac, "-cert", "--cert", &val)) {
            o->user_cert = val;
        } else if (opt_take_value(&ac, "-key", "--key", &val)) {
            o->user_key = val;
        } else if (opt_take_value(&ac, "-out", "--out", &val)) {
            o->out_path = val;
        } else if (opt_take_value(&ac, "-bits", "--bits", &val)) {
            o->bits = atoi(val);
        } else {
            return 0;
        }
    }
    return 1;
}

/*
 * WHAT: Run `xrdgsiproxy init`, returning the process exit code.
 * WHY:  Owns init end-to-end — parse, create the proxy, then echo it back —
 *       so the dispatcher stays a flat table lookup.
 * HOW:  Parse opts (usage=50 on error); brix_proxy_create failure surfaces via
 *       brix_shellcode; success re-reads the fresh proxy with brix_proxy_info.
 */
static int
cmd_init(int argc, char **argv, brix_status *st)
{
    brix_proxy_opts o;
    int             rc;

    if (!init_parse_opts(argc, argv, &o)) {
        usage();
        return 50;
    }
    rc = brix_proxy_create(&o, st);
    if (rc != 0) {
        fprintf(stderr, "xrdgsiproxy: init: %s\n", st->msg);
        return brix_shellcode(st);
    }
    return brix_proxy_info(o.out_path, stdout, st);  /* echo what we made */
}

/*
 * WHAT: Parse the shared `-file`/`--file FILE` option of info/destroy.
 * WHY:  info and destroy accept exactly one option with identical grammar;
 *       one parser keeps their acceptance sets in lockstep.
 * HOW:  Walk argv[2..] capturing the file path; any other token → 0 (usage).
 */
static int
file_parse_opts(int argc, char **argv, const char **file)
{
    arg_cursor ac = { argv, argc, 0 };

    *file = NULL;
    for (ac.i = 2; ac.i < argc; ac.i++) {
        if (!opt_take_value(&ac, "-file", "--file", file)) {
            return 0;
        }
    }
    return 1;
}

/*
 * WHAT: Run `xrdgsiproxy info`, returning the process exit code.
 * WHY:  info is tolerant of an absent proxy (mirroring stock xrdgsiproxy): a
 *       missing file is a soft "not found" notice + exit 1, not a hard error.
 * HOW:  Parse -file; brix_proxy_info on success returns 0; XRDC_ENOENT prints
 *       the notice and returns 1; any other failure escalates via brix_shellcode.
 */
static int
cmd_info(int argc, char **argv, brix_status *st)
{
    const char *file;
    int         rc;

    if (!file_parse_opts(argc, argv, &file)) {
        usage();
        return 50;
    }
    rc = brix_proxy_info(file, stdout, st);
    if (rc == 0) {
        return 0;
    }
    if (st->kxr == XRDC_ENOENT) {
        printf("%s\n", st->msg);
        return 1;
    }
    fprintf(stderr, "xrdgsiproxy: info: %s\n", st->msg);
    return brix_shellcode(st);
}

/*
 * WHAT: Run `xrdgsiproxy destroy`, returning the process exit code.
 * WHY:  destroy shares info's -file grammar but has no absent-proxy tolerance;
 *       any failure is a hard error.
 * HOW:  Parse -file; brix_proxy_destroy success → 0, failure → brix_shellcode.
 */
static int
cmd_destroy(int argc, char **argv, brix_status *st)
{
    const char *file;
    int         rc;

    if (!file_parse_opts(argc, argv, &file)) {
        usage();
        return 50;
    }
    rc = brix_proxy_destroy(file, st);
    if (rc == 0) {
        return 0;
    }
    fprintf(stderr, "xrdgsiproxy: destroy: %s\n", st->msg);
    return brix_shellcode(st);
}

/* Subcommand dispatch table: verb → handler (parse + execute). */
typedef int (*cmd_fn)(int argc, char **argv, brix_status *st);

static const struct {
    const char *name;
    cmd_fn      fn;
} cmd_table[] = {
    { "init",    cmd_init    },
    { "info",    cmd_info    },
    { "destroy", cmd_destroy },
};

/*
 * WHAT: Resolve a verb string to its handler, or NULL if unknown.
 * WHY:  Keeps the table private and main a flat lookup + call.
 * HOW:  Linear scan of the small fixed table.
 */
static cmd_fn
cmd_lookup(const char *cmd)
{
    size_t n;

    for (n = 0; n < sizeof(cmd_table) / sizeof(cmd_table[0]); n++) {
        if (strcmp(cmd, cmd_table[n].name) == 0) {
            return cmd_table[n].fn;
        }
    }
    return NULL;
}

int
main(int argc, char **argv)
{
    brix_status  st;
    const char  *cmd;
    cmd_fn       fn;

    if (argc < 2) { usage(); return 50; }
    cmd = argv[1];

    /* --help / --version as the first argument. */
    if (strcmp(cmd, "--version") == 0) {
        printf("xrdgsiproxy (BriX-Cache client) %s\n", brix_client_version());
        return 0;
    }
    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        usage_fp(stdout);
        return 0;
    }

    brix_crypto_init();
    brix_status_clear(&st);

    fn = cmd_lookup(cmd);
    if (fn == NULL) {
        usage();
        return 50;
    }
    return fn(argc, argv, &st);
}
