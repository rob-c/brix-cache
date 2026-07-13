/*
 * xrdfs.c - (kept) routing + shared helpers
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"
#include "core/version.h"
#include "cli/suggest.h"    /* brix_suggest(): did-you-mean at unknown-command sites */
#include "cli/cli_hint.h"   /* brix_cli_hint(): TTY-gated hint output */

volatile sig_atomic_t tail_stop = 0;

const xrdfs_cmd COMMANDS[] = {
    { "stat",     do_stat,     "stat [-j] <path>" },
    { "ls",       do_ls,       "ls [-l] [-R] [-h, --human] [-j] [path]" },
    { "du",       do_du,       "du [-h, --human] [-j] <path>...  (recursive size)" },
    { "df",       do_df,       "df [-h, --human] [path]  (disk space, oss.* Qspace)" },
    { "tree",     do_tree,     "tree [-d, --dirs-only] [-L, --depth N] [path]" },
    { "find",     do_find,     "find <path> [-name GLOB] [-type f|d] [-size +N|-N]" },
    { "mkdir",    do_mkdir,    "mkdir [-p] [-m mode] <path>" },
    { "rm",       do_rm,       "rm [-r] [-v, --verbose] <path>" },
    { "rmdir",    do_rmdir,    "rmdir <path>" },
    { "mv",       do_mv,       "mv <src> <dst>" },
    { "chmod",    do_chmod,    "chmod [-R] <path> <octal-mode>" },
    { "touch",    do_touch,    "touch [-c] [-a] [-m] [-t, --timestamp STAMP] <path>" },
    { "ln",       do_ln,       "ln [-s] [-f] <target> <linkpath>" },
    { "readlink", do_readlink, "readlink <path>" },
    { "truncate", do_truncate, "truncate <path> <size>" },
    { "cat",      do_cat,      "cat [-z codec] <path>" },
    { "head",     do_head,     "head [-c BYTES] [-n LINES] <path>" },
    { "tail",     do_tail,     "tail [-c BYTES] [-n LINES] [-f] <path>" },
    { "wc",       do_wc,       "wc [-c] [-l] [-w] <path>" },
    { "grep",     do_grep,     "grep [-i] [-n] PATTERN <path>" },
    { "hexdump",  do_hexdump,  "hexdump [-n BYTES] <path>" },
    { "dd",       do_dd,       "dd [if=]<path> [bs=N] [skip=N] [count=N] [rate=R]" },
    { "upload",   do_upload,   "upload [bs=N] [rate=R] [-f] [--io-uring on|off|auto] <localfile|-> <remote>" },
    { "download", do_download, "download [bs=N] [rate=R] [-f] [--io-uring on|off|auto] <remote> [localfile|-]" },
    { "cmp",      do_cmp,      "cmp <path1> <path2>" },
    { "cksum",    do_cksum,    "cksum [-a algo] <path>" },
    { "xattr",    do_xattr,    "xattr ls|get|set|rm <path> [name] [value]" },
    { "readv",    do_readv,    "readv <path> <off len>...  (scatter-gather read)" },
    { "writev",   do_writev,   "writev <path> <off hexdata>...  (scatter-gather write)" },
    { "locate",   do_locate,   "locate <path>" },
    { "query",    do_query,    "query <config|space|checksum|stats> [args]" },
    { "statvfs",  do_statvfs,  "statvfs [path]" },
    { "prepare",  do_prepare,  "prepare [-s|-w|-c|-f|-e] <path>..." },
    { "stage",    do_stage,    "stage [--wait[=SECS]] <path>..." },
    { "evict",    do_evict,    "evict <path>..." },
    { "explain",  do_explain,  "explain (connection/auth/TLS facts)" },
    { NULL, NULL, NULL }
};



/* Poll a path's residency until it is online (kXR_offline clears) or `timeout_s`
 * elapses. Returns 0 online, 1 still offline at timeout, -1 on a stat error. */
int
wait_online(brix_conn *c, const char *path, int timeout_s, brix_status *st)
{
    int waited = 0;
    for (;;) {
        brix_statinfo si;
        struct timespec ts;
        brix_status_clear(st);
        if (brix_stat(c, path, &si, st) != 0) { return -1; }
        if (!(si.flags & kXR_offline)) { return 0; }
        if (waited >= timeout_s) { return 1; }
        ts.tv_sec = 1; ts.tv_nsec = 0;
        nanosleep(&ts, NULL);
        waited++;
    }
}


/* §15: narrate the connection — protocol caps, signing, auth choice, TLS. The
 * session is already established (main connected before dispatch); this is a
 * read-only report over the conn fields conn.c/auth.c populated. */
int
do_explain(brix_conn *c, const char *cwd, int argc, char **argv)
{
    (void) cwd; (void) argc; (void) argv;
    brix_explain_conn(c, &c->opts, stdout);
    return 0;
}


/*
 * WHAT: emit the "unknown command '<name>'" error plus a TTY did-you-mean hint.
 * WHY:  spec WS-7 — unknown-subcommand sites must offer a did-you-mean hint for
 *       interactive users without polluting pipeline output (C3). Factored out
 *       of dispatch() so the router stays a flat table lookup.
 * HOW:  build a NULL-terminated name array from COMMANDS[] (bounded), then pass
 *       it to brix_suggest() (Damerau-Levenshtein distance ≤ 2 match).
 */
static void
dispatch_unknown(const char *name)
{
    int                  ncmds;
    const char          *names[48 + 1]; /* COMMANDS has ≤ 47 entries */
    const xrdfs_cmd     *h;
    const char          *suggestion;

    ncmds = 0;
    for (h = COMMANDS; h->name != NULL && ncmds < 48; h++) {
        names[ncmds++] = h->name;
    }
    names[ncmds] = NULL;

    fprintf(stderr, "xrdfs: unknown command '%s'\n", name);
    suggestion = brix_suggest(name, names);
    if (suggestion != NULL) {
        brix_cli_hint("hint: did you mean '%s'?\n", suggestion);
    }
}


/*
 * WHAT: handle the REPL-builtin verbs (exit/quit/pwd/cd/help) that are not in
 *       COMMANDS[]. Returns 1 when it owned the verb (all builtins yield shell
 *       code 0); returns 0 when tok[0] is not a builtin.
 * WHY:  splitting the builtin ladder out of dispatch() drops the router's
 *       branch count below the complexity gate while freezing behavior/output.
 * HOW:  string-compare ladder with early return; cd rebuilds cwd via build_path,
 *       exit/quit set *quit. State (cwd/quit) is passed in explicitly.
 */
static int
dispatch_builtin(char *cwd, size_t cwdsz, int ntok, char **tok, int *quit)
{
    if (strcmp(tok[0], "exit") == 0 || strcmp(tok[0], "quit") == 0) {
        if (quit != NULL) { *quit = 1; }
        return 1;
    }
    if (strcmp(tok[0], "pwd") == 0) {
        printf("%s\n", cwd);
        return 1;
    }
    if (strcmp(tok[0], "cd") == 0) {
        char next[XRDC_PATH_MAX];
        build_path(cwd, ntok >= 2 ? tok[1] : "/", next, sizeof(next));
        snprintf(cwd, cwdsz, "%s", next);
        return 1;
    }
    if (strcmp(tok[0], "help") == 0) {
        for (const xrdfs_cmd *h = COMMANDS; h->name != NULL; h++) {
            printf("  %s\n", h->help);
        }
        printf("  cd <path> | pwd | help | exit\n");
        return 1;
    }
    return 0;
}


/* Run one tokenized command. cwd/cwdsz hold the mutable working directory (for
 * the REPL's cd/pwd). Returns a shell code; sets *quit when asked to leave. */
int
dispatch(brix_conn *c, char *cwd, size_t cwdsz, int ntok, char **tok, int *quit)
{
    const xrdfs_cmd *cmd;

    if (ntok == 0) {
        return 0;
    }
    if (dispatch_builtin(cwd, cwdsz, ntok, tok, quit)) {
        return 0;   /* all REPL builtins yield shell code 0 */
    }

    cmd = find_command(tok[0]);
    if (cmd == NULL) {
        dispatch_unknown(tok[0]);
        return 50;
    }
    /* <cmd> --help: print the one-line synopsis for this command. */
    if (ntok >= 2 && strcmp(tok[1], "--help") == 0) {
        printf("usage: xrdfs <endpoint> %s\n", cmd->help);
        printf(BRIX_USAGE_FOOTER("xrdfs"));
        return 0;
    }
    return cmd->fn(c, cwd, ntok, tok);
}


/* interactive shell                                                   */

int
tokenize(char *line, char **tok, int maxtok)
{
    int   n = 0;
    char *p = line;

    while (*p != '\0' && n < maxtok) {
        while (*p != '\0' && isspace((unsigned char) *p)) { p++; }
        if (*p == '\0') { break; }
        tok[n++] = p;
        while (*p != '\0' && !isspace((unsigned char) *p)) { p++; }
        if (*p != '\0') { *p++ = '\0'; }
    }
    return n;
}


int
repl(brix_conn *c, const char *host, int port)
{
    char    cwd[XRDC_PATH_MAX] = "/";
    char   *line = NULL;
    size_t  cap = 0;
    int     last = 0;

    for (;;) {
        char   *tok[XRDFS_MAXTOK];
        int     ntok, quit = 0;
        ssize_t r;

        printf("[%s:%d] %s > ", host, port, cwd);
        fflush(stdout);

        r = getline(&line, &cap, stdin);
        if (r < 0) {
            printf("\n");
            break;   /* EOF */
        }
        ntok = tokenize(line, tok, XRDFS_MAXTOK);
        last = dispatch(c, cwd, sizeof(cwd), ntok, tok, &quit);
        if (quit) {
            break;
        }
    }
    free(line);
    return last;
}


/* main                                                                */

/*
 * usage_fp — print xrdfs usage to the given stream.
 * WHY: --help (WS-2) goes to stdout; no-arg / parse-error goes to stderr.
 */
static void
usage_fp(FILE *out)
{
    fprintf(out,
        "usage: xrdfs [opts] host[:port]|root[s]://host[:port]|http[s]|dav[s]://host/path [command [args]]\n"
        "  with no command, drops into an interactive shell (root:// only).\n"
        "  opts:\n"
        "    --tls --notlsok --noverifyhost   in-protocol TLS controls\n"
        "    --auth <gsi|ztn|krb5|sss|unix>   force an auth protocol (root://)\n"
        "    --token TOK | -T TOK             bearer token for http(s)/WebDAV ($BEARER_TOKEN)\n"
        "    --version                         print version and exit\n"
        "  http(s)/WebDAV endpoints support read-only metadata: ls, stat\n"
        "  commands (root://):\n"
        "    stat ls du df tree find mkdir rm rmdir mv chmod touch ln readlink\n"
        "    truncate cat head tail wc grep hexdump dd upload download cmp cksum\n"
        "    xattr readv writev locate query statvfs prepare stage evict explain\n"
        "      (cd/pwd/help/exit in the shell)\n"
        "    (<cmd> --help prints per-command usage)\n"
        BRIX_USAGE_FOOTER("xrdfs"));
}

void
usage(void)
{
    usage_fp(stderr);
}


/*
 * WHAT: outcome of the leading-option scan: how far argv was consumed, the
 *       optional WebDAV bearer token, and whether an early-exit verb (--version/
 *       --help/-h) already handled everything (with its exit code).
 * WHY:  lets parse_global_opts() report all three back to main() without new
 *       globals, so main() stays a thin driver.
 */
typedef struct {
    int         argi;        /* index of the first non-option argv token   */
    const char *web_token;   /* --token / -T bearer (NULL = env fallback)  */
    int         done;        /* 1 = an early-exit verb fired; use exit_code */
    int         exit_code;   /* process exit code when done == 1           */
} xrdfs_optscan;

/*
 * WHAT: handle the early-exit option verbs (--version / --help / -h). Returns 1
 *       (and prints) when a==one of them; 0 otherwise.
 * WHY:  these three verbs terminate option parsing with side effects; pulling
 *       them out keeps parse_global_opts()'s branch count under the gate.
 * HOW:  --version/--help go to stdout (WS-2), -h keeps its stderr usage (C1).
 */
static int
opt_early_exit(const char *a)
{
    if (strcmp(a, "--version") == 0) {
        printf("xrdfs (BriX-Cache client) %s\n", brix_client_version());
        return 1;
    }
    if (strcmp(a, "--help") == 0) {
        usage_fp(stdout);    /* --help → stdout (WS-2) */
        return 1;
    }
    if (strcmp(a, "-h") == 0) {
        usage();             /* -h keeps existing stderr behavior (C1) */
        return 1;
    }
    return 0;
}


/*
 * WHAT: apply one two-argument option (--auth / --token|-T / --capture) at
 *       sc->argi. Returns 1 when consumed (advancing argi by 2), 0 otherwise.
 * WHY:  the value-flags carry the argi+1<argc guard and are the compound arms
 *       of the ladder; isolating them keeps opt_apply_flag() under the gate.
 * HOW:  each arm checks the token name and that a value follows, exactly as the
 *       original inline loop did.
 */
static int
opt_apply_valueflag(int argc, char **argv, brix_opts *opts, xrdfs_optscan *sc)
{
    char *a = argv[sc->argi];
    if (strcmp(a, "--auth") == 0 && sc->argi + 1 < argc) {
        opts->auth_force = argv[sc->argi + 1]; sc->argi += 2; return 1;
    }
    if ((strcmp(a, "--token") == 0 || strcmp(a, "-T") == 0)
        && sc->argi + 1 < argc) {
        sc->web_token = argv[sc->argi + 1]; sc->argi += 2; return 1;   /* http(s)/WebDAV bearer */
    }
    if (strcmp(a, "--capture") == 0 && sc->argi + 1 < argc) {
        opts->capture = argv[sc->argi + 1]; sc->argi += 2; return 1;
    }
    return 0;
}


/*
 * WHAT: apply one leading -/-- option token at sc->argi to *opts, advancing
 *       sc->argi. Returns 1 when the token was a recognized option, 0 when it
 *       is not an option we consume (caller stops the scan).
 * WHY:  the flag ladder is the bulk of parse_global_opts()'s branches; keeping
 *       the flag arms in helpers holds each function under the gate.
 * HOW:  boolean flags handled inline here; two-arg flags delegate to
 *       opt_apply_valueflag(). Relative order matches the original inline loop.
 */
static int
opt_apply_flag(int argc, char **argv, brix_opts *opts, xrdfs_optscan *sc)
{
    char *a = argv[sc->argi];
    if (strcmp(a, "--no-cwd") == 0)        { sc->argi++; return 1; }
    if (strcmp(a, "--tls") == 0)           { opts->want_tls = 1; sc->argi++; return 1; }
    if (strcmp(a, "--notlsok") == 0)       { opts->notlsok = 1; sc->argi++; return 1; }
    if (strcmp(a, "--noverifyhost") == 0)  { opts->verify_host = 0; sc->argi++; return 1; }
    if (opt_apply_valueflag(argc, argv, opts, sc)) { return 1; }
    if (strcmp(a, "--wire-trace") == 0)      { opts->wire_trace = 1; sc->argi++; return 1; }
    if (strncmp(a, "--wire-trace=", 13) == 0) { opts->wire_trace = atoi(a + 13); sc->argi++; return 1; }
    if (strcmp(a, "--timing") == 0)          { opts->timing = 1; sc->argi++; return 1; }
    if (strcmp(a, "--redirect-trace") == 0)  { opts->redir_trace = 1; sc->argi++; return 1; }
    return 0;
}


/*
 * WHAT: parse the leading -/-- options into *opts, advancing over argv.
 * WHY:  the option ladder is the bulk of main()'s branch count; isolating it
 *       drops main below the complexity gate with byte-identical behavior.
 * HOW:  per token, try opt_early_exit() (terminates via sc->done) then
 *       opt_apply_flag() (value flags); an unrecognized token stops the scan.
 *       Order matches the original inline loop exactly.
 */
static void
parse_global_opts(int argc, char **argv, brix_opts *opts, xrdfs_optscan *sc)
{
    sc->argi = 1;
    sc->web_token = NULL;
    sc->done = 0;
    sc->exit_code = 0;

    while (sc->argi < argc && argv[sc->argi][0] == '-'
           && strcmp(argv[sc->argi], "-") != 0) {
        if (opt_apply_flag(argc, argv, opts, sc)) {
            continue;
        }
        if (opt_early_exit(argv[sc->argi])) {
            sc->done = 1; sc->exit_code = 0;
            return;
        }
        break;
    }
}


/*
 * WHAT: run an http(s)/WebDAV endpoint — no root:// session; serve read-only
 *       metadata (ls, stat) over WebDAV PROPFIND, mirroring official xrdfs.
 * WHY:  extracted from main() so each transport branch is its own unit; keeps
 *       the WebDAV error strings and exit codes exactly as before.
 * HOW:  parse the web URL, reject s3://, trim the export base, populate web_ctx,
 *       require a command, then hand off to web_dispatch(). endpoint/opts are
 *       passed in; args[] is the remaining argv slice.
 */
static int
run_web_endpoint(const char *endpoint, const brix_opts *opts,
                 const char *web_token, int nargs, char **args)
{
    brix_weburl wu;
    char        base[XRDC_PATH_MAX];
    size_t      bl;
    web_ctx     w;

    if (brix_weburl_parse(endpoint, &wu) != 0) {
        fprintf(stderr, "xrdfs: bad web URL: %s\n", endpoint);
        return 50;
    }
    if (wu.is_s3) {
        fprintf(stderr, "xrdfs: s3:// endpoints are not supported "
                        "(use http/https/dav/davs)\n");
        return 50;
    }
    snprintf(base, sizeof(base), "%s", wu.path);   /* URL path = export base */
    bl = strlen(base);
    while (bl > 0 && base[bl - 1] == '/') {
        base[--bl] = '\0';
    }
    w.u      = &wu;
    w.base   = base;
    w.bearer = web_token != NULL ? web_token : getenv("BEARER_TOKEN");
    w.verify = opts->verify_host;
    w.ca_dir = brix_resolve_ca_dir(NULL);
    if (nargs <= 0) {
        fprintf(stderr, "xrdfs: an http(s)/WebDAV endpoint needs a command "
                        "(e.g. ls); the interactive shell is root:// only\n");
        return 50;
    }
    return web_dispatch(&w, nargs, args);
}


/*
 * WHAT: run a root:// endpoint — resolve the URL, connect, then either drop
 *       into the interactive shell (no command) or dispatch one command.
 * WHY:  extracted from main() so the root:// path is a single unit and main is
 *       a thin driver; connect error strings + shell codes are unchanged.
 * HOW:  endpoint_to_url → brix_connect_resilient → repl()/dispatch() → close.
 *       nargs<=0 selects the REPL. opts is passed in; a private cwd is used.
 */
static int
run_root_endpoint(const char *endpoint, brix_opts *opts, int nargs, char **args)
{
    brix_url    u;
    brix_conn   c;
    brix_status st;
    char        cwd[XRDC_PATH_MAX] = "/";
    int         rc;

    brix_status_clear(&st);
    if (endpoint_to_url(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrdfs: %s\n", st.msg);
        return 50;
    }
    if (brix_connect_resilient(&c, &u, opts, &st) != 0) {
        fprintf(stderr, "xrdfs: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return brix_shellcode(&st);
    }

    if (nargs <= 0) {
        rc = repl(&c, u.host, u.port);   /* no command → interactive shell */
    } else {
        rc = dispatch(&c, cwd, sizeof(cwd), nargs, args, NULL);
    }

    brix_close(&c);
    return rc;
}


int
main(int argc, char **argv)
{
    brix_opts     opts;
    xrdfs_optscan sc = {0};
    const char   *endpoint;

    memset(&opts, 0, sizeof(opts));
    opts.verify_host = 1;
    brix_crypto_init();   /* arm libxrdproto SHA-256/HMAC for GSI + sigver */

    parse_global_opts(argc, argv, &opts, &sc);
    if (sc.done) {
        return sc.exit_code;
    }

    if (sc.argi >= argc) { usage(); return 50; }
    endpoint = argv[sc.argi++];

    /* http(s)/WebDAV endpoint: no root:// session (read-only metadata). */
    if (brix_is_web_url(endpoint)) {
        return run_web_endpoint(endpoint, &opts, sc.web_token,
                                argc - sc.argi, &argv[sc.argi]);
    }

    return run_root_endpoint(endpoint, &opts, argc - sc.argi, &argv[sc.argi]);
}
