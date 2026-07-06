/*
 * xrdfs.c - (kept) routing + shared helpers
 * Phase-38 split of xrdfs.c; behavior-identical.
 */
#include "xrdfs_internal.h"

volatile sig_atomic_t tail_stop = 0;

const xrdfs_cmd COMMANDS[] = {
    { "stat",     do_stat,     "stat <path>" },
    { "ls",       do_ls,       "ls [-l] [-R] [-h] [path]" },
    { "du",       do_du,       "du [-h] <path>...  (recursive size)" },
    { "df",       do_df,       "df [-h] [path]  (disk space, oss.* Qspace)" },
    { "tree",     do_tree,     "tree [-d] [-L N] [path]" },
    { "find",     do_find,     "find <path> [-name GLOB] [-type f|d] [-size +N|-N]" },
    { "mkdir",    do_mkdir,    "mkdir [-p] [-m mode] <path>" },
    { "rm",       do_rm,       "rm [-r] [-v] <path>" },
    { "rmdir",    do_rmdir,    "rmdir <path>" },
    { "mv",       do_mv,       "mv <src> <dst>" },
    { "chmod",    do_chmod,    "chmod [-R] <path> <octal-mode>" },
    { "touch",    do_touch,    "touch [-c] [-a] [-m] [-t STAMP] <path>" },
    { "ln",       do_ln,       "ln [-s] [-f] <target> <linkpath>" },
    { "readlink", do_readlink, "readlink <path>" },
    { "truncate", do_truncate, "truncate <path> <size>" },
    { "cat",      do_cat,      "cat <path>" },
    { "head",     do_head,     "head [-c BYTES] [-n LINES] <path>" },
    { "tail",     do_tail,     "tail [-c BYTES] [-n LINES] [-f] <path>" },
    { "wc",       do_wc,       "wc [-c] [-l] [-w] <path>" },
    { "grep",     do_grep,     "grep [-i] [-n] PATTERN <path>" },
    { "hexdump",  do_hexdump,  "hexdump [-n BYTES] <path>" },
    { "dd",       do_dd,       "dd [if=]<path> [bs=N] [skip=N] [count=N] [rate=R]" },
    { "upload",   do_upload,   "upload [bs=N] [rate=R] [-f] <localfile|-> <remote>" },
    { "download", do_download, "download [bs=N] [rate=R] [-f] <remote> [localfile|-]" },
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


/* Run one tokenized command. cwd/cwdsz hold the mutable working directory (for
 * the REPL's cd/pwd). Returns a shell code; sets *quit when asked to leave. */
int
dispatch(brix_conn *c, char *cwd, size_t cwdsz, int ntok, char **tok, int *quit)
{
    const xrdfs_cmd *cmd;

    if (ntok == 0) {
        return 0;
    }
    if (strcmp(tok[0], "exit") == 0 || strcmp(tok[0], "quit") == 0) {
        if (quit != NULL) { *quit = 1; }
        return 0;
    }
    if (strcmp(tok[0], "pwd") == 0) {
        printf("%s\n", cwd);
        return 0;
    }
    if (strcmp(tok[0], "cd") == 0) {
        char next[XRDC_PATH_MAX];
        build_path(cwd, ntok >= 2 ? tok[1] : "/", next, sizeof(next));
        snprintf(cwd, cwdsz, "%s", next);
        return 0;
    }
    if (strcmp(tok[0], "help") == 0) {
        for (const xrdfs_cmd *h = COMMANDS; h->name != NULL; h++) {
            printf("  %s\n", h->help);
        }
        printf("  cd <path> | pwd | help | exit\n");
        return 0;
    }

    cmd = find_command(tok[0]);
    if (cmd == NULL) {
        fprintf(stderr, "xrdfs: unknown command '%s'\n", tok[0]);
        return 50;
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

void
usage(void)
{
    fprintf(stderr,
        "usage: xrdfs [opts] host[:port]|root[s]://host[:port]|http[s]|dav[s]://host/path [command [args]]\n"
        "  with no command, drops into an interactive shell (root:// only).\n"
        "  opts:\n"
        "    --tls --notlsok --noverifyhost   in-protocol TLS controls\n"
        "    --auth <gsi|ztn|krb5|sss|unix>   force an auth protocol (root://)\n"
        "    --token TOK | -T TOK             bearer token for http(s)/WebDAV ($BEARER_TOKEN)\n"
        "  http(s)/WebDAV endpoints support read-only metadata: ls, stat\n"
        "  commands (root://):\n"
        "    stat ls du df tree find mkdir rm rmdir mv chmod touch ln readlink\n"
        "    truncate cat head tail wc grep hexdump dd upload download cmp cksum\n"
        "    xattr readv writev locate query statvfs prepare stage evict explain\n"
        "      (cd/pwd/help/exit in the shell)\n");
}


int
main(int argc, char **argv)
{
    brix_url    u;
    brix_conn   c;
    brix_status st;
    brix_opts   opts;
    const char *endpoint;
    const char *web_token = NULL;   /* --token / $BEARER_TOKEN for http(s)/WebDAV */
    char        cwd[XRDC_PATH_MAX] = "/";
    int         argi = 1, rc;

    memset(&opts, 0, sizeof(opts));
    opts.verify_host = 1;
    brix_crypto_init();   /* arm libxrdproto SHA-256/HMAC for GSI + sigver */

    while (argi < argc && argv[argi][0] == '-' && strcmp(argv[argi], "-") != 0) {
        if (strcmp(argv[argi], "--no-cwd") == 0)        { argi++; continue; }
        if (strcmp(argv[argi], "--tls") == 0)           { opts.want_tls = 1; argi++; continue; }
        if (strcmp(argv[argi], "--notlsok") == 0)       { opts.notlsok = 1; argi++; continue; }
        if (strcmp(argv[argi], "--noverifyhost") == 0)  { opts.verify_host = 0; argi++; continue; }
        if (strcmp(argv[argi], "--auth") == 0 && argi + 1 < argc) {
            opts.auth_force = argv[argi + 1]; argi += 2; continue;
        }
        if ((strcmp(argv[argi], "--token") == 0 || strcmp(argv[argi], "-T") == 0)
            && argi + 1 < argc) {
            web_token = argv[argi + 1]; argi += 2; continue;   /* http(s)/WebDAV bearer */
        }
        if (strcmp(argv[argi], "--wire-trace") == 0)      { opts.wire_trace = 1; argi++; continue; }
        if (strncmp(argv[argi], "--wire-trace=", 13) == 0) { opts.wire_trace = atoi(argv[argi] + 13); argi++; continue; }
        if (strcmp(argv[argi], "--timing") == 0)          { opts.timing = 1; argi++; continue; }
        if (strcmp(argv[argi], "--redirect-trace") == 0)  { opts.redir_trace = 1; argi++; continue; }
        if (strcmp(argv[argi], "--capture") == 0 && argi + 1 < argc) { opts.capture = argv[argi + 1]; argi += 2; continue; }
        if (strcmp(argv[argi], "-h") == 0 || strcmp(argv[argi], "--help") == 0) {
            usage();
            return 0;
        }
        break;
    }

    if (argi >= argc) { usage(); return 50; }
    endpoint = argv[argi++];

    /* http(s)/WebDAV endpoint: no root:// session — serve read-only metadata
     * (ls, stat) over WebDAV PROPFIND, mirroring the official xrdfs. */
    if (brix_is_web_url(endpoint)) {
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
        w.verify = opts.verify_host;
        w.ca_dir = brix_resolve_ca_dir(NULL);
        if (argi >= argc) {
            fprintf(stderr, "xrdfs: an http(s)/WebDAV endpoint needs a command "
                            "(e.g. ls); the interactive shell is root:// only\n");
            return 50;
        }
        return web_dispatch(&w, argc - argi, &argv[argi]);
    }

    brix_status_clear(&st);
    if (endpoint_to_url(endpoint, &u, &st) != 0) {
        fprintf(stderr, "xrdfs: %s\n", st.msg);
        return 50;
    }
    if (brix_connect_resilient(&c, &u, &opts, &st) != 0) {
        fprintf(stderr, "xrdfs: connect %s:%d: %s\n", u.host, u.port, st.msg);
        return brix_shellcode(&st);
    }

    if (argi >= argc) {
        rc = repl(&c, u.host, u.port);   /* no command → interactive shell */
    } else {
        rc = dispatch(&c, cwd, sizeof(cwd), argc - argi, &argv[argi], NULL);
    }

    brix_close(&c);
    return rc;
}
