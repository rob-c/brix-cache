/*
 * dirfanout_test.c — unit checks for the W7.2b cluster readdir fan-out
 *                    (client/lib/fs/dirfanout.c).
 *
 * WHAT: Verifies the two pure kernels the fan-out is built from — turning a
 *       kXR_locate reply into the set of data servers to ask, and collapsing
 *       the concatenated listings into one deduplicated answer.
 * WHY:  Both kernels consume SERVER-CONTROLLED input.  The locate reply is a
 *       string a manager (or anything that can answer as one) hands us, and it
 *       is fed straight into fixed-size buffers; the entry union is built from
 *       names several nodes supply.  A parser that keeps a manager token would
 *       make the fan-out re-enter the redirect it exists to avoid, and one that
 *       mis-splits a bracketed IPv6 literal would dial the wrong host — neither
 *       is visible from an end-to-end listing that merely looks short.
 * HOW:  The implementation is #included so the file-static kernels are directly
 *       reachable (the house pattern — see tests/c/krb5_deleg_capture_test.c).
 *       No sockets: every check is a pure call.  Exit 0 = pass, 1 = fail.
 *
 * Build+run:  make -C client dirfanout && client/bin/dirfanout_test
 */
#include "fs/dirfanout.c"

#include <stdio.h>

static int failures;

static void
check(int cond, const char *what)
{
    if (cond) {
        fprintf(stderr, "  ok: %s\n", what);
    } else {
        fprintf(stderr, "  FAIL: %s\n", what);
        failures++;
    }
}

static void
set_name(brix_dirent *e, const char *name)
{
    memset(e, 0, sizeof(*e));
    snprintf(e->name, sizeof(e->name), "%s", name);
}


/* ---- 1. which locate tokens become nodes -------------------------------- */
static void
t_token_selection(void)
{
    /* Real locate-token shape: "S<r|w><host>:<port>", no space after the two
     * prefix bytes (see xcp_sources_from_locate in lib/xfer/copy_xcp_sources.c
     * and the kXR_locate reply the manager builds). */
    char        reply[] = "Srhost1:1094 Mwmgr:1213 swhost2:1095 "
                          "Srhost1:1094 mrmgr2:1213 junk S";
    dirfan_node n[DIRFAN_MAX_NODES];
    size_t      c;

    fprintf(stderr, "== token selection\n");
    c = dirfan_nodes_from_locate(reply, n, DIRFAN_MAX_NODES);
    check(c == 2, "two distinct data servers out of six tokens");
    check(strcmp(n[0].host, "host1") == 0 && n[0].port == 1094,
          "first server parsed host and port");
    check(strcmp(n[1].host, "host2") == 0 && n[1].port == 1095,
          "lowercase 's' (a server too) is kept");
    /* The manager tokens must be absent: dialing one re-enters the single-node
     * redirect this whole feature exists to bypass. */
    check(strcmp(n[0].host, "mgr") != 0 && strcmp(n[1].host, "mgr") != 0,
          "manager 'M'/'m' entries are never dialed");
    check(c == 2, "the repeated host1:1094 was collapsed, not listed twice");
}


/* ---- 2. bracketed IPv6 literals ----------------------------------------- */
static void
t_ipv6(void)
{
    char        reply[] = "Sr[::1]:1094 Sw[2001:db8::5]:1095";
    dirfan_node n[DIRFAN_MAX_NODES];
    size_t      c;

    fprintf(stderr, "== IPv6 literals\n");
    c = dirfan_nodes_from_locate(reply, n, DIRFAN_MAX_NODES);
    check(c == 2, "both bracketed endpoints parsed");
    /* A naive rsplit on ':' would leave "[::1" here — the reason this parser
     * hands the token to brix_url_parse instead of splitting it itself. */
    check(strcmp(n[0].host, "::1") == 0 && n[0].port == 1094,
          "loopback literal unbracketed with its port intact");
    check(strcmp(n[1].host, "2001:db8::5") == 0 && n[1].port == 1095,
          "a multi-colon literal is not split at the wrong colon");
}


/* ---- 3. the reply cannot make us exceed the table ----------------------- */
static void
t_cap(void)
{
    char        reply[16 * 1024];
    dirfan_node n[DIRFAN_MAX_NODES];
    size_t      c, i, off = 0;

    fprintf(stderr, "== node cap\n");
    for (i = 0; i < DIRFAN_MAX_NODES + 40; i++) {
        off += (size_t) snprintf(reply + off, sizeof(reply) - off,
                                 "Srh%zu:1094 ", i);
    }
    c = dirfan_nodes_from_locate(reply, n, DIRFAN_MAX_NODES);
    check(c == DIRFAN_MAX_NODES, "an over-long reply is clamped to the table");
    check(strcmp(n[DIRFAN_MAX_NODES - 1].host, "h63") == 0,
          "the clamp keeps the FIRST nodes named, in order");
}


/* ---- 4. hostile reply: over-long and malformed tokens ------------------- */
static void
t_hostile(void)
{
    char        reply[8192];
    dirfan_node n[DIRFAN_MAX_NODES];
    size_t      c, i;

    fprintf(stderr, "== hostile reply\n");
    memset(reply, 0, sizeof(reply));
    memcpy(reply, "Sr", 2);
    memset(reply + 2, 'a', 4000);          /* a 4000-char host */
    memcpy(reply + 4002, ":1094 Sr: Srh:99999999999 Srgood:1094", 38);

    c = dirfan_nodes_from_locate(reply, n, DIRFAN_MAX_NODES);
    /* The over-long token must be dropped, not truncated into a real hostname:
     * a silently truncated host is a connection to the WRONG server. */
    for (i = 0; i < c; i++) {
        check(strncmp(n[i].host, "aaaa", 4) != 0,
              "no truncated form of the over-long host was recorded");
        check(strnlen(n[i].host, sizeof(n[i].host)) < sizeof(n[i].host),
              "every recorded host is NUL-terminated inside its buffer");
    }
    check(c <= DIRFAN_MAX_NODES, "malformed input never overruns the table");
}


/* ---- 5. the union is deduplicated -------------------------------------- */
static void
t_dedup(void)
{
    brix_dirent e[6];
    size_t      kept;

    fprintf(stderr, "== dedup\n");
    set_name(&e[0], "beta");
    set_name(&e[1], "alpha");
    set_name(&e[2], "beta");      /* the same file, named by a second holder */
    set_name(&e[3], "gamma");
    set_name(&e[4], "alpha");
    set_name(&e[5], "beta");

    kept = dirfan_dedup(e, 6);
    check(kept == 3, "three distinct names survive six entries");
    check(strcmp(e[0].name, "alpha") == 0
          && strcmp(e[1].name, "beta") == 0
          && strcmp(e[2].name, "gamma") == 0,
          "the survivors are sorted and each appears once");
}


/* ---- 6. degenerate sizes ------------------------------------------------ */
static void
t_dedup_small(void)
{
    brix_dirent e[1];

    fprintf(stderr, "== dedup of 0 and 1 entries\n");
    check(dirfan_dedup(e, 0) == 0, "an empty union stays empty");
    set_name(&e[0], "only");
    check(dirfan_dedup(e, 1) == 1, "a single entry is kept untouched");
    check(strcmp(e[0].name, "only") == 0, "and is not disturbed");
}


int
main(void)
{
    t_token_selection();
    t_ipv6();
    t_cap();
    t_hostile();
    t_dedup();
    t_dedup_small();

    if (failures != 0) {
        fprintf(stderr, "dirfanout_test: %d FAILURE(S)\n", failures);
        return 1;
    }
    fprintf(stderr, "dirfanout_test: all checks passed\n");
    return 0;
}
