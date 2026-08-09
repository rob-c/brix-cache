/* _xrd_part2.c — fragment 2 of xrd.c (auto-split).
 * Do not compile directly; it is #included by xrd.c. */
#ifndef _XRD_PART2_C_INC
#define _XRD_PART2_C_INC
#ifndef __XRD_C_COMPILED__
/*
 * xrd.c - (kept) routing + shared helpers
 * Phase-38 split of xrd.c; behavior-identical.
 */
#include "xrd_internal.h"
#include "core/version.h"
#include "core/progname.h"  /* brix_prog_*(): argv[0]-derived identity + exec prefix */
#include "cli/suggest.h"    /* brix_suggest(): did-you-mean at unknown-command sites */
#include "cli/cli_hint.h"   /* brix_cli_hint(): TTY-gated hint output */

#endif /* __XRD_C_COMPILED__ */

/*
 * WHAT: filesystem verb -> exec `xrdfs <endpoint> <verb> [paths...]`.
 * WHY:  xrdfs separates the connect endpoint from the path, so when the target
 *       is a full root:// URL (or an alias that resolves to one) carrying a
 *       path, split it: `xrd stat root://h//d/f` -> `xrdfs root://h:port stat
 *       /d/f`. A bare host:port (or anything not a root:// URL) is passed
 *       through unchanged.
 * HOW:  fs_find_endpoint() scans for the endpoint URL; split mode maps every
 *       arg via fs_map_split_args(), pass-through mode copies args verbatim.
 */
static int
cmd_fs_verb(int argc, char **argv)
{
    const char *cmd = argv[1];
    const char *pfx = brix_prog_prefix(brix_prog_base(argv[0]));
    fs_split_t  sp;
    char      **nv;
    int         i, k = 0, split;

    if (argc < 3) {
        fprintf(stderr, "xrd %s: needs an <endpoint>\n", cmd);
        return 50;
    }
    split = fs_find_endpoint(argc, argv, &sp);
    nv = (char **) malloc((size_t) (argc + 3) * sizeof(char *));
    if (nv == NULL) { fprintf(stderr, "xrd: out of memory\n"); return 51; }
    nv[k++] = (char *) "xrdfs";
    if (split) {
        nv[k++] = sp.endpoint;         /* connect endpoint (host:port) */
        nv[k++] = (char *) cmd;        /* the verb */
        k = fs_map_split_args(nv, k, argc, argv, &sp);
        if (k < 0) {
            free(nv);
            return 50;
        }
    } else {
        nv[k++] = argv[2];             /* bare endpoint as given */
        nv[k++] = (char *) cmd;
        for (i = 3; i < argc; i++) {   /* paths/flags verbatim */
            nv[k++] = argv[i];
        }
    }
    nv[k] = NULL;
    exec_tool(pfx, "xrdfs", nv);
    return 127;   /* unreachable: exec_tool does not return */
}


/*
 * WHAT: emit a did-you-mean hint when the user typed an unrecognised xrd
 *       command; search both the named xrd dispatch table and FS_VERBS.
 * WHY:  spec WS-7: every unknown-command site must offer a suggestion when
 *       one exists within DL distance ≤ 2 (TTY-gated, C3 compliant).
 * HOW:  build a merged NULL-terminated names array — dispatch-table names in
 *       their historical order, skipping '-'-prefixed flag aliases, then
 *       FS_VERBS — and pass it to brix_suggest().
 */
static void
report_unknown_command(const char *cmd)
{
    const char *all_names[80];   /* FS_VERBS(36) + named commands(24) + pad */
    int         n = 0;
    int         i;
    const char *suggestion;

    for (i = 0; XRD_DISPATCH[i].name != NULL && n < 79; i++) {
        if (XRD_DISPATCH[i].name[0] != '-') {
            all_names[n++] = XRD_DISPATCH[i].name;
        }
    }
    for (i = 0; FS_VERBS[i] != NULL && n < 79; i++) {
        all_names[n++] = FS_VERBS[i];
    }
    all_names[n] = NULL;

    fprintf(stderr, "xrd: unknown command '%s'\n\n", cmd);
    suggestion = brix_suggest(cmd, all_names);
    if (suggestion != NULL) {
        brix_cli_hint("hint: did you mean '%s'?\n", suggestion);
    }
}


int
main(int argc, char **argv)
{
    const char *cmd;
    int         i;

    if (argc < 2) {
        usage(argv[0]);
        return 50;
    }
    cmd = argv[1];

    for (i = 0; XRD_DISPATCH[i].name != NULL; i++) {
        if (strcmp(XRD_DISPATCH[i].name, cmd) == 0) {
            return XRD_DISPATCH[i].fn(argc, argv);
        }
    }

    if (is_fs_verb(cmd)) {
        return cmd_fs_verb(argc, argv);
    }

    report_unknown_command(cmd);
    usage(argv[0]);
    return 50;
}
#endif /* _XRD_PART2_C_INC */
