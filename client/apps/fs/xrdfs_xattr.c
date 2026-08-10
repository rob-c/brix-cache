/*
 * xrdfs_xattr.c — xrdfs extended-attribute verb (kXR_fattr, client/lib/fattr.c).
 *
 * Split from xrdfs_attr.c (2026-08-10, 600-line file gate): the `xattr` verb
 * (BriX `xattr <code> <path>` + the stock `xattr <path> <code>` drop-in form,
 * §7.12) owns its own TU now that the query-code and cksum verbs share the
 * sibling file. Behaviour-identical to the pre-split code.
 */
#include "xrdfs_internal.h"

/* xattr ls|get|set|rm — extended attributes via kXR_fattr (client/lib/fattr.c).
 *   xattr ls  <path>                  list attribute names
 *   xattr get <path> <name>           print one value
 *   xattr set <path> <name> <value>   set/replace a value
 *   xattr rm  <path> <name>           delete an attribute
 * `xattr <path>` with no subcommand is treated as `ls`. */
int
xattr_ls(brix_conn *c, const char *path)
{
    brix_status st;
    char        names[8192];
    size_t      total = 0, off;

    brix_status_clear(&st);
    if (brix_fattr_list(c, path, names, sizeof(names), &total, &st) != 0) {
        return xrdfs_report_err("xattr ls", path, &st, 0, c);
    }
    /* The server returns a NUL-separated list of managed names tagged with a
     * one-letter namespace prefix ("U.<name>" for the user namespace). Strip the
     * "<X>." tag so the printed names round-trip directly through xattr get/set. */
    for (off = 0; off < total && names[off] != '\0'; ) {
        const char *name = names + off;
        if (name[0] >= 'A' && name[0] <= 'Z' && name[1] == '.') { name += 2; }
        printf("%s\n", name);
        off += strlen(names + off) + 1;
    }
    return 0;
}


/* ---- Is argv[1] a recognised xattr subcommand keyword? ----
 *
 * WHAT: Returns 1 when the token is one of ls/get/set/rm, 0 otherwise.
 *
 * WHY:  `xattr <path>` with no subcommand is shorthand for `xattr ls <path>`;
 *       factoring the four-way keyword test out keeps do_xattr's dispatch under
 *       the complexity cap.
 *
 * HOW:  Compare the token against each of the four recognised subcommand names.
 */
static int
xattr_is_subcommand(const char *s)
{
    return strcmp(s, "ls") == 0 || strcmp(s, "get") == 0
        || strcmp(s, "set") == 0 || strcmp(s, "rm") == 0;
}


/* ---- xattr get <path> <name> ----
 *
 * WHAT: Fetches one attribute value and writes it to stdout followed by a
 *       newline. Returns 0 on success, 50 on a usage error, or the mapped shell
 *       code on a protocol failure.
 *
 * WHY:  Splits the get branch out of do_xattr's dispatch so each subcommand is
 *       independently readable and the dispatcher stays flat.
 *
 * HOW:  1. Require the <name> argument.
 *       2. Call brix_fattr_get; on error report the message and map the status.
 *       3. Write the raw value bytes (clamped to the buffer) and a newline.
 */
static int
xattr_get(brix_conn *c, const char *path, int argc, char **argv)
{
    brix_status st;
    char        val[8192];
    size_t      vlen = 0;

    if (argc < 4) { fprintf(stderr, "usage: xattr get <path> <name>\n"); return 50; }
    brix_status_clear(&st);
    if (brix_fattr_get(c, path, argv[3], val, sizeof(val), &vlen, &st) != 0) {
        fprintf(stderr, "xrdfs: xattr get %s [%s]: %s\n", path, argv[3], st.msg);
        return brix_shellcode(&st);
    }
    fwrite(val, 1, vlen < sizeof(val) ? vlen : sizeof(val), stdout);
    printf("\n");
    return 0;
}


/* ---- xattr set <path> <name> <value> ----
 *
 * WHAT: Sets or replaces one attribute value. Returns 0 on success, 50 on a
 *       usage error, or the mapped shell code on a protocol failure.
 *
 * WHY:  Splits the set branch out of do_xattr's dispatch so each subcommand is
 *       independently readable and the dispatcher stays flat.
 *
 * HOW:  1. Require the <name> and <value> arguments.
 *       2. Call brix_fattr_set with the value's byte length; on error report
 *          the message and map the status.
 */
static int
xattr_set(brix_conn *c, const char *path, int argc, char **argv)
{
    brix_status st;

    if (argc < 5) { fprintf(stderr, "usage: xattr set <path> <name> <value>\n"); return 50; }
    brix_status_clear(&st);
    if (brix_fattr_set(c, path, argv[3], argv[4], strlen(argv[4]), 0, &st) != 0) {
        fprintf(stderr, "xrdfs: xattr set %s [%s]: %s\n", path, argv[3], st.msg);
        return brix_shellcode(&st);
    }
    return 0;
}


/* ---- xattr rm <path> <name> ----
 *
 * WHAT: Deletes one attribute. Returns 0 on success, 50 on a usage error, or the
 *       mapped shell code on a protocol failure.
 *
 * WHY:  Splits the rm branch out of do_xattr's dispatch so each subcommand is
 *       independently readable and the dispatcher stays flat.
 *
 * HOW:  1. Require the <name> argument.
 *       2. Call brix_fattr_del; on error report the message and map the status.
 */
static int
xattr_rm(brix_conn *c, const char *path, int argc, char **argv)
{
    brix_status st;

    if (argc < 4) { fprintf(stderr, "usage: xattr rm <path> <name>\n"); return 50; }
    brix_status_clear(&st);
    if (brix_fattr_del(c, path, argv[3], &st) != 0) {
        fprintf(stderr, "xrdfs: xattr rm %s [%s]: %s\n", path, argv[3], st.msg);
        return brix_shellcode(&st);
    }
    return 0;
}


/* ---- Is `s` a STOCK xrdfs xattr code (set/get/del/list)? ---- */
static int
xattr_is_stock_code(const char *s)
{
    return strcmp(s, "set") == 0 || strcmp(s, "get") == 0
        || strcmp(s, "del") == 0 || strcmp(s, "list") == 0;
}

/* ---- Stock xrdfs grammar: `xattr <path> <code> <params>` ----
 *
 * WHAT: Handles the STOCK spelling (path first, then set/get/del/list; set
 *       takes a single `name=value`) by mapping onto BriX's own xattr helpers.
 *       Returns 0 / shell code.
 *
 * WHY:  §7.12 — a script written for stock xrdfs (`xattr /f set a=b`) used to
 *       be silently mis-read as a bare list of `/f`. Accepting the stock form
 *       as a drop-in alias closes the grammar incompatibility; BriX's own
 *       `xattr <code> <path>` form is unchanged and still takes priority
 *       (disambiguated by the caller: the stock form is reached only when the
 *       FIRST token is a path, not a BriX subcommand).
 *
 * HOW:  Build a BriX-shaped argv ({prog, code, path, name[, value]}) and call
 *       the same xattr_ls/get/set/rm helpers, splitting set's name=value in
 *       place. `path` is already cwd-resolved by the caller.
 */
static int
xattr_stock_form(brix_conn *c, const char *path, int argc, char **argv)
{
    const char *code = argv[2];
    char       *nargv[5] = { argv[0], NULL, (char *) path, NULL, NULL };

    if (strcmp(code, "list") == 0) {
        return xattr_ls(c, path);
    }
    if (argc < 4) {
        fprintf(stderr, "usage: xattr <path> %s <args>\n", code);
        return 50;
    }
    if (strcmp(code, "get") == 0) {
        nargv[1] = "get"; nargv[3] = argv[3];
        return xattr_get(c, path, 4, nargv);
    }
    if (strcmp(code, "del") == 0) {
        nargv[1] = "rm"; nargv[3] = argv[3];
        return xattr_rm(c, path, 4, nargv);
    }
    /* set <name=value> — split at the first '=' (in place; argv is mutable). */
    {
        char *eq = strchr(argv[3], '=');

        if (eq == NULL) {
            fprintf(stderr, "xrdfs: xattr set: expected name=value, got '%s'\n",
                    argv[3]);
            return 50;
        }
        *eq = '\0';
        nargv[1] = "set"; nargv[3] = argv[3]; nargv[4] = eq + 1;
        return xattr_set(c, path, 5, nargv);
    }
}

int
do_xattr(brix_conn *c, const char *cwd, int argc, char **argv)
{
    char path[XRDC_PATH_MAX];

    if (argc < 2) {
        fprintf(stderr, "usage: xattr ls|get|set|rm <path> [name] [value]\n"
                        "   or: xattr <path> set|get|del|list [args]  (stock)\n");
        return 50;
    }
    /* First token is NOT a BriX subcommand → it is a path: either the bare
     * `xattr <path>` list shorthand, or the STOCK `xattr <path> <code>` form
     * (§7.12) when a stock code follows. BriX's own `xattr <code> <path>`
     * form (below) keeps priority so existing usage is unaffected. */
    if (!xattr_is_subcommand(argv[1])) {
        build_path(cwd, argv[1], path, sizeof(path));
        if (argc >= 3 && xattr_is_stock_code(argv[2])) {
            return xattr_stock_form(c, path, argc, argv);
        }
        return xattr_ls(c, path);
    }
    if (argc < 3) {
        fprintf(stderr, "usage: xattr %s <path> ...\n", argv[1]);
        return 50;
    }
    build_path(cwd, argv[2], path, sizeof(path));

    if (strcmp(argv[1], "ls") == 0)  { return xattr_ls(c, path); }
    if (strcmp(argv[1], "get") == 0) { return xattr_get(c, path, argc, argv); }
    if (strcmp(argv[1], "set") == 0) { return xattr_set(c, path, argc, argv); }
    return xattr_rm(c, path, argc, argv);   /* the only remaining subcommand */
}
