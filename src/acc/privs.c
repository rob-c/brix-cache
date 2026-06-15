/*
 * privs.c — XrdAcc privilege algebra (operation requirements, parser, test).
 *
 * WHAT: implements the three pure functions declared in privs.h — the
 *   operation->required-privilege table (xrootd_acc_op_needs), the grant test
 *   (xrootd_acc_test), and the single-letter privilege parser
 *   (xrootd_acc_parse_privs).
 *
 * WHY: faithful ports of XrdAccAccess::Test() (the need[] table) and
 *   XrdAccConfig::PrivsConvert() so the `xrdacc` engine reproduces stock XRootD
 *   authorization decisions bit-for-bit.  Pure leaf — depends only on privs.h.
 *
 * HOW: a static need[] table indexed by Access_Operation; Test() returns
 *   (need & priv) == need; PrivsConvert() walks the letter string accumulating
 *   into a 2-slot table that the single '-' advances from positive to negative.
 */

#include "privs.h"

/*
 * need[] — privilege bits required per operation, 1:1 with xrootd_acc_op_t.
 * Mirrors XrdAccAccess::Test()'s table.  AOP_EXCL_* (13,14) require 0xffff so
 * they can never be satisfied by the privilege model (exclusivity is enforced
 * elsewhere).  We additionally pin AOP_STAGE/AOP_POLL (15,16) — XRootD's own
 * table stops at index 14 and reads out of bounds for these; we map them to
 * their documented composites instead.
 */
static const xrootd_acc_privs_t  xrootd_acc_op_need[XROOTD_AOP_LAST + 1] = {
    [XROOTD_AOP_ANY]         = XROOTD_ACC_PRIV_NONE,
    [XROOTD_AOP_CHMOD]       = XROOTD_ACC_PRIV_CHMOD,
    [XROOTD_AOP_CHOWN]       = XROOTD_ACC_PRIV_CHMOD,   /* Chown == Chmod (0x063) */
    [XROOTD_AOP_CREATE]      = XROOTD_ACC_PRIV_CREATE,
    [XROOTD_AOP_DELETE]      = XROOTD_ACC_PRIV_DELETE,
    [XROOTD_AOP_INSERT]      = XROOTD_ACC_PRIV_INSERT,
    [XROOTD_AOP_LOCK]        = XROOTD_ACC_PRIV_LOCK,
    [XROOTD_AOP_MKDIR]       = XROOTD_ACC_PRIV_INSERT,  /* Mkdir == Insert */
    [XROOTD_AOP_READ]        = XROOTD_ACC_PRIV_READ,
    [XROOTD_AOP_READDIR]     = XROOTD_ACC_PRIV_READ,    /* Readdir == Read */
    [XROOTD_AOP_RENAME]      = XROOTD_ACC_PRIV_RENAME,
    [XROOTD_AOP_STAT]        = XROOTD_ACC_PRIV_LOOKUP,  /* Stat == Lookup */
    [XROOTD_AOP_UPDATE]      = XROOTD_ACC_PRIV_UPDATE,
    [XROOTD_AOP_EXCL_CREATE] = 0xffffu,
    [XROOTD_AOP_EXCL_INSERT] = 0xffffu,
    [XROOTD_AOP_STAGE]       = XROOTD_ACC_PRIV_STAGE,
    [XROOTD_AOP_POLL]        = XROOTD_ACC_PRIV_POLL,
};

xrootd_acc_privs_t
xrootd_acc_op_needs(xrootd_acc_op_t op)
{
    if (op < 0 || op > XROOTD_AOP_LAST) {
        return 0xffffu;   /* unknown operation -> unsatisfiable -> deny */
    }
    return xrootd_acc_op_need[op];
}

int
xrootd_acc_test(xrootd_acc_privs_t priv, xrootd_acc_op_t op)
{
    xrootd_acc_privs_t  need = xrootd_acc_op_needs(op);

    /* Grant iff every required bit is present.  For AOP_ANY (need==0) this is
     * trivially true; the engine returns the privilege set directly for that. */
    return (xrootd_acc_privs_t) (need & priv) == need;
}

const char *
xrootd_acc_op_name(xrootd_acc_op_t op)
{
    static const char *const names[XROOTD_AOP_LAST + 1] = {
        "any", "chmod", "chown", "create", "delete", "insert", "lock",
        "mkdir", "read", "readdir", "rename", "stat", "update",
        "excl_create", "excl_insert", "stage", "poll"
    };
    if (op < 0 || op > XROOTD_AOP_LAST) {
        return "???";
    }
    return names[op];
}

int
xrootd_acc_parse_privs(const char *s, size_t len, xrootd_acc_priv_caps_t *caps)
{
    xrootd_acc_privs_t  tab[2] = { XROOTD_ACC_PRIV_NONE, XROOTD_ACC_PRIV_NONE };
    int                 slot = 0;   /* 0 = positive, 1 = negative */
    size_t              i;

    for (i = 0; i < len; i++) {
        switch (s[i]) {
        case 'a': tab[slot] |= XROOTD_ACC_PRIV_ALL;    break;
        case 'd': tab[slot] |= XROOTD_ACC_PRIV_DELETE; break;
        case 'i': tab[slot] |= XROOTD_ACC_PRIV_INSERT; break;
        case 'k': tab[slot] |= XROOTD_ACC_PRIV_LOCK;   break;
        case 'l': tab[slot] |= XROOTD_ACC_PRIV_LOOKUP; break;
        case 'n': tab[slot] |= XROOTD_ACC_PRIV_RENAME; break;
        case 'r': tab[slot] |= XROOTD_ACC_PRIV_READ;   break;
        case 'w': tab[slot] |= XROOTD_ACC_PRIV_WRITE;  break;
        case '-':
            /* Exactly one '-' is allowed: it switches to negative privileges. */
            if (slot != 0) {
                return -1;
            }
            slot = 1;
            break;
        default:
            return -1;   /* unknown privilege character */
        }
    }

    caps->pprivs = tab[0];
    caps->nprivs = tab[1];
    return 0;
}
