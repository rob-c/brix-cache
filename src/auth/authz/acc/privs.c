/*
 * privs.c — XrdAcc privilege algebra (operation requirements, parser, test).
 *
 * WHAT: implements the three pure functions declared in privs.h — the
 *   operation->required-privilege table (brix_acc_op_needs), the grant test
 *   (brix_acc_test), and the single-letter privilege parser
 *   (brix_acc_parse_privs).
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
 * need[] — privilege bits required per operation, 1:1 with brix_acc_op_t.
 * Mirrors XrdAccAccess::Test()'s table.  AOP_EXCL_* (13,14) require 0xffff so
 * they can never be satisfied by the privilege model (exclusivity is enforced
 * elsewhere).  We additionally pin AOP_STAGE/AOP_POLL (15,16) — XRootD's own
 * table stops at index 14 and reads out of bounds for these; we map them to
 * their documented composites instead.
 */
static const brix_acc_privs_t  brix_acc_op_need[BRIX_AOP_LAST + 1] = {
    [BRIX_AOP_ANY]         = BRIX_ACC_PRIV_NONE,
    [BRIX_AOP_CHMOD]       = BRIX_ACC_PRIV_CHMOD,
    [BRIX_AOP_CHOWN]       = BRIX_ACC_PRIV_CHMOD,   /* Chown == Chmod (0x063) */
    [BRIX_AOP_CREATE]      = BRIX_ACC_PRIV_CREATE,
    [BRIX_AOP_DELETE]      = BRIX_ACC_PRIV_DELETE,
    [BRIX_AOP_INSERT]      = BRIX_ACC_PRIV_INSERT,
    [BRIX_AOP_LOCK]        = BRIX_ACC_PRIV_LOCK,
    [BRIX_AOP_MKDIR]       = BRIX_ACC_PRIV_INSERT,  /* Mkdir == Insert */
    [BRIX_AOP_READ]        = BRIX_ACC_PRIV_READ,
    [BRIX_AOP_READDIR]     = BRIX_ACC_PRIV_READ,    /* Readdir == Read */
    [BRIX_AOP_RENAME]      = BRIX_ACC_PRIV_RENAME,
    [BRIX_AOP_STAT]        = BRIX_ACC_PRIV_LOOKUP,  /* Stat == Lookup */
    [BRIX_AOP_UPDATE]      = BRIX_ACC_PRIV_UPDATE,
    [BRIX_AOP_EXCL_CREATE] = 0xffffu,
    [BRIX_AOP_EXCL_INSERT] = 0xffffu,
    [BRIX_AOP_STAGE]       = BRIX_ACC_PRIV_STAGE,
    [BRIX_AOP_POLL]        = BRIX_ACC_PRIV_POLL,
};

brix_acc_privs_t
brix_acc_op_needs(brix_acc_op_t op)
{
    if (op < 0 || op > BRIX_AOP_LAST) {
        return 0xffffu;   /* unknown operation -> unsatisfiable -> deny */
    }
    return brix_acc_op_need[op];
}

int
brix_acc_test(brix_acc_privs_t priv, brix_acc_op_t op)
{
    brix_acc_privs_t  need = brix_acc_op_needs(op);

    /* Grant iff every required bit is present.  For AOP_ANY (need==0) this is
     * trivially true; the engine returns the privilege set directly for that. */
    return (brix_acc_privs_t) (need & priv) == need;
}

const char *
brix_acc_op_name(brix_acc_op_t op)
{
    static const char *const names[BRIX_AOP_LAST + 1] = {
        "any", "chmod", "chown", "create", "delete", "insert", "lock",
        "mkdir", "read", "readdir", "rename", "stat", "update",
        "excl_create", "excl_insert", "stage", "poll"
    };
    if (op < 0 || op > BRIX_AOP_LAST) {
        return "???";
    }
    return names[op];
}

int
brix_acc_parse_privs(const char *s, size_t len, brix_acc_priv_caps_t *caps)
{
    brix_acc_privs_t  tab[2] = { BRIX_ACC_PRIV_NONE, BRIX_ACC_PRIV_NONE };
    int                 slot = 0;   /* 0 = positive, 1 = negative */
    size_t              i;

    for (i = 0; i < len; i++) {
        switch (s[i]) {
        case 'a': tab[slot] |= BRIX_ACC_PRIV_ALL;    break;
        case 'd': tab[slot] |= BRIX_ACC_PRIV_DELETE; break;
        case 'i': tab[slot] |= BRIX_ACC_PRIV_INSERT; break;
        case 'k': tab[slot] |= BRIX_ACC_PRIV_LOCK;   break;
        case 'l': tab[slot] |= BRIX_ACC_PRIV_LOOKUP; break;
        case 'n': tab[slot] |= BRIX_ACC_PRIV_RENAME; break;
        case 'r': tab[slot] |= BRIX_ACC_PRIV_READ;   break;
        case 'w': tab[slot] |= BRIX_ACC_PRIV_WRITE;  break;
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
