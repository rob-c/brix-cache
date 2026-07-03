/*
 * privs.h — XrdAcc privilege + operation model (pure leaf, no nginx deps).
 *
 * WHAT: the faithful re-implementation of XRootD's XrdAccPrivs.hh privilege
 *   bitmask, the Access_Operation enum (AOP_*), the operation->privilege
 *   requirement table, the single-letter privilege parser, and the grant test.
 *
 * WHY: this is the heart of the `xrdacc` authorization engine — keeping the
 *   numeric privilege values byte-identical to XrdAccPrivs.hh means a stock
 *   XRootD `authdb` file yields exactly the same access decisions here.  This
 *   header deliberately depends only on <stdint.h>/<stddef.h> (no nginx types)
 *   so the privilege algebra can be unit-tested as a standalone leaf.
 *
 * HOW: bits mirror XrdAccPrivs.hh exactly; brix_acc_parse_privs() ports
 *   XrdAccConfig::PrivsConvert() (positive privileges, then optional '-' then
 *   negatives); brix_acc_op_needs() + brix_acc_test() port
 *   XrdAccAccess::Test() (grant iff every required bit is present).
 */

#ifndef NGX_BRIX_ACC_PRIVS_H
#define NGX_BRIX_ACC_PRIVS_H

#include <stddef.h>
#include <stdint.h>

/* Authorization-database engine selected by `brix_authdb_format`. */
#define BRIX_AUTHDB_FORMAT_NATIVE  0   /* original src/path/authdb.c (default) */
#define BRIX_AUTHDB_FORMAT_XRDACC  1   /* faithful XrdAcc engine (src/acc/) */

/* `brix_authdb_audit` levels (bitmask: 1=deny, 2=grant). */
#define BRIX_AUTHDB_AUDIT_NONE   0
#define BRIX_AUTHDB_AUDIT_DENY   1
#define BRIX_AUTHDB_AUDIT_GRANT  2
#define BRIX_AUTHDB_AUDIT_ALL    3

/*
 * Privilege bits — numerically identical to enum XrdAccPrivs (XrdAccPrivs.hh).
 * Single primitives plus the composite operations XRootD pre-computes.
 */
#define BRIX_ACC_PRIV_NONE    0x000u
#define BRIX_ACC_PRIV_DELETE  0x001u  /* 'd' */
#define BRIX_ACC_PRIV_INSERT  0x002u  /* 'i' (also mkdir, create target) */
#define BRIX_ACC_PRIV_LOCK    0x004u  /* 'k' (historically unused) */
#define BRIX_ACC_PRIV_LOOKUP  0x008u  /* 'l' (stat / traversal) */
#define BRIX_ACC_PRIV_RENAME  0x010u  /* 'n' (mv source) */
#define BRIX_ACC_PRIV_READ    0x020u  /* 'r' (open r/o, readdir) */
#define BRIX_ACC_PRIV_WRITE   0x040u  /* 'w' (open w/append) */
#define BRIX_ACC_PRIV_POLL    0x100u  /* stage polling */
#define BRIX_ACC_PRIV_ALL     0x1ffu  /* 'a' */

/* Composite operations (XrdAccPrivs.hh): */
#define BRIX_ACC_PRIV_UPDATE  (BRIX_ACC_PRIV_READ | BRIX_ACC_PRIV_WRITE)   /* 0x060 */
#define BRIX_ACC_PRIV_CREATE  (BRIX_ACC_PRIV_INSERT | BRIX_ACC_PRIV_UPDATE) /* 0x062 */
#define BRIX_ACC_PRIV_CHMOD   (BRIX_ACC_PRIV_INSERT | BRIX_ACC_PRIV_UPDATE \
                                 | BRIX_ACC_PRIV_DELETE)                        /* 0x063 */
#define BRIX_ACC_PRIV_STAGE   (BRIX_ACC_PRIV_POLL | 0x080u)                   /* 0x180 */

typedef uint16_t brix_acc_privs_t;

/*
 * Single, positive + negative privilege capabilities (struct XrdAccPrivCaps).
 * The effective grant from a set of capabilities is (pprivs & ~nprivs).
 */
typedef struct {
    brix_acc_privs_t pprivs;   /* positive (granted) bits */
    brix_acc_privs_t nprivs;   /* negative (explicitly denied) bits */
} brix_acc_priv_caps_t;

/*
 * Operations — numerically identical to enum Access_Operation
 * (XrdAccAuthorize.hh).  AOP_ANY (0) is the "return privileges, no test" form.
 */
typedef enum {
    BRIX_AOP_ANY         = 0,
    BRIX_AOP_CHMOD       = 1,
    BRIX_AOP_CHOWN       = 2,
    BRIX_AOP_CREATE      = 3,
    BRIX_AOP_DELETE      = 4,
    BRIX_AOP_INSERT      = 5,
    BRIX_AOP_LOCK        = 6,
    BRIX_AOP_MKDIR       = 7,
    BRIX_AOP_READ        = 8,
    BRIX_AOP_READDIR     = 9,
    BRIX_AOP_RENAME      = 10,
    BRIX_AOP_STAT        = 11,
    BRIX_AOP_UPDATE      = 12,
    BRIX_AOP_EXCL_CREATE = 13,
    BRIX_AOP_EXCL_INSERT = 14,
    BRIX_AOP_STAGE       = 15,
    BRIX_AOP_POLL        = 16,
    BRIX_AOP_LAST        = 16
} brix_acc_op_t;

/*
 * brix_acc_op_needs() — the privilege bits an operation requires.
 *
 * Ports XrdAccAccess::Test()'s need[] table.  AOP_EXCL_* return 0xffff (a value
 * no real privilege set can satisfy) because exclusivity is enforced outside the
 * privilege model.  AOP_ANY returns 0 (no requirement).  Out-of-range ops return
 * 0xffff (deny).
 */
brix_acc_privs_t brix_acc_op_needs(brix_acc_op_t op);

/*
 * brix_acc_test() — does `priv` satisfy `op`?  Returns 1 (granted) iff every
 * required bit is present: (need & priv) == need.  Ports XrdAccAccess::Test().
 */
int brix_acc_test(brix_acc_privs_t priv, brix_acc_op_t op);

/*
 * brix_acc_parse_privs() — parse a privilege letter string [s, s+len) into
 * positive/negative capabilities.  Ports XrdAccConfig::PrivsConvert():
 *   letters a/d/i/k/l/n/r/w accumulate into the positive set, a single '-'
 *   switches the remainder into the negative set; a second '-' or any unknown
 *   character is an error.  Returns 0 on success, -1 on a malformed string.
 *   Note (vs the native engine): 'r' does NOT imply 'l'.
 */
int brix_acc_parse_privs(const char *s, size_t len, brix_acc_priv_caps_t *caps);

/* brix_acc_op_name() — the XrdAcc operation name ("read", "stat", ...) for
 * audit/logging; "???" for an out-of-range operation. */
const char *brix_acc_op_name(brix_acc_op_t op);

#endif /* NGX_BRIX_ACC_PRIVS_H */
