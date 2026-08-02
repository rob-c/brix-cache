/*
 * storascan_internal.h — private glue shared across the xrdstorascan TUs.
 *
 * WHAT: the exit codes, sweep/buffer limits, shared connect/parse helpers and
 *       the three subcommand entry points (`cmd_verify`, `cmd_bench`,
 *       `cmd_scan`) that main() dispatches to.
 * WHY:  xrdstorascan.c was split per subcommand (verify / bench / scan) to keep
 *       each file within the Phase-38 size budget; this header is the only
 *       surface those siblings share — nothing here is public client API.
 * HOW:  the shared helpers live in xrdstorascan.c (the dispatcher TU); each
 *       cmd_* lives in its own storascan_<mode>.c. Constants stay macros so the
 *       frozen defaults/limits remain identical across every TU.
 */
#ifndef STORASCAN_INTERNAL_H
#define STORASCAN_INTERNAL_H

#include <stdio.h>

#include "brix.h"
#include "brix_net.h"

/* buffer / sweep limits (shared by the verify + bench siblings) */
#define STORASCAN_HEX_MAX 129
#define STORASCAN_MAX_SWEEP 16        /* cells per block/parallel list           */
#define STORASCAN_LAT_CAP (5u << 20)  /* per-worker latency-sample ceiling        */
#define STORASCAN_MSG (XRDC_MSG_MAX + 32) /* room for a short prefix + st.msg     */

/* exit codes (verify mirrors xrdckverify) — shared by every subcommand */
#define SX_OK        0
#define SX_MISMATCH  1
#define SX_NORECORD  2
#define SX_ERROR     3
#define SX_USAGE     64

/* ---- shared helpers (defined in xrdstorascan.c) --------------------------- */

/* Print xrdstorascan usage to stderr and return rc. */
int usage(const char *prog, int rc);

/* Match argv[*i] against a value-taking option and consume it (1) or not (0). */
int opt_take(const char *name, int argc, char **argv, int *i, const char **out);

/* Parse + connect to the endpoint in `url`. 0 on success (c/u filled), else a
 * shell exit code already reported to stderr. */
int storascan_connect(const char *url, brix_url *u, brix_conn *c,
                      brix_status *st);

/* ---- subcommand entry points (one per storascan_<mode>.c) ----------------- */

int cmd_verify(int argc, char **argv, const char *prog);      /* storascan_verify.c */
int cmd_bench(int argc, char **argv, const char *prog);       /* storascan_bench.c  */
int cmd_scan(const char *mode, int argc, char **argv,
             const char *prog);                               /* storascan_scan.c   */

#endif /* STORASCAN_INTERNAL_H */
