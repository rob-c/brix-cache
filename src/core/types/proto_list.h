#ifndef BRIX_PROTO_LIST_H
#define BRIX_PROTO_LIST_H

/*
 * proto_list.h — THE single declaration of every protocol plane.
 *
 * WHAT: one X-macro row per protocol this module speaks. Everything that
 *       enumerates protocols generates from this list: the unified metrics
 *       enum + its {proto="..."} label strings (observability/metrics/
 *       unified.h/.c), the dashboard transfer-slot ids + display names
 *       (observability/dashboard/dashboard.h, api.c), and the dashboard's
 *       per-protocol JSON buckets (history "active_<name>", totals
 *       "<name>_bytes_rx/tx" + "<name>_errors_total", protocols summary).
 * WHY:  before phase-68 the list lived in five hand-maintained places; the
 *       cvmfs plane had to be threaded through each one separately. Adding
 *       a protocol must be ONE row here, not an archaeology exercise.
 * HOW:  X(ID, metric_label, dash_name, http_plane)
 *         ID           enum suffix: BRIX_PROTO_<ID> (unified metrics,
 *                      value = row index) and BRIX_XFER_PROTO_<ID>
 *                      (dashboard slots, value = row index + 1; 0 stays
 *                      "untracked"). Both are SHM-persisted as small ints,
 *                      so rows are APPEND-ONLY — never reorder or remove.
 *         metric_label the exported /metrics {proto=...} value. FROZEN:
 *                      the stream plane has always exported "stream".
 *         dash_name    the dashboard display name and per-proto JSON key
 *                      stem ("active_<dash_name>", "<dash_name>_bytes_rx").
 *                      FROZEN: the dashboard has always shown "root".
 *                      Identical to metric_label for every HTTP plane.
 *         http_plane   1 = serves on nginx's HTTP side and gets per-proto
 *                      byte/error totals in the dashboard JSON; 0 = stream
 *                      plane (covered by the global stream counters).
 *
 * Adding a protocol — the full checklist (everything else is generated):
 *   1. append the row here (build: header-only, plain `make`)
 *   2. give it a protocol-specific SHM counter family if it needs one:
 *      member struct in observability/metrics/metrics.h + a dedicated
 *      exporter fanned out from metrics/stream.c (cf. cvmfs.c, s3)
 *   3. source its dashboard byte/error totals in
 *      observability/dashboard/api_snapshot.c dashboard_collect_totals()
 *      (per-proto SHM families are heterogeneous by design — the glue
 *      that reads them cannot be generated)
 *   4. pass BRIX_PROTO_<ID> to brix_vfs_ctx_init() and
 *      BRIX_XFER_PROTO_<ID> in the serve opts at the handler
 *   5. if it is HTTP-only, ensure the shared SHM zones from its
 *      postconfiguration (brix_metrics_ensure_zone +
 *      brix_configure_dashboard — cf. protocols/cvmfs/module.c)
 *   6. docs: CLAUDE.md ROUTING + OP→FILE rows, docs/04-protocols/ page
 *   7. tests: metrics scrape + dashboard visibility asserts (cf.
 *      tests/run_cvmfs_reverse.sh T16 blocks)
 *
 * Related name surface (hand-wired, uses these dash_names): the
 * $brix_protocol variable in protocols/webdav/module_init.c reports
 * which HTTP module claimed a request ("webdav"/"s3"/"cvmfs", "http"
 * fallback) — extend its claim chain when adding an HTTP protocol
 * (checklist step 4a).
 */

#define BRIX_PROTO_LIST(X)                                                  \
    X(ROOT,   "stream", "root",   0)  /* native root:// stream plane        */ \
    X(WEBDAV, "webdav", "webdav", 1)  /* WebDAV/HTTP (davs://, http://)     */ \
    X(S3,     "s3",     "s3",     1)  /* S3-compatible REST                 */ \
    X(CVMFS,  "cvmfs",  "cvmfs",  1)  /* cvmfs:// site cache (phase-68)     */

#endif /* BRIX_PROTO_LIST_H */
