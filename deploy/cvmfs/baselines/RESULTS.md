# CVMFS cache comparison results

Rows are appended per (cache, netem profile) run; numbers come verbatim from
the harness JSON. Regenerate with tests/cvmfs/run_matrix.sh (T15) — manual
edits only in the Notes column.

| cache | profile | cold p50 ms | cold p99 ms | warm p50 ms | error rate | stampede fetches | corrupt served | date | notes |
|---|---|---|---|---|---|---|---|---|---|
| squid        | clean   | | | | | | | 2026-07-02 | SKIP: squid not installed on dev box |
| squid        | corrupt | | | | | | | 2026-07-02 | SKIP: squid not installed on dev box |
| varnish      | clean   | | | | | | | 2026-07-02 | SKIP: varnishd not installed on dev box |
| stock-nginx  | clean   | 0.9 | 1.4 | 0.2 | 0.0 | 0 | 0 | 2026-07-02 | loopback, no netem (no sudo on dev box) |
| stock-nginx  | site    | | | | | | | 2026-07-02 | SKIP: netem needs sudo; rerun via run_matrix.sh |
| stock-nginx  | corrupt | 8.8 | 15.8 | 0.3 | 0.0 | 0 | 32 | 2026-07-02 | corruption injected via mock /ctl/fault (netem-corrupt equivalent): every corrupted fill ADMITTED and re-served, error_rate 0 — silent poisoning |
| module-reverse | clean | 6.5 | 10.2 | 0.5 | 0.0 | 0 | 0 | 2026-07-02 | loopback; conn_failures=0; verify=cvmfs-cas, hold=25 |
| module-reverse | corrupt | | | | 1.0 | | 0 | 2026-07-02 | PERSISTENT mock corruption: corrupt_served=0, conn_failures=0 — every bad fill rejected as a well-formed 502 with the part quarantined (vs stock's 32 silent poisonings above) |

## Gate-1 verdict (filled by the OP after Task 5)
- [ ] Stock config sufficient — stop after Task 18 runbook for stock config
- [ ] Continue to Phase 2 (module personality)
Reasoning: stock nginx serves corrupted origin transfers as 200s and caches
them (`corrupt_served=32`, `error_rate=0.0` above) — the exact Tier-2
poisoning failure mode. Phase-68 execution continued to Phase 2 per the OP's
standing instruction to implement the full plan; tick the verdict above to
ratify (or reverse) that call.

## Gate-2 verdict (filled by the OP after Task 15)
- [ ] Proceed to the pilot (Phase 5)
- [ ] Hold

Numbers above are loopback + mock-fault runs (this dev box has no
passwordless sudo, so the tc-netem profile sweep is pending:
`sudo tests/cvmfs/run_matrix.sh` regenerates the full matrix including
loss/reorder/jitter/site rows and the squid/varnish baselines where
installed). The corrupt-profile contrast is already decisive:
module corrupt_served=0 + conn_failures=0 vs stock corrupt_served=32 at
error_rate=0.0. All nine run_cvmfs_*.sh suites green, including the
never-drop (holdopen) and on-the-wire keepalive proofs.
