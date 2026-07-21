# Phase 88 — Open-work audit: doc/memory truth sweep + verified remaining-work register

**Status:** AUDIT EXECUTED 2026-07-20 (doc corrections landed, UNCOMMITTED). The
register below (§3–§5) is the *verified* open-work backlog for the module as of
this date; the doc fixes (§2) are complete.
**Scope:** every open/remaining/deferred/not-shipped claim across `docs/`,
`docs/refactor/`, and the session memory index — EXCLUDING CVMFS work (phase-84
corpus, cvmfs-automount, phase-68/85/87 CVMFS legs).
**Method:** three parallel sweeps enumerated every claim; each load-bearing claim
was then verified against the current tree (grep for the code, read the gate
test, run the checker) rather than trusted. Docs claiming work was needed when it
was in fact done were corrected in place (§2); claims that survived verification
form the register (§3–§5).

---

## 1. Why this phase exists

The docs are chronological build logs: a section written in June saying
"⛔ still needs X" is routinely superseded by a section further down the same
file saying "X landed". Two long-open items (native TPC vs stock `ofs.tpc`
sources; the A-2 WebDAV-proxy heap corruption) had already been closed this
month, but four-plus places each still declared them open. This phase is the
reconciliation pass: make the docs stop claiming dead work, and produce one
verified register of what actually remains to complete the module.

Recurring doc pattern worth keeping in mind for future audits: **"Status:"
headers and mid-file "Remaining:" blocks go stale; the chronologically-last
progress section in a phase doc is the truth.** When correcting, prefer an
inline `> SUPERSEDED:` blockquote at the stale claim (preserving the historical
record) over rewriting history.

---

## 2. Doc corrections landed (claimed open, verified done)

| Doc | Stale claim | Verified truth | Fix |
|---|---|---|---|
| `09-developer-guide/pblock-metadata-performance.md` | linked `tests/run_pblock_meta_gsi.sh` (deleted) | Python port = `pblock-meta-gsi` scenario in `tests/cmdscripts/pblock_live.py` | links + repro commands repointed |
| `10-reference/conformance/README.md` | linked `tests/c/run_x509_oracle.sh` + `tests/run_x509_differential.sh` (deleted) | ports = `cmdscripts/c_auth_units.py` (`x509_oracle`) + `cmdscripts/x509_differential.py` | links repointed, pytest wrappers named; `check_doc_links.sh` now green |
| `09-developer-guide/history-security-and-credentials.md` | "**STILL OPEN, not fixed:** `xrootd_webdav_proxy` … heap-corrupts … needs an ASan build" | A-2 RESOLVED 2026-07-20 by **surface retirement** — the corruption lived in the already-dead reverse-proxy transport (`proxy_response.c::webdav_proxy_process_header`), which was deleted whole | paragraph rewritten as RESOLVED with pointer to hyper-hardening § A-2 |
| `07-security/hyper-hardening-plan.md` (×3 spots) | exec-summary Deferred list, §11 register row "❌ (no ASan lane → B-2)", B-2 prose — all framed A-2 as open/blocked | same as above; B-2 no longer a dependency for A-2 | Deferred list pruned + note; register row → ✅ resolved; B-2 prose annotated (lane remains the *systemic* gap) |
| `refactor/phase-57-tpc-delegation-zip-locks.md` (×3 spots) | header "Status: Planned"; W1 "⛔ Stock-source interop … needs async attn handling"; "F6 … designed, gated, NOT shipped" | phase is code-complete per its own later sections; the stock-source "push-model" theory was a **misdiagnosis** of a `tpc.org` strcmp mismatch, fixed by `tpc_build_origin_id` (f36eb208, gate `tests/test_tpc_gsi_stock_source_only.py` green 2026-07-20); F6 shipped — `test_tpc_delegation.py::test_dest_pulls_as_user_via_delegation` is a hard-green assertion in-tree, no xfail | status line rewritten; SUPERSEDED blockquotes at both stale claims |
| `09-developer-guide/fast-lane-burndown-2026-07.md` §6 | `tpc_gsi_nginx_source` listed as remaining while §3.2 of the same doc records it green 2026-07-20 | green | moved to the "Fixed after the first draft" paragraph |
| `refactor/phase-82-gridftp-gateway.md` | "Still pending: P82.5 hardening (evil-actor MODE E offset attacks) + k8s lab" | offset-attack class IS guarded: `ftp_ev_mode_e.c` overlap/overflow-checks every block (`ftp_eb_range_overlaps`, abort on violation), gated by `test_gridftp_mode_e_truncation.py` + the evil suites | Update blockquote added; **k8s lab stays open** (§4) |

Memory-side corrections (same sweep): `hybrid_mesh_webdav_proxy_xrdhttp_crash`
rewritten as RESOLVED pointer; stale "still open" cross-refs to the resolved
native-TPC-GSI item fixed in `hybrid_mesh_webdav_redirect_gap`,
`af_bridging_monitoring_proxy`, `pblock_lab_phase83`.

Also verified-fine (no fix needed): the `history-security-and-credentials.md`
"general nginx-managed proxy/upstream TLS has no chain verification by default"
backlog note is accurate as a config-default statement — the opt-in
`proxy_ssl_verify` wiring exists (`module_directives.c` hashed-CA-dir seeding).

---

## 3. VERIFIED remaining work — bugs and gates (actionable now)

Ordered by signal. Each was re-verified 2026-07-20, not just quoted.

1. ~~**FRM stage ownership not enforced**~~ — **STALE CLAIM, closed on
   re-verification (2026-07-20):** `brix_stage_request_owner_check`
   (`src/fs/xfer/stage_request_registry_query.c`) already gates Tape REST
   DELETE and body-less POST `/cancel` (403 for a foreign principal, fail-open
   only for anonymous/owner-less/absent — no enumeration oracle);
   `tests/test_frm_owner.py` 5/5 green. Burndown §6 corrected to match.
2. ~~**`test_cmd_*` live-scenario cluster** still failing (non-CVMFS legs)~~ —
   **CLOSED on re-verification (2026-07-20):** all 13 non-CVMFS scenarios
   (`pblock_live` 5, `tpc_fwd_live` 3, `fwd_matrix_live` 5) now exit 0 both
   standalone (`python3 -m cmdscripts.pblock_live <s>` etc.) and through the
   pytest wrappers (15 passed, 1 xpassed — `fwd-brix-brix` xfail now xpasses).
   The recorded failures were cured earlier by the burndown's §2.2
   worker-ownership fixes (`pblock_worker_own`), the §2.4 `-g "user root;"`
   injection, and the TPC `tpc.org` host-string fix (f36eb208); the burndown §6
   entry was stale. One transient repro of `pblock-meta-gsi` failing 976/976
   inside a wrapper batch traced to a concurrent session wiping the shared PKI
   mid-run (missing proxy ⇒ every GSI op fails instantly), not to the scenario.
   Remaining sibling: `brixcvmfs_live` 3 (CVMFS, out of this phase's scope).
3. ~~**`x509_oracle` xfailed on a link error**~~ — **FIXED in this phase
   (2026-07-20):** the compile lists in `cmdscripts/c_auth_units.py` predated
   the `store_policy.c` file-split; added `store_policy_store.c` +
   `store_policy_conformance.c` to both the `x509_oracle` and
   `x509_conformance` runners, removed both xfails, and added
   `@pytest.mark.timeout(600)` (the clause forge runs ~5 min, tripping the
   default 30 s). Verified: `x509_conformance` PASSED under pytest;
   `x509_oracle` **558 oracle checks, 0 failures** (the unity-build-vs-file-
   split lesson from the hyper-hardening record, striking again). Regression
   guard added so this class of break can't hide again: the harness link lines
   are now a single shared list (`X509_POLICY_SOURCES` in
   `cmdscripts/c_auth_units.py`), a fast link-only runner (`x509_link`)
   gcc-links both harnesses in seconds on every suite run, and
   `test_c_auth_units.py::test_x509_link_guard_detects_stale_source_list`
   re-creates the original stale-list break and asserts the guard reports it.
   Un-xfailing also exposed a latent flake: under pytest the forged fixture
   corpus landed in pytest's basetemp under `TMPDIR=/tmp/xrd-test/tmp`
   (conftest), which **concurrent pytest sessions rotate to `garbage-*` and
   `rm_rf` mid-run** — the CAs vanish and every accept clause fails closed
   (observed as 554 checks/201 accept→reject; direct CLI runs were immune
   because they use plain `/tmp`). The race hits **three** artifact classes in
   turn — the forged fixture corpus, the harness binary's output path, and even
   gcc's intermediate `.s` files (child processes inherit `TMPDIR`). Fixed
   hermetically: `x509_fixture_dir()` forges into a private `/tmp` dir (env
   `BRIX_X509_FIXTURES` still overrides), binaries compile into that same dir,
   `HERMETIC_ENV` pins `TMPDIR=/tmp` for every child process (gcc, harness,
   forge), and the pytest file uses a `private_tmp` fixture instead of
   `tmp_path` (whose *setup* can itself FileNotFoundError when a concurrent
   session rotates the basetemp root). Guarded by
   `test_x509_fixture_dir_avoids_shared_basetemp`; full file green 9/9 under
   active concurrent-session churn.
4. ~~**Phase-18 auth-gate migration incomplete (or needs a won't-do ruling)**~~ —
   **CLOSED (2026-07-20):** ruled per-site in
   `phase-18-auth-gate-completion.md` § Resolution. statx.c hid one REAL bug
   (its per-path predicate called bare `brix_check_authdb`, so the xrdacc
   engine never gated STATX — an unruled path leaked its flag byte) — fixed
   by routing the tier through `brix_authz_check`; denial logging was already
   correct via `BRIX_RETURN_ERR` at the call site. prepare.c was materially
   already migrated (its authdb tier consumes `brix_authz_check`; the "zero
   auth_gate references" grep was textually true but stale) and stays on its
   doc-sanctioned error-sink form. webdav/access.c is won't-do: HTTP plane,
   denials metrics-counted + natively access-logged as 403; the stream gate
   API doesn't apply. Tests: `tests/test_acc.py::TestXrdAccStatx` (3 new) +
   `tests/test_new_opcodes.py::TestStatx` regression — green.
5. ~~**Admin-API rate limiting**~~ — **CLOSED (2026-07-20):** implemented as a
   per-source-IP leaky-bucket gate in `brix_admin_dispatch()` (between auth and
   routing), reusing the Phase-25 `brix_rl_*` helpers against a dedicated
   built-in `brix_admin_api` SHM zone. Separate generous read/write buckets
   (defaults 1200 GET-HEAD/min, 120 POST-PUT-DELETE/min per IP) so extensive
   legitimate querying under load keeps working; 429 + `Retry-After` + audit on
   throttle; `brix_admin_rate_limit off | <w/min> [<r/min>]` knob. Tests:
   `tests/test_admin_rate_limit.py` (5 green); existing admin suites re-run
   green (28 passed / 2 pre-existing skips). Full record →
   `docs/refactor/phase-23-dynamic-upstreams.md` § Rate limiting.
6. ~~**Fleet-cutover final gate**~~ — **CLOSED (2026-07-20):** the live native
   gate ran end-to-end: fast tier (`operator_runtime suite --fast`, full
   120-spec fleet boot under xdist) finished **7628 passed / 7 failed**, and
   all 7 failures re-verified green in isolation (4 were vanished forged
   fixtures + 3 `SSL: UNEXPECTED_EOF` drops — both signatures of a concurrent
   session wiping `/tmp/xrd-test` mid-run, plus one cross-file fixture
   dependency: `test_webdav_tpc_cred` needs `test_webdav_tpc`'s session
   nginx). Then `stop-all` → `RegistryLauncher.final_leak_check()` **CLEAN** →
   `start-all` relaunched **120/120 with zero non-critical failures** — the
   first fully clean boot, because the gate also flushed out a real cutover
   regression: the six `[::1]`-tier specs bind v6-only but `_wait_ready`
   probed `settings.HOST` (127.0.0.1), so every boot mis-reported them as
   failed-to-start. Fixed by a `host` field on `NginxInstanceSpec`
   (`endpoint_for` honours it; IPv6 literals bracketed in `.url`) declared as
   `host=S.HOST6` on the ipv6 specs; 3 guard tests in
   `test_server_registry_smoke.py` incl. one asserting every `ipv6-*` spec
   declares `HOST6`.
7. ~~Cosmetic: s3 origin logs `op:"xattr"` for a served GET~~ — **FIXED
   2026-07-20:** every served GET probes the optional usermeta/tagging xattrs
   (`s3_echo_user_metadata`), and the absent-attribute ENODATA came out of
   `brix_vfs_xattr_observe_count` as a failed op:"xattr" line with
   status:"other". Absence of an optional attribute is an expected negative
   lookup: the observe tail (`src/fs/vfs/vfs_xattr.c`) now records ENODATA on
   get/list as a clean zero-byte ok (callers still see -1/ENODATA unchanged;
   real errors still book their errno class). Tests: 3 new in
   `tests/test_metrics_vfs_ops.py` (no-metadata GET books ok not other;
   usermeta round-trip; missing-object ?tagging books nothing) — file 7/7
   green live.

---

## 4. VERIFIED remaining work — blocked on infra unavailable from this shell

- **Hyper-hardening tail** (the only genuinely-open items of the 19+):
  **B-1** analyzer blocking-flip (needs pinned CI toolchain baseline),
  **B-2** ASan+UBSan CI lane, **remaining C-1** fuzz targets (GSI ASN.1, SSS
  frames, macaroon, SigV4 canonicaliser — each needs a pure `(data,len)` entry
  carved from its TU first), **C-2** framing fuzz (same prerequisite, attach to
  the B-3 lane), B-3 corpus auto-grow-back (needs a git-write bot).
- **Write mirroring (phase-24 / 57-W3)** — e2e runtime validation + ASan never
  completed; required before production enable.
- **Phase-82 k8s interop lab** — globus-url-copy/gfal2/VOMS container matrix +
  FTS bulk lane (the one still-open item from the gridftp phase).
- **Perf-host-blocked**: phase-33 P0/P1/P3-B1,B3/P5; phase-32 WS3
  recv-state-machine flip; phase-29 P3 AIO read pipelining; phase-31 readv/
  pgread resident-windowing follow-up.
- **Pelican cache registration** — public-key handshake with the federation
  registry, blocked on the operator running the `pelican` CLI out-of-band.

---

## 5. Feature backlog (designed/planned — not bugs)

Plan-only phases: **70** (full credential delegation — not started), **27/28**
(memory-safety / adversarial hardening), **54/55** (VFS thread-safe IO core /
storage-backend abstraction — check overlap with landed 63/64/71 before
starting). Design-only: **60** (Ceph beyond the basic `sd_ceph.c` driver),
**61** (CMS parity spec), **64** (fully-tiered composable storage +
generic-slice-fill BACKLOG) — *re-verified against the tree 2026-07-21 and
reduced to an implementation umbrella,
`phase-89-design-backlog-burndown.md`: 60 is ~half landed (remainder = the
namespace plane), 61 is fully open (~9 wk, W2 re-grounded on the
stage-request registry), 64 is substantially landed (slice-fill follow-up
DONE; remainder = directive-grammar decision + infra-blocked/deferred tail)*.
Partial: **59** (staged CSI-counter + W3b
reservation TPC call-site rows; deferred W2 per-page CSI+scrub), **58**
(remaining wire wrappers; 5g test deferred), **80** stretch (P80.11–14,
P80.21–25 zero-provisioning multi-user), **56** (remaining VFS perf-audit
migrations, e.g. `webdav_handle_mkcol`), **49** tail (low-value client
code-sharing sweep), **38** (6 of 28 files still unsplit), **83**
(`pblock-fsck --replay` deferred).

> **SUPERSEDED 2026-07-21 — all 8 loose ends below CLOSED** (implemented +
> tested in one sweep; each item annotated inline):

1. `evict_at`/`evict_to` no consumer — **FIXED**: watermark scan consumer
   landed + parse-tested (`test_cmd_cache_watermark_config.py`).
2. `xrdckverify --cache` no producer — **FIXED**: verified-fill now records
   the checksum server-side; client xmeta reader + 13-unit suite + live e2e
   (`test_cache_verify_require.py`, `test_xrdckverify.py`).
3. Generic S3 `listxattr` over `x-amz-meta-*` — **FIXED**: `resp_headers_raw`
   transport extension + `sd_s3_list_meta`/`sd_remote_listxattr`; live smoke
   (`cmdscripts.metadata_live_ports sd-s3-meta`). Gotcha: the mid-struct
   vtable insert required a stale-object purge in ALL THREE build systems
   (shared/xrdproto has zero dep tracking — ABI skew crashed `resp_free`).
4. CSI `.xrdt` hidden from dirlist — **FIXED** + 4 tests.
5. TPC outbound GSI 10300→10600 signed-DH — **FIXED**, live-verified vs stock
   (`test_tpc_gsi_stock_source_only.py`, `test_tpc_tls.py`).
6. Phase-71 deferred e2e wire tests — **DONE**: `test_readonly_backend_wire.py`
   proves kXR_mkdir/mv → kXR_NotAuthorized and truncate → kXR_Unsupported over
   the root wire on an s3 backend, with a byte-exact read success leg.
7. Phase-34 `ffecho` — the "unimplemented" claim above was **STALE**: the
   root:// echo timer already existed; the real gap was the min-30s clamp,
   now landed + tested (`test_pmark.py`).
8. Phase-22 probe TLS upgrade (Step F) — **IMPLEMENTED** via the shared
   `brix_outbound_start_tls()` seam; TLS-capable probes advertise
   `kXR_ableTLS` and defer login past the protocol verdict (a pipelined
   plaintext login corrupts the server's TLS handshake). Deep/verify-fail/
   shallow-fallback legs in `test_phase22_health_check.py` §4.

Original register (kept for the record): `evict_at`/`evict_to` directives
had no consumer; `xrdckverify --cache` no producer; generic S3 `listxattr`
needed a transport extension; CSI `.xrdt` not hidden from dirlist; TPC
outbound GSI advertised unsigned-DH 10300; phase-71 e2e wire tests deferred;
phase-34 `ffecho` (mis)flagged unimplemented; phase-22 probe path had no TLS
upgrade (as-built divergence).

Standing refactor backlog: `docs/refactor/QUALITY_ROADMAP.md` (score 6.5→9.5
target) remains the primary live code-quality queue.

**Needs reconciliation, deliberately not done here:** the 2026-07-03
brix-symbol-rebrand checklist (~60 unchecked boxes) — the tree is clearly
already `brix_`-rebranded, so the checklist is likely executed-but-unticked;
tick-or-annotate it against the tree in its own pass rather than trusting
either direction.

---

## 6. Out of scope

All CVMFS work (phase-84 conformance corpus, cvmfs-automount packaging,
phase-68/85/87 CVMFS legs) was excluded per the audit's brief. By-design parity
gaps (`gaps-vs-xrootd.md`, feature-matrix "not implemented" rows, phase-20/21
won't-do items) are documented decisions, not open work, and are not listed.
