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

### 2.1 Addendum (2026-07-27): in-code comment truth sweep

Same method applied to **source comments**: every "placeholder / not yet
implemented / future / until then / stub / stopgap" comment in `src/`,
`shared/`, `client/` was verified against the tree; ten had been overtaken by
landed work and were corrected (comment-only edits; clean rebuild verified).

| File(s) | Stale claim | Verified truth |
|---|---|---|
| `src/fs/xfer/stage_engine.h` | durable queue/scheduler/reconcile "no-ops until SP4"; frm driver "(future)" | all landed (`stage_engine_{scheduler,reconcile,journal}.c`, registry, `sd_frm.c`); async submit journals + returns durable reqid |
| `src/fs/xfer/stage_engine_reconcile.c` | — | leftover duplicate function comment removed |
| `src/fs/backend/sd.h` | SD seam "not yet wired into any VFS callsite (55.B+)" | VFS routes all raw storage I/O through it (invariant 12, `check_vfs_seam.py`) |
| `src/fs/backend/cache/sd_cache.{h,c}` | cache not on live root:// path; recall awaits frm driver; NEARLINE "cannot be served" | tier grammar wires it (`tier_build.c`); async-fill seam live (`src/protocols/shared/http_cache_fill.c`); recall = EAGAIN/retry-poll contract |
| `src/fs/cache/cstore.c` | XATTR/SIDECAR cinfo modes "ENOSYS until SP2" | both implemented via the xmeta carrier; remaining ENOSYS are NULL-slot guards |
| `src/fs/backend/s3/sd_s3.h` | write/MPU "follow (later)" | `sd_s3_write.c` implements single-PUT + multipart |
| `src/net/cms/server_recv_frame.c` | `usage/stats/statfs` cited as unwired example opcodes | phase-89 routed all three (`cms_srv_frame_routes[]`) |
| `src/fs/vfs/vfs_internal.h` | "(future) data-plane ops route through the storage driver" | they do (`vfs_io_core.c`) |
| `src/protocols/cvmfs/{gate,geo}.c` | manifests bypass the cache "until T12" | T12 landed — manifests cache TTL-stamped; only the geo API uses the passthrough |

Verified accurate and left alone: `sd_remote.c` namespace ops (genuinely
absent), the client S3 cred-store deferral (task C2, consistently open across
`cred_bearer.c`/`cred_x509.c`), the gridftp thread-pool offload (P82.2, still
deferred — the `worker_processes 2` workaround confirms it), `tier_needs_dev`
(real fallback for builds without optional libraries), and RFC 4918
lock-null / HTML / template "placeholder" terminology.

Related: the TODO/FIXME ratchet backlog is at its terminal floor of 3
permanent prose markers and FIXME count is zero repo-wide — see
`QUALITY_ROADMAP.md` §3.7 update + Document History v2.4.

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

- **Hyper-hardening tail** — ✅ **ALL CLOSED 2026-07-30.** The whole tail is now
  landed (was: the only genuinely-open items of the 19+):
  - ~~**B-1** analyzer blocking-flip~~ *[LANDED 2026-07-30 — `fanalyzer.yml` +
    `codechecker.yml` flipped to BLOCKING per-PR: `pull_request`+`push` triggers,
    `continue-on-error` dropped, and both now run in `container: almalinux:9` (the
    dev distro — gcc 11.5.0 / clang 21.1.8) so the frozen ratchet baselines
    reproduce and the gate is stable enough to block. Guard
    `tests/test_ci_analyzer_gate.py`. See hyper-hardening § B-1]*.
  - ~~**B-2** ASan+UBSan CI lane~~ *[LANDED 2026-07-30 — `tools/ci/asan.py` +
    `.github/workflows/asan.yml`: sanitized build → fleet → real root:// I/O →
    fail on any ASan/UBSan/LSan finding (post-run report scan, `tests/lsan.supp`
    curates third-party leaks); PR/push smoke + nightly fast-tier cron, both
    self-skipping when infra is absent. Guard `tests/test_ci_asan_lane.py`. See
    hyper-hardening § B-2]*.
  - ~~**C-1** remaining fuzz targets (GSI ASN.1, SSS frames, macaroon, SigV4
    canonicaliser)~~ *[LANDED 2026-07-30 — each carved into a pure `(data,len)` TU
    (`sss_framing.c`, `macaroon_frame.c`, GSI `gsi_buf.c` already pure, SigV4 via a
    `BRIX_SIGV4_STANDALONE`-guarded include) with the nginx-coupled caller
    delegating; harnesses `fuzz_gsi_bucket`/`fuzz_sss_frame`/`fuzz_macaroon_frame`/
    `fuzz_sigv4_canonical`. See hyper-hardening § C-1]*.
  - ~~**C-2** framing fuzz~~ *[LANDED 2026-07-30 — `brix_max_payload_for_request` +
    new `brix_root_frame_dlen_ok` carved into `recv_frame_bounds.{c,h}`; harness
    `fuzz_root_frame` makes the "reject oversized `dlen` before allocation"
    invariant executable. See hyper-hardening § C-2]*.
  - ~~**B-3** corpus auto-grow-back (needs a git-write bot)~~ *[LANDED 2026-07-30 —
    `tools/ci/fuzz_corpus_writeback.py` + the `corpus-writeback` job in `fuzz.yml`:
    nightly `-merge=1` minimization committed back to `main`, never on
    `pull_request`, stages nothing outside `tests/fuzz/corpus_*`. Guard
    `tests/test_ci_fuzz_corpus_writeback.py`. See hyper-hardening § B-3 Fix 2]*.
  - Behaviour of every carved parser is pinned by `kat_carved_parsers.c` /
    `tests/test_fuzz_carved_parsers.py` (success + error + security-neg per function).
- **Write mirroring (phase-24 / 57-W3)** — e2e runtime validation + ASan never
  completed; required before production enable.
  > **UPDATE 2026-07-28:** the **e2e runtime validation** half is now DONE for the
  > XRootD stream data-write mirror (`stream_wmirror*.c`), which previously had only
  > source-marker + config-parse coverage. Three live tests drive a real root://
  > `open(create)->write->close` on a primary with `brix_mirror_writes on` against a
  > **live, writable embedded shadow origin** and assert the detached replay end to
  > end: byte-exact file landing on the shadow + `brix_mirror_requests_total{surface=
  > "stream"}` increment (success); a non-sequential/gapped write aborting in the
  > accumulator so **no** replay ever launches (error path — neither requests nor
  > errors counter moves, no shadow file); and total inertness with
  > `brix_mirror_writes off` (production-safety gate). Added:
  > `tests/configs/nginx_mirror_stream_wpair.conf`,
  > `test_phase24_mirror.py::test_stream_data_write_{mirrored_byte_exact,abort_not_replayed,off_not_mirrored}`
  > (3 lc-mir-stream-wr* ledger triples). Full phase-24 suite green (24/24). The
  > **ASan** half stays infra-blocked (needs the §4 B-2 ASan+UBSan CI lane) — the
  > disconnect-mid-write UAF / heap-buffer-ownership paths in the detached replay
  > are only machine-checkable there, so production-enable still gates on B-2.
  > **UPDATE 2026-07-30:** B-2 has since LANDED (`tools/ci/asan.py` +
  > `.github/workflows/asan.yml`), so the *lane* now exists — pointing its nightly
  > `ASAN_TEST_CMD` at a mirror-write suite (or adding the disconnect-mid-write
  > case to the smoke) is the remaining step to close the mirror ASan half; the
  > machine to run it is no longer the blocker, the targeted driver is.
  > **UPDATE 2026-07-30 (b) — CLOSED. The targeted driver landed and is wired
  > into the B-2 lane.** Two halves:
  > 1. *Driver* — three disconnect-mid-write tests
  >    (`test_phase24_mirror.py::test_stream_data_write_{disconnect_midwrite_no_replay,
  >    close_then_immediate_disconnect_replays,disconnect_churn_survives}`, ledger
  >    triples `lc-mir-stream-wr{drop,cdrop,churn}` 31174-31189) exercise the two
  >    lifetime hazards this bullet flagged: (a) a client that RST-drops mid-upload
  >    with **no** `kXR_close` — the accumulator's live `ngx_alloc` per-file buffers
  >    must be freed exactly once by `brix_stream_wmirror_cleanup` on teardown
  >    (LSan: leak; ASan: UAF if teardown races a launch) and no replay may fire;
  >    (b) a client that closes (launching the detached replay, which **steals**
  >    `f->data`) then immediately RST-drops — the replay must own and free the
  >    stolen heap buffer on its own cycle-pool lifetime with the client gone
  >    (ASan: UAF on the stolen buffer), landing byte-exact on the shadow; plus a
  >    12-cycle alloc/free/cleanup churn. All three assert worker survival on every
  >    run and pass green today (7/7 for `-k data_write`); under the sanitizer they
  >    are the memory-safety gate.
  > 2. *Wiring* — the driver runs under the sanitized fleet via a new second
  >    driver leg: `tools/ci/asan.py` honours `ASAN_TEST_CMD2` (a second command run
  >    in the same sanitized+attached fleet before stop+scan; a non-zero exit from
  >    *either* leg fails the job, both legs' reports scanned together), and the
  >    `asan.yml` nightly cron sets it to
  >    `pytest test_phase24_mirror.py -k data_write` — the suite the "not serial"
  >    fast tier drops. Guarded by `test_ci_asan_lane.py`
  >    (`test_asan_runner_supports_second_driver_leg` +
  >    `test_asan_nightly_drives_write_mirror_disconnect_suite`). Production-enable
  >    of `brix_mirror_writes` no longer gates on an unbuilt ASan driver — the
  >    disconnect-mid-write UAF / heap-ownership paths are now machine-checked
  >    nightly under ASan+UBSan+LSan.
  > **UPDATE 2026-07-31 — the READ-side counterpart is now closed too.** The
  > write-mirror drivers above covered the *write* detached-replay UAF; the *read*
  > AIO path (a stale thread-pool pread completion firing after the client is gone,
  > the concurrent recv-flip's destroyed-guard prerequisite) had only ONE
  > clean-close driver. Added the two missing stressors to
  > `test_aio.py::TestAioDestroyedGuard`:
  > `test_disconnect_during_large_read_rst_midflight` (hard RST, not FIN — the
  > completion lands against an already-reset fd) and
  > `test_disconnect_read_churn_survives` (12 open→read→drop cycles alternating
  > RST/FIN, exercising the per-read AIO-ctx alloc/free/destroyed-guard churn so a
  > double-free / UAF / leak is caught, not just a single miss). They carry no
  > slow/serial mark, so the nightly `ASAN_TEST_CMD` (`not slow and not serial`)
  > already runs them under ASan+UBSan+LSan — no lane wiring change; the `asan.yml`
  > comment now documents the read-side coverage next to the write-side. All 3
  > pass green functionally (2.3s). This retires the "read-AIO UAF coverage" that
  > the concurrent-AIO recv-flip was blocked behind.
- **Phase-82 k8s interop lab** — globus-url-copy/gfal2/VOMS container matrix +
  FTS bulk lane (the one still-open item from the gridftp phase).
  > **UPDATE 2026-07-31 — the code/lab side is CLOSED; only live-cluster
  > execution remains** (the same residual as every `s3voms`/`pbgsi` stretch
  > scenario). The `charts/gridftp-interop` chart + `test_gridftp_interop.py`
  > existed but were **unwired**: no `lab_suite.py` scenario, no VOMS-proxy
  > provisioning, and a naïve-loop "FTS" cell. Landed (phase-82 § P82.10):
  > (1) the chart is now **self-contained** (like `pb-gsi`) — its own
  > pre-install `pki-bootstrap` Job mints CA/host material + two client proxies
  > (`user_proxy.pem` plain, `vuser_proxy.pem` VOMS-AC `vo=atlas` via
  > `voms_proxy_fake.py`) into `gridftp-pki`, and `role.auth` mounts the host
  > credential so it no longer needs a lab-release `auth-authority`; `helm lint`/
  > `helm template` clean, templated bootstrap bash `bash -n`-parses. (2)
  > `lab_suite._gridftp` + a `gridftp` dispatch entry (release `gf` → Service
  > `gf-gridftp`, gsiftp 2811/ftp 2810), so `xrd-lab test gridftp` works. (3) a
  > real **VOMS interop cell** (`test_voms_attributed_proxy_roundtrip` — proves
  > the GSI control channel accepts an AC-bearing, out-of-issuer-order proxy
  > chain; interop, NOT gateway VO-ACL, which stays future work) and a real
  > **FTS bulk lane** — `test_fts_transfer_list_batch` (`globus-url-copy -f`
  > transfer-list, one invocation) + `test_fts_third_party_copy` (gsiftp→gsiftp
  > third-party copy, what an FTS server orchestrates). (4) **local guards
  > runnable without a cluster**: `pytests/test_remote_suite.py::test_gridftp_
  > scenario_dry_run_wires_interop_matrix` (+ explicit-selection) — 4 passed; the
  > interop module collects all 12 cells and self-skips at the container tier.
  > **Still blocked:** a live k8s cluster + the grid-client images to *run* the
  > matrix.
  > **UPDATE 2026-07-31 (b) — the cluster half is now CLOSED; the matrix runs
  > locally under rootless podman** (phase-82 § P82.11). Two parts: (1) a **real
  > bug fixed** — the `Dockerfiles/gridftp-client` image (authored P82.10, never
  > built) based its single stage on `almalinux:9-minimal`, which ships only
  > `microdnf`, so its `el-target.sh`+`dnf install` failed with `dnf: command not
  > found`; rebased on the full `almalinux:9` it now builds and ships
  > globus-url-copy + gfal-copy + voms-proxy-* + pytest. (2) a **local (no-k8s)
  > runner** `tests/cmdscripts/gridftp_interop_local.py` boots a combined
  > gsiftp+ftp gateway locally (`tests/configs/nginx_gridftp_interop.conf`, the
  > chart's two-listeners-over-one-export topology) and drives the identical
  > `test_gridftp_interop.py` matrix from the image with `--network=host`, the
  > test PKI proxy/CA mounted in, `TEST_GRIDFTP_*` pointed at the host gateway;
  > every missing prerequisite self-skips (exit 77). A new drift guard
  > `tools/ci/check_gridftp_interop_image.py` (guards.yml + fast lane) keeps the
  > image/runner/matrix contract from silently degrading a cell to a skip. Tests:
  > `tests/test_gridftp_interop_local.py` (8, offline — plan wiring incl. the
  > VOMS branch, the combined config validating under `nginx -t`, guard green +
  > injected-drift negatives). **The first-ever matrix run caught a real gateway
  > bug** (that is the whole point of an interop matrix): `globus-url-copy -cd`
  > issues `MKD interop/` with a **trailing slash**, which `brix_mkdir_beneath()`
  > (`src/fs/path/beneath.c`) split into a non-existent parent + empty leaf →
  > `550`, while `gfal`'s no-slash `MKD` worked. Fixed by stripping trailing
  > slashes before the parent/leaf split (matching the recursive path's existing
  > `brix_mkdir_normalise()`); the matrix now carries `-cd`/`-p` so it is
  > self-sufficient on any bare gateway and runs **9 passed / 3 skipped / 0
  > failed**. Fast-lane regression:
  > `test_gridftp_verbs.py::test_mkd_trailing_slash_and_confinement` (also
  > registered the previously-unregistered `gridftp-plain` fixed port → verbs
  > file 17/17). **Residual now:** only a one-time `podman build`
  > (network) + rootless podman — no k8s cluster; the remaining cluster-only
  > surface is the multi-node/FTS-*server* topology, not the client-interop matrix.
  > **UPDATE 2026-07-31 (c) — actually drove `xrd-lab test gridftp` live on
  > minikube; the whole path works except a stale server image, now diagnosed to
  > the exact package.** minikube v1.38.1 up, helm v3.21.2: `helm dependency
  > build` + `helm template` render clean (7 objects), the chart installs, and the
  > self-contained pki-bootstrap **Job completes** (mints CA/host + plain +
  > VOMS-AC proxies into `gridftp-pki`). The lone failure is the gateway pod
  > crash-looping on `nginx: [emerg] unknown directive "brix_gridftp"` — the
  > cluster's `brix-server:dev` image predates the phase-82 gateway. Verified at
  > the byte level: the rel-6 module RPM's `ngx_stream_brix_module.so` has **zero**
  > `brix_gridftp` symbols, so the RPM is stale, not just the image. The
  > current-tree rebuild (`k8s-tests/scripts/build.sh all`) then surfaced a second,
  > precise infra bug: the `rpm-builder` image's `dnf install` fails with `No match
  > for argument: libradosstriper-devel libcephfs-devel` — those two headers are in
  > the **CentOS Storage SIG Ceph** repo, which `lib/el-target.sh` adds only under
  > `BRIX_ENABLE_CEPH_SIG=1`, while `Dockerfiles/rpm-builder/Dockerfile` defaults it
  > `0` and lists them unconditionally (CRB is already enabled by el-target, so CRB
  > is not the gap). Unblock: build the rpm-builder with `--build-arg
  > BRIX_ENABLE_CEPH_SIG=1`, then `build.sh images` → tag `brix-server:dev` →
  > `minikube image load` → re-run. This narrows the residual from "needs a
  > cluster" (a cluster IS up and the chart works) to "the CI server image must be
  > rebuilt from the current tree with the ceph-SIG build-arg". Full recipe:
  > phase-82 doc §"Still open" UPDATE 2026-07-31.
  > **UPDATE 2026-07-31 (d) — DONE: the live gateway BOOTS and moves real data on
  > minikube.** Rebuilt the RPM (ceph-SIG on) + `brix-server:dev` and drove the
  > gateway pod to `1/1 Running` — which exposed that the "one stale image" was
  > actually an ~8-defect stale-lab cascade (the lab was never green; each earlier
  > report stopped at the first `emerg`). Beyond the two already-noted (rpm-builder
  > ceph-SIG + rebuild): rpm-builder `source_name` (`nginx-xrootd-` vs the spec's
  > `brix-`) + missing `-devel`s; `.dockerignore` `deploy/cvmfs` whitelist; server
  > image base (`:9-minimal`→`:9`) + `voms`/`--allowerasing`/`nginx-mod-stream` +
  > runtime libs; **`entrypoint.sh` regressed to `exec "$@"`** (ran nginx against
  > the stock conf-path, ignoring the `/etc/brix` mount, + mkdir'd RO PKI mounts) →
  > restored `nginx -c "$NGINX_CONF"`; **the rendered configmap never loaded the
  > dynamic modules** → added `include /usr/share/nginx/modules/*.conf;` to
  > `topology-role`'s configmap; `lab.py` missing the `gridftp` dispatch entry;
  > stale vendored subchart `.tgz`. LIVE PROOF: `nginx -t` clean, listening on
  > 2811/2810, and a pure-`ftplib` STOR/RETR round-trip through the cleartext
  > channel is byte-exact in PASV **and** active mode (md5-verified), landing in
  > the posix export `/data/xrootd/`. Guards: `tests/test_k8s_gridftp_gateway_
  > guard.py` (6, offline, green). **Remaining (not gateway work):** the
  > reference-client interop *test-runner* — the `_gridftp` driver points at
  > `brix-client` (plain xrootd tools) not the `gridftp-client` image (globus/
  > gfal2/VOMS), and `remote-suite/tests/test_gridftp_interop.py` + its full-infra
  > `conftest.py` are not shipped into the runner (whose `/opt/brix` layout no
  > current Dockerfile builds). The gateway data path it exercises is already
  > proven live; wiring that runner is a deeper half-done image migration.
  > **UPDATE 2026-07-31 (e) — CLOSED: the reference-client test-runner drives the
  > gateway live.** `xrd-lab test gridftp` now builds/loads `gridftp-client:dev`
  > (`Dockerfiles/gridftp-client/Dockerfile` — globus/gfal2/VOMS + the `/opt/brix`
  > runner layout: `remote-suite/tests/`→`/opt/brix/tests`, `remote-suite/utils/`,
  > `client-pki-init.sh`; `WORKDIR /opt/brix`) and runs the interop matrix against
  > the live `gf-gridftp` Service — full-lab-path result **8 passed / 4 skipped /
  > 0 failed**: all 4 GSI matrix cells (`{PROT C,P}×{MODE S,E}`), cleartext-active,
  > `gfal-copy`, the VOMS-AC proxy, and the FTS transfer-list batch are byte-exact
  > reference-client round-trips through the gateway. Load-bearing wiring (all
  > guarded, `test_k8s_gridftp_gateway_guard.py` now 11/11): `PYTHONPATH=/opt/brix/
  > tests` (settings.py lives in `tests/`); `auth-pki` secret volume `defaultMode:
  > 0600` (globus refuses a proxy/key looser than 600); lab mounts the
  > `gridftp-ca-bundle` configMap and `client-pki-init.sh` dereferences it into
  > **real** files under `$TEST_ROOT/pki/ca` (configMap mounts are symlinks; the
  > bare `ca.pem+hash` rebuild lacks the issuer `signing_policy` the handshake
  > needs); the `pki-bootstrap` Job is **idempotent** (its `pre-*` hook reuses
  > existing PKI instead of regenerating the CA and desyncing the running gateway
  > host cert) and **re-mints the host cert `CN=$HOSTCN`+SAN** so globus authorizes
  > the gsiftp server by the Service name it dialled (`blitz_test_pki()` issues
  > `CN=localhost` → CN-mismatch denial). **Known limitation (documented, gated —
  > not a wiring gap):** passive `PASV/EPSV` STOR/RETR and a same-endpoint
  > `gsiftp→gsiftp` TPC are `skip`ped in the container tier via
  > `TEST_GRIDFTP_DATACHAN_PINNED=1` — the gateway pins every data channel to the
  > control peer (anti-hijack invariant), so behind one k8s Service it exposes no
  > passive data-port range (`Connection refused`) and refuses a data address ≠ the
  > control peer (`500 Data address must match control peer`); both cells still run
  > on host-network / dual-endpoint deployments (topology-scoped gate, not a global
  > skip).
  > **UPDATE 2026-08-01 — the non-posix backend rows are now DRIVEN, not skipped;
  > the "backends not yet gateway-wired" claim was stale.** The gateway routes
  > every data-plane op through the VFS storage seam and registers
  > `brix_gridftp_storage_backend` via the shared `brix_vfs_backend_config_str`
  > (ceph/rados/tape/http/s3/root(s):///pblock/posix), so ALL backends are
  > gateway-wired with no data-path change — proven natively today
  > (`test_gridftp_pblock.py` 7/7 + `test_gridftp_verify_write.py` 6/6 = 13/13
  > green, STOR/RETR/CKSM through pblock over the FTP wire, and `test_gridftp_s3.py`
  > through an embedded `brix_s3` origin). The remaining gap was purely that the
  > *reference-client* interop matrix never drove a non-posix backend: its
  > `test_nonposix_backend_matrix` was a permanent `pytest.skip` falsely tagged
  > "not yet wired". Replaced with two real driven cells
  > (`test_gridftp_interop.py::test_{pblock,s3}_backend_roundtrip`) that run
  > `globus-url-copy` STOR/RETR through the backend export over gsiftp and assert a
  > byte-exact round-trip. The **pblock cell is cluster-free** — the local runner
  > (`gridftp_interop_local.py`) now boots a third gsiftp listener over a
  > pblock-backed export (`nginx_gridftp_interop.conf` + `{PBLOCK_GSIFTP_PORT}`/
  > `{PBLOCK_ROOT}`) and exports `TEST_GRIDFTP_BACKEND_PBLOCK_PORT`, so the
  > reference client proves a non-posix backend round-trip over gsiftp with no k8s
  > cluster and no MinIO. The **s3 cell** (`TEST_GRIDFTP_BACKEND_S3_PORT`)
  > self-skips until the lab exports a MinIO/radosgw origin (the only residual is a
  > clustered object-store endpoint, not gateway wiring). Guards: the extended
  > config validates under `nginx -t` and carries the pblock registration
  > (`check_gridftp_interop_image.py` + `test_gridftp_interop_local.py`, 11/11
  > offline green incl. two injected-drift negatives). **Residual now:** the s3
  > interop cell's clustered origin + the datachan-pinned passive/TPC cells on a
  > dual-endpoint deployment — both topology/infra, not code.
  > **UPDATE 2026-08-01 (ii) — the s3 interop cell is now CLOSED cluster-free, and
  > wiring it exposed + fixed a real pre-existing pblock mkdir bug. The whole
  > reference-client matrix is green (11 passed / 1 skipped — the lone skip is the
  > VOMS cell, absent proxy).** The s3 cell no longer needs an external
  > MinIO/radosgw: the local runner boots a *second* nginx instance
  > (`nginx_gridftp_interop_s3.conf`, `worker_processes 2`) with an embedded
  > `brix_s3` origin over a posix root in its `http{}` plane and an `s3://`-backed
  > gsiftp listener in `stream{}` (`TEST_GRIDFTP_BACKEND_S3_PORT`), so
  > `globus-url-copy` proves the object-store write/read path over gsiftp with no
  > cluster. It is a *separate* instance because the s3 leg needs two workers (the
  > outbound SigV4 leg to the co-hosted origin would self-deadlock a lone worker)
  > while the pblock leg in the main gateway must stay single-worker (its block
  > catalog is per-worker). Guard `check_gridftp_interop_image.py` §2b + three new
  > `test_gridftp_interop_local.py` cases (s3-config `nginx -t`, port-wiring, and a
  > drop-the-`s3://`-backend drift negative) hold the contract; offline suite now
  > 15/15. **Pblock bug found & fixed:** driving the reference client surfaced that
  > a GridFTP `-cd` MKD arrives with a *trailing slash* (`/interop/`); the pblock
  > catalog keys directories WITHOUT one, so `parent_of("/interop/")` split into
  > the non-existent parent `/interop` + empty leaf and both the plain
  > (`sd_pblock_mkdir_as`) and per-user (`sd_pblock_mkdir_cred`, whose W+X parent
  > check runs first under GSI) slots failed with a spurious `ENOENT` /
  > `not_found`. Posix was unaffected (`mkdirat` tolerates a trailing slash; the
  > POSIX path already strips it in `brix_mkdir_beneath`). Fixed with a shared
  > `pblock_path_canon()` that strips the trailing slash at both mkdir slots — the
  > pblock analogue of the POSIX normalisation — so quota/audit/catalog rows key
  > the canonical dir and children resolve. Tests: `sd_pblock_unittest_core.c`
  > `test_mkdir_trailing_slash` (plain slot: success + EEXIST dedup +
  > still-ENOENT-on-real-missing-parent) and `sd_pblock_unittest_ident.c` (cred
  > slot, the GSI runtime path). **Residual now:** only the datachan-pinned
  > passive/TPC cells on a dual-endpoint deployment — topology/infra, not code.
- **Perf-host-blocked**: phase-33 P0/P1/P3-B1/P5; phase-32 WS3
  recv-state-machine flip; phase-29 P3 AIO read pipelining; phase-31 readv/
  pgread resident-windowing follow-up.
  > **STATUS 2026-08-01:** the *code-side* of this bullet is fully closed — P3-B1
  > sendfile-span and the P1.2/WS3/P29.P3 concurrent-AIO recv flip both LANDED
  > (see the UPDATE 2026-08-01 at the end of this bullet). What remains is purely
  > physical infra: the **P5** kTLS-on-HW-offload NIC and the *throughput
  > magnitude* trend numbers (a high-BDP host for the existing A/B + netem
  > harnesses).
  > **UPDATE 2026-07-28:** phase-33 **P3-B3** partially closed — the
  > `SO_SNDBUF`/`SO_RCVBUF` accept-path sizing knob (`brix_socket_sndbuf` /
  > `brix_socket_rcvbuf`) landed as correct-on-merits, byte-exact-gated code
  > (`connection/netopt.h::brix_apply_socket_buffers`, `test_socket_buffers.py`);
  > only the *magnitude* of the throughput gain still needs the P0 perf host. The
  > rest of this bullet is genuinely still blocked: **P1 / phase-32 WS3 / phase-29
  > P3 are the SAME concurrent-AIO recv-state-machine flip** the phase-29/32 docs
  > flag as gateway-fatal-risky and *untestable in this environment* (a mis-wired
  > refcount leaks/hangs connections; the disconnect-mid-AIO UAF path is not
  > exercisable without an ASan lane) — deliberately NOT landed here rather than
  > shipped untested. P3-B1 (sendfile-span) remains throughput-only: the XRootD wire
  > interleaves a kXR response header between every 16 MiB chunk
  > (`BRIX_SLOT_HDR_MAX` = one header per chunk), so a single `sendfile(2)` cannot
  > span frames for reads >16 MiB — the only lever is raising `BRIX_READ_CHUNK_MAX`,
  > a hot-path geometry change the phase-33 doc keeps P0-gated.
  > **P5 (kTLS): the safe half LANDED 2026-07-28** — both TLS planes defaulted kTLS
  > *ON* (a latent software-kTLS regression contradicting the P5 instruction); flipped
  > to OFF (opt-in, HW-offload-only), byte-exact/behaviour-preserving since
  > `SSL_OP_ENABLE_KTLS` is a no-op on non-offloadable ciphers. Only the HW-offload
  > A/B *throughput* comparison still needs P0. Guarded by
  > `tests/test_ktls_default.py` (parse-tier: on→NOTICE, default/off→no NOTICE,
  > bogus→reject) + the `system_live_ports.py` HTTP-plane runtime assertion. See
  > phase-33 doc § P5.
  > **UPDATE 2026-07-30 — the P0 regression-gate *harness* LANDED**, closing the
  > code-side half of P0 (P0 = "perf host + regression gate"; the gate is now
  > written and loopback-validated, so the residual is only *acquiring* the host).
  > `tests/_perf_ab_helpers.py` is an unprivileged, self-contained A/B throughput
  > measurer (boots single-process nginx via the lifecycle registry, streams a
  > page-cached file over the root:// wire with the module's 4 MiB chunked reads,
  > draining kXR_oksofar segments, and reports best-of-N MiB/s knob-on vs
  > knob-off). `tests/test_perf_ab_gate.py` drives it: an always-on harness
  > self-test (byte-exact serve + positive MiB/s — a correctness gate) and an
  > opt-in (`BRIX_PERF_AB=1`) A/B over the P3-B3 socket-buffer knob with a JSON
  > artifact (`BRIX_PERF_AB_JSON`) for a perf-host CI to trend. Loopback has no
  > BDP so the A/B leg reports magnitude but asserts only a noise-tolerant
  > gross-regression floor. **Still perf-host-blocked:** the trustworthy P3-B3
  > *magnitude* (aim the harness at a high-BDP link) and the P5 kTLS-on-HW-offload
  > A/B (needs an offload-capable NIC; the harness is generic so the TLS leg plugs
  > in with no new measurement code). The P1/WS3/P3 recv-flip stays ASan-gated
  > (deliberately not landed); P3-B1 sendfile-span stays a P0-gated hot-path
  > geometry change. See phase-33 doc § P0.
  > **UPDATE 2026-07-30 — the code-side residuals of this bullet are now CLOSED;
  > only the physical infra remains.** Three unprivileged closures (phase-33 doc
  > § UPDATE 2026-07-30 (b)): (1) **P1.1** — the `brix_pipeline_depth` runtime
  > knob (default 4→8, clamped [1,64], rings sized to depth) had shipped
  > *untested*; `tests/test_pipeline_depth.py` (7 green) now is the correctness
  > gate P1 demands — byte-exact serial reads at depth 1 and 32 plus a
  > **pipelined-burst** test that keeps `depth` reads in flight and asserts every
  > response drains byte-exact in order, plus parse/clamp/reject coverage.
  > (2) **P5** — the A/B harness gained a genuine `roots://` userspace-TLS leg
  > (`measure_read_throughput(..., tls=True)`) with an always-on byte-exact
  > self-test, so the kTLS-on-HW-offload A/B needs only a NIC + `brix_ktls on`.
  > (3) **P0/B3** — a standalone remote-host CLI (`python3 _perf_ab_helpers.py
  > --host … [--tls]`) aims the client half across a real link at a running brix
  > server. **Still genuinely infra-blocked:** the high-BDP perf host (a userspace
  > relay can't synthesize a *server-socket* BDP — only a real link or root
  > `netem` can, so P3-B3/P1 magnitude + the P5 kTLS A/B still need hardware) and
  > the concurrent-AIO recv flip (P1.2 / WS3 / P29.P3) — now *approachable* behind
  > the landed B-2 ASan lane's disconnect-mid-AIO UAF coverage, but deliberately
  > NOT a fast inline change; P3-B1 sendfile-span stays P0-gated geometry.
  > **UPDATE 2026-07-31 — the P3-B3/P1 *magnitude* is no longer perf-host-blocked;
  > it is now measured unprivileged.** The premise above ("only a real link or
  > *root* `netem` can synthesize a server-socket BDP") was too strong: a user +
  > network namespace grants `CAP_NET_ADMIN` **inside** the namespace, so a fully
  > unprivileged process can build a `veth` pair and attach `tc netem delay/rate`
  > to synthesize a genuine bandwidth-delay product. `tests/_perf_netem_helpers.py`
  > does exactly this — launcher `podman unshare unshare -n -m` (podman's rootless
  > subuid map is required so the brix worker's force-drop to `nobody`/65534
  > succeeds; a bare `unshare -Ur` maps one uid and the worker exits fatal), a
  > **two-netns** veth straddle (two ends in one netns bypass netem via the kernel
  > local-delivery shortcut — verified), and a pinned sub-BDP `tcp_wmem[2]` ceiling
  > so the explicit `SO_SNDBUF` knob is the isolated variable. It boots baseline
  > (kernel-default buffers) + tuned (`brix_socket_sndbuf`/`rcvbuf` pinned) root://
  > servers on the two ends and A/Bs them: on the dev box at 30 ms RTT / 400 mbit
  > the window-limited baseline runs ~4 MiB/s while the tuned pipe fills at
  > ~33 MiB/s (**~8×**; ~12× at 40 ms / 500 mbit) — the exact P3-B3 magnitude the
  > perf host was for. Gate `tests/test_perf_netem_bdp.py` asserts the synthesized
  > RTT is genuinely on the wire (ping ≈ 2·delay, i.e. netem not bypassed), both
  > legs serve byte-exact, and tuned ≥ 2× baseline (generous floor vs the ~8×
  > observed); it self-skips CI-safely when podman/namespaces/`tc` are absent.
  > **Still genuinely infra-blocked:** only the **P5 kTLS-on-HW-offload** A/B (needs
  > a TLS-ULP-capable offload NIC; the host has no `tls` ULP) and the concurrent-AIO
  > recv flip (deliberately not landed) remain; P3-B1 sendfile-span stays P0-gated.
  > **UPDATE 2026-08-01 — the concurrent-AIO recv flip (P1.2 / WS3 / P29.P3) and
  > P3-B1 sendfile-span are now LANDED; the perf-host set shrinks to P5 + magnitude
  > numbers.** Both landed unprivileged and inline, each with a deterministic
  > *correctness* gate (these are a teardown-ordering fix and a geometry constant,
  > not throughput knobs — only the wall-clock magnitude still wants a high-BDP
  > host). (1) **Recv flip** — the read pipeline no longer serializes AIO behind a
  > single slot; the recv path dispatches up to `brix_pipeline_depth` reads
  > concurrently and a per-connection **`aio_inflight` counter defers teardown**
  > until the last AIO drains, closing the disconnect-mid-AIO UAF the old
  > single-slot design only masked by never overlapping. Gated by the ASan-lane
  > disconnect drivers `test_aio.py::TestAioDestroyedGuard` (RST + churn) and the
  > byte-exact concurrency proof `test_concurrent.py::TestPipelinedTLSReads` (16
  > concurrent 1 MiB TLS reads demux back byte-exact on one conn + 6-round churn);
  > full `test_aio + test_concurrent` regression **31 passed**. (2) **P3-B1** —
  > `BRIX_READ_CHUNK_MAX` 16→32 MiB (halves worst-case `BRIX_SLOT_HDR_MAX` frame
  > count 4→2 → ABI-affecting, full recompile). Gated by the C unit
  > `tests/c/test_chunk_geometry.c` (links the real `buffers.o`, pins
  > `brix_chunk_geometry` at the new cap + a compile-time `#error` guard; runner in
  > `c_regression_units.py`, parametrized in `test_c_regression_units.py`) — **not
  > e2e, and that is correct:** a `brix_storage_backend posix:` sets
  > `sd_obj.driver != NULL`, routing reads through the 2 MiB **windowed** path not
  > the sendfile CHUNK_MAX framing, so every driver-backed fleet endpoint makes the
  > 32 MiB geometry unreachable e2e; the linked unit over the shipped object is the
  > honest anchor. **Still infra-blocked:** only **P5** (kTLS-on-HW-offload NIC)
  > and the *throughput magnitude* trend numbers for P3-B1/P3-B3/P1 remain. See
  > phase-33 doc § UPDATE 2026-08-01.
- **Pelican cache registration** — public-key handshake with the federation
  registry, blocked on the operator running the `pelican` CLI out-of-band.
- **Phase-70 STS/krb5 origin legs** — the materialiser hooks
  (`brix_vfs_deleg_sts_cred` / `brix_vfs_deleg_krb5_token`), the STS client
  (`src/auth/s3/sts.c`) and the krb5 GSSAPI-forward client
  (`src/auth/krb5/forward.c`) are all implemented and call-ready; SSS identity
  injection is fully wired. What stays container-blocked is the FULL origin-leg
  *invocation* from `brix_vfs_deleg_live_cred` — STS needs a service-key config
  source + a capture-site `brix_vfs_ctx_bind_backend_sts()` + `sd_remote`
  `open_cred` ak/sk/session mapping (needs MinIO STS); krb5 needs the delegated
  `gss_cred_id_t` carried onto the VFS ctx + the multi-leg `origin_auth.c`
  negotiation (needs a forwardable KDC).
  > **UPDATE 2026-07-28:** the load-time trust-validation residual for the S3
  > STS directive (the §6-"validated at load" polish this doc flagged for STS) is
  > now DONE — `brix_conf_set_backend_sts_endpoint` rejects a malformed
  > `brix_backend_s3_sts_endpoint` at `nginx -t` (http+https both accepted;
  > SigV4 never transmits the secret), guarded by
  > `tests/test_sts_endpoint_load_validation.py` (5 green). The STS exchange
  > *seam* the deferred origin leg calls into (XML parse + SigV4 build) is now
  > container-free unit-covered: `tests/c/sts_units_test.c` (runner `sts_units`
  > in `cmdscripts/c_auth_units.py`) links the real `sts_http.o` + `sts_sign.o`
  > and asserts parse/build success, a stable signature, and the fail-closed
  > paths. The origin-leg *invocation* above stays container-blocked; the
  > KDC-realm directive validation lands with that deferred directive. See
  > phase-70 doc status header.
  > **UPDATE 2026-07-28 (b):** the S3 STS **exchange** half is now LIVE-verified
  > against a real MinIO, closing a genuine AWS-vs-MinIO wire divergence the
  > offline unit masked (MinIO speaks **only** POST + form-body + header-auth
  > `AssumeRole`, never AWS GET/presigned or `GetSessionToken`). Added an
  > additive `brix_backend_s3_sts_flavor aws|minio` dialect (default `aws`, AWS
  > path byte-unchanged) across both planes + `deleg_wire` stamp; new
  > `sts_build_post`/`sts_http_post` MinIO transport. Live proof
  > `tests/test_sts_minio_live.py` (docker-direct, opt-out `STS_MINIO_LIVE=0`, 3
  > green) drives the **production** `brix_s3_sts_assume(flavor=MINIO)` via the
  > `tests/c/sts_live_assume.c` harness and shows the returned temp creds fetch a
  > seeded object byte-for-byte, no-token GET → 403, wrong-secret AssumeRole
  > fails closed. Full detail: phase-70 doc §5.5.1. **Still blocked:** the
  > end-to-end *nginx-runtime* STS invocation (front-door capture → VFS gate →
  > `sd_remote` open) and the entire krb5 leg (forwardable KDC).
  >
  > **UPDATE 2026-07-28 (c):** the krb5 leg's **crypto core** is no longer
  > blocked — it is now LIVE-verified against a real MIT KDC stood up
  > *unprivileged* in a user namespace (`unshare -Ur`, high port). Both halves
  > proven: **capture** (`src/auth/krb5/capture.c`
  > `brix_krb5_capture_fwd_cred` — `KRB_CRED` → `krb5_rd_cred` → MEMORY ccache →
  > `gss_krb5_import_cred`) and **forward** (`forward.c` origin leg), plus the
  > **derive-from-backend-host** origin principal
  > (`brix_krb5_origin_princ_from_host`) and the `brix_backend_krb5_forwardable`
  > directive wired onto the **stream** plane (was HTTP-only) + load-validated.
  > Live proof `tests/test_krb5_forward_live.py` (opt-out `KRB5_LIVE=0`, 4 green
  > incl. the full forward→capture→origin chain) + offline
  > `tests/test_krb5_origin_princ.py` (3 green). Full detail: phase-70 §5.7.1.
  > **Still blocked:** the runtime *wire* invocation only — the inbound two-round
  > `kXR_authmore`/`"fwdtgt"` state machine in `auth.c` (needs an XrdSeckrb5
  > *forwarding* client) and the outbound `origin_auth.c` multi-leg drive (needs a
  > GSSAPI origin backend). Neither exists in this environment.
  >
  > **UPDATE 2026-07-31:** both origin-leg **crypto cores** re-verified green
  > together on the now-provisioned box (`test_sts_minio_live.py` 3/3 vs a real
  > MinIO + `test_krb5_forward_live.py` 4/4 vs a real MIT KDC = **7/7**), both
  > self-provisioning their infra and opt-out-gated, so this is a durable
  > regression floor, not a one-off. The two harnesses carry `timeout(300)` and
  > ride the default (non-slow, non-serial) fast tier. **The honest residual is
  > unchanged and is a genuine subsystem build, not a polish item:** the runtime
  > *wire* into `sd_remote`'s origin auth. Concretely — (a) `brix_vfs_deleg_live_cred`
  > (`src/fs/vfs/vfs_deleg.c`) has a wired STS branch but **no krb5 branch**; the
  > delegated `gss_cred_id_t` + origin service principal are not carried on
  > `brix_vfs_ctx_t` (needs a capture-site bind); and (b) the multi-leg GSS
  > negotiation belongs in `origin_auth.c` feeding origin replies back through
  > `gss_init_sec_context`. Implementing (a) alone would mint a first-leg token
  > with no consumer (a half-wire that is worse than none), so both land together
  > or not at all — deferred as the correct call, not a gap in verification. The
  > read-side AIO disconnect UAF coverage this leg is entangled with (the concurrent
  > recv-flip prerequisite) IS now closed — see §4 ASan below.
  >
  > **UPDATE 2026-07-31 (b) — residual-(b) is now LANDED and live-verified; the
  > residual narrows to just the kXR transport bridge + the synchronous cred
  > carry.** The named-missing subsystem in (b) — *"the multi-leg GSS negotiation
  > … feeding origin replies back through `gss_init_sec_context`"* — is built as a
  > reusable, transport-agnostic engine and proven end-to-end against a real MIT
  > KDC:
  > - **Engine** `brix_krb5_deleg_negotiate()` (`src/auth/krb5/forward.c`, decl in
  >   `forward.h`) owns the WHOLE loop where `brix_krb5_deleg_to_origin()` did one
  >   step: it initialises the context, hands each output token to a caller-supplied
  >   `brix_krb5_wire_fn` transceiver for delivery to the origin, feeds the origin's
  >   reply straight back into `gss_init_sec_context()`, and repeats until
  >   `GSS_S_COMPLETE`. It **requests mutual auth and refuses to complete without
  >   `GSS_C_MUTUAL_FLAG`** (a spoofed origin cannot finish the exchange), fails
  >   closed when the origin ends the exchange with no token or still owes one after
  >   `kXR_ok`, carries an 8-leg runaway guard, and never leaks the GSS context or
  >   target name on any path. The transceiver seam is exactly the kXR
  >   `kXR_authmore`/`kXR_ok` framing, so the future `origin_auth.c` consumer is a
  >   thin wire adapter over an already-proven core, not new crypto.
  > - **Live proof** — `tests/test_krb5_forward_live.py` gained a `negotiate` mode
  >   (`tests/c/krb5_forward_live.c`): the engine drives to completion against an
  >   **in-process acceptor loop** (one `gss_accept_sec_context` step per outbound
  >   token, reply fed back), and BOTH sides independently reach completion carrying
  >   `alice@BRIX.TEST`. Three cases (success + two security-negatives): multi-leg
  >   completion carries the user identity; a **wrong-keytab origin** (the gateway's
  >   keytab, not the origin's) makes the acceptor reject the token so the engine
  >   fails closed with no identity leaked; a **wrong client password** yields no
  >   forwardable credential so the engine is never entered. Suite now **7/7 green**
  >   vs the real KDC (was 4/4).
  >
  > **What genuinely remains (unchanged blockers, now the *only* residual):**
  > (i) the kXR `krb5` **wire adapter** in `origin_auth.c` that implements
  > `brix_krb5_wire_fn` over a real `brix_cache_origin_conn_t` (send `kXR_auth`
  > credtype krb5 → read `kXR_authmore`/`kXR_ok`) — deliberately NOT built yet
  > because it cannot be exercised without a live **GSSAPI/krb5 XRootD origin**,
  > which does not exist in this environment; building it blind would be untestable
  > dead wire code. (ii) The **synchronous carry** of the delegated
  > `gss_cred_id_t` + origin service principal from the front-door capture onto the
  > request path: a live GSS cred handle is request-scoped and not safe to embed in
  > the async `brix_cache_fill_t` (worker-thread, outlives the request), so the
  > krb5 branch in `brix_vfs_deleg_live_cred` waits on a request-synchronous origin
  > auth path rather than the async fill. The hard part named in §4(b) — the
  > multi-leg negotiation itself — is no longer a gap; what is left is transport
  > plumbing gated on a GSSAPI origin backend and an async-lifetime refactor.
  >
  > **UPDATE 2026-07-31 (e) — the S3 STS runtime wire is now LANDED + live-verified;
  > the residual is krb5-only.** The remaining STS half of (b) — the *end-to-end
  > nginx-runtime invocation* (front-door capture → VFS deleg gate → `sd_remote`
  > origin open), the piece the §5.5.1 direct-exchange proof did not cover — is
  > closed. A booted `root://` gateway (`tests/configs/nginx_root_s3_sts.conf`,
  > `brix_auth token` front door, `s3://` backend, `brix_backend_delegation
  > exchange` + full `brix_backend_s3_sts_*` triple) reads an object byte-exact
  > through a live worker whose static `brix_storage_credential` carries a
  > **deliberately WRONG** secret — so the read is a proof that the STS-minted
  > temporary credential (RoleSessionName = token sub) authenticated the origin leg.
  > `mc admin trace` confirms MinIO receives an `AssumeRole` POST then an object GET
  > signed with a **temporary** access key. `tests/test_sts_runtime_e2e.py` **3/3**
  > (positive + `delegation off` refused + corrupted STS service-secret fail-closed).
  > Two product fixes fell out of being the first runtime exerciser, both
  > correctness: (1) **gate ordering** in `brix_vfs_deleg_live_cred` — with STS armed
  > and an S3-accepting leaf, STS is decided *before* the bearer branch (a WLCG
  > bearer is the caller's identity, not an S3-consumable secret; `sd_remote` accepts
  > both kinds, so it previously shadowed STS and fell back to the wrong static key →
  > 403). Narrowed to armed-STS only; STS-unarmed bearers still forward. Unit cases
  > `deleg_gate_test.c` #13/#14. (2) the **read staging pre-flight probe**
  > (`open_resolved_file_staging.c`) now threads `ctx->identity` so its STS exchange
  > is caller-scoped, not `anonymous` (a policy-scoped AssumeRole could otherwise
  > answer probe vs. real-open differently → spurious `kXR_NotFound`). Full detail:
  > phase-70 doc §5.5.2. **The only Phase-70 origin-leg residual now is krb5** (items
  > (i)/(ii) above — infra-blocked GSSAPI XRootD origin + async GSS-cred carry).
  >
  > **UPDATE 2026-07-31 (f) — krb5 residual (i), the kXR wire adapter, is now
  > LANDED + live-verified over real frame bytes.** The claim above that (i) "would
  > be untestable dead wire code" is superseded: the adapter was built as a
  > *transport-agnostic* codec `brix_krb5_kxr_wire()` (`src/auth/krb5/kxr_wire.c` +
  > `kxr_wire.h`) over `send`/`recv` seams, so the **identical production frame
  > bytes** are driven in a live test against a real-GSS kXR-framed acceptor — the
  > production path *is* the tested path, not an analogy. It frames each
  > `brix_krb5_deleg_negotiate` leg as an XRootD `ClientAuthRequest` (24-byte header,
  > credtype `"krb5"`, BE `dlen`), reads the `ServerResponseHeader`, and classifies
  > (`kXR_authmore`→continue / `kXR_ok`→settle / else→fail closed) with an anti-OOM
  > reply cap. The production origin-leg wrapper `brix_cache_origin_auth_krb5()`
  > (`src/fs/cache/origin_auth.c`, guarded `brix_krb5_forward_available()`) binds it
  > to a real `brix_cache_origin_conn_t`. `tests/test_krb5_forward_live.py` gained a
  > `classify` self-test + a `kxrwire` multi-leg drive over a socketpair to a
  > real-GSS acceptor thread (identity `alice@BRIX.TEST` arrives at the far side)
  > plus two security-negatives (wrong-keytab origin, wrong password — both fail
  > closed, no leak). Suite now **11/11 green** vs the real KDC (was 7/7). **What
  > stays open in (i) is only the *dispatch site*** — the selection branch in
  > `origin_protocol_bootstrap.c` that invokes this wrapper on a live `&P=krb5`
  > origin advert — deferred as a unit with (ii)'s async cred carry, since
  > dispatching would mint a leg with no request-synchronous cred to carry. Full
  > detail: phase-70 doc §5.7.1.
  >
  > **UPDATE 2026-07-31 (g) — krb5 residual (ii), the async-safe cred carry AND the
  > `vfs_deleg.c` krb5 gate branch, are now LANDED + live/unit-verified; the ONLY
  > krb5 residual left is the infra-blocked `&P=krb5` dispatch.** The async-lifetime
  > blocker in (ii) — *"a live GSS cred handle is request-scoped and not safe to
  > embed in the async `brix_cache_fill_t`"* — is solved exactly as the gsi leg
  > carries an x509 proxy: **serialise the delegated TGT to a 0600 FILE ccache and
  > carry the PATH** (async-safe), never the live handle. New `src/auth/krb5/carry.c`
  > + `carry.h` (in `./config`): `brix_krb5_cred_to_ccache` exports the captured
  > initiator cred via **RFC 5588 `gss_store_cred_into`** with an explicit `ccache`
  > store element + `overwrite=1` (the deprecated `gss_krb5_copy_ccache` was tried
  > first and rejected — it cannot initialise the target and fails an empty temp
  > with "bad format"); `brix_krb5_cred_from_ccache` re-imports on a FRESH handle for
  > the fill task; `brix_krb5_cred_carry_release` frees cred + backing ccache/context
  > together. Live-proven by `test_krb5_forward_live.py` mode `carry`: export alice's
  > forwarded TGT → re-import on a fresh handle → drive the SAME production kXR
  > multi-leg engine → the acceptor still observes `alice@BRIX.TEST` (functionally
  > identical); mode `carry-badpath` proves re-import from a non-existent path fails
  > closed. Suite now **13/13 green** vs the real KDC (was 11/11). Residual-(ii)'s
  > gate half is also landed: a new `BRIX_SD_CRED_GSS_KRB5` accept-kind;
  > `brix_deleg_live_s.krb5_ccache`/`.krb5_origin_princ` carry the async-safe path +
  > SPN; `brix_vfs_deleg_set_krb5` (`vfs_deleg_bind.c`) is the capture-site setter;
  > and `brix_vfs_deleg_live_cred` (`vfs_deleg.c`) now has the **krb5 branch** it was
  > missing in §4(a) — selecting krb5 GSSAPI EXCHANGE right after the x509-proxy
  > branch (a forwarded TGT is a real forwardable user credential, so it outranks
  > STS/bearer/SSS), accept-gated (EACCES before any origin contact when the leaf
  > does not consume krb5), carrying `krb5_ccache`/`krb5_princ` onto the POD
  > `brix_sd_cred_t`. Unit-covered by `deleg_gate_test.c` #15 (selection SUCCESS),
  > #16 (FAIL_KIND deny, no service fallback), #17 (setter allocate-bag + guards) —
  > suite green. **Both original §4(a) sub-clauses are now closed** ("no krb5 branch"
  > and "delegated cred + SPN not carried on the ctx"). **The only krb5 residual now
  > is the `&P=krb5` production dispatch** in `origin_protocol_bootstrap.c` (re-import
  > from `t->cred->krb5_ccache` → `brix_cache_origin_auth_krb5`) — a thin call-site
  > atop two tested foundations, deferred solely because wire-testing it needs a live
  > GSSAPI XRootD origin (as does item 1's inbound two-round capture state machine).
  > Full detail: phase-70 doc §5.7.1.
  >
  > **UPDATE 2026-07-31 (h) — the `&P=krb5` production dispatch has LANDED; the only
  > krb5 residuals left are the two genuinely infra-blocked live legs.** The fill
  > task now carries `cred_krb5_ccache` (async-safe FILE-ccache PATH) + `cred_krb5_princ`
  > (`cache_internal.h`), copied out of the POD `brix_sd_cred_t` by
  > `sd_xroot_copy_cred_into_task` (`sd_xroot.c`) exactly like x509/bearer/sss.
  > `origin_bs_parse_advert` now detects `&P=krb5` → `has_krb5`, and
  > `origin_bs_auth_dispatch` (`origin_protocol_bootstrap.c`) gained a krb5 branch
  > (placed after x509-proxy — a forwardable USER TGT outranks bearer/sss). New static
  > `origin_bs_auth_krb5()` re-imports the carried TGT via `brix_krb5_cred_from_ccache`,
  > drives `brix_cache_origin_auth_krb5` against `cred_krb5_princ`, and releases the
  > fresh cred whatever the outcome. Per-user fail-closed is preserved end-to-end: a
  > bad carried ccache → `kXR_AuthFailed` (never a service-cred fallback), a
  > non-krb5-advertising origin for a carried TGT is refused, and an advert-less
  > `kXR_authmore` hard-stops (`origin_bs_authmore_fallback`). Unit-covered by
  > `tests/c/origin_krb5_dispatch_test.c` (RUNNER `origin_krb5_dispatch`, auto-picked
  > up by `test_c_auth_units.py`): advert parse (detected/mixed/absent), dispatch
  > selection w/ carried SPN, the not-advertised refusal, the fail-closed re-import,
  > and the authmore hard-stop; the harness `#include`s the TU to reach its static
  > helpers and stubs the whole external surface (no krb5/OpenSSL/project objects
  > linked). Full build clean under -Werror with `BRIX_HAVE_KRB5=1`. **What remains
  > deferred is now ONLY** the live GSSAPI handshake against a real `&P=krb5` XRootD
  > origin (the wire codec itself is proven byte-for-byte by the `kxrwire` live test —
  > only the live origin is missing) and item 1's inbound XrdSeckrb5-*forwarding*
  > capture state machine in `auth.c`. Every synchronous, testable seam is now built
  > and unit- or live-verified. Full detail: phase-70 doc §5.7.1.
  >
  > **UPDATE 2026-07-31 (i) — item 1, the inbound two-round delegation-CAPTURE state
  > machine, has LANDED; the ONLY krb5 residuals left are the two live GSSAPI
  > handshakes.** The last synchronous krb5 seam named across (f)/(g)/(h) as still
  > open is built. It lives in a new `src/auth/krb5/deleg_capture.{c,h}` module (in
  > `./config`; the file/CCN caps forbid inlining it into `auth.c`), armed by the new
  > `brix_krb5_delegate on|off` directive (default off, stream-plane) and driven by a
  > connection-scoped `brix_ctx_krb5_t` (`ctx_structs.h`, opaque `void*` handles keep
  > krb5.h out of the shared header). **Round 1** (`brix_krb5_begin_delegation`,
  > `auth.c`): after `krb5_rd_req` verifies the AP-REQ, instead of finalizing,
  > `brix_krb5_deleg_park` copies the verified client principal and parks it + the
  > round-1 `krb5_auth_context` (the session subkey) on the ctx behind an
  > `ngx_pool_cleanup_add` handler (frees the handles + `unlink`s the 0600 ccache at
  > connection close), sets `round=1`, and `brix_krb5_send_fwdtgt` replies
  > `kXR_authmore` carrying `"krb5"`+`"fwdtgt"`. **Round 2** (`brix_krb5_finish_delegation`
  > → `brix_krb5_deleg_capture`): the payload post-`"krb5"` prefix
  > (optional-NUL-stripped by `brix_krb5_deleg_credbytes`) feeds the live-proven
  > `brix_krb5_capture_fwd_cred(context, parked_auth_ctx, parked_client, …)`; the
  > forwarded TGT is serialised to a fresh 0600 FILE ccache whose PATH is stashed on
  > `ctx->krb5.ccache`, every round-1 + capture handle is released on all paths, and
  > `brix_krb5_session_grant` (extracted from `brix_krb5_finalize` so the single-round
  > path is byte-for-byte unchanged) finalizes the login. At request time
  > `brix_root_vfs_bind_deleg` (`op_path.c`) derives the origin SPN
  > (`brix_krb5_deleg_origin_spn`, gated on `backend_krb5_forwardable`) and binds the
  > carried ccache PATH + SPN via `brix_vfs_deleg_set_krb5` — closing the loop into the
  > already-landed vfs_deleg → `&P=krb5` dispatch chain from (g)/(h). Unit-covered by
  > `tests/c/krb5_deleg_capture_test.c` (RUNNER `krb5_deleg_capture`, `#include`s the
  > TU compiled WITHOUT `BRIX_HAVE_KRB5`, stubs the wire/pool surface — no
  > krb5/OpenSSL/project objects linked): the `_wanted` gate, `_credbytes`
  > native/NUL/short/empty framing, `_send_fwdtgt` wire bytes, `_origin_spn`
  > gate + derivation + fail-closed security-negatives; plus `test_krb5_delegate_load.py`
  > (`nginx -t` directive on/off parse + bogus-value hard reject, 3/3). Full build
  > clean under -Werror with `BRIX_HAVE_KRB5=1`; the krb5/GSSAPI capture core beneath
  > is live-proven vs a real MIT KDC by `test_krb5_forward_live.py` mode `capture`.
  > **The only krb5 work now deferred** is driving both legs end-to-end with the live
  > krb5 peers this shell lacks: an XrdSeckrb5-*forwarding* client for the capture
  > round-trip, and a live `&P=krb5` XRootD origin for the outbound handshake. Full
  > detail: phase-70 doc §5.7.1.
  >
  > **UPDATE 2026-08-01 (ii) — the forwarding client is built; the inbound leg is
  > now LIVE end-to-end.** The clean-room client's krb5 module
  > (`client/lib/auth/sec/sec_krb5.c`) gained a round-2 `more()` handler that, on the
  > server's `"fwdtgt"` continuation, forwards the caller's TGT via
  > `krb5_fwd_tgt_creds()` under the round-1 auth context and replies `"krb5"` +
  > `KRB_CRED` (round state parked file-static across rounds — sound for the
  > synchronous single-connection auth driver — freed in `more()` / a new
  > `cleanup()`; the single-round AP-REQ path is byte-for-byte unchanged, native-krb5
  > suite still 7/7). New live e2e `test_krb5_delegation_e2e.py` (3/3 vs a real MIT
  > KDC): forwardable TGT → two-round exchange completes + server logs
  > `"krb5 delegation captured forwarded TGT"` (info marker added to
  > `brix_krb5_deleg_capture`); non-forwardable TGT → fail closed. **Only the outbound
  > live `&P=krb5` XRootD-origin handshake now remains infra-blocked** — the inbound
  > delegation leg is fully live-verified.
  >
  > **UPDATE 2026-08-01 (iii) — the native client krb5 wire is now REFERENCE-verified
  > against stock `xrootd`+`libXrdSeckrb5`; the outbound leg is reclassified from
  > "no live peer" to a *dialect mismatch*.** Bringing up a real reference `xrootd`
  > krb5 data server locally (`tests/test_krb5_xrootd_interop.py`, self-contained: own
  > `xrootd` on a free port + the session MIT KDC) surfaced two things a same-project
  > brix↔brix pairing had hidden. **(1) Client fix:** `sec_krb5.c` emitted a bare
  > 4-byte `"krb5"` credential prefix; the brix acceptor tolerates it (auto-skips the
  > optional NUL, `auth.c:288`) but *no* reference XrdSec acceptor does —
  > `XrdSecInterface.hh` mandates the payload *begin with the protocol name as a
  > string*. A packet capture of the stock client (`/usr/bin/xrdfs`) via a TCP tap
  > pinned the exact wire: payload = `"krb5\0"` + a **raw AP-REQ** (ASN.1
  > `[APPLICATION 14]`, tag `0x6e`), `dlen` = 5 + AP-REQ. `sec_krb5.c` now emits
  > `"krb5\0"` on both the round-1 AP-REQ and round-2 forwarded-TGT payloads; the
  > native `xrdfs`/`xrdcp` authenticate to the reference origin (stat/ls/byte-exact
  > download + no-ccache negative, **4/4**), and brix tiers are unchanged (native-krb5
  > 7/7, delegation-e2e 3/3). **(2) Outbound reclassified:** the same capture proves
  > stock XRootD krb5 is *raw* `krb5_rd_req`, whereas the outbound leg
  > (`brix_krb5_deleg_negotiate`, `forward.c`) emits a **GSSAPI** `gss_init_sec_context`
  > token (tag `0x60`, mech-OID wrapper) with no name-prefix (`kxr_wire.c:111`). A GSS
  > init token is not an AP-REQ, so the outbound leg cannot authenticate to *any* stock
  > `&P=krb5` origin — the block is a dialect gap, not merely a missing peer. The
  > de-risked closure (exact wire now known): add a *raw-krb5* outbound path that, from
  > the delegated per-user TGT (`t->cred_krb5_ccache`), gets a service ticket for the
  > origin SPN + `krb5_mk_req_extended` an AP-REQ and sends `"krb5\0"`+AP-REQ (exactly
  > the reference-verified client wire), then live-tests brix-cache → the same reference
  > origin — a bounded new subsystem alongside the KDC-verified GSS engine, deferred
  > here to avoid destabilising it. Full detail: phase-70 doc §5.7.1 REMAINING + UPDATE (f).
  >
  > **UPDATE 2026-08-01 (iv) — the raw-krb5 outbound leg is BUILT, LANDED, and
  > live-verified; production dispatch switched off GSS. The krb5 residual is now
  > infra-blocked ONLY.** The de-risked closure from (iii) is shipped. New
  > `src/auth/krb5/apreq.{c,h}` `brix_krb5_apreq_from_ccache()` renders the
  > `"krb5\0"`+AP-REQ payload straight from the delegated per-user TGT
  > (`krb5_cc_resolve` the carried ccache PATH → `krb5_get_credentials` a service ticket
  > for the origin SPN → `krb5_mk_req_extended`), byte-identical to the reference-verified
  > native client. `origin_auth.c` `brix_cache_origin_auth_krb5_raw()` presents it in one
  > `kXR_auth` leg over the existing `brix_krb5_kxr_wire` codec; the origin dispatch
  > (`origin_protocol_bootstrap.c` `origin_bs_auth_krb5`) now routes to the RAW path —
  > ticket target from the advertised `&P=krb5,<spn>`, falling back to the request-time
  > carried principal — with no GSS re-import. The GSSAPI engine (`forward.c`,
  > `brix_cache_origin_auth_krb5`) is retained (unused in production) with its unit
  > intact. **Live proof:** the new `apreq` mode of `tests/c/krb5_forward_live.c` builds
  > the AP-REQ from alice's delegated TGT against the unprivileged MIT KDC lab and
  > validates it with `krb5_rd_req` against the origin keytab — exactly what a real
  > `&P=krb5` origin does — asserting the recovered identity is `alice`, plus
  > bound-to-origin-principal and wrong-password negatives (`test_krb5_forward_live.py`
  > **16/16**). The dispatch unit `origin_krb5_dispatch_test.c` was rewritten to the raw
  > contract (advertised-SPN-wins + bare-advert fallback + fail-closed). Build clean
  > `-Werror -DBRIX_HAVE_KRB5=1` (both symbols `T` in the linked binary); delegation-e2e
  > 3/3 + interop 4/4 regress green; vfs-seam + namespace guards OK. **The sole residual
  > is now the end-to-end brix-cache → LIVE `xrootd`-origin handshake — environment-blocked
  > only**, the crypto and the exact wire being reference-proven on both the build (apreq)
  > and validate (`krb5_rd_req`) sides. Full detail: phase-70 doc §5.7.1 UPDATE (g).
  >
  > **UPDATE 2026-08-01 (v) — the end-to-end brix-cache → LIVE stock-`xrootd`-origin
  > krb5 handshake is now CLOSED. The Phase-70 §5.7 outbound leg has NO residual.**
  > The "environment-blocked only" gate in (iv) is lifted: a stock `xrootd`
  > krb5-ONLY origin (`sec.protbind * krb5`, `libXrdSeckrb5`) *does* run in this
  > shell, so the whole delegated chain is provable with three real processes and
  > no mocks — native client ─krb5(+deleg)→ brix-cache ─raw AP-REQ→ stock xrootd.
  > `tests/test_krb5_cache_origin_e2e.py` (**5/5** vs the session MIT KDC): a
  > **forwardable** TGT drives capture → 0600-ccache carry → `"krb5\0"`+AP-REQ →
  > `krb5_rd_req` acceptor → **byte-exact** `probe.txt` download
  > (`test_delegated_fetch_byte_exact`); a `stat` fires the `"krb5 delegation
  > captured forwarded TGT"` marker (`test_cache_captured_forwarded_tgt`); a missing
  > object fails clean (`test_missing_object_clean_error`); a **non-forwardable**
  > TGT is refused with no service-cred fallback (`test_nonforwardable_tgt_refused`);
  > and a delegated `ls /` enumerates the origin AS the user
  > (`test_delegated_dirlist_forwards_krb5`, exercises the path-op leg — `blob.bin`
  > is never cached, so its presence proves the origin was contacted under the
  > delegated identity).
  >
  > **Three product fixes fell out of being the first live exerciser of the
  > cache-MISS outbound leg** (all correctness, all landed):
  > (1) **`sd_xroot` accept-mask** (`sd_xroot.c` `.cred_accept`) was missing
  >     `BRIX_SD_CRED_GSS_KRB5`, so the VFS deny-gate refused the delegated krb5
  >     cred before any origin contact (accept `0xb & 0x20 == 0`). Added the bit.
  > (2) **NULL-safe log** in `brix_cache_origin_auth_krb5_raw` (`origin_auth.c`):
  >     the bespoke-origin path carries `t->c`, but the composed SOURCE-backend fill
  >     task (`sd_xroot_session`) has `t->c == NULL` — deriving the log as
  >     `(t->c != NULL) ? t->c->log : ngx_cycle->log` stops a worker SIGSEGV on the
  >     fill path.
  > (3) **Cache miss-fill forwarded NO per-user credential** — the real gap. The
  >     composed-tier offload (`brix_cache_open_fill_offload` →
  >     `brix_cache_fill_composed_thread` → `brix_sd_cache_fill_key`) opened the
  >     source **anonymously** (`sd_cache_fill(…, NULL)`), so a krb5/bearer/proxy-gated
  >     origin refused every MISS even though the whole cred-carry infra existed one
  >     layer down (`cache_fill_acquire` already calls `brix_sd_open_maybe_cred(src,
  >     …, cred, …)`). Closed by: resolving the delegated cred on the MAIN thread in
  >     `brix_open_try_cache_offload` (the `open_request_resolve.c` recipe: transient
  >     vctx + `brix_vfs_ctx_bind_backend_cred` + `brix_root_vfs_bind_deleg` +
  >     `brix_vfs_backend_cred`, fail-closed on a deny-mode gate), carrying the
  >     resolved strings onto the fill task's `cred_*` fields
  >     (`cache_fill_carry_cred`, cache-layer — no reach into a backend), and
  >     projecting them back to a borrowed `brix_sd_cred_t` for the source open
  >     (`cache_fill_cred_view`) threaded through the now-cred-aware
  >     `brix_sd_cache_fill_key(inst, key, cred)`. The HTTP-cache and CVMFS-prewarm
  >     fill callers pass `NULL` (service credential — behaviour unchanged).
  > **This fix is generic** — it forwards bearer / x509-proxy / SSS / krb5 identity
  > on *every* composed-cache MISS, not just krb5. A latent adjacent bug was also
  > closed: `sd_xroot_cred_must_deny` / `sd_xroot_cred_copy` (`sd_xroot_ns.c`, the
  > path-op session copier) omitted `krb5_ccache`, so write/namespace ops under a
  > krb5 EXCHANGE cred would silently drop the TGT and fall back to the service
  > credential even under `fallback_deny`; both now handle krb5 (covered by
  > `test_delegated_dirlist_forwards_krb5`). Full detail: phase-70 doc §5.7.1.

---

## 5. Feature backlog (designed/planned — not bugs)

Plan-only phases: **70** (full credential delegation — not started), **27/28**
(memory-safety / adversarial hardening), **54/55** (VFS thread-safe IO core /
storage-backend abstraction — check overlap with landed 63/64/71 before
starting).

> SUPERSEDED (2026-07-25, re-audited against the tree): the "plan-only" clause
> above is stale — see `phase-90-plan-phase-remainder-register.md` for the
> verified per-item residual register. 54 is fully LANDED (`brix_vfs_io_core`),
> 55 substantially landed/exceeded (`brix_sd_*` seam + phase-63/64 decorators),
> 27/28 substantially landed (residual = the §4 infra-blocked set this doc
> already tracks), 70 substantially landed (bearer/x509-proxy passthrough +
> token exchange live; residual = STS/krb5/SSS origin legs + polish). Design-only: **60** (Ceph beyond the basic `sd_ceph.c` driver),
**61** (CMS parity spec), **64** (fully-tiered composable storage +
generic-slice-fill BACKLOG) — *burned down via
`phase-89-design-backlog-burndown.md` (implemented 2026-07-21, closed out
2026-07-27): 60 COMPLETE (namespace plane landed — `sd_ceph_dir.c` listing +
copy+delete rename + synthetic dirs, live Docker lab verified), 61
**COMPLETE 2026-07-27** (PR-1…PR-8 via phase-89 §C, then the W7 remainder —
full `stats` XML, `brix_cms_role` manVOps/supVOps, server-leg Admit roles +
`kYR_metaman`, `brix_cms_state_relay` recursion — landed directly; see the
phase-61 LANDED block, incl. divergence rulings + out-of-scope register; the
ADR-4 phase-62 split was not needed), 64 CLOSED
(slice-fill DONE; `brix_frm_*` directive grammar RATIFIED as engine/adapter
knobs, ADR-3 + pin test; residual tail = the §4 infra-blocked set —
HPSS/CTA adapters — plus deferred-on-profile serve off-load and
resolve-on-touch §21 questions, no silent drops)* — *[HPSS/CTA CLOSED for the
operational path 2026-07-30: `tape://hpss` and `tape://cta` are now first-class
named exec-family MSS dialects over the classic FRM stage-command transport
(`frm_adapter_is_exec_family` / `frm_exec_stagecmd` in `sd_frm.c`), each with a
per-dialect stagecmd override (`$BRIX_FRM_{HPSS,CTA}_STAGECMD` → generic
`$BRIX_FRM_STAGECMD`) — the production model real XRootD uses; unknown names are
now the only stub fallthrough. Tests `test_frm_scratch.py::test_named_hsm_dialect_
recalls_via_dialect_stagecmd[hpss,cta]`. **The library-native (non-stagecmd)
adapter is now CLOSED too (2026-07-30):** `src/fs/backend/frm/sd_frm_lib.c` drives
a real HSM by `dlopen`ing an operator `.so` and `dlsym`ing the
`sd_frm_lib_abi.h` verbs (`brix_frm_hsm_exists`/`recall`/`migrate`, optional
`purge`), so each residency probe / recall is an in-process call instead of a
per-verb `fork+exec` of a stage command — removing the fork latency that
dominates small-object staging on a busy silo. Three dialects `lib`/`libhpss`/
`libcta` resolve the `.so` from `$BRIX_FRM_LIB` → per-dialect
`$BRIX_FRM_{HPSS,CTA}_LIB` (`frm_adapter_is_lib_family` / `frm_lib_path` /
`frm_select_lib_adapter` in `sd_frm.c`, tried before exec/stub in the create
orchestrator). The vendor library is a runtime plug-in: an absent/unresolvable
`.so` or a missing required symbol WARN-logs and degrades to exec/stub, never a
boot failure. Tests: live data plane `test_frm_lib_adapter.py` (4/4 — recall
serves byte-exact via `dlsym`, generic-env dialect, absent-not-fabricated,
graceful missing-library fallback) with a compiled mock HSM `.so`
(`tests/cmdscripts/frm_mock_hsm.c`). See phase-89 §D.4]*.
Partial: **59** (staged CSI-counter + W3b
reservation TPC call-site rows; ~~deferred W2 per-page CSI+scrub~~ *[W2b paced
background scrub CLOSED 2026-07-29 — pure engine `fs/backend/csi_scrub.{c,h}`
re-verifying xmeta per-block CRC32c at rest, unit-tested 12/12
`tests/c/test_csi_scrub.c`, wired as a per-server timer via directive
`brix_csi_scrub_interval` + metric `brix_csi_scrub_mismatch_total`; see phase-59
§0.IMPL PR-4]*), **58**
*[CLOSED 2026-07-30 for the CNS emit wire wrappers: the §6 data-server namespace-mutation
emitters (`rm`→DEL, `rmdir`→RMDIR, `mkdir`→MKDIR) landed via a shared
`src/net/cms/cns_emit.{c,h}::brix_cns_emit` seam (ADD-on-close refactored onto it);
apply/receive already handled all four ops. `tests/test_cns.py` now 4/4 on a real 2-node
cluster incl. rm-delete + mkdir/rmdir round-trip. **The async-backend RM/RMDIR queue path
is now CLOSED too (2026-07-30):** it used to return from `op_table.c` before the inline
emit; it now emits its own late `BRIX_CNS_DEL`/`RMDIR` from the durable-queue waker
`baq_root_done` (`backend_async_root.c`) once the removal actually runs (success-only,
MV/RENAME excluded). `test_cns.py` 6/6 — two new async-cluster tests
(`test_manager_reflects_async_backend_rm_delete`/`_rmdir`, `nginx_cns_data_async.conf`,
`lc-cns-data-async` 30427). **The SHM-multi-worker inventory follow-up is now CLOSED
too (2026-07-30):** the manager's path→metadata inventory moved off the per-worker
heap into a slab-backed cross-worker table. The pure POD table logic
(`src/net/cms/cns_inventory.{c,h}` — apply ADD/DEL/MKDIR/RMDIR + stat, nginx-free
and standalone-unit-tested, `test_cns_inventory.py` 6/6) is layered under the
SHM/nginx plumbing in `cns.c`: `brix_cns_configure` registers the
`brix_cns_inventory` zone (Invariant #10 via `brix_shm_table_alloc`, mutex bound
to the slab-pool lock), wired from `postconfiguration.c` whenever
`brix_cns_collecting()`; every apply/stat/count takes `cns_mtx` under a
`cns_active_table()` that returns the SHM table when the zone is up and a lazy
per-worker heap otherwise (single-worker parity preserved). `test_cns.py` 6/6 on
a real 2-node cluster is unchanged; a `worker_processes 2` manager config parses
clean (`nginx -t`). — an infra/design item, now landed. **The outbound-GSI epic (§5.8 Phase-2 consume) is now CLOSED too**
(2026-07-30): the ADR-3 gate is lifted (the outbound blocker was the `tpc.org`
mismatch cleared 2026-07-19), 5g is live-verified
(`test_tpc_delegation.py::test_dest_pulls_as_user_via_delegation`), and the two
remaining §5.8 sub-tasks landed — a pre-launch proxy-expiry gate
(`brix_tpc_proxy_pem_expired`, refuse-not-downgrade per §5.9 T5;
`tests/c/tpc_proxy_expiry_test.c`) and the
`brix_tpc_gsi_delegated_total{result="ok|expired|absent"}` metric
(`tests/test_tpc_gsi_deleg_metrics.py`)]*,
**80** stretch *[CLOSED 2026-07-27 — reconciled against the tree 2026-07-31:
the "Partial" tag was stale. All ten stretch tasks (P80.11–14, P80.21–25
zero-provisioning multi-user) are LANDED — the phase-80 doc's own header and the
P80.14/P80.24/P80.25 "Status — LANDED" blocks
(`phase-80-s3-backend-forwarding-closure.md` §2/§6) confirm it, and every cited
gate exists in-tree: the local P80.24 suite `tests/test_pblock_group_multiuser.py`
(+ `tests/c/{test_ucred,gsi_eec}.c`, `tests/configs/nginx_pblock_group_gsi.conf`,
`docs/05-operations/pblock-multiuser.md`) and the two k8s charts
`k8s-tests/charts/{s3-voms,pb-gsi}` with their remote suites
`k8s-tests/remote-suite/tests/test_{s3voms,pbgsi}_multiuser.py`. See memory
`phase80-stretch-landed`. Design rulings, not open work: `@=` authdb token
substitution was never viable (`brix_identity_user_token` unimplemented) so
P80.14 uses `o <org>` VO rules; identity keys on the EEC DN, not the proxy
leaf]*, **56** *[CLOSED 2026-07-27: the cited
"remaining migrations" example was stale — `webdav_handle_mkcol` and the whole
F-pillar were already on the VFS seam (guard `check_vfs_seam.py` green proves
it); the real remainder was D-2 (data-plane op-latency histogram), now DONE —
see phase-56 doc status header]*, **49** tail *[CLOSED 2026-07-27: `xrdfs`
`brix_report_err` sweep, ~46 sites; `tests/test_xrdfs_report_err_sweep.py`]*,
**38** *[CLOSED 2026-07-30: the "6 of 28 files still unsplit" count was stale —
the `client/` tree is now fully split behavior-identically and the file-size
guard's scan was widened from `src/` to also cover `client/` (excluding
`client/tests/`). Zero `client/` offenders remain (largest is 598 raw);
`check_file_size.py --regen`-frozen backlog gains no `client/` entries. See
phase-38 doc § "client/ tree — DONE (2026-07-30)" + memory
`file-size-burndown-under-600`. NB: the guard/`test_ci_guards.py` band-fail on
3 `src/` files (`http_common.c`, `vfs_deleg.c`, `vfs_internal.h`) is unrelated
pre-existing work from other workstreams, not a phase-38 client residual]*, **83** *[CLOSED 2026-07-27:
`pblock-fsck --replay` landed, `tests/test_pblock_fsck_replay.py` 7 green]*.

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

**~~Needs reconciliation, deliberately not done here:~~** the 2026-07-03
brix-symbol-rebrand checklist (~60 unchecked boxes) — the tree is clearly
already `brix_`-rebranded, so the checklist is likely executed-but-unticked;
tick-or-annotate it against the tree in its own pass rather than trusting
either direction.
> **CLOSED 2026-07-30 (reconciliation pass run).** Verified against the tree:
> all seven rebrand tasks are landed; `brix_verify.sh` reports **0** residuals
> for both server and client scopes. The checklist was executed-but-unticked as
> predicted — a status banner ticking it lives at the top of
> `2026-07-03-brix-symbol-rebrand.md`. One **genuine drift** surfaced and was
> fixed: phase-44 io_uring code reintroduced a stale `xrdc_aconn` in an
> `aio_internal.h` comment (the mechanical engine only ran once, so later code
> could regress spellings). A standing regression guard now prevents recurrence —
> `tools/ci/check_brix_namespace.py` (reuses the rename engine's rule + EXCLUDE
> tables), wired into `.github/workflows/guards.yml` and the pytest fast lane
> (`tests/test_ci_guards.py::test_ci_guard_green[check_brix_namespace]` +
> `test_brix_namespace_guard_catches_drift` injected-drift negatives).

---

## 6. Out of scope

All CVMFS work (phase-84 conformance corpus, cvmfs-automount packaging,
phase-68/85/87 CVMFS legs) was excluded per the audit's brief. By-design parity
gaps (`gaps-vs-xrootd.md`, feature-matrix "not implemented" rows, phase-20/21
won't-do items) are documented decisions, not open work, and are not listed.
