# Phase-4 Bucket-1 conversion inventory (fixed-port harness refactor)

Status: **IN PROGRESS 2026-07-22.** This doc is the durable work-list for converting the
remaining ~120 lifecycle-harness consumer files (Bucket 1 of Phase 4) off dynamic
`-{pid}`/`free_port` registration and onto **fixed ports** sourced from a ledger, with
per-file `@pytest.mark.xdist_group(...)` serialisation. Plan + PROGRESS:
`~/.claude/plans/linear-churning-stallman.md`; memory `test-harness-fixed-port-refactor`.

## Model (decided with OP 2026-07-22 — "Hybrid")

- **The bulk (~110 instances / ~114 files):** each named instance gets a dedicated fixed
  port from the **lifecycle-shared band 30000–30999** via a new `LIFECYCLE_SHARED_PORTS`
  dict in `fleet_lifecycle_ports.py`; `lifecycle_ports_for(name)` consults it (and the
  existing exclusive dict). The file keeps its `lifecycle.start(NginxInstanceSpec(...))`
  calls but is serialised with one `@pytest.mark.xdist_group("<family>")` so a fixed port
  never has two concurrent drivers. `extra_ports` the instance owns come from the ledger
  `extra` map (overrides any inline `free_port()`).
- **Genuine cross-file dedup (marginal):** the "static-24" candidates turned out mostly
  DYNAMIC (inline `free_port()` / `tmp_path` / `os.getpid()` / cross-instance peer ports).
  Only ~2 truly-identical cross-file clusters exist (≈4 ports); cross-file config sharing
  couples two tests to one spec, so apply dedup ONLY where free and low-risk. Default =
  ledger every instance.

## Key mechanics learned

- `LifecycleHarness.register` (server_launcher.py:1046) already: `fixed_port, fixed_extra =
  lifecycle_ports_for(spec.name)` → fixed port + `extra_ports={**spec.extra_ports,
  **fixed_extra}`, no `-{pid}` suffix. Render injects `**endpoint.extra_ports` into
  template_values (lines 311/391/511/586).
- **Peer references need NO change:** `MANAGER_PORT=manager.port`, `ORIGIN_PORT=origin.port`,
  `BACKEND_PORT=backend.port`, `UPSTREAM=HOST:hop.port` all read a *started* instance's
  `.port` at runtime → still correct once that instance has a fixed ledger port.
- **Only the instance's OWN listen ports** (primary + `extra_ports=`/port-valued
  `template_values` set via inline `free_port()`) must move to the ledger.
- Register-only / `nginx -t` instances (never bind) still mint a ledger key but need no live
  port — give them a shared parse placeholder or a normal key (harmless, never bound).
- `guard-stub`, `introspect-idp`, `cluster-redir`, `mirror-shadow`, `static-origin` are
  Phase-2 registry mock singletons referenced via `@pytest.mark.registry_server(...)` — NOT
  lifecycle instances; leave those markers, they are already correct.

## Simultaneity flags (need ≥2 distinct ledger ports live at the same instant)

- `test_cns.py` — lc-cns-manager + lc-cns-data
- `test_gohep_interop.py` — lc-gohep-ds + lc-gohep-anon + lc-gohep-redirector (3)
- `test_host_auth.py` — lc-host-ok + lc-host-deny
- `test_stream_guard.py` — origin + guarded + unguarded (3)
- `test_tpc_gsi_nginx_source.py` — source + dest; `test_tpc_tls.py` — source + dest
- `test_slice_cache.py` — lc-slice-cache-origin + lc-slice-cache-node
- `test_pblock_lab_dedup.py` (dd-sec+dd-off), `_locks` (lk-sec+lk-off), `_nearline`
  (nl-sec+nl-off) — a sec+off pair started together in one test
- `test_delegated_cred.py` — badpem+token soft overlap in one test
- Multi-listen single instances (primary + extra_ports on ONE name): crc64 (S3_PORT,
  WEBDAV_PORT), frm_phase1_http (STREAM/S3/WEBDAV), guard_endpoints (DAV/S3/OPS/XRD/CMS),
  tape_rest (STREAM), put_content_encoding (S3), scan (OFF), stage_hydration (ORIGIN),
  proxy_ssl_capath (BACKEND), xrddiag_compare_davs (OK/BAD), xrddiag_multiproto
  (HTTP/HTTPS/S3), client_web_transfer (S3), cache_reap_metrics (METRICS), ssi_metrics
  (METRICS), frm_phase4/_engines-f5 (METRICS), frm_owner (HTTP), cms_blacklist_file (HTTP),
  dashboard_config_anon (ROOT), dashboard_files (OFF).

## Genuine dedup clusters (identical template+protocol+STATIC values)

- **A** `nginx_lc_checksum_on_write.conf` http {BIND_HOST, EXTRA_DIRECTIVES=""}:
  checksum_on_write→lc-checksum-plain ≡ webdav_put_digest→lc-put-digest
- **D** `nginx_mu_stage_modes_webdav.conf` https {CERT,KEY,CA,data_root=MU.DATA_ROOT}:
  mu_sidecar_hidden→lc-mu-sidecar-webdav ≡ mu_stage_modes→lc-mu-stage-webdav
- Same-file hoist only (no cross-file coupling): conformance_topologies tap (lc-ct-proxy ≡
  lc-ct-mesh1), mirror (lc-ct-mirror ≡ lc-ct-mirror_rw).
- The `nginx_lc_ssi.conf` variants differ by whitespace only — do NOT auto-merge.

## Conversion waves (each = edit ledger + files, then OP-owner runs pytest, confirm green)

Ordered simplest→hardest. `[ ]` = todo, `[x]` = done+green.

### Wave 1 — trivial single-instance, root, no extra ports (`nginx_lc_stream_posix_anon.conf` family + kin) ✅ DONE + GREEN 2026-07-22
`[x]` test_client_xrdcp_bulk (lc-xrdcp-bulk 30010) · test_client_xrd_doctor_login (lc-xrd-doctor-login 30011) ·
test_client_xrd_frontend (lc-xrd-frontend 30012) · test_client_xrdfs_tools (lc-xrdfs-tools 30013) ·
test_client_xrdrc_alias (lc-xrdrc-alias 30014) · test_native_client_diagnostics (lc-native-client-diag 30015) ·
test_xrd_busybox (lc-xrd-busybox 30016) · test_xrddiag_capture (lc-xrddiag-capture 30017) ·
test_xrddiag_probe (lc-xrddiag-probe 30018) · test_xrdmapc (lc-xrdmapc 30019)
Each got a per-file `@pytest.mark.xdist_group(<name>)` (serial no-op; confines a file's tests
to one worker so a fixed port never has two concurrent drivers). **Result: 112 passed (8 files)
+ 10 lc-xrdmapc tests green.** ONLY failures = the 2 cluster-redir tests in test_xrdmapc — see
KNOWN ISSUE below (pre-existing, orthogonal).

**KNOWN ISSUE (pre-existing, NOT Bucket-1): cluster-redir subset-boot holder gap.**
`test_xrdmapc::test_map_cluster_redirector` + `::test_redirect_trace_hops_via_cluster` fail
deterministically: the `cluster-redir` dedicated spec (fleet_specs.py:536, port 11160) boots
(so the `if not _port_up: skip` guard does NOT skip) but `xrdmapc locate /` returns NotFound
(rc 54) — the redirector has no data-server HOLDERS because they aren't in cluster-redir's
dependency closure under subset-boot (default-on since 2026-07-20). This is a Phase-3
declaration-graph gap (cluster-redir `requires=` needs its backing data servers), fixable in
the declaration sweep — unrelated to the fixed-port work (the other 10 lc-xrdmapc tests pass).
Other `nginx_cluster_redir.conf` consumers (cms-test-mgr, chaos-discovery-redir, cluster-mp/ms/
mw/3t) likely share this gap — verify during Wave 5 (the cms/cluster peer files).

### Wave 2 — single-instance webdav/http/root, + 3 multi-listen ✅ DONE + GREEN 2026-07-22
`[x]` test_krb5_auth (lc-krb5-auth 30020) · test_native_krb5 (lc-native-krb5 30021) ·
test_macaroon_negative (30022) + test_macaroon_request (30023) ·
test_token_aud_array (30024) + test_token_es256 (30025) ·
test_pwd_auth (30026) · test_readv_segment_size (lc-readv-seg16m 30027) + test_readv_variable_blocks (lc-readv-var1m 30028) ·
test_s3_auth_oracle (30029) · test_s3_list_cache (30030) ·
test_srr_endpoint (lc-srr 30031) · test_frm_async (30032) · test_frm_control_locality (30033) ·
test_xfer_resume_sweep (lc-resume-sweep 30034) · test_xfer_wt_journal (30035) ·
test_zip_scratch (lc-zip-scratch 30036, lc-zip-inplace 30037) ·
test_xrddiag_remote_doctor (5: lc-rdoctor-{anon 30039,rw 30040,empty 30041,sss 30042,token 30043}, group lc-rdoctor) ·
test_xrddiag_watch (30038) · test_xrddiag_compare_davs (30044 +OK 30045/BAD 30046) ·
test_xrddiag_multiproto (30047 +HTTP 30048/HTTPS 30049/S3 30050)
**Result: 97 passed (77 non-doctor + 20 remote_doctor), 0 failed.** Each file got ONE per-file
`@pytest.mark.xdist_group(...)`; distinct files carry distinct ports so no shared-template group
was needed (the two krb5 / two readv / two macaroon / two token files each own their own port).
**KEY DECISION — own-vs-peer ports:** the extraction proved NO file references another started
instance's `.port`; the only own bound listens beyond the primary were 3 files' inline `free_port()`
(compare_davs OK/BAD, multiproto HTTP/HTTPS/S3, remote_doctor anon primary+::1). Those were moved
to the ledger `extra` map and the `free_port()` calls DELETED (register's
`extra_ports={**spec.extra_ports, **fixed_extra}` merge means ledger wins; dropping the arg entirely
lets fixed_extra supply the keys). remote_doctor's anon fixture now sources the primary from
`lifecycle_ports_for("lc-rdoctor-anon")` so its ::1 listen shares the fixed number — the v4/v6
asymmetry test ran (did NOT skip), proving the shared-port ::1 listen bound correctly. This also
advances Phase 5 (3 more `free_port` sites gone) for free.

### Wave 3 — parse/register-only families (+ their live-bind siblings) ✅ DONE + GREEN 2026-07-22
`[x]` test_upstream_tls_verify (6 lc-a1-* 30051-56, group lc-a1) · test_ocsp_require_nonce (3 lc-a6-nonce-* 30057-59, group lc-a6-nonce) ·
test_mu_sidecar_config_guard (9 lc-mu-guard-* 30060-68, group lc-mu-guard) · test_stage_default_gateway (4 stage-default-* 30069-72, group stage-default; unprefixed names kept) ·
test_slice_cache (validate 30073-74 + LIVE origin 30075/node 30076, group lc-slice-cache — **also covers Wave-5's slice_cache**) ·
test_client_certificate_folder (30077-81, group lc-certfolder) · test_credential_dir_default (30082-85, group lc-cred-dir) ·
test_delegated_cred (30086-89, group lc-delegcred) · test_proxy_ssl_capath (30090-98 incl. per-name BACKEND_PORT extras, group lc-proxycapath) ·
test_ssl_client_capath (30099-30102, group lc-capath) · test_webdav_lock_startup_sweep (30103-05, group lc-sweep) ·
test_ssi_config (30106-09, group lc-ssi-cfg)
**Result: 58 passed, 12 skipped, 7 xfailed, 0 failed.** Skips/xfails all pre-existing
(stage privatetmp root-only, slice_cache @skip stubs + C-unit + xcache `xfail(strict=False)`).
**KEY MECHANIC — parse-only instances get a fixed port too:** a `register`+`nginx -t` check
(accept OR reject case) never binds, but without a ledger entry `register` falls to the
`-{pid}` name + `endpoint_for` free_port fallback. Ledgering every parse name (unique, never-
bound) removes both — the port is metadata the listener never claims. The two `_GATE`-decorator
files (upstream_tls_verify, ocsp) have no module `pytestmark`; added a module-level
`pytestmark = pytest.mark.xdist_group(...)` (additive to the per-test `@_GATE`).
proxy_ssl_capath's own `BACKEND_PORT` https backend listen moved from an inline `_free_port()`
to a per-name ledger `extra`, read back in `_spec` via `lifecycle_ports_for(name)` and kept as a
`template_value` (robust regardless of the parse-path render's extra_ports injection) — retires
the file's `_free_port()`/`socket` import (another Phase-5 site gone).

### Wave 4 — multi-listen single instances (extra_ports on one name) ✅ DONE + GREEN 2026-07-22
Ledger ports 30110-30152. Per file: one `xdist_group(<lc-name>)`; every own-listen extra port
re-sourced from `ep.extra_ports[...]` POST-register (the Wave-4 correctness rule — never a stale
local free_port var while nginx binds the ledger value) with the `extra_ports={free_port...}`
kwarg dropped; template_values-injected ports (stage_hydration ORIGIN_PORT, cms_blfile HTTP_PORT)
drop the explicit entry so render injects from ledger `extra`; test_client_web_transfer KEEPS its
local `_free_port()` for the one-shot throwaway PROPFIND mock (Phase-6 exempt), converting only
the fixture. **Serial: 124 passed / 8 skipped (env-gated) / 0 fail (56s).**
`[x]` test_crc64 (S3/WEBDAV) · test_frm_phase1_http (STREAM/S3/WEBDAV) · test_frm_phase4 (METRICS) ·
test_frm_phase4_engines (f3, f5+METRICS) · test_frm_owner (HTTP) · test_frm_staging (2) ·
test_cache_reap_metrics (METRICS) · test_ssi_metrics (METRICS) · test_tape_rest (STREAM) ·
test_put_content_encoding (S3) · test_scan (OFF) · test_stage_hydration (ORIGIN) · test_client_web_transfer (S3) ·
test_guard_endpoints (DAV/S3/OPS/XRD/CMS) · test_cms_blacklist_file (HTTP) ·
test_dashboard_config_anon (ROOT extra) · test_dashboard_files (OFF extra) · test_storage_backend_panel (REMOTE_NS getpid)

### Wave 5 — multi-instance-simultaneous + peer refs ✅ DONE + GREEN 2026-07-22
`[x]` test_cns (mgr+data) · test_gohep_interop (3) · test_host_auth (2) · test_stream_guard (3) ·
test_tpc_async_open, test_tpc_delegation, test_tpc_gsi_nginx_source (2), test_tpc_gsi_outbound, test_tpc_tls (2) [group lc-tpc] ·
test_slice_cache (origin+node) — ✅ DONE in Wave 3 · test_proxy_large_read (be+px) · test_conformance_topologies (7, mixed) ·
test_metadata_stress (3) · test_min_sec_level (3) · test_negcache_backoff (2) · test_opaque_strict (4) ·
the cms_* peer-port files (affinity/fanout/locate/prepadd/resilience/state/wire) ·
mu_cache_serve_authz (origin+node) · native_gsi_interop (2) · phase21_proxy_filter (2) · phase27_memsafety (2)

**As-built (ledger 30153–30212, `LIFECYCLE_SHARED_PORTS`):** 25 files, families lc-cns / lc-gohep /
lc-stream-guard / lc-proxy-large-read / lc-mu-cache / lc-ct (conformance_topologies+proxy_large_read
mesh) / lc-metadata-stress / lc-host-auth / lc-opq / lc-memsafety / lc-minsec / lc-negcache / lc-tpc /
lc-native-gsi / lc-cms-affinity / lc-cms-fanout / lc-cms-locate-have / lc-cms-prep / lc-cms-resilience /
lc-cms-state / lc-cms-wire. **Peer-wiring rule applied:** nginx↔nginx shared-`free_port` peers (cns,
ct-cluster `_build_cluster`) CONVERTED — producer instance listed first in ledger, consumer sources the
peer's port from `producer_ep.extra_ports["CMS_PORT"]`; nginx-reads-peer.`.port` peers (gohep/stream_guard/
proxy/mu_cache/ct-mesh) auto-follow the ledger → **marker-only**; nginx-dials-Python-mock-bind peers (cms
prepadd/resilience/state/wire/fast-settle) KEEP `free_port` (Phase-5/mock scope) → nginx primary ledgered,
marker-only. The 3 CMS-manager own-extra-listen files (affinity MULTI_PORT+CMS_PORT / fanout CMS_PORT /
locate CMS_PORT) converted `free_port`→ledger `extra`, sourced post-start from `ep.extra_ports[...]`.
**Serial run: 142 passed / 1 shared-fleet contention flake** (`test_cms_locate_have::test_have_wins…`
`silent` node registration-probe race — **passes 3/3 in isolation**, pre-existing shared-fleet timing
class, not the port conversion). **DEFERRED:** `test_cms_fast_settle.py` — dynamic per-index node pool
(node count varies per test) doesn't fit a fixed ledger cleanly; carry to Wave 7.

### Wave 6 — pblock-lab family ✅ DONE + GREEN 2026-07-22
`[x]` anomaly(4) · audit(3) · crash(2) · csi(3) · dedup(4) · locks(4) · nearline(4) · quota(3) ·
snapshot(3, start/stop toggle) · versioning(3 webdav, toggle)
NOTE snapshot/versioning use start→stop→start_registered toggles (offline fsck windows) —
single instance per test, one fixed port suffices.

**As-built (ledger 30213–30245, 33 instance names; xform already ledgered 31160-31164 in Bucket 2):**
**MARKER + LEDGER ONLY** — no `free_port`, no peer wiring, no template_values port. Every server is built
by `pblock_live.pblock_lab_spec(name, tail, workers=)` whose `template_values` is `{BIND_HOST, TAIL,
WORKERS}` (no port) → the listen is owned entirely by the ledger; render injects `{PORT}` from
`endpoint.port`. No file reads another instance's `.port`. Each file serialised with its OWN
`xdist_group("lc-pblock-<file>")` (anomaly/audit/crash/csi/dedup/locks/nearline/quota/snapshot/
versioning) — per-file (not one umbrella group) so the 10 files parallelise across workers while each
file's fixed ports have exactly one driver (unique names → unique ports, no cross-file sharing).
snapshot+versioning are lifecycle SUBJECTS (stop→start_registered offline-fsck toggles) but reuse the
same registered port, so one fixed port per name still suffices. crash arms a compiled-in worker
`_exit(86)`/master-respawn (in-process, not a lifecycle toggle). **Serial run: 31 passed / 0 fail** (119s).

### Wave 7 — remaining singletons / clients / acc / dig / access-log / cache-verify / etc.

#### Wave 7a — ✅ DONE + GREEN 2026-07-22
Part-A `lc-`named files (27 files, ledger `LIFECYCLE_SHARED_PORTS` 30246–30281). Each got one
`@pytest.mark.xdist_group(<lc-name>)`. Three `free_port`→ledger conversions:
- **test_delegation_t4_credential.py** (lc-t4-delegation 30253 + extra VERIFY_PORT 30254): dropped
  `settings.free_ports` + `extra_ports={"VERIFY_PORT":…}`; source `verify_port = ep.extra_ports["VERIFY_PORT"]`
  post-start (second embedded mTLS-verifier listen owned by the ledger).
- **test_pwd_auth_multiproto.py** (lc-pwd-multiproto 30269 + extra HTTP_PORT 30270 / HTTPS_PORT 30271):
  dropped `free_ports` import+call+`extra_ports=`; after `start_registered` read
  `http_port/https_port = ep.extra_ports["HTTP_PORT"/"HTTPS_PORT"]` (root:// + http:// + https:// against
  the one export).
- **test_phase20_kv_shm.py** (lc-phase20-ratelimit 30264 + extra METRICS_PORT 30265): parse-fixture
  `kv_check` rewritten to `config_parse.nginx_t("nginx_phase20_kv_stream.conf", root, PORT=SHARED_PARSE_PLACEHOLDER_PORT, …)`
  (per-call `root = tmp_path/f"kv{next(_SEQ)}"`, no registry spec/`-{pid}`); module globals
  `WEBDAV_PORT/METRICS_PORT` now come from `lifecycle_ports_for("lc-phase20-ratelimit")`; live fixture drops
  `port=`/`extra_ports=`.

Plus **test_cvmfs_cold_tier.py** (lc-cvmfs-cold-demote 30252): file previously LACKED
`uses_lifecycle_harness` — converted its single `skipif` mark into a list ADDING
`uses_lifecycle_harness` + `xdist_group("lc-cvmfs-cold-demote")`.

Marker-only files (24): test_acc (lc-acc), test_acc_residual (lc-acc-residual), test_arc_guard
(lc-arc-guard), test_chkpoint_recover_export (lc-chkpoint-recover), test_dropin_byte_for_byte
(lc-dropin-front), test_evil_paths (lc-evil-cms-node), test_mu_sidecar_hidden (lc-mu-sidecar),
test_mu_stage_modes (lc-mu-stage-modes), test_mu_webdav_authz (lc-mu-webdav-authz), test_native_sss
(lc-native-sss), test_netfault_stream (lc-netfault-stream), test_pblock_pwd_multiuser (lc-pblock-pwd),
test_phase21_proxy_filter (lc-phase21-proxy-filter), test_pmark (lc-pmark),
test_root_open_existence_oracle (lc-mu-direct-authz), test_s3_verify_write (lc-s3-verify-write),
test_ssi (lc-ssi), test_ssi_wire (lc-ssi-wire), test_tpc_token_exchange_staging
(lc-tpc-token-exchange), test_upstream_auth_multiround (lc-upstream-multiround),
test_webdav_verify_write (lc-webdav-verify-write), test_xrdhttp_guard (lc-xrdhttp-guard),
test_xrootd_conformance (lc-xrootd-conformance).

**Serial run: 198 passed / 21 skipped (env-gated) / 0 fail** (48s). Ledger lint 11 passed; 219
tests collected clean.

#### Wave 7b — ✅ DONE + GREEN 2026-07-22
Part-B non-`lc-`named plain-string singletons + evil-actor targets (17 files, ledger
`LIFECYCLE_SHARED_PORTS` 30282–30319). Ledgered under their **historical descriptive names** (least
churn — the ledger keys off the name, not an `lc-` prefix). Only nginx server binds are ledgered;
each file's client-flood / Python-mock binds stay dynamic (Phase-6 exempt).

Marker-only (9): test_cache_truncation_poison (lc-trunc-cache), test_official_vs_brix_cache_faults
(lc-fault-cache), test_chaos_mixed_auth (lc-chaos, 5 chaos-* instances), test_seccomp_tape_stub
(lc-frmsec), test_client_gaps (lc-cgaps, 2 cgaps-*), test_integrity_matrix (lc-im, 5 im-*),
test_gridftp_engine_event (lc-gridftp-ev, `_EvGateway` factory), test_gridftp_mode_e_truncation
(lc-gridftp-mode-e), test_gridftp_gsi_evil (lc-gridftp-gsi-evil).

`free_port`→ledger conversions (8, own-listen extras re-sourced post-start; the now-dead `_free_port`
def removed where fully unused):
- test_gridftp_s3 (lc-gridftp-s3, S3_PORT 30298), test_pgwrite_staged_sync_gate (lc-staged, S3_PORT
  30306), test_readonly_backend_wire (lc-readonly-wire, S3_PORT 30308), test_root_require_pgwrite
  (lc-require-pgwrite, OFF_PORT 30310): drop `_free_port()` + `extra_ports=` kwarg, source from
  `endpoint.extra_ports[...]` after start; `_free_port` def deleted (was sole user).
- test_tpc_pull_integrity (lc-tpc-harden, PORT_OFF 30313): PORT_OFF sourced post-start; `_free_port`
  def KEPT (mock `_KxrPullFaultProxy.self.listen` still uses it).
- test_backend_put_checksum (lc-putck, S3_PORT 30283 + PORT_OFF 30284): S3_PORT needed PRE-start
  (the `_BodyCorruptProxy` targets it) → read up-front via `lifecycle_ports_for("root-s3-putck")[1]`;
  CORRUPT_PORT stays the proxy's own dynamic bind; `_free_port` def KEPT (proxy uses it).
- test_evil_actor (lc-evil-actor, HTTP_PORT 30315) + test_evil_actor_v2 (lc-evil-actor-v2,
  METRICS/S3/WEBDAV_PORT 30317-19): the **target** nginx server + its own extra listens are now
  ledgered (dropped inline `free_port()` from `extra_ports`, ledger merge supplies, read from
  `endpoint.extra_ports`); the `_free_ports(n)` **client-flood** helper stays (Phase-6 exempt);
  `from settings import … free_port` dropped (now unused); both marked `serial` + xdist_group.

**Serial run: 131 passed / 9 skipped / 4 xfailed / 4 failed** (113s). The 4 failures are BOTH
PRE-EXISTING, NOT the port conversions (verified):
- `test_backend_put_checksum::test_knob_on_body_corruption_is_rejected` — fails **identically with
  dynamic ports** (`socket closed after 0/8 bytes`); a pre-existing bug in the corruption-rejection
  path (the OFF-knob test, same proxy write path, passes).
- `test_integrity_matrix[cluster-cms-root]` ×3 — the `cluster-cms` endpoint on the fleet
  `CLUSTER_REDIR_PORT` (11160, NOT my ledger), the documented Wave-3 **cluster-redir subset-boot
  holder gap** (Phase-3 declaration-graph). My ledgered `im-*` mirror/proxy topologies all pass.

#### Wave 7c — ✅ DONE + GREEN 2026-07-22 (Phase-4 end-state verify sweep)
The end-state verify criterion "no `-{pid}` dynamic registration remains" surfaced a class my
earlier `name="…"`-literal scans missed: harness specs whose name is an **f-string**
(`name=f"lc-ct-{name}"`). A dedicated f-string-prefix scan (`grep 'name=f"'` + arg resolution)
found the residual offenders; the ones with a small, statically-enumerable name-set were ledgered
(30320-30329) and the genuinely-dynamic / root-only / conformance-suite ones confirmed as the
already-documented deferred set:

- `[x]` **lc-ct-mirror_rw** (30320) — `_build_mirror(lifecycle, "mirror_rw")` in
  `test_conformance_topologies.py:346` builds `name=f"lc-ct-{name}"` = `lc-ct-mirror_rw`, the RW
  read-back leg, distinct from the read-only `lc-ct-mirror` (30172). Ledgered; file already carries
  `xdist_group("lc-ct")`.
- `[x]` **brix-verify-{ok,req,neg,be,ckv}** (30321-30325) — `test_cache_verify_require.py`, one
  brix-cache node per verify-mode case. Added `xdist_group("lc-verify-require")` (file was `serial`
  only). Live: **8 passed / 1 timing-flake** — `test_verified_fill_records_checksum_for_xrdckverify`
  (the ckv/xrdckverify sidecar-producer, the heaviest leg) hung `rc=124` under 3-file batch load but
  **passes in isolation (1.29s)**; classic shared-fleet-contention / WSL2-clock-step flake, NOT the
  port work (a fixed port fails nginx *startup*, never a mid-transfer).
- `[x]` **seccomp-{enforce,audit}** (30326-30327) — `test_seccomp_enforce.py`. Dropped the spurious
  `-{L.worker_tag()}` name suffix (the harness `data_root=tmp_path` already isolates workers; the tag
  was copy-pasted from the shared-export conf pattern where it *is* needed) and added
  `uses_lifecycle_harness` + `xdist_group("lc-seccomp-enforce")`. The sibling bogus-mode test stays a
  standalone `render_config_to_path`+`nginx -t` parse (not a registration).
- `[x]` **frmexec-{allow,deny}** (30328-30329) — `test_seccomp_exec_frm.py`, allow_exec on/off on a
  module-scoped harness; added `xdist_group("lc-seccomp-exec-frm")`.

Env-gated (need stock xrootd / built seccomp+frm modules); converted mechanically per the established
pattern. Ledger lint **11 passed** after all 10 entries; touched files collect clean.

**Confirmed NOT offenders / already-deferred (verified this sweep):**
- `lc-interop-off/-our-%s` (`official_interop_lib.py`) — the **slow/x509 conformance suite**, port-
  pinned to its own `worker_port()` band via `LifecycleHarness` with an explicit `port=`. Keeps the
  `-{pid}` *name* but on a **fixed** worker-banded port (not dynamic free_port) — a separate
  fixed-port model, Phase-5/7 cleanup, out of fast-tier Bucket-1 scope.
- `lc-wlcgconf-{grp}` (`wlcg_conformance_fleet.py`) — one instance per **manifest-driven** davs
  config-group (dynamic set); the slow x509-conformance matrix, collection-only from this shell.
  Same deferred class as cms-fast-settle.
- `wdeesc-{name}` (`test_worker_deescalation_root.py`) — `skipif(os.geteuid() != 0)` root-only,
  excluded from the fast tier.
- `brix-deleg-test` (`test_arc_httpg_proxy.py`) — a `jobname=` (ARC-CE job name), not a spec `name=`
  (regex substring false-positive).
- `winread-{tag}` (`test_windowed_read_handle_binding.py`) — a `threading.Thread` name, not a spec.
- `lc-slice-validate-{128m,100k}` — ledgered (30073-30074) and the whole file is `@pytest.mark.skip`
  (slice caching deferred); `lc-mu-guard-*` ledgered (30060-30068) in Wave 3.

#### Wave 7 remaining (deferred, not tractable from this shell)
`[ ]` dedup pair: test_checksum_on_write + test_webdav_put_digest (share template
`nginx_lc_checksum_on_write.conf` but differ in EXTRA_DIRECTIVES → cannot collapse to one spec).
`[ ]` DEFERRED: test_cms_fast_settle + wlcg_conformance_fleet `lc-wlcgconf-{grp}` (dynamic pools);
the 5 CVMFS origins (fuse/docker-gated, unrunnable from this shell — carried from Phase 2);
`lc-interop-*` conformance suite + `wdeesc-*` root-only (fixed-band / root-gated, Phase-5/7).

## Verify each wave
`PYTHONPATH=. python3 -m pytest <wave files> -p no:cacheprovider` (OP-owner runs; subagents
never run pytest). Band+ledger lints: `test_fleet_ports.py` (must stay green after each
ledger edit). Collection clean for the whole set.
