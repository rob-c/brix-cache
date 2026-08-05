"""Fixed-port ledger for Phase-4 lifecycle-subject (mutation) test instances.

Bucket 2 of the fixed-port/registry-only harness refactor: reload/restart/
reopen/kill-worker tests each drive ONE named nginx whose whole point is that the
test mutates it — so it cannot be a shared session singleton.  Each such instance
gets a stable fixed port from the ``lifecycle-exclusive`` band (31000-31999)
here, and the owning test serialises access with ``@pytest.mark.xdist_group()``
keyed on the same name, so the fixed port never has two concurrent drivers.
``LifecycleHarness`` sources the port from this ledger — dropping the old per-pid
dynamic-port suffix — whenever the spec name is present.

These specs are deliberately NOT in ``fleet_specs._all_specs()``: they must never
join the session's default/full boot set (that would race the test that owns the
instance's lifecycle).  The owning test starts and stops its own instance through
the harness, which registers it into the live registry for the test's duration
and unregisters it on teardown.

Every port here MUST fall in the ``lifecycle-exclusive`` band; ``test_fleet_ports``
lints that and that no two entries collide.  That band sits BELOW the OS ephemeral
port floor (32768) on purpose — a fixed listen inside the ephemeral range is a
latent flake (an outbound client socket can transiently steal the number, and
nginx then fails to bind).  See ``fleet_ports.PORT_BANDS``.
"""

from __future__ import annotations

# base spec name -> {"port": <primary listen>, "extra": {<template_key>: <port>}}
#
# The ``extra`` ports are template placeholders the config needs beyond the
# primary listen (e.g. a second stream listen).  They override any dynamic value
# a not-yet-converted call site still passes.
LIFECYCLE_EXCLUSIVE_PORTS: dict[str, dict] = {
    "lc-reload": {"port": 31010, "extra": {"STREAM_PORT": 31011}},
    # WLCG x509-conformance davs:// instance (wlcg_fleet.WlcgInstance).  All four
    # test_wlcg_conformance_*.py files share this one fixed port and one
    # xdist_group("lc-wlcg"): within each file only ONE instance is ever live at a
    # time (start→test→stop, strictly sequential), and the shared group serialises
    # the files so the fixed port never has two concurrent drivers.
    "lc-wlcg": {"port": 31020},
    # FRM prepare/stage queue subject (test_frm_queue.py) — restart()ed mid-test.
    "lc-frm-queue": {"port": 31030},
    # Write-through replay-journal subject (test_xfer_wt_replay.py) — restart()ed.
    "lc-xfer-wt-replay": {"port": 31040},
    # SHM/fork slab-clobber master+workers (test_shm_fork_safety.py) —
    # kill_worker()ed; needs three secondary listens (mgr/http/s3).
    "lc-shmfork": {"port": 31050,
                   "extra": {"MGR_PORT": 31051, "HTTP_PORT": 31052,
                             "S3_PORT": 31053}},
    # Worker-teardown / mid-transfer resume subjects (test_shutdown_resume.py) —
    # three distinct instances the file's tests reload()/kill mid-transfer; all
    # share xdist_group("lc-shutdown-resume") so the file owns the whole band.
    "lc-shutdown-resume-dual": {"port": 31060, "extra": {"HTTP_PORT": 31061}},
    "lc-shutdown-resume-stage": {"port": 31062},
    "lc-shutdown-resume-reaper": {"port": 31063},
    # Registry lifecycle-harness smoke subject (test_server_registry_smoke.py)
    # — reconfigure/reload/reopen/restart on one throwaway instance.
    "lc-smoke": {"port": 31070},
    # Health-check manager instances (test_phase22_health_check.py) — all in one
    # file, serialised under xdist_group("lc-hc").  The cluster/TLS variants each
    # need three secondary listens (cms/ds/metrics).
    # Accept-case parse (test_all_directives_parse): register + `nginx -t` only,
    # but it needs the harness-created prefix (logs/ + export dir) so brix_export's
    # accessibility check passes — hence a fixed registry port, not standalone.
    "lc-hc-parse": {"port": 31080},
    "lc-hc-off": {"port": 31081},
    "lc-hc-on": {"port": 31082},
    "lc-hc-cluster": {"port": 31083,
                      "extra": {"CMS_PORT": 31084, "DS_PORT": 31085,
                                "METRICS_PORT": 31086}},
    "lc-hc-tls-deep": {"port": 31087,
                       "extra": {"CMS_PORT": 31088, "DS_PORT": 31089,
                                 "METRICS_PORT": 31090}},
    "lc-hc-tls-badca": {"port": 31091,
                        "extra": {"CMS_PORT": 31092, "DS_PORT": 31093,
                                  "METRICS_PORT": 31094}},
    "lc-hc-tls-shallow": {"port": 31095,
                          "extra": {"CMS_PORT": 31096, "DS_PORT": 31097,
                                    "METRICS_PORT": 31098}},
    # Dashboard admin-API instances (test_phase23_admin_api.py) — one accept-parse
    # (harness + `nginx -t`) and one running http instance.
    "lc-admin-parse": {"port": 31100},
    "lc-admin-api": {"port": 31101},
    # Rate-limit instances (test_phase25_ratelimit.py) — accept-parse (harness +
    # `nginx -t`) and functional http/stream instances, all single-listen, all in
    # one file serialised under xdist_group("lc-rl").
    "lc-rl-hparse": {"port": 31110},
    "lc-rl-subj-http": {"port": 31111},
    "lc-rl-subj-stream": {"port": 31112},
    "lc-rl-coexist": {"port": 31113},
    "lc-rl-429": {"port": 31114},
    "lc-rl-nodelay": {"port": 31115},
    "lc-rl-bw": {"port": 31116},
    "lc-rl-dash": {"port": 31117},
    "lc-rl-swait": {"port": 31118},
    "lc-rl-sstat": {"port": 31119},
    "lc-rl-cparse": {"port": 31120},
    "lc-rl-conc": {"port": 31121},
    "lc-rl-conc-hi": {"port": 31122},
    "lc-rl-keycache": {"port": 31123},
    "lc-rl-volume": {"port": 31124},
    # phase-92 XrdBwm bandwidth reservation (test_phase92_bwm_reservation.py) —
    # single instance, serialised under xdist_group("lc-bwm").  The reservation
    # engine is a per-worker static registry, so this MUST run on its own worker
    # with worker_processes 1 (one registry) to make the acquire→refuse→release
    # sequence deterministic.
    "lc-bwm-reserve": {"port": 31125},
    # Mirror/shadow instances (test_phase24_mirror.py) — serialised under
    # xdist_group("lc-mir") (+ the file is `serial`: the shadow mock is shared
    # global state).  Three accept-parse (harness + `nginx -t`), five single-listen
    # HTTP primaries that mirror to the fixed mirror-shadow mock, and two stream
    # pairs that bind an embedded shadow + metrics listen in the SAME instance.
    "lc-mir-hparse": {"port": 31130},
    "lc-mir-sparse": {"port": 31131},
    "lc-mir-wparse": {"port": 31132},
    "lc-mir-http": {"port": 31133},
    "lc-mir-dead": {"port": 31134},
    "lc-mir-zero": {"port": 31135},
    "lc-mir-writes": {"port": 31136},
    "lc-mir-writesoff": {"port": 31137},
    "lc-mir-stream-ok": {"port": 31138,
                         "extra": {"SHADOW_PORT": 31139, "METRICS_PORT": 31140}},
    "lc-mir-stream-div": {"port": 31141,
                          "extra": {"SHADOW_PORT": 31142, "METRICS_PORT": 31143}},
    # Phase-24 W3 DATA-write mirror e2e pairs (test_phase24_mirror.py) — each is
    # ONE nginx binding a writable primary root:// listen, an embedded writable
    # shadow root:// listen the primary replays open->write->close to, and a
    # metrics listen.  `-wr` (brix_mirror_writes on) backs both the byte-exact
    # success leg and the non-sequential-abort leg; `-wroff` (writes off) is the
    # production-safety gate (a write must never replay unless opted in).
    "lc-mir-stream-wr": {"port": 31144,
                         "extra": {"SHADOW_PORT": 31145, "METRICS_PORT": 31146}},
    "lc-mir-stream-wroff": {"port": 31147,
                            "extra": {"SHADOW_PORT": 31148, "METRICS_PORT": 31149}},
    "lc-mir-stream-wrabort": {"port": 31153,
                              "extra": {"SHADOW_PORT": 31154, "METRICS_PORT": 31155}},
    "lc-mir-stream-wrcap": {"port": 31156,
                            "extra": {"SHADOW_PORT": 31157, "METRICS_PORT": 31158}},
    # Disconnect-mid-write UAF / heap-ownership drivers (phase-88 audit § 4;
    # exercised under the B-2 ASan lane via ASAN_TEST_CMD2 → -k data_write).
    "lc-mir-stream-wrdrop": {"port": 31174,
                             "extra": {"SHADOW_PORT": 31175, "METRICS_PORT": 31176}},
    "lc-mir-stream-wrcdrop": {"port": 31177,
                              "extra": {"SHADOW_PORT": 31178, "METRICS_PORT": 31179}},
    "lc-mir-stream-wrchurn": {"port": 31187,
                              "extra": {"SHADOW_PORT": 31188, "METRICS_PORT": 31189}},
    # Phase-51 resilience directive parse-only instances (test_phase51_resilience.py)
    # — register + `nginx -t` on the harness (fixed port, never binds).
    "lc-phase51-directives": {"port": 31150},
    "lc-phase51-disable": {"port": 31151},
    # Phase-83 pblock transform-lab instances (test_pblock_lab_xform.py) — single
    # WebDAV listen each; -shift is a lifecycle subject (reconfigure + restart).
    "lc-pblock-xform-crypt": {"port": 31160},
    "lc-pblock-xform-zstd": {"port": 31161},
    "lc-pblock-xform-bad": {"port": 31162},
    "lc-pblock-xform-nokey": {"port": 31163},
    "lc-pblock-xform-shift": {"port": 31164},
    # Durable async backend-op queue subjects (test_backend_async_root.py /
    # test_backend_async_reboot.py) — RM/RMDIR park + bulk flush.  The reboot
    # subject is restart()ed mid-test (kill before flush → replay from journal),
    # so both take exclusive fixed ports; each file serialises its own family with
    # one xdist_group so a fixed port never has two concurrent drivers.
    "lc-backend-async": {"port": 31170},
    "lc-backend-async-reboot": {"port": 31171},
    # HTTP-plane async backend queue (test_backend_async_s3.py /
    # test_backend_async_webdav.py) — DELETE/MOVE park via r->main->count++ until
    # the batch flushes; each family serialises on its own xdist_group.
    "lc-backend-async-s3": {"port": 31172},
    "lc-backend-async-webdav": {"port": 31173},
    # Phase-44 io_uring runtime subject (test_io_uring_runtime.py) — one
    # instance with a stream root:// export (`brix_io_uring on` +
    # `brix_io_uring_admin on`) and an HTTP dashboard listen for the admin
    # kill-switch endpoint.  The suite flips the cross-worker kill switch at
    # runtime (ring quiesce/teardown + re-enable), so the subject is a
    # Bucket-2 mutation and takes exclusive fixed ports.
    "lc-uring": {"port": 31180, "extra": {"HTTP_PORT": 31181}},
    # Phase-44 P44-C client cleartext RECV/SEND multishot tier
    # (test_io_uring_rxtx.py).  One instance with two anon root:// exports over
    # the same data dir: a cleartext listen the rxtx ring engages on, and a TLS
    # (roots://) listen the rxtx path MUST decline (ac->ssl != NULL falls back
    # to SSL_*).  The C client harness (aio_smoke) is driven at both under
    # XRDC_IO_URING_LOOP=rxtx; the instance itself is never mutated but takes a
    # fixed exclusive port because the harness serialises the C driver on it.
    "lc-uring-rxtx": {"port": 31182, "extra": {"TLS_PORT": 31183}},
    # phase-33 P0 A/B throughput gate (test_perf_ab_gate.py): each server boots
    # fresh with a per-test data file and is torn down — mutation subjects, so
    # the exclusive band.  One xdist_group serialises the three (self-test +
    # baseline/tuned A/B pair).
    "lc-perf-ab-self": {"port": 31184},
    "lc-perf-ab-base": {"port": 31185},
    "lc-perf-ab-tuned": {"port": 31186},
    # phase-33 P1 pipeline-depth correctness gate (test_pipeline_depth.py); one
    # exclusive listen per depth exercised, serialised by xdist_group.
    "lc-pipeline-depth-1": {"port": 31191},
    "lc-pipeline-depth-32": {"port": 31192},
    # phase-33 P5 userspace-TLS A/B harness self-test (test_perf_ab_gate.py).
    "lc-perf-ab-tls": {"port": 31193},
    # CMS 4-tier cluster (test_cms_tier_topology.py): ONE nginx master hosting
    # six cmsd node identities as separate stream server blocks, each needing its
    # own listen.  The primary port is the root manager; the other five are
    # template placeholders the config addresses by node name.  The whole tree is
    # a mutation subject (the test reads the settle sequence out of its error
    # log), so it takes an exclusive block serialised by xdist_group("lc-cms-tier").
    "lc-cms-tier": {"port": 31200, "extra": {"PORT_SUB1": 31201,
                                             "PORT_LEAFA": 31202,
                                             "PORT_LEAFB": 31203,
                                             "PORT_SUB2": 31204,
                                             "PORT_LEAFC": 31205}},
    # Paged-I/O + readv against the NON-posix storage drivers
    # (test_pgio_nonposix.py): one pblock:// export and one block:<device>
    # export.  Both are mutation subjects — the tests pgwrite into them and one
    # asserts the device file did not grow — so each takes an exclusive port,
    # serialised by xdist_group("lc-pgio-nonposix").
    "lc-pgio-pblock": {"port": 31210},
    "lc-pgio-block": {"port": 31211},
    # Cross-device (EXDEV) staged commit over the WebDAV plane
    # (test_stage_cross_device_commit.py): one HTTP export whose
    # `brix_webdav_stage_dir` sits on tmpfs, so every PUT commit has to take the
    # copy+fsync+rename fallback instead of rename(2).  The tests PUT, overwrite
    # and DELETE in the export and read the stage dir between requests, so it is
    # a mutation subject on an exclusive port, serialised by
    # xdist_group("lc-stage-xdev").
    "lc-stage-xdev": {"port": 31212},
    # Backend capability negatives against the REAL sd_http driver struct
    # (test_backend_caps_negative.py): a WebDAV origin plus two root:// exports
    # backed by it — one with the default write-stage tier, one with
    # `brix_stage off` — so an xattr-less backend is reached both through a
    # composed tier (leaf-dispatch ENOSYS) and directly (ENOTSUP).  The tests
    # write through the origin, so the whole instance is a mutation subject on
    # exclusive ports, serialised by xdist_group("lc-caps-http").
    "lc-caps-http": {"port": 31213,
                     "extra": {"ORIGIN_PORT": 31214,
                               "STAGE_OFF_PORT": 31215}},
    # Nested S3 gateway (test_s3_nested_gateway.py): an S3 front whose storage
    # backend is a co-hosted s3:// origin, i.e. `brix_s3 on` on both ends of the
    # same transfer.  The two blocks carry DIFFERENT SigV4 keys on purpose — that
    # is what pins the per-secret signing-key cache — and the tests PUT/DELETE
    # through the front, so both ports are mutation subjects held exclusively and
    # serialised by xdist_group("lc-s3-nested").
    "lc-s3-nested": {"port": 31216,
                     "extra": {"ORIGIN_PORT": 31217}},
    # Namespace MUTATIONS through a storage driver (test_ns_mutation_gateways.py):
    # one plain-POSIX root:// export as the control, plus two root:// gateways
    # over co-hosted origins — one `http://` (sd_http) and one `root://`
    # (sd_xroot) — so mkdir/rm/rmdir/mv/dirlist answers can be compared against
    # the POSIX truth on the same operations.  Every test creates and destroys
    # namespace entries on all four ports, so the instance is a mutation subject
    # held exclusively and serialised by xdist_group("lc-ns-gateways").
    # worker_processes 2: both gateways connect back to origins in this same
    # nginx (see the template header).
    "lc-ns-gateways": {"port": 31218,
                       "extra": {"HTTP_ORIGIN_PORT": 31219,
                                 "GW_HTTP_PORT": 31220,
                                 "GW_XROOT_PORT": 31221}},
    # TLS x send-path behavioural matrix (test_tls_sendfile_matrix.py): the same
    # objects served over {cleartext, TLS} x {posix, pblock}, where pblock is the
    # backend that actually takes BOTH branches of the INVARIANT-2 fork depending
    # on the requested range.  The tests PUT their own fixtures into both exports,
    # so the instance is a mutation subject on an exclusive block, serialised by
    # xdist_group("lc-tls-sendfile").
    "lc-tls-sendfile": {"port": 31222,
                        "extra": {"TLS_PORT": 31223,
                                  "PB_PORT": 31224,
                                  "PB_TLS_PORT": 31225}},
    # Store-then-evict cache passthrough beyond the WebDAV plane
    # (test_cache_passthrough_planes.py): a WebDAV origin plus S3, CVMFS and
    # root:// fronts over it, each with its own cache store, in passthrough-on
    # and passthrough-off pairs.  Every test fills and evicts cache entries, so
    # the instance is a mutation subject on an exclusive block, serialised by
    # xdist_group("lc-cache-passthrough").
    "lc-cache-passthrough": {"port": 31226,
                             "extra": {"S3_PORT": 31228,
                                       "S3_OFF_PORT": 31229,
                                       "CV_PORT": 31230,
                                       "CV_OFF_PORT": 31231,
                                       "ROOT_PORT": 31232}},

    # S3 REST front over a native root:// origin in the same nginx — the write
    # half of the S3 x xroot cell. {PORT} is the origin (stream) so the
    # registry's readiness probe watches the listener the front depends on.
    "lc-s3-xroot": {"port": 31233,
                    "extra": {"S3_PORT": 31234}},
}

# Non-binding placeholder port for standalone `nginx_t` parse tests (nginx -t
# never binds a listen) that render a config needing a {PORT} value.  Kept in the
# lifecycle-exclusive band but deliberately NOT a registered listener (well clear
# of the allocated ledger ports above).
PARSE_PLACEHOLDER_PORT = 31999


# base spec name -> {"port": <primary listen>, "extra": {<template_key>: <port>}}
#
# Phase-4 Bucket 1: the bulk of remaining lifecycle-harness consumers are
# *idempotent* read-only instances (no reload/restart/kill — just start, drive,
# stop) that each still need a dedicated fixed listen because the test bakes a
# per-test data dir / forged fixture content into the config, so they cannot
# collapse into one shared session singleton.  Each named instance draws a fixed
# port from the ``lifecycle-shared`` band (30000-30999); the owning file
# serialises the family with one ``@pytest.mark.xdist_group(<family>)`` so a
# fixed port never has two concurrent drivers.  Register-only (`nginx -t`)
# instances still take a key but never bind it.  See
# ``docs/refactor/phase-4-bucket-1-inventory.md`` for the full work-list.
LIFECYCLE_SHARED_PORTS: dict[str, dict] = {
    # Wave 1 — trivial single-instance root clients/tools (nginx_lc_stream_posix_
    # anon.conf and kin); one instance, no extra listens, serialised per file.
    "lc-xrdcp-bulk": {"port": 30010},
    "lc-xrd-doctor-login": {"port": 30011},
    "lc-xrd-frontend": {"port": 30012},
    "lc-xrdfs-tools": {"port": 30013},
    "lc-xrdrc-alias": {"port": 30014},
    "lc-native-client-diag": {"port": 30015},
    "lc-xrd-busybox": {"port": 30016},
    "lc-xrddiag-capture": {"port": 30017},
    "lc-xrddiag-probe": {"port": 30018},
    "lc-xrdmapc": {"port": 30019},
    # Wave 2 — single-instance webdav/http/root/s3 auth + client-tool servers;
    # one instance per file (serialised per-file), no extra listens unless noted.
    "lc-krb5-auth": {"port": 30020},
    "lc-native-krb5": {"port": 30021},
    "lc-native-krb5-deleg": {"port": 30457},  # inbound TGT-delegation e2e (test_krb5_delegation_e2e.py)
    "lc-krb5-cache-origin": {"port": 30458},  # delegated cache->origin krb5 e2e (test_krb5_cache_origin_e2e.py)
    "lc-macaroon-negative": {"port": 30022},
    "lc-macaroon-request": {"port": 30023},
    "lc-token-aud-array": {"port": 30024},
    "lc-token-es256": {"port": 30025},
    "lc-pwd-auth": {"port": 30026},
    "lc-readv-seg16m": {"port": 30027},
    "lc-readv-var1m": {"port": 30028},
    "lc-s3-auth-oracle": {"port": 30029},
    "lc-s3-list-cache": {"port": 30030},
    "lc-srr": {"port": 30031},
    "lc-frm-async": {"port": 30032},
    "lc-frm-control-locality": {"port": 30033},
    "lc-resume-sweep": {"port": 30034},
    "lc-xfer-wt-journal": {"port": 30035},
    "lc-zip-scratch": {"port": 30036},
    "lc-zip-inplace": {"port": 30037},
    "lc-xrddiag-watch": {"port": 30038},
    # xrddiag remote-doctor — five single-listen instances across the file's
    # fixtures (only one live per test); all serialised under xdist_group
    # ("lc-rdoctor").  lc-rdoctor-anon additionally binds a ::1 listen on the
    # SAME primary port (the v6/v4-asymmetry probe) — the test reads the primary
    # from this ledger so the two listens share the fixed number.
    "lc-rdoctor-anon": {"port": 30039},
    "lc-rdoctor-rw": {"port": 30040},
    "lc-rdoctor-empty": {"port": 30041},
    "lc-rdoctor-sss": {"port": 30042},
    "lc-rdoctor-token": {"port": 30043},
    # phase-93 config-audit (test_config_audit.py) — one anon export, serialised
    # under xdist_group("lc-cfgaudit").
    "lc-cfgaudit-anon": {"port": 30459},
    # phase-93 tpc-egress self-test (test_xrddiag_tpc_egress.py) — two
    # TPC-capable gateways (default SSRF policy vs allow_local=on), one live per
    # test, serialised under xdist_group("lc-tpcegress").
    "lc-tpceg-default": {"port": 30460},
    "lc-tpceg-local": {"port": 30461},
    # xrddiag compare --davs — ONE nginx, root primary + two WebDAV planes
    # (match / mismatch) as owned extra listens.
    "lc-xrddiag-compare-davs": {"port": 30044,
                                "extra": {"OK_PORT": 30045, "BAD_PORT": 30046,
                                          "TLS_PORT": 30449}},
    # xrddiag multiproto — ONE nginx serving root primary + http/https/s3 planes
    # as owned extra listens.
    "lc-xrddiag-multiproto": {"port": 30047,
                              "extra": {"HTTP_PORT": 30048, "HTTPS_PORT": 30049,
                                        "S3_PORT": 30050}},
    # Wave 3 — parse/register-only families.  Most instances here NEVER bind a
    # listener: they are `register` + `nginx -t` accept-case (PARSE-ONLY) or
    # reject-case (REJECT-PARSE) checks.  They still take a unique fixed port so
    # LifecycleHarness.register uses the stable-name path (no `-{pid}` suffix, no
    # free_port fallback in endpoint_for); the port is simply never bound.
    # LIVE-BIND instances (marked) actually serve on their fixed port.
    # test_upstream_tls_verify.py (group lc-a1) — all PARSE/REJECT, never bind.
    "lc-a1-redir-ca": {"port": 30051},
    "lc-a1-proxy-ca": {"port": 30052},
    "lc-a1-redir-noca": {"port": 30053},
    "lc-a1-proxy-noca": {"port": 30054},
    "lc-a1-redir-off": {"port": 30055},
    "lc-a1-proxy-off": {"port": 30056},
    # test_ocsp_require_nonce.py (group lc-a6-nonce) — all PARSE/REJECT.
    "lc-a6-nonce-on": {"port": 30057},
    "lc-a6-nonce-off": {"port": 30058},
    "lc-a6-nonce-bad": {"port": 30059},
    # test_mu_sidecar_config_guard.py (group lc-mu-guard) — all PARSE/REJECT.
    "lc-mu-guard-stream-stage-nested": {"port": 30060},
    "lc-mu-guard-stream-stage-outside": {"port": 30061},
    "lc-mu-guard-stream-state-nested": {"port": 30062},
    "lc-mu-guard-stream-state-outside": {"port": 30063},
    "lc-mu-guard-webdav-cacheroot-nested": {"port": 30064},
    "lc-mu-guard-webdav-cacheroot-outside": {"port": 30065},
    "lc-mu-guard-webdav-stage-nested": {"port": 30066},
    "lc-mu-guard-s3-cacheroot-nested": {"port": 30067},
    "lc-mu-guard-s3-cacheroot-outside": {"port": 30068},
    # test_stage_default_gateway.py (group stage-default) — all PARSE/REJECT;
    # names deliberately keep their existing unprefixed form.
    "stage-default-on": {"port": 30069},
    "stage-default-off": {"port": 30070},
    "stage-on-no-store": {"port": 30071},
    "stage-default-ro": {"port": 30072},
    # test_slice_cache.py (group lc-slice-cache) — 2 PARSE/REJECT validate + 2
    # LIVE-BIND (origin+node started together; node reads origin.port as a peer).
    "lc-slice-validate-128m": {"port": 30073},
    "lc-slice-validate-100k": {"port": 30074},
    "lc-slice-cache-origin": {"port": 30075},   # LIVE-BIND
    "lc-slice-cache-node": {"port": 30076},      # LIVE-BIND
    # test_client_certificate_folder.py (group lc-certfolder) — 2 LIVE + 3 REJECT.
    "lc-certfolder-ok": {"port": 30077},         # LIVE-BIND
    "lc-certfolder-nomatch": {"port": 30078},
    "lc-certfolder-missing": {"port": 30079},
    "lc-certfolder-misorder": {"port": 30080},
    "lc-certfolder-deny": {"port": 30081},       # LIVE-BIND
    # test_credential_dir_default.py (group lc-cred-dir) — 1 LIVE + 3 PARSE.
    "lc-cred-dir-default": {"port": 30082},      # LIVE-BIND
    "lc-cred-dir-uncreatable": {"port": 30083},
    "lc-cred-dir-lax": {"port": 30084},
    "lc-cred-dir-optout": {"port": 30085},
    # test_delegated_cred.py (group lc-delegcred) — all LIVE-BIND (badpem+token
    # may be live together in one test).
    "lc-delegcred-ok": {"port": 30086},          # LIVE-BIND
    "lc-delegcred-badpem": {"port": 30087},      # LIVE-BIND
    "lc-delegcred-token": {"port": 30088},       # LIVE-BIND
    "lc-delegcred-deny": {"port": 30089},        # LIVE-BIND
    # test_proxy_ssl_capath.py (group lc-proxycapath) — 2 LIVE + 3 REJECT.  The
    # default template binds a BACKEND_PORT https backend listen in the SAME
    # instance (own listener) — sourced here so the file's local _free_port()
    # is retired; the REJECT specs take one too (rendered but never bound).
    "lc-proxycapath-ok": {"port": 30090, "extra": {"BACKEND_PORT": 30091}},   # LIVE-BIND
    "lc-proxycapath-missing": {"port": 30092, "extra": {"BACKEND_PORT": 30093}},
    "lc-proxycapath-empty": {"port": 30094, "extra": {"BACKEND_PORT": 30095}},
    "lc-proxycapath-noproxy": {"port": 30096},   # different template, no backend
    "lc-proxycapath-deny": {"port": 30097, "extra": {"BACKEND_PORT": 30098}},  # LIVE-BIND
    # test_ssl_client_capath.py (group lc-capath) — 2 LIVE + 2 REJECT.
    "lc-capath-ok": {"port": 30099},             # LIVE-BIND
    "lc-capath-missing": {"port": 30100},
    "lc-capath-file": {"port": 30101},
    "lc-capath-deny": {"port": 30102},           # LIVE-BIND
    # test_webdav_lock_startup_sweep.py (group lc-sweep) — 2 LIVE + 1 PARSE.
    "lc-sweep-on": {"port": 30103},              # LIVE-BIND
    "lc-sweep-off": {"port": 30104},             # LIVE-BIND
    "lc-sweep-cfgtest": {"port": 30105},
    # test_ssi_config.py (group lc-ssi-cfg) — 3 LIVE + 1 REJECT (bogus fails
    # nginx -t during start, never binds).
    "lc-ssi-cfg-default": {"port": 30106},       # LIVE-BIND
    "lc-ssi-cfg-cta": {"port": 30107},           # LIVE-BIND
    "lc-ssi-cfg-bogus": {"port": 30108},
    "lc-ssi-cfg-inflight": {"port": 30109},      # LIVE-BIND

    # -- Wave 4: multi-listen single instances (one named instance binds a
    #    primary listen PLUS one or more embedded extra listens).  The extra
    #    listens are supplied here as `extra` and merged into the spec at
    #    register time (ledger wins), so the file drops every free_port()/local
    #    _free_port() call and reads the port back from ep.extra_ports[...].
    "lc-crc64": {"port": 30110, "extra": {"S3_PORT": 30111, "WEBDAV_PORT": 30112}},
    "lc-frm-phase1-http": {"port": 30113,
                           "extra": {"STREAM_PORT": 30114, "S3_PORT": 30115,
                                     "WEBDAV_PORT": 30116}},
    "lc-frm-phase4": {"port": 30117, "extra": {"METRICS_PORT": 30118}},
    "lc-frm-p4eng-f3": {"port": 30119},          # primary only, no extra listen
    "lc-frm-p4eng-f5": {"port": 30120, "extra": {"METRICS_PORT": 30121}},
    "lc-frm-owner": {"port": 30122, "extra": {"HTTP_PORT": 30123}},
    "lc-frm-posix-stat": {"port": 30124},        # primary only
    "lc-frm-recall": {"port": 30125},            # primary only
    "lc-cache-reap-metrics": {"port": 30126, "extra": {"METRICS_PORT": 30127}},
    "lc-ssi-metrics": {"port": 30128, "extra": {"METRICS_PORT": 30129}},
    "lc-tpc-gsi-deleg-metrics": {"port": 30422, "extra": {"METRICS_PORT": 30423}},
    "lc-tape-rest": {"port": 30130, "extra": {"STREAM_PORT": 30131}},
    "lc-put-content-encoding": {"port": 30132, "extra": {"S3_PORT": 30133}},
    # WebDAV front (primary {PORT}) over a co-hosted posix-backed s3:// origin
    # ({ORIGIN_PORT}); the front's PUT writer is a driver-backed object session
    # with no kernel fd — exercises the Content-Encoding decode-to-writer path.
    "lc-ce-driver-s3": {"port": 30445, "extra": {"ORIGIN_PORT": 30447}},
    # WebDAV front (primary {PORT}) over a co-hosted posix-backed s3:// origin
    # ({ORIGIN_PORT}); exercises the s3:// namespace-mutation slots end-to-end
    # (MKCOL->mkdir marker, nested PUT->parent-prefix marker, MOVE->rename
    # copy+delete, DELETE collection->rmtree+rmdir marker) — #4-rest.
    "lc-s3-driver-ns": {"port": 30446, "extra": {"ORIGIN_PORT": 30448}},
    "lc-scan-dashboard": {"port": 30134, "extra": {"OFF_PORT": 30135}},
    "lc-stage-hydration": {"port": 30136, "extra": {"ORIGIN_PORT": 30137}},
    "lc-client-web-transfer": {"port": 30138, "extra": {"S3_PORT": 30139}},
    "lc-guard-endpoints": {"port": 30140,
                           "extra": {"DAV_PORT": 30141, "S3_PORT": 30142,
                                     "OPS_PORT": 30143, "XRD_PORT": 30144,
                                     "CMS_PORT": 30145}},
    "lc-cms-blfile": {"port": 30146, "extra": {"HTTP_PORT": 30147}},
    "lc-dashboard-config-anon": {"port": 30148, "extra": {"ROOT_PORT": 30149}},
    "lc-dashboard-files": {"port": 30150, "extra": {"OFF_PORT": 30151}},
    "lc-storage-backend-panel": {"port": 30152},  # primary only

    # -- Wave 5: multi-instance-simultaneous + peer refs.  Producers are listed
    #    BEFORE their consumers; a consumer instance that dials a peer reads the
    #    peer's fixed port from the started producer endpoint (peer.port or
    #    producer_ep.extra_ports[...]), never a stale local free_port var.  Mock
    #    Python-peer bind ports (nginx dials an in-process manager mock) and the
    #    native-xrootd source ports remain on free_port (Phase-5 / mock scope).
    # cns: manager BINDS the CMS extra port; data DIALS it.
    "lc-cns-manager": {"port": 30153, "extra": {"CMS_PORT": 30154}},
    "lc-cns-data": {"port": 30155},
    # phase-58: CNS data server with brix_backend_async on — the durable-queue
    # RM/RMDIR path emits its late CNS event from the queue waker (baq_root_done).
    "lc-cns-data-async": {"port": 30427},
    # gohep: redirector references ds.port.
    "lc-gohep-ds": {"port": 30156},
    "lc-gohep-anon": {"port": 30157},
    "lc-gohep-redirector": {"port": 30158},
    # stream-guard: both relays reference origin.port.
    "lc-stream-guard-origin": {"port": 30159},
    "lc-stream-guard-guarded": {"port": 30160},
    "lc-stream-guard-unguarded": {"port": 30161},
    # proxy-large-read: proxy references backend.port.
    "lc-proxy-large-read-be": {"port": 30162},
    "lc-proxy-large-read-px": {"port": 30163},
    # mu-cache: node references origin.port.
    "lc-mu-cache-origin": {"port": 30164},
    "lc-mu-cache-node": {"port": 30165},
    # conformance-topologies (serial): mesh2 refs mesh1.port; cluster redir BINDS
    # CMS extra, ds DIALS it.
    "lc-ct-proxy": {"port": 30166},
    "lc-ct-mesh1": {"port": 30167},
    "lc-ct-mesh2": {"port": 30168},
    "lc-ct-clu-redir": {"port": 30169, "extra": {"CMS_PORT": 30170}},
    "lc-ct-clu-ds": {"port": 30171},
    "lc-ct-mirror": {"port": 30172},
    # metadata-stress: one instance live per test.  The mesh redirector
    # advertises a data-node TARGET that the redirector answers itself, so the
    # target is never bound — a fixed unused DS_PORT stands in (was free_port).
    "lc-metadata-stress-stream": {"port": 30173},
    "lc-metadata-stress-http": {"port": 30174},
    "lc-metadata-stress-mesh": {"port": 30175, "extra": {"DS_PORT": 30395}},
    # host-auth: allow vs deny (one live at a time).
    "lc-host-ok": {"port": 30176},
    "lc-host-deny": {"port": 30177},
    # opaque-strict: one live at a time.
    "lc-opq-valid": {"port": 30178},
    "lc-opq-type": {"port": 30179},
    "lc-opq-unknown": {"port": 30180},
    "lc-opq-off": {"port": 30181},
    # phase27 memsafety readv.
    "lc-memsafety-readv-valid": {"port": 30182},
    "lc-memsafety-readv-oversized": {"port": 30183},
    # min-sec-level live instances (parse-reject test keeps free_ports + nginx_t).
    "lc-minsec-cleartext": {"port": 30184},
    "lc-minsec-tls": {"port": 30185},
    "lc-minsec-intense": {"port": 30186},
    # negcache-backoff live instances (parse-reject test keeps free_ports).
    "lc-negcache-harvest": {"port": 30187},
    "lc-negcache-isolation": {"port": 30188},
    # TPC dests/pairs (client-driven tpc.src; native-xrootd source stays free_port).
    "lc-tpc-async-dest": {"port": 30189},
    "lc-tpc-delegation-dest": {"port": 30190},
    "lc-tpc-gsi-outbound-dest": {"port": 30191},
    "lc-tpc-gsi-nginx-source": {"port": 30192},
    "lc-tpc-gsi-nginx-dest": {"port": 30193},
    "lc-tpc-tls-source": {"port": 30194},
    "lc-tpc-tls-dest": {"port": 30195},
    # native GSI interop (native-xrootd source is a fixed constant 21094).
    "lc-nginx-gsi": {"port": 30196},
    "lc-nginx-gsi-signed": {"port": 30197},
    # CMS managers that BIND their own CMS/multi login listens (mock nodes dial).
    "lc-cms-affinity": {"port": 30198, "extra": {"MULTI_PORT": 30199,
                                                 "CMS_PORT": 30200}},
    "lc-cms-fanout": {"port": 30201, "extra": {"CMS_PORT": 30202}},
    "lc-cms-locate-have": {"port": 30203, "extra": {"CMS_PORT": 30204}},
    # CMS managers where nginx DIALS an in-process Python mock peer (mock bind
    # port stays free_port; only the nginx primary listen is ledgered).
    "lc-cms-prep-client": {"port": 30205},
    "lc-cms-prep-noengine": {"port": 30206},
    "lc-cms-resilience-server": {"port": 30207},
    "lc-cms-resilience-node": {"port": 30208},
    "lc-cms-state-client": {"port": 30209},
    "lc-cms-state-server": {"port": 30210},
    "lc-cms-wire-node": {"port": 30211},
    "lc-cms-wire-server": {"port": 30212},
    # Phase-61 W7 role/relay stacks (same dial-out-to-mock-peer shape).
    "lc-cms-wire-mgr-node": {"port": 30412},
    "lc-cms-wire-super": {"port": 30413},
    "lc-cms-wire-super-norelay": {"port": 30414},
    "lc-cms-wire-srv-node": {"port": 30415},
    # Phase-61 W7 hostile-network conformance (test_cms_hostile_conformance.py):
    # dedicated instances so adversarial framing never contends on the ports the
    # well-behaved conformance suite uses.
    "lc-cms-hostile-server": {"port": 30416},
    "lc-cms-hostile-node": {"port": 30417},
    "lc-cms-hostile-super": {"port": 30418},
    "lc-cms-hostile-hardened": {"port": 30419},
    # Class-scoped opcode/size/path FUZZ SWEEPS (parametrized, hundreds of cases)
    # — one shared instance per sweep class so the matrix does not pay an nginx
    # boot per parametrized case.
    "lc-cms-hostile-sweep-srv": {"port": 30420},
    "lc-cms-hostile-sweep-node": {"port": 30421},
    # -- Wave 6: pblock-lab family (test_pblock_lab_*.py).  Every instance is
    # built by pblock_live.pblock_lab_spec(name, tail, workers=) — no port in
    # template_values, so the listen is owned entirely by this ledger.  Only ONE
    # instance is ever live at a time per file (sequential `with` blocks), and
    # each file serialises onto one worker via its own xdist_group("lc-pblock-*"),
    # so no fixed port ever has two concurrent drivers.  (xform already ledgered
    # in Bucket 2 above at 31160-31164.)  All read-only/idempotent except snapshot
    # + versioning, which stop→start_registered toggle the same registered port.
    "lc-pblock-an-ok": {"port": 30213},
    "lc-pblock-an-stale": {"port": 30214},
    "lc-pblock-an-sec": {"port": 30215},
    "lc-pblock-an-off": {"port": 30216},
    "lc-pblock-audit": {"port": 30217},
    "lc-pblock-audit-be": {"port": 30218},
    "lc-pblock-audit-attr": {"port": 30219},
    "lc-pblock-crash": {"port": 30220},
    "lc-pblock-crash-off": {"port": 30221},
    "lc-pblock-csi-ok": {"port": 30222},
    "lc-pblock-csi-flip": {"port": 30223},
    "lc-pblock-csi-tag": {"port": 30224},
    "lc-pblock-dd-ok": {"port": 30225},
    "lc-pblock-dd-cow": {"port": 30226},
    "lc-pblock-dd-sec": {"port": 30227},
    "lc-pblock-dd-off": {"port": 30228},
    "lc-pblock-lk-ok": {"port": 30229},
    "lc-pblock-lk-exp": {"port": 30230},
    "lc-pblock-lk-sec": {"port": 30231},
    "lc-pblock-lk-off": {"port": 30232},
    "lc-pblock-nl-ok": {"port": 30233},
    "lc-pblock-nl-fail": {"port": 30234},
    "lc-pblock-nl-sec": {"port": 30235},
    "lc-pblock-nl-off": {"port": 30236},
    "lc-pblock-quota-ok": {"port": 30237},
    "lc-pblock-quota-full": {"port": 30238},
    "lc-pblock-quota-uid": {"port": 30239},
    "lc-pblock-snap-ok": {"port": 30240},
    "lc-pblock-snap-sec": {"port": 30241},
    "lc-pblock-snap-off": {"port": 30242},
    "lc-pblock-ver-ok": {"port": 30243},
    "lc-pblock-ver-sec": {"port": 30244},
    "lc-pblock-ver-off": {"port": 30245},
    # -- Wave 7a: remaining singleton / small-cluster lifecycle files.  Each file
    # serialises onto one worker via its own xdist_group(<lc-name>).  Peer refs in
    # this batch are ALL Python mocks / registry_server stubs (guard-stub,
    # introspect-idp, StubOrigin, mock CMS, firefly sink) — those keep their own
    # port; only the nginx primary(+own extras) is ledgered here.
    "lc-acc-stream": {"port": 30246},
    "lc-acc-http": {"port": 30247},
    "lc-acc-residual-stream": {"port": 30248},
    "lc-acc-residual-webdav": {"port": 30249},
    "lc-arc-guard": {"port": 30250},
    "lc-chkpoint-recover": {"port": 30251},
    "lc-cvmfs-cold-demote": {"port": 30252},
    "lc-t4-delegation": {"port": 30253, "extra": {"VERIFY_PORT": 30254}},
    "lc-dropin-front": {"port": 30255},
    "lc-evil-cms-node": {"port": 30256},
    "lc-mu-sidecar-webdav": {"port": 30257},
    "lc-mu-sidecar-root": {"port": 30258},
    "lc-mu-stage-webdav": {"port": 30259},
    "lc-mu-webdav-authz": {"port": 30260},
    "lc-native-sss": {"port": 30261},
    "lc-netfault-stream": {"port": 30262},
    "lc-socketbuf-stream": {"port": 30442},
    "lc-pblock-pwd": {"port": 30263},
    "lc-phase20-ratelimit": {"port": 30264, "extra": {"METRICS_PORT": 30265}},
    "lc-xrdhttp-filter": {"port": 30266},
    "lc-introspect": {"port": 30267},
    "lc-pmark": {"port": 30268},
    "lc-pwd-multiproto": {"port": 30269,
                          "extra": {"HTTP_PORT": 30270, "HTTPS_PORT": 30271}},
    "lc-mu-direct-authz": {"port": 30272},
    "lc-s3-verify-write": {"port": 30273},
    "lc-ssi-on": {"port": 30274},
    "lc-ssi-off": {"port": 30275},
    "lc-ssi-wire": {"port": 30276},
    "lc-tpc-token-exchange": {"port": 30277},
    "lc-upstream-multiround": {"port": 30278},
    "lc-webdav-verify-write": {"port": 30279},
    "lc-xrdhttp-guard": {"port": 30280},
    "lc-xrootd-conformance": {"port": 30281},
    # ---- Wave 7b: Part-B non-lc-named singletons + evil-actor targets ----
    # These keep their historical descriptive names (least churn); the ledger
    # keys off the name, not an lc- prefix.  Only the nginx server binds are
    # ledgered here.
    #
    # § Phase-6 client-flood / mock-bind exemption.  A handful of hostile-client
    # tests use OS-ephemeral ports that are DELIBERATELY not fixed and are NOT
    # goal-1 ("every *server* binds a fixed port") violations, because none is a
    # registry server:
    #   * client-side connection floods — test_evil_actor{,_v2,_v3}.py open many
    #     `socket.create_connection((HOST, <ledgered port>))` client sockets to
    #     torture disconnect-mid-AIO / teardown-reuse paths.  The FLOODED targets
    #     ARE ledgered (evil-actor 30314 / -v2 30316 / -v3 30357); only the CLIENT
    #     source ports are kernel-assigned ephemerals (never bound), so there is
    #     no fixed port to assign.  All three files are `serial` + one
    #     xdist_group so the flood never starves a shared singleton's accepts.
    #   * in-process Python mocks the brix node DIALS — test_evil_paths.py binds
    #     an ephemeral mock CMS manager the ledgered `lc-evil-cms-node` (30256)
    #     connects out to; `_BodyCorruptProxy` (put_checksum) is the same shape.
    #     The mock is a client-of-brix's-perspective peer, not a fleet server.
    "root-s3-putck": {"port": 30282, "extra": {"S3_PORT": 30283, "PORT_OFF": 30284}},
    "brix-trunc-cache": {"port": 30285},
    "chaos-gsi-origin": {"port": 30286},
    "chaos-sss-origin": {"port": 30287},
    "chaos-cache-gsi": {"port": 30288},
    "chaos-proxy-sss": {"port": 30289},
    "chaos-proxy-sss-bad": {"port": 30290},
    "cgaps-rw-root": {"port": 30291},
    "cgaps-srr": {"port": 30292},
    "gridftp-plain": {"port": 30424},
    # GridFTP verb/lifecycle gateways (test_gridftp_*.py) — each a cleartext
    # gsiftp control listen the file's `serial` tests drive with ftplib
    # (start→drive→stop, one instance live at a time per file).  The passive
    # DATA-channel ports are runtime-negotiated from a per-test _contiguous_free_
    # range window, not an nginx listen, so only the control listen is ledgered.
    "gridftp-pblock": {"port": 30431},
    "gridftp-evil": {"port": 30432},
    "gridftp-mode-e-event": {"port": 30433},
    "gridftp-mode-e-evil": {"port": 30434},
    "gridftp-allo-lenient": {"port": 30435},
    "gridftp-allo-require": {"port": 30436},
    "gridftp-verify-pblock": {"port": 30437},
    "gridftp-verify-posix": {"port": 30438},
    "gridftp-vo": {"port": 30450},
    "gridftp-vo-gsi": {"port": 30451},
    # test_xrdcp_gsiftp.py — gateways for the NATIVE brix xrdcp gsiftp client
    # (client/lib/protocols/ftp): one cleartext ftp:// control listen and two GSI
    # gateways (trusting / empty trust store for the security negative).
    "xrdcp-gsiftp-plain": {"port": 30452},
    "xrdcp-gsiftp-gsi": {"port": 30453},
    "xrdcp-gsiftp-untrusting": {"port": 30454},
    "gridftp-pasv-range": {"port": 30439},
    "gridftp-pasv-xfer": {"port": 30440},
    "gridftp-pasv-exhaust": {"port": 30441},
    "gridftp-plain-ev": {"port": 30293},
    "gridftp-plain-ev-ro": {"port": 30294},
    "gridftp-mode-e-truncation": {"port": 30295},
    "gridftp-gsi-evil": {"port": 30296},
    "gridftp-s3": {"port": 30297, "extra": {"S3_PORT": 30298}},
    # test_gridftp_translation.py — one posix export fronted by BOTH a gsiftp
    # gateway (PORT) and a WebDAV endpoint (DAV_PORT); proves cross-protocol
    # byte-identity through the shared brix_vfs_* seam.
    "gridftp-xproto": {"port": 30443, "extra": {"DAV_PORT": 30444}},
    "im-mirror-sink": {"port": 30299},
    "im-mirror-front": {"port": 30300},
    "im-proxy-storage": {"port": 30301},
    "im-proxy-hop1": {"port": 30302},
    "im-proxy-hop2": {"port": 30303},
    "brix-fault-cache": {"port": 30304},
    "root-s3-staged": {"port": 30305, "extra": {"S3_PORT": 30306}},
    "root-s3-readonly-wire": {"port": 30307, "extra": {"S3_PORT": 30308}},
    # Runtime S3-STS origin-leg e2e subject (test_sts_runtime_e2e.py, group
    # lc-sts-e2e, serial) — booted three times in sequence (exchange / select /
    # broken-STS variants) against an external docker MinIO; single listen, the
    # MinIO S3+STS authority is external so no embedded extra listen is needed.
    "root-s3-sts": {"port": 30456},
    "root-require-pgwrite": {"port": 30309, "extra": {"OFF_PORT": 30310}},
    "frmsec-stub": {"port": 30311},
    "tpc-harden": {"port": 30312, "extra": {"PORT_OFF": 30313}},
    "evil-actor": {"port": 30314, "extra": {"HTTP_PORT": 30315}},
    "evil-actor-v2": {"port": 30316,
                      "extra": {"METRICS_PORT": 30317, "S3_PORT": 30318,
                                "WEBDAV_PORT": 30319}},
    # Second conformance-topologies mirror variant: _build_mirror(lifecycle,
    # "mirror_rw") registers name=f"lc-ct-{name}" = "lc-ct-mirror_rw" (the RW
    # read-back leg), distinct from the read-only "lc-ct-mirror" (30172).
    "lc-ct-mirror_rw": {"port": 30320},
    # test_cache_verify_require.py (group lc-verify-require, serial) — one
    # brix-cache node per verify-mode case; name=f"brix-verify-{name}" with the
    # five literal suffixes ok/req/neg/be/ckv (env-gated on official xrootd).
    "brix-verify-ok": {"port": 30321},
    "brix-verify-req": {"port": 30322},
    "brix-verify-neg": {"port": 30323},
    "brix-verify-be": {"port": 30324},
    "brix-verify-ckv": {"port": 30325},
    # test_seccomp_enforce.py (group lc-seccomp-enforce) — one live server per
    # filter mode; the old name carried a spurious worker_tag suffix (the harness
    # data_root already isolates workers), dropped so the fixed port is stable.
    "seccomp-enforce": {"port": 30326},
    "seccomp-audit": {"port": 30327},
    # test_seccomp_exec_frm.py (group lc-seccomp-exec-frm) — allow_exec on/off.
    "frmexec-allow": {"port": 30328},
    "frmexec-deny": {"port": 30329},

    # ---- Phase 5: remaining lifecycle families that still reached the
    # endpoint_for `port is None` free_port fallback (now removed).  Each is a
    # binding nginx instance whose port was previously dynamic; ledgered here so
    # the stable-name path supplies the fixed listen and the owning file
    # serialises with one xdist_group.  Parse-only helpers do NOT appear here —
    # they pass an explicit non-binding placeholder port instead (see
    # SHARED_PARSE_PLACEHOLDER_PORT).  free_port binds that are genuinely client
    # floods / raw-lab proxies / native-xrootd sources stay dynamic (Phase-6
    # exempt) and are NOT ledgered.
    # test_access_log_batch.py (group lc-access-log-batch) — one root instance
    # per batching mode; single listen each.
    "lc-access-log-batch-close": {"port": 30330},
    "lc-access-log-batch-interleave": {"port": 30331},
    "lc-access-log-batch-escape": {"port": 30332},
    # test_admin_rate_limit.py (group lc-admin-rl) — one admin-API instance per
    # rate-limit config; the bad-directive test is parse-only (placeholder port).
    "lc-admin-rl-defaults": {"port": 30333},
    "lc-admin-rl-tight": {"port": 30334},
    "lc-admin-rl-unauth": {"port": 30335},
    "lc-admin-rl-off": {"port": 30336},
    # test_checksum_on_write.py (group lc-checksum) — checksum-on-write control
    # instances; single listen each.
    "lc-checksum-cow": {"port": 30337},
    "lc-checksum-xrdcks": {"port": 30338},
    "lc-checksum-plain": {"port": 30339},
    # test_dig.py (group lc-dig) — dig-enabled vs dig-off, single listen each.
    "lc-dig": {"port": 30340},
    "lc-dig-off": {"port": 30341},
    # test_webdav_put_digest.py (group lc-put-digest) — RFC-3230 digest accept
    # vs require, single listen each.
    "lc-put-digest": {"port": 30342},
    "lc-put-require-digest": {"port": 30343},
    # _cache_partial_helpers.py (group lc-cache-partial) — origin + cache peer
    # pair; the cache dials the origin's fixed port (read from origin_ep.port).
    "lc-cache-partial-origin": {"port": 30344},
    "lc-cache-partial-cache": {"port": 30345},
    # test_pblock_privilege_drop.py (group pb-privdrop) — one pblock export per
    # ownership/stripe/fail-closed case; single listen each.
    "pb-owned": {"port": 30346},
    "pb-stripe": {"port": 30347},
    "pb-failclosed": {"port": 30348},
    # test_gridftp_gsiftp.py (group gridftp-gsiftp) + test_gridftp_gsiftp_ev.py
    # (group gridftp-gsiftp-ev) — gsiftp gateway control listen (the GridFTP data
    # channel uses runtime-negotiated passive ports, not an nginx listen).
    "gridftp-gsiftp-trusting": {"port": 30349},
    "gridftp-gsiftp-untrusting": {"port": 30350},
    "gridftp-tpc-src": {"port": 30351},
    "gridftp-tpc-dst": {"port": 30352},
    "gridftp-gsiftp-ev-trusting": {"port": 30353},
    "gridftp-gsiftp-ev-untrusting": {"port": 30354},
    "gridftp-tpc-ev-src": {"port": 30355},
    "gridftp-tpc-ev-dst": {"port": 30356},
    # _test_evil_actor_v3_helpers.py (group evil-actor-v3) — one target server
    # binding a cleartext root:// front plus three extra planes (TLS/HTTPS/
    # metrics); the attack threads' client-flood binds stay dynamic (Phase-6).
    "evil-actor-v3": {"port": 30357,
                      "extra": {"ROOT_TLS_PORT": 30358, "HTTPS_PORT": 30359,
                                "METRICS_PORT": 30360}},
    # resilience/servers.py harness-launched nginx origins (the raw-launched
    # origin and the brix-fault-proxy listen/control stay on the lab's own
    # free_port — proxy/raw-bind scope, Phase-6 exempt).  These serve one at a
    # time within a resilience run.
    "resil-nginx-gsi": {"port": 30361},
    "resil-nginx-anon": {"port": 30362},
    "resil-nginx-webdav-anon": {"port": 30363},
    "resil-nginx-s3-anon": {"port": 30364},
    # The TLS and token legs of the same sweep harness: the fault sweeps were
    # cleartext+GSI only, so neither the TLS record layer nor a token login had
    # ever met loss, truncation or corruption.
    "resil-nginx-tls-anon": {"port": 30462},
    "resil-nginx-token": {"port": 30463},
    # resilience/run_http_reorder.py's WebDAV origin.  The runner is standalone
    # (not collected by pytest), so this omission went unnoticed until
    # test_sweep_runners.py drove it: without the entry the registry refuses the
    # spec and the sweep dies before it starts.
    "resil-http-reorder": {"port": 30464},
    # The three SERVER-SIDE legs of the sweep (audit §6): every other resilience
    # module damages the client->server leg, so a fault on a leg the client
    # cannot see had never been injected at all.  `resil-nginx-http-front` is a
    # root:// front whose storage backend is a remote http:// origin reached
    # through the proxy; `resil-nginx-tpc-dest` is a TPC destination whose PULL
    # leg goes through it; `resil-nginx-sss` closes the last unswept login
    # mechanism.
    # 30468/30469 rather than 30465/30466: those two were already owned by
    # `lc-matrix-*` below, and a shared-band port may have exactly one owner —
    # two instances on one fixed port is a bind() race, not a sharing scheme.
    "resil-nginx-http-front": {"port": 30468},
    "resil-nginx-tpc-dest": {"port": 30469},
    "resil-nginx-sss": {"port": 30467},
    # tests/matrix_layer.py — the (protocol × auth × tls × backend) cells.  Two
    # names for the whole matrix: only one cell is up at a time (every matrix
    # module carries xdist_group("lc-matrix")), and the origin name is only
    # bound for the remote-backend cells.
    "lc-matrix-node": {"port": 30465},
    "lc-matrix-origin": {"port": 30466},
    # test_lifecycle_speed.py (group lc-speed) — keypool boot-speed subject; one
    # running instance per test (the _SEQ counter is retired for a fixed name).
    # Binds a primary listen plus a GSI plane listen (GSI_PORT).
    "lc-speed": {"port": 30365, "extra": {"GSI_PORT": 30391}},
    # test_cms_fast_settle.py (group lc-cms-fast-settle) — one CMS data node per
    # test (the per-test fixture counter starts at 0; retired for a fixed name).
    "lc-cms-fast-settle-0": {"port": 30366},
    # (official_interop_lib.py's conformance pair is NOT ledgered here: every
    # start_pair() call site already passes fixed per-worker ports via
    # L.worker_port(base), so start_pair binds those directly — a distinct fixed
    # port band per xdist worker — and never reached the removed free_port
    # fallback once wired through.  See official_interop_lib.start_pair.)
    # mu_authz_lib/fleet.py (group mu-fleet) — the six multiuser-authz servers,
    # all live simultaneously; ports back-fill ports.MU.<ATTR> from the ledger.
    "mu-origin_noimp": {"port": 30369},
    "mu-cache_noimp": {"port": 30370},
    "mu-direct_authz": {"port": 30371},
    "mu-sidecar_root": {"port": 30372},
    "mu-webdav_authz": {"port": 30373},
    "mu-webdav_stage": {"port": 30374},
    # wlcg_conformance_fleet.py (group lc-wlcgconf) — one https instance per
    # x509forge signing-policy/CRL group; up to all seven live at once.
    "lc-wlcgconf-sp_on_crl_off": {"port": 30375},
    "lc-wlcgconf-sp_off_crl_off": {"port": 30376},
    "lc-wlcgconf-sp_require_crl_off": {"port": 30377},
    "lc-wlcgconf-sp_on_crl_try": {"port": 30378},
    "lc-wlcgconf-sp_on_crl_require": {"port": 30379},
    "lc-wlcgconf-sp_off_crl_try": {"port": 30380},
    "lc-wlcgconf-bundle": {"port": 30381},
    # Root-only families (skipif not root) — ledgered so a root run takes the
    # stable-name path instead of the removed fallback.
    # test_impersonation_gridmap_root.py (group impgm).
    "impgm-single": {"port": 30382},
    "impgm-s3": {"port": 30383},
    "impgm-root-gsi": {"port": 30384},
    # test_privilege_hardening_root.py (group hard-priv).
    "hard-caps-off": {"port": 30385},
    "hard-http-seccomp": {"port": 30386},
    "hard-map": {"port": 30387},
    # test_worker_deescalation_root.py (group wdeesc).
    "wdeesc-default": {"port": 30388},
    "wdeesc-configured": {"port": 30389},
    "wdeesc-missing": {"port": 30390},

    # ---- Phase 5 (continued): the last free_port-importing registry nginx
    # binds.  Their native-xrootd upstream sources / in-process mocks stay on
    # OS-assigned ephemeral ports via ``ephemeral_port`` (documented exemption);
    # only the brix nginx instance is ledgered here.
    # test_gridftp_delegate_xrootd.py (group gridftp-deleg, serial) — the gsiftp
    # gateway nginx in front of a stock xrootd upstream; two cred-mode variants,
    # one live at a time.  (The stock xrootd source keeps ephemeral_port.)
    "gridftp-deleg-xrd": {"port": 30367},
    "gridftp-deleg-xrd-select": {"port": 30368},
    # test_mirror_upstream.py (group lc-mirror-upstream, serial) — the traffic-
    # mirror nginx front over a stock xrootd upstream.  Two persistent fronts
    # (checksum + no-checksum upstream) plus the opcode-selection factory front
    # (one live at a time; the file is serial so a fixed name suffices).  The two
    # stock xrootd upstreams keep ephemeral_port (native-source exemption).
    "mirror-up-front": {"port": 30392},
    "mirror-up-front-bare": {"port": 30393},
    "mirror-up-sel": {"port": 30394},

    # ---- Phase 5 (fast-lane close-out): lifecycle-harness families that were
    # never converted in Phase 4 and so still relied on the removed
    # `-{pid}`/free_port fallback.  The unconditional fixed-port lane (which now
    # RAISES on an unledgered lifecycle spec) surfaced them on the first full
    # fast-lane run; each is a single-listen brix nginx driven serially by one
    # file.  All ledgered in the SHARED band + the owning file serialised with
    # one xdist_group so the shared fixed port never has two concurrent drivers.
    #
    # test_gsi_handshake.py + test_gsi_handshake_b.py (group gsihs) — both files
    # `from _test_gsi_handshake_helpers import *`, sharing the module-scoped GSI
    # server fixtures; one xdist_group("gsihs") on the shared helper's pytestmark
    # serialises BOTH files onto one worker (each module tears its fixtures down
    # before the next module runs, so the fixed ports are reused, not contended).
    # `nginx_root` is params=[off,auto,require] → three concurrent instances, so
    # each policy gets its own port.  All single-listen (`_gsi_nginx` never sets
    # extra_ports).  The stock-xrootd + VOMS material use their own fixed/native
    # ports and are not lifecycle specs.
    "gsihs-root-off": {"port": 30396},
    "gsihs-root-auto": {"port": 30397},
    "gsihs-root-require": {"port": 30398},
    "gsihs-root-neg": {"port": 30399},
    "gsihs-root-both": {"port": 30400},
    "gsihs-root-aes256": {"port": 30401},
    "gsihs-voms": {"port": 30402},
    "gsihs-root-tls": {"port": 30403},
    "gsihs-root-sigver": {"port": 30404},
    "gsihs-rsa4096": {"port": 30405},
    "gsihs-webdav": {"port": 30406},
    # test_xrddiag.py (group xrddiag) — two module-scoped anon root servers
    # (`_anon_server`), both potentially live at once, single-listen each.
    # (The `test_xrddiag_*.py` split files are separately ledgered as
    # `lc-xrddiag-*` above.)
    "xrddiag-netdiag": {"port": 30407},
    "xrddiag-doctor": {"port": 30408},
    # test_frm_scratch.py (group lc-frm-scratch) — self-contained frm:// recall
    # server, exec or stub adapter, single-listen.  The per-call `next(_SEQ)`
    # name suffix (a relic of the dynamic-port scheme) is dropped in favour of
    # one stable name per adapter now the file is serial and the harness is
    # closed at each test's teardown, so the fixed port is reused.
    "lc-frm-exec": {"port": 30409},
    "lc-frm-stub": {"port": 30410},
    # test_frm_scratch.py — hpss/cta exec-family MSS dialects (phase-64 SP5):
    # frm://hpss and frm://cta drive the exec transport via the per-dialect
    # $BRIX_FRM_{HPSS,CTA}_STAGECMD override (same serial lc-frm-scratch group).
    "lc-frm-hpss": {"port": 30425},
    "lc-frm-cta": {"port": 30426},
    # test_frm_lib_adapter.py (group lc-frm-lib) — library-native (dlopen) MSS
    # dialects (phase-64 residual): frm://lib, frm://libhpss and frm://libcta
    # dlopen the operator HSM .so and dlsym the sd_frm_lib_abi.h verbs instead of
    # forking a stage command; the .so path resolves from $BRIX_FRM_LIB or the
    # per-dialect $BRIX_FRM_{HPSS,CTA}_LIB override.
    "lc-frm-lib": {"port": 30428},
    "lc-frm-libhpss": {"port": 30429},
    "lc-frm-libcta": {"port": 30430},
    # test_cvmfs_global_cas.py (group lc-cvmfs-gcas-evict) — phase-87 G13
    # watermark-reaper stream instance asserting the gcas canonical-hardlink GC.
    "lc-cvmfs-gcas-evict": {"port": 30411},
    # test_neg_stat_cache.py (group lc-negstat) — phase-56 C-2 subject: the
    # per-worker negative-stat cache enabled via BRIX_NEG_STAT_CACHE=1 in the
    # spec env, single-listen single-worker anon root export.
    "lc-negstat": {"port": 30455},
    # test_cachemx_*.py (group lc-cachemx, serial) — BriX-Cache metrics
    # conformance matrix.  One anon posix origin, one multi-plane cache subject
    # (stream none/gsi/token/sss + http webdav/davs/davs-gsi/s3/s3-sigv4 + a
    # /metrics listener), one eviction/watermark trim subject rendered with
    # test-computed watermarks, and a cms manager + cache data-server pair for
    # the cmsd:// route.  All files share xdist_group("lc-cachemx") so these
    # fixed shared-band ports never have two concurrent drivers.
    "lc-cachemx-origin": {"port": 30470, "extra": {"METRICS_PORT": 30488}},
    "lc-cachemx": {"port": 30471,
                   "extra": {"GSI_PORT": 30472, "TOK_PORT": 30473,
                             "SSS_PORT": 30474, "METRICS_PORT": 30475,
                             "HTTP_PORT": 30476, "DAVS_PORT": 30477,
                             "DAVS_GSI_PORT": 30478, "S3_PORT": 30479,
                             "S3_SIG_PORT": 30480,
                             "S3_TLS_PORT": 30506,
                             "DAV_ORIGIN_PORT": 30507,
                             "DAV_TPC_PORT": 30508}},
    "lc-cachemx-evict": {"port": 30481, "extra": {"METRICS_PORT": 30482}},
    "lc-cachemx-redir": {"port": 30483,
                         "extra": {"CMS_PORT": 30484, "METRICS_PORT": 30485}},
    "lc-cachemx-cmsds": {"port": 30486, "extra": {"METRICS_PORT": 30487}},
    # `unix` auth peer-trust matrix (test_unix_auth_wire.py) — three read-only
    # instances differing only in listen address and brix_unix_trust_remote; the
    # two "remote" ones bind this host's non-loopback address so the peer the
    # server sees is not loopback.  One xdist_group("lc-unix-auth") serialises them.
    "lc-unix-loopback": {"port": 30489},
    "lc-unix-remote-deny": {"port": 30490},
    "lc-unix-remote-trust": {"port": 30491},
    # Macaroon over the root:// stream plane (test_macaroon_root_wire.py): one
    # instance with a single secret, one with a rotated secret pair so the
    # grace-period old-secret retry has a live path.  xdist_group
    # ("lc-macaroon-root") serialises them.
    "lc-macaroon-root": {"port": 30492},
    "lc-macaroon-root-rotate": {"port": 30493},

    # brix_authdb authorization granularity behind the four non-GSI mechanisms
    # (test_authdb_mechanism_scope.py): one server per mechanism, each with the
    # same rule shapes (user scope + group/VO scope + host scope).  xdist_group
    # ("lc-authdb-mech") serialises them.
    "lc-authdb-pwd": {"port": 30494},
    "lc-authdb-sss": {"port": 30495},
    "lc-authdb-host": {"port": 30496},
    "lc-authdb-krb5": {"port": 30497},

    # HTTP-TPC pull completion gate (test_webdav_tpc_completion_gate.py): one
    # COPY destination per gate setting — both halves on, size half only, and
    # neither (the non-vacuity control).  All three pull from the same in-test
    # https fake source.  xdist_group ("lc-tpc-gate") serialises them.
    "lc-tpcgate-both": {"port": 30498},
    "lc-tpcgate-size": {"port": 30499},
    "lc-tpcgate-off": {"port": 30500},

    # Native root:// TPC × WLCG token auth (test_tpc_token_auth.py): one nginx,
    # four brix_root planes — token-auth source, plus three destinations that
    # differ only in how the outbound source leg is credentialed (passthrough,
    # static bearer file, nothing).  xdist_group ("lc-tpc-token") serialises it.
    "lc-tpc-token": {"port": 30501,
                     "extra": {"PORT_SRC": 30502, "PORT_BFILE": 30503,
                               "PORT_NOPASS": 30504}},

    # root:// trusted cache-STORE surface (test_mu_sidecar_hidden.py): same
    # export and the same planted sidecars as "lc-mu-sidecar-root", but with
    # brix_cache_store_endpoint on, so the reserved-name guard is lifted for
    # open/stat.  Paired with the default node so both halves of the switch are
    # asserted against one namespace.
    "lc-mu-sidecar-store": {"port": 30505},
    # CMS/AAA federation-join node (test_cms_aaa_join_noise.py): dials its
    # redirector through a brix-fault-proxy on an ephemeral port, so only the
    # data listen and the /metrics listen are ledgered here.
    "lc-cms-aaa-node": {"port": 30509, "extra": {"METRICS_PORT": 30510}},
    # phase-97 §5: one export, four planes (root:// + WebDAV + S3 + gridftp) all
    # reporting into one manager inventory (test_cns_http.py).  The root:// port
    # is the primary; the other three planes bind the extras.  Dials the shared
    # "lc-cns-manager" CMS port, so it is serial with the other CNS suites.
    "lc-cns-http-data": {"port": 30511, "extra": {"HTTP_PORT": 30512,
                                                  "S3_PORT": 30513,
                                                  "FTP_PORT": 30514}},
    # CMS multi-manager redundancy (test_cms_multi_manager.py): one manager-mode
    # parent-lookup node and one CNS-emit data node, each dialling TWO in-test
    # stub managers on ephemeral ports (client-side listeners, Phase-6 exempt).
    # xdist_group ("lc-cms-multi") serialises the file over these fixed ports.
    "lc-cms-multi-node": {"port": 30515},
    "lc-cms-multi-emit": {"port": 30516},
    # The s3:// sibling of `resil-nginx-http-front` above: a root:// front whose
    # storage backend is a remote S3 origin reached through the fault proxy.  A
    # second name rather than a reuse of the http one because both fronts are up
    # at once in test_server_leg_faults.py, and it is numerically here rather
    # than beside its sibling because 30470+ was already taken by the cachemx
    # block when the resilience band was allocated.
    "resil-nginx-s3-front": {"port": 30517},
    # Background block-prefetch WebDAV front (test_vfs_prefetch.py): a slice
    # partial cache served memory-backed over a throwaway http static origin
    # (origin port is registry-assigned; only the front + its /metrics listen
    # are ledgered).  The suite is serial (shares the cache-partial harness
    # doctrine), so one fixed pair suffices.
    "lc-vfs-prefetch-webdav": {"port": 30518, "extra": {"METRICS_PORT": 30519}},
    # Per-capability TLS gating subjects (test_tls_require.py): one throwaway
    # nginx per brix_tls_require mask / ztn-cleartext posture, all serialised
    # under xdist_group("lc-tlsreq") so the block never has concurrent drivers.
    "lc-tlsreq-session": {"port": 30520},
    "lc-tlsreq-data": {"port": 30521},
    "lc-tlsreq-login": {"port": 30522},
    "lc-tlsreq-except": {"port": 30523},
    "lc-tlsreq-tls": {"port": 30524},
    "lc-tlsreq-adv": {"port": 30525},
    "lc-tlsreq-adv-none": {"port": 30526},
    "lc-tlsreq-ztn-refuse": {"port": 30527},
    "lc-tlsreq-ztn-optin": {"port": 30528},
    "lc-tlsreq-ztn-tls": {"port": 30529},
    # 30506/30507/30508 are the cachemx matrix's S3-over-TLS, remote-origin
    # WebDAV and HTTP-TPC WebDAV planes; they live in the "lc-cachemx" extras
    # block above, out of numeric order because that entry predates them.
}

# Non-binding placeholder for lifecycle-shared-band `nginx -t`-only instances
# (register + render + nginx_test, never a live listen).  Distinct from the
# exclusive-band placeholder; kept well clear of the allocated shared ports.
SHARED_PARSE_PLACEHOLDER_PORT = 30999


def lifecycle_ports_for(name: str) -> tuple[int | None, dict[str, int]]:
    """Fixed ``(primary_port, extra_ports)`` for a lifecycle-subject spec name.

    Consults the exclusive (Bucket-2 mutation) ledger first, then the shared
    (Bucket-1 idempotent) ledger.  Returns ``(None, {})`` when the name is on
    neither, so the caller falls back to the legacy per-pid dynamic-port path
    unchanged.
    """
    entry = LIFECYCLE_EXCLUSIVE_PORTS.get(name) or LIFECYCLE_SHARED_PORTS.get(name)
    if entry is None:
        return None, {}
    return entry["port"], dict(entry.get("extra", {}))
