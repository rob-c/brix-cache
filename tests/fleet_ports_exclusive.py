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

The port numbers below are the historical seeds the owning tests were written
against.  ``fleet_lifecycle_ports`` rebases every one of them onto the
``TEST_PORT_START`` ladder at import (in place, through the entry objects this
module and the merged mapping share), so read a live port from there — never
from this module directly.
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

    # Audit-fix subjects (test_audit_fixes_2026_08_09.py), all serialised under
    # xdist_group("lc-audit-fixes").  Each mutates its own cache/export state:
    #   only-if-cached — a read MISS must be refused, never filled (§4.4);
    #   cold-purge     — the reaper must delete a clean read-fill by age (§4.2);
    #   signing        — brix_security_level over an anonymous (unsignable)
    #                    session, reconfigured between required-on and -off so
    #                    the pair costs ONE ladder slot instead of two (§5.2).
    "lc-audit-onlyifcached": {"port": 31240},
    "lc-audit-coldpurge": {"port": 31241},
    "lc-audit-signing": {"port": 31242},
    # §4.3 uvkeep — fills an UNVERIFIED entry, swaps the source, and proves the
    # entry is revalidated only once it ages past the keep window (its own cache/
    # export state, serialised by xdist_group("lc-cache-uvkeep")).
    "lc-cache-uvkeep": {"port": 31243},
    # §4.7 max_bytes — fills the cache past an owned-bytes cap and proves the
    # reaper evicts back down to it (its own cache/export state, serialised by
    # xdist_group("lc-cache-maxbytes")).
    "lc-cache-maxbytes": {"port": 31244},
}
