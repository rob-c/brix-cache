"""Lifecycle-shared port ledger, part 1: conversion waves 1-7a.

The ``lifecycle-shared`` band is split across two modules purely so neither
grows past the file-size tiers; ``fleet_lifecycle_ports`` merges them into the
single ``LIFECYCLE_SHARED_PORTS`` mapping every consumer imports, and rejects a
spec name declared in both.  See ``fleet_ports_shared_phase5`` for the second
half.

This half holds the Phase-4 conversion waves in their original order: the
single-instance client/tool/auth servers (waves 1-2), the parse/register-only
families (wave 3), the multi-listen single instances (wave 4), the
peer-referencing clusters (wave 5), the pblock lab (wave 6) and the remaining
``lc-``-named singletons (wave 7a).  Entry order is load-bearing:
``port_ladder.rebase_lifecycle_ledger`` assigns ladder slots by iteration order,
so moving an entry between the halves — or reordering one — moves every port
after it.

The port numbers below are the historical seeds the owning tests were written
against.  ``fleet_lifecycle_ports`` rebases every one of them onto the
``TEST_PORT_START`` ladder at import (in place, through the entry objects this
module and the merged mapping share), so read a live port from there — never
from this module directly.
"""

from __future__ import annotations

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
LIFECYCLE_SHARED_PORTS_WAVES: dict[str, dict] = {
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
    # §3.15 OssStats slowop classifier: stream root op + HTTP /metrics scrape.
    "lc-slowop": {"port": 30424, "extra": {"METRICS_PORT": 30425}},
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
    # §2.4 brix_cms_min_free node (same dial-out-to-mock-peer shape) — asserts
    # the configured mSpace policy floor reaches the kYR_login wire field.
    "lc-cms-wire-minfree-node": {"port": 30411},
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
    "lc-pmark-s3": {"port": 30268},   # phase-101 W1 SciTags-on-S3 (canonical value
                                      # ignored; rebased by insertion order)
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
    "lc-xrdfs-web-write-rw": {"port": 30530},
    "lc-xrdfs-web-write-ro": {"port": 30531},
    "lc-xrdhttp-guard": {"port": 30280},
    "lc-xrootd-conformance": {"port": 30281},
}
