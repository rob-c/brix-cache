"""Lifecycle-shared port ledger, part 2: Part-B singletons and the Phase-5 close-out.

Second half of the ``lifecycle-shared`` band; see ``fleet_ports_shared_waves``
for the first half and the entry-order contract, and ``fleet_lifecycle_ports``
for the merge and the band's rules.

This half holds the wave-7b singletons that kept their historical descriptive
names (evil-actor targets, GridFTP gateways, STS/mirror/seccomp families), the
Phase-5 pass that ledgered every family still falling back to a dynamic port,
and the per-feature entries added since.  **A new shared-band entry belongs at
the end of this module**, which is where every later wave has landed.

The port numbers below are the historical seeds the owning tests were written
against.  ``fleet_lifecycle_ports`` rebases every one of them onto the
``TEST_PORT_START`` ladder at import (in place, through the entry objects this
module and the merged mapping share), so read a live port from there — never
from this module directly.
"""

from __future__ import annotations

# base spec name -> {"port": <primary listen>, "extra": {<template_key>: <port>}};
# same contract as the first half, spelled out in ``fleet_ports_shared_waves``.
LIFECYCLE_SHARED_PORTS_PHASE5: dict[str, dict] = {
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
    # 2026-08-09 CMS parity wave (test_cms_parity_wave.py): ONE manager name
    # and ONE node name reused sequentially with per-test {CMS_EXTRA} policy
    # directives; xdist_group("lc-cms-parity") serialises the file.  Fake
    # data-node peers and the in-test stub manager use client-side/ephemeral
    # sockets (Phase-6 exempt); only these nginx binds are ledgered.
    "lc-cms-parity-mgr": {"port": 30540, "extra": {"CMS_PORT": 30545}},
    "lc-cms-parity-node": {"port": 30541},
    # HTTP redirect-to-dataserver (§6.1, test_webdav_redirect_ds.py): a
    # manager (stream CMS server + http webdav front) and a data-server-side
    # verifier instance; xdist_group("lc-webdav-redirect") serialises.
    "lc-webdav-redirect-mgr": {"port": 30542,
                               "extra": {"HTTP_PORT": 30543, "CMS_PORT": 30546}},
    "lc-webdav-redirect-ds": {"port": 30544, "extra": {"HTTP_PORT": 30547}},
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
    # kXR_bind refusal subject (test_bind_substreams.py), owned by one
    # module-scoped lifecycle and serialised as bind-substreams-off.
    "lc-bind-substreams-off": {"port": 30530},
    # GridFTP unified-metrics subject (test_gridftp_metrics.py): one nginx whose
    # process-wide metrics zone is fed by TWO gsiftp gateways — a writable one
    # (PORT) for the success/error rows and a read-only one (RO_PORT) for the
    # refusal rows — and scraped over HTTP_PORT.  All three must be on the same
    # instance: the zone is per-process, so a second nginx would carry its own
    # counters and prove nothing about the seam.
    "lc-gridftp-metrics": {"port": 30531,
                           "extra": {"HTTP_PORT": 30532, "RO_PORT": 30533}},
    # 2026-08-15 combinatorial-coverage-audit closure (test_audit15_*.py):
    # live subjects for the zero-coverage whole features of
    # docs/refactor/testsuite-combinatorial-coverage-audit-2026-08-15.md.
    # Each family is serialised under its own xdist_group.
    "lc-audit15-throttle": {"port": 30548},
    "lc-audit15-readonly-http": {"port": 30549},
    "lc-audit15-readonly-http-ctl": {"port": 30550},
    "lc-audit15-readonly-stream": {"port": 30551},
    "lc-audit15-guard-knobs": {"port": 30552},
    "lc-audit15-guard-defaults": {"port": 30553},
    "lc-audit15-mac-rotation": {"port": 30554},
    # 2026-08-15 second tranche (test_audit15b_*.py): the §B pairwise combos
    # and §A2 residuals of the same audit — virtual-redirector role bits,
    # guard×WebDAV-TPC COPY pin, substreams×TLS, readonly×TPC destination,
    # webdav token_config parity, SRR on a live cache member (3 planes).
    "lc-audit15b-vrdr-on": {"port": 30555},
    "lc-audit15b-vrdr-off": {"port": 30556},
    "lc-audit15b-guard-copy": {"port": 30557},
    "lc-audit15b-subs-tls": {"port": 30558},
    "lc-audit15b-tpc-ro": {"port": 30559},
    "lc-audit15b-tpc-rw": {"port": 30560},
    "lc-audit15b-webdav-tokcfg": {"port": 30561},
    "lc-audit15b-srr-cache": {"port": 30562, "extra": {"ORIGIN_PORT": 30563,
                                                       "SRR_PORT": 30564}},
    # 2026-08-15 third tranche (test_audit15c_*.py): the deferred-but-mockable
    # audit residuals — WebDAV token introspection (+ a colocated nginx mock
    # IdP on IDP_PORT), dashboard users-file auth, native-TPC outbound RFC 8693
    # token exchange against a capturing Python token endpoint (MOCK_PORT),
    # SSI journal/cap knobs, and ZIP central-directory caps on both planes.
    "lc-audit15c-introspect": {"port": 30565, "extra": {"IDP_PORT": 30566}},
    "lc-audit15c-dash-users": {"port": 30567},
    "lc-audit15c-tpcx-good": {"port": 30568, "extra": {"MOCK_PORT": 30569}},
    "lc-audit15c-tpcx-cc": {"port": 30570},
    "lc-audit15c-tpcx-dead": {"port": 30571},
    "lc-audit15c-tpcx-junk": {"port": 30572},
    "lc-audit15c-ssi-journal": {"port": 30573},
    "lc-audit15c-ssi-caps": {"port": 30574},
    "lc-audit15c-zipcaps": {"port": 30575, "extra": {"CTRL_PORT": 30576,
                                                     "HTTP_PORT": 30577}},
    # 2026-08-15 fourth tranche (test_audit15d_*.py): the last locally-drivable
    # audit residuals — the tls_require tpc capability mask at the native-TPC
    # open choke point (mask / TLS-positive / no-mask control instances),
    # brix_inherit_parent_group group-policy inheritance, and
    # checksum-on-write xattrs through a write-through stage tier (front +
    # colocated WebDAV origin on ORIGIN_PORT).
    "lc-audit15d-tlstpc-mask": {"port": 30578},
    "lc-audit15d-tlstpc-tls": {"port": 30579},
    "lc-audit15d-tlstpc-none": {"port": 30580},
    "lc-audit15d-inherit": {"port": 30581},
    "lc-audit15d-ckstage": {"port": 30582, "extra": {"ORIGIN_PORT": 30583}},
    # 2026-08-15 fifth tranche (test_audit15e_*.py): the audit's tier and
    # cluster crosses — backend_async over cache/stage tiers, io_uring under
    # cache/stage spools, passthrough co-resident with stage and read_only,
    # checksum-on-write over an s3:// origin, and the cms-member pairs (SRR
    # endpoint on a mesh member; a member that proxies / initiates TPC).
    "lc-audit15e-async": {"port": 30584, "extra": {"ORIGIN_PORT": 30585}},
    "lc-audit15e-uring": {"port": 30586, "extra": {"STAGE_PORT": 30587,
                                                   "ORIGIN_PORT": 30588}},
    "lc-audit15e-pt": {"port": 30589, "extra": {"ORIGIN_PORT": 30590}},
    "lc-audit15e-cks3": {"port": 30591, "extra": {"ORIGIN_PORT": 30592}},
    "lc-audit15e-cmsmgr": {"port": 30593},
    "lc-audit15e-srrcms": {"port": 30594, "extra": {"SRR_PORT": 30595}},
    "lc-audit15e-cmsmgr2": {"port": 30596},
    "lc-audit15e-cmsact": {"port": 30597, "extra": {"ORIGIN_PORT": 30598,
                                                    "TPC_PORT": 30599,
                                                    "SRC_PORT": 30600}},
    # 2026-08-15 sixth tranche (test_audit15f_*.py): the audit's remaining
    # locally-drivable surface — the WebDAV TPC tuning knobs driven against a
    # capturing TLS mock source (marker streaming, multi-stream ranges, the
    # low-speed stall bound, the RFC 8693 client credentials and the curl-path
    # directive).
    # MOCK_PORT is the TLS pull source; IDP_PORT the plain-HTTP token endpoint
    # (the exchange subprocess is a bare `curl` with no CA options of its own,
    # so it cannot reach an https IdP holding a test-minted cert).
    "lc-audit15f-tpctune": {"port": 30601, "extra": {"MOCK_PORT": 30602,
                                                     "IDP_PORT": 30603}},
    # Credential forwarding under REAL bearer auth (test_audit15f_tpc_cred_
    # forward.py): rctx->bearer_token is only ever set by webdav_verify_bearer_
    # token, so the on/off cross needs a token-authenticated location plus its
    # own capturing TLS source (MOCK_PORT) to report what travelled onward.
    "lc-audit15f-credfwd": {"port": 30604, "extra": {"MOCK_PORT": 30605}},
    # host auth x {tls, cache, stage, tpc, cms} (test_audit15f_host_auth_
    # crosses.py, audit §B1.9: `brix_auth host` only ever paired with authdb).
    # One instance carries every plane so the SAME reverse-DNS allowlist gates
    # all of them: PORT is the TLS listener, DENY_PORT its allowlist-excluded
    # twin, ORIGIN_PORT the http backend the CACHE_PORT and STAGE_PORT tiers
    # sit over, SRC_PORT / SRCHOST_PORT the native-TPC sources (auth none and
    # host) feeding TPC_PORT, CMS_PORT the mesh member.  The manager is its own
    # instance so the joins are real CMS logins.
    "lc-audit15f-hostmgr": {"port": 30606},
    "lc-audit15f-hostx": {"port": 30607, "extra": {"DENY_PORT": 30608,
                                                   "ORIGIN_PORT": 30609,
                                                   "CACHE_PORT": 30610,
                                                   "STAGE_PORT": 30611,
                                                   "TPC_PORT": 30612,
                                                   "SRC_PORT": 30613,
                                                   "SRCHOST_PORT": 30614,
                                                   "CMS_PORT": 30615}},
    # sigver x native TPC and sigver x substreams (test_audit15f_sigver_
    # crosses.py, audit §B1.1/§B1.2).  One instance, six planes: PORT and
    # LAX_PORT are TPC destinations under `brix_security_level standard` with
    # brix_signing_required on/off, SRC_PORT / SRCSIG_PORT the matching pull
    # sources (unsigned and signing-required), BIND_PORT / BINDLAX_PORT the
    # substream planes under `intense` with the flag flipped.
    "lc-audit15f-sigx": {"port": 30616, "extra": {"LAX_PORT": 30617,
                                                  "SRC_PORT": 30618,
                                                  "SRCSIG_PORT": 30619,
                                                  "BIND_PORT": 30620,
                                                  "BINDLAX_PORT": 30621}},
    # Read-cache admission whitelist + the bounded cinfo L1
    # (test_audit15f_cache_admission_and_staging.py, audit §B3.17).  The origin
    # is its own instance so a test can stop it and prove what the cache still
    # answers from its own store; PORT is the brix_cache_allow_prefix plane and
    # L1_PORT the brix_cache_index_cache plane, both tiered over that origin.
    "lc-audit15f-cacheorigin": {"port": 30622},
    "lc-audit15f-cacheadm": {"port": 30623, "extra": {"L1_PORT": 30624}},
    # Load-weighted selection + the cluster panel's staleness window
    # (test_audit15f_cluster_tuning.py, audit §B1).  PORT is the root://
    # redirector face kXR_locate reads the verdict off, CMS_PORT the face fake
    # nodes register into, and HTTP_PORT / HTTP2_PORT two dashboards over the
    # SAME registry whose brix_dashboard_cluster_stale_after differ (90s vs
    # 1ms) — two servers because the panel routes on a literal URI.
    "lc-audit15f-cltune": {"port": 30625, "extra": {"CMS_PORT": 30626,
                                                    "HTTP_PORT": 30627,
                                                    "HTTP2_PORT": 30628}},
    # CMS client-leg tuning (test_audit15f_cms_node_legs.py, audit §B1): the
    # perf-feed freshness window, the connect/first-write bound, and the
    # upward socket's dead-peer options.  METRICS_PORT exposes
    # brix_cms_connect_failures_total — the only external witness that a dial
    # was torn down before LOGIN.
    "lc-audit15f-clnode": {"port": 30629, "extra": {"METRICS_PORT": 30630}},
    # A fifth token-exchange destination for test_audit15c_tpc_token_exchange.py
    # (audit §B1 brix_tpc_outbound_scope, closed in the sixth tranche): the same
    # capturing IdP mock, this one with an explicit outbound scope.  Allocated
    # here rather than beside its four siblings so the existing instances keep
    # the ports they were developed on.
    "lc-audit15c-tpcx-scope": {"port": 30631},
    # Macaroon issuance policy (test_audit15f_macaroon_issue_policy.py, audit
    # §B1): one WebDAV server whose two locations differ only in
    # brix_webdav_macaroon_location and brix_webdav_macaroon_max_validity, so a
    # single port carries both arms of the cross.
    "lc-audit15f-macpol": {"port": 30632},
    # acc OS-group resolution (test_audit15f_acc_group_resolution.py, audit
    # §B1): brix_acc_pgo and brix_acc_gidretran are process globals, so the
    # arms are separate nginx processes on one port — the lifecycle fixture is
    # function-scoped and restarts per `reason`.
    "lc-audit15f-accgrp": {"port": 30633},
    # 2026-08-15 seventh tranche (test_audit15g_*.py): the audit's §C carry-over
    # rows — the three mid-transfer legs the 2026-08-04 pass recorded as having
    # no test at all (reload during a cache fill, unlink during an active
    # transfer, eviction during an active read), plus the sd_http deadline the
    # same pass left unasserted because a 180 s stall hangs CI.
    #
    # One shared root:// posix origin serves the unlink and eviction planes;
    # each file starts it under its own `reason`, and the function-scoped
    # lifecycle fixture stops it again at teardown, so the name is reused
    # across files exactly as _cache_partial_helpers reuses ORIGIN_NAME.
    "lc-audit15g-mtorigin": {"port": 30634},
    "lc-audit15g-unlink": {"port": 30635, "extra": {"CACHE_PORT": 30636}},
    "lc-audit15g-evict": {"port": 30637, "extra": {"COLD_PORT": 30638}},
    # The two http://-origin planes.  Their origin is a Python PacedSource on
    # MOCK_PORT rather than an nginx instance, because both files need the fill
    # to advance at a KNOWN rate and to be freezable mid-body — a real origin
    # can only be stopped, which is a different fault.
    "lc-audit15g-fill": {"port": 30639, "extra": {"MOCK_PORT": 30640}},
    "lc-audit15g-sdhttp": {"port": 30641, "extra": {"MOCK_PORT": 30642}},
    # TPC x {cache_store, non-posix backend, authdb} — the §C carry-over pairs
    # plus §B1.7.  One instance carries every plane so the same pull driver
    # reaches all of them: PORT is the cache-tiered destination, HTTP_PORT the
    # destination whose backend is the http:// origin on ORIGIN_PORT, CTL_PORT
    # the plain posix destination the other two are attributed against, and
    # ACC_PORT the xrdacc-gated destination.  SRC_PORT / CSRC_PORT /
    # ASRC_PORT are the pull sources: plain posix, cache-tiered over the same
    # origin, and xrdacc-gated.
    #
    # ACC_PORT and not AUTHDB_PORT: the launcher renders `{NAME}_PORT` for every
    # REGISTERED SPEC after the instance's own extras (_server_launcher_part2_
    # mixina.py:300-301), so an extra whose name collides with a spec name —
    # there is a dedicated "authdb" server — is silently overwritten by that
    # spec's port, and the block listens somewhere else entirely.
    "lc-audit15g-tpcx": {"port": 30643, "extra": {"ORIGIN_PORT": 30644,
                                                  "SRC_PORT": 30645,
                                                  "CSRC_PORT": 30646,
                                                  "ASRC_PORT": 30647,
                                                  "HTTP_PORT": 30648,
                                                  "CTL_PORT": 30649,
                                                  "ACC_PORT": 30650}},
    # An authdb that fails to PARSE (test_audit15g_authdb_load_failure.py, the
    # tail of §B1.7).  Two planes over two separate authdb files: the static one
    # is only read at worker start, the REFRESH_PORT one re-reads on a timer, and
    # the same malformed file is fatal to the first and harmless to the second.
    # Separate files because a worker that dies at init takes both planes with it.
    "lc-audit15g-badacc": {"port": 30651, "extra": {"REFRESH_PORT": 30652}},
    # `xrdcp --verify` against a plane that answers kXR_Qcksum normally
    # (test_audit15g_verify_strict.py): the subject is the CLIENT's verdict
    # policy, so the server is the stock writable-anon posix template.
    "lc-audit15g-verify": {"port": 30653},
    # 2026-08-16 eighth tranche (test_audit15h_*.py): the rows the earlier
    # tranches recorded as "still open" — the kill-switches, the identity-
    # bearing crosses that need a real KDC / proxy chain, and cvmfs x gridftp.
    #
    # The two TPC lifetime kill-switches (test_audit15h_tpc_lifetime.py, §A2).
    # SRC_PORT is the plain source, PORT the destination that caps the pull,
    # FREE_PORT the identical destination with no cap (the control that makes a
    # capped failure attributable), and DASH_PORT an anonymous dashboard on the
    # same instance — the TPC registry is SHM shared by every worker, so the
    # dashboard reads the very slots the stream planes write.
    "lc-audit15h-tpclife": {"port": 30654, "extra": {"SRC_PORT": 30655,
                                                     "FREE_PORT": 30656,
                                                     "DASH_PORT": 30657}},
    # Dashboard session-TTL expiry (test_audit15h_dashboard_session_ttl.py,
    # §A1).  Three planes because the dashboard's routes are absolute
    # ("/brix/api/v1/...", module_dispatch.c:77-104), so two auth modes cannot
    # share one server: PORT is single-password with an explicit 120s TTL,
    # MU_PORT is the users-file mode with the same TTL (its cookie signs
    # "<ts>.<user>", a different message), and DEF_PORT carries no TTL
    # directive at all so the 28800s merge default is what answers.
    "lc-audit15h-dashttl": {"port": 30658, "extra": {"MU_PORT": 30659,
                                                     "DEF_PORT": 30660}},
    # krb5 x TLS (test_audit15h_krb5_tls.py, §B1.8 — `brix_auth krb5` had never
    # been configured on a TLS listener anywhere in the suite).  Three planes off
    # one KDC: PORT is krb5 over an in-protocol TLS upgrade, PLAIN_PORT is the
    # same acceptor with no TLS at all (the control that proves the realm and
    # keytab are sound, so a failure on PORT is attributable to the cross), and
    # TLSREQ_PORT adds `brix_tls_require all` so a cleartext login is refused
    # outright rather than authenticated in the clear.
    "lc-audit15h-krb5tls": {"port": 30661, "extra": {"PLAIN_PORT": 30662,
                                                     "TLSREQ_PORT": 30663}},
    # Abandoned in-protocol TLS upgrade (test_audit15h_tls_upgrade_abort.py) —
    # DEFECT CANDIDATE #23, found while wiring krb5 x TLS above.  Its own
    # instance because the trigger kills the worker: sharing a daemon with any
    # other subject would make those tests flaky for a reason that has nothing
    # to do with them.  PORT is the anonymous TLS plane, CLEAR_PORT the
    # no-TLS control (the upgrade is never armed, so nothing can be abandoned),
    # AUTHED_PORT a gsi plane that proves the crash lands before any credential.
    "lc-audit15h-tlsabort": {"port": 30664, "extra": {"CLEAR_PORT": 30665,
                                                      "AUTHED_PORT": 30666}},
    # authdb x a delegated identity (test_audit15h_authdb_delegation.py, §B1.7).
    # Every `u` rule the suite has ever written is `u *`, so no test has ever
    # asked WHICH DN a proxy login is authorized as.  PORT carries an authdb
    # whose rules name the EEC subject; LEAF_PORT carries the same rules
    # rewritten to name the proxy leaf DN instead (the operator mistake, which
    # must NOT grant); OPEN_PORT is the same gsi acceptor with no authdb at all,
    # so a denial elsewhere is attributable to authz and not to the handshake;
    # METRICS_PORT is the Prometheus face — brix_unique_users_total is what
    # shows whether the counted identity agrees with the authorized one.
    "lc-audit15h-authdeleg": {"port": 30667, "extra": {"LEAF_PORT": 30668,
                                                       "OPEN_PORT": 30669,
                                                       "METRICS_PORT": 30670}},
    # macaroon x VOMS / x delegation (test_audit15h_macaroon_voms.py, §B1.10).
    # Every macaroon test in the suite authenticates its issuance request with
    # another macaroon, so no test has ever minted one for an identity that came
    # from a certificate.  PORT is the authdb-gated WebDAV face where the
    # minting proxy is authorized by DN and by VO; FREE_PORT is the same face
    # with no authdb, which is what makes every 403 on PORT attributable to a
    # rule rather than to a token the server could not read.
    "lc-audit15h-macvoms": {"port": 30671, "extra": {"FREE_PORT": 30672}},
    # native TPC x TLS x GSI (test_audit15h_tpc_gsi_tls.py, §C).  The two files
    # that already describe this cross — test_tpc_tls.py and
    # test_tpc_gsi_nginx_source.py — both drive it through a built xrdcp and
    # therefore SKIP on every tree where client/bin/xrdcp is absent, so the
    # destination's outbound pull leg has never actually executed a TLS upgrade
    # or a GSI handshake under pytest.  One source instance carries all three
    # faces the row needs:
    #   PORT         gsi + brix_tls_require all — the cross itself.
    #   GSIONLY_PORT the same gsi acceptor in cleartext, so a failure on PORT
    #                is attributable to the TLS half rather than the GSI half.
    #   ARM_PORT     an anonymous face used ONLY to register the rendezvous key
    #                (the registry is one process-wide SHM table, so a key armed
    #                here is consumable on either authenticated face).  The arm
    #                is the initiating CLIENT's leg, not the destination's; it is
    #                unauthenticated so that the credential under test is the
    #                destination's and nothing else.
    "lc-audit15h-tpcgsitls-src": {"port": 30673,
                                  "extra": {"ARM_PORT": 30674,
                                            "GSIONLY_PORT": 30675}},
    # Four destinations over one template, differing only in the outbound knobs:
    # the full cross, no outbound TLS, no credential to present, and a trust
    # anchor that does not sign the source.
    "lc-audit15h-tpcgsitls-good": {"port": 30676},
    "lc-audit15h-tpcgsitls-notls": {"port": 30677},
    "lc-audit15h-tpcgsitls-nocred": {"port": 30678},
    "lc-audit15h-tpcgsitls-rogueca": {"port": 30679},
    # ...and one with no anchor at all, which is what makes DEFECT CANDIDATE
    # #26 statable as an equivalence rather than a bare wrong-answer pin: on
    # the cleartext-GSI leg this destination and -rogueca behave identically.
    "lc-audit15h-tpcgsitls-noca": {"port": 30680},
    # TPC x sss (test_audit15h_tpc_sss.py, §C).  Three plain single-face
    # instances: the sss-guarded source the destination cannot pull from, the
    # anonymous source it can (the attribution control), and the destination
    # whose CLIENT face is sss and whose keytab is the same one.
    "lc-audit15h-tpcsss-src": {"port": 30681},
    "lc-audit15h-tpcsss-open": {"port": 30682},
    "lc-audit15h-tpcsss-dst": {"port": 30683},
    # WebDAV HTTP-TPC GSI/delegation PUSH leg (test_audit15h_webdav_gsi_push.py,
    # §C).  One nginx, six faces: four initiators that differ by one knob each
    # (delegation default / forwarding off / no service cert / an outbound
    # anchor that does not sign the peer) and two peers that log
    # $ssl_client_s_dn — the lax one a proxy chain can reach, the strict one
    # that will not complete a handshake without a CA-issued client cert.
    "lc-audit15h-wdpush": {"port": 30684,
                           "extra": {"FWDOFF_PORT": 30685,
                                     "NOCERT_PORT": 30686,
                                     "ROGUECA_PORT": 30687,
                                     "PEER_PORT": 30688,
                                     "STRICT_PORT": 30689}},
    # cvmfs × gridftp co-residence (test_audit15h_cvmfs_gridftp.py, §B3.17).
    # One nginx, one worker, both planes: an http{} CVMFS Stratum-0 front on
    # the spec port and two stream{} GridFTP faces over the SAME export root —
    # FTPRW_PORT with brix_gridftp_allow_write on, FTPRO_PORT without it.
    "lc-audit15h-cvmfsftp": {"port": 30690,
                             "extra": {"FTPRW_PORT": 30691,
                                       "FTPRO_PORT": 30692}},
    # Whole-object staged writer WITHOUT the ring (test_audit15i_staged_writev.py,
    # the §B2.13 isolation arm).  One nginx: an http{} WebDAV posix origin on
    # ORIGIN_PORT and a stream{} root:// staged writer over it on the spec port,
    # no brix_io_uring anywhere — the control that separates "the ring broke
    # writev" from "writev never worked on a descriptor-less staged handle".
    "lc-audit15i-stagewv": {"port": 30693,
                            "extra": {"ORIGIN_PORT": 30694,
                                      "POSIX_PORT": 30695}},
    # The backend audience gate (test_audit15j_zero_coverage_stragglers.py).
    # One cleartext WebDAV nginx, two locations that differ ONLY in whether
    # brix_backend_token_audience_ok is present, so "the gate never spoke" can
    # be separated from "there was no gate".  Cleartext on purpose: the gate is
    # about which ORIGIN a captured bearer may be replayed to, and TLS on the
    # inbound leg would add a variable without adding a claim.
    "lc-audit15j-audgate": {"port": 30696},
    # The S3 plane's security options in ONE server block
    # (test_audit15k_s3_coresidency.py).  Seven locations on a single cleartext
    # listener — control, two read-only orderings, the inert WebDAV directives,
    # brix_s3_token, the xrdacc tier, and the dashboard face — because the
    # §Method step-3 matrix scored those pairs co-tested per FILE while no
    # server block in the tree ran any of them together.
    "lc-audit15k-s3cores": {"port": 30698},
    # The HTTP plane's storage tiers and faces in ONE server block
    # (test_audit15l_http_coresidency.py).  SRR + posix + read-through cache +
    # passthrough + an xrdacc tier over a remote origin + the dashboard, all on
    # {PORT}; ORIGIN_PORT is the second server block those remote tiers fetch
    # from (same nginx, worker_processes 2, so a self-fetch cannot deadlock a
    # lone worker); CVMFS_PORT is the third block, because
    # brix_http_proto_exclusive_check() allows exactly one brix protocol per
    # listen port and cvmfs may not join the webdav face.
    "lc-audit15l-httpcores": {"port": 30699,
                              "extra": {"ORIGIN_PORT": 30700,
                                        "CVMFS_PORT": 30701}},
    # The STREAM plane's co-residency backlog in one nginx
    # (test_audit15m_stream_coresidency.py).  {PORT} is the tap proxy carrying
    # client-leg TLS and brix_read_only; ORIGIN_PORT is the writable root
    # origin it fronts; GRIDFTP_PORT is a door wearing the root plane's storage
    # directive, `brix_root on` and the CMS client leg; HTTPBE_PORT is a
    # cluster member whose backend is HTTP_ORIGIN_PORT (same nginx, hence
    # worker_processes 2); MGR_PORT/CMS_PORT are the manager's root and CMS
    # faces — brix_cms_server replaces the stream handler for its whole server
    # block, so it cannot share a listener.  SHADOW_PORT carries the same two
    # protocol directives as GRIDFTP_PORT in the opposite order, which is the
    # only difference between a door and a root server.
    "lc-audit15m-streamcores": {"port": 30702,
                                "extra": {"ORIGIN_PORT": 30703,
                                          "GRIDFTP_PORT": 30704,
                                          "HTTPBE_PORT": 30705,
                                          "MGR_PORT": 30706,
                                          "CMS_PORT": 30707,
                                          "HTTP_ORIGIN_PORT": 30708,
                                          "SHADOW_PORT": 30709}},
    # The WebDAV response surface (test_audit15n_webdav_cors.py), the first of
    # the tranche-14 parse-only directives: the CORS trio and the redirect
    # signing window on one http listener.  MEMBER_PORT/CMS_PORT are a stream
    # data server and the CMS face it registers with — webdav_redirect_
    # dataserver() serves locally when the registry is empty, so a 307 cannot
    # be observed at all until a member has checked in.
    "lc-audit15n-cors": {"port": 30710,
                         "extra": {"MEMBER_PORT": 30711,
                                   "CMS_PORT": 30712}},
    # The CMS timing plane (test_audit15o_cms_windows.py), the tranche-14
    # parse-only directives whose only observable is elapsed time: {PORT} and
    # SLOW_PORT are two managers differing ONLY in brix_cms_locate_timeout,
    # brix_cms_state_fanout and brix_cms_fanout_window, so a value is read off
    # the difference between them rather than off an absolute clock.  CMS_PORT
    # is the registration face both managers and the Python data nodes log
    # into (brix_cms_server replaces the stream handler for its whole server
    # block).  META_PORT is the brix_metadata_only server — a role flag, not a
    # window, but it shares this file because it is the last stream-plane
    # survivor of the sharpened step 2.
    "lc-audit15o-cmswindows": {"port": 30713,
                               "extra": {"SLOW_PORT": 30714,
                                         "CMS_PORT": 30715,
                                         "META_PORT": 30716}},
    # The S3 bearer gate's time window (test_audit15p_s3_token.py).  One port
    # is enough: the four arms are four locations on one http listener that
    # differ ONLY in brix_s3_token_clock_skew and the JWKS they trust, so a
    # single minted token collects four verdicts without a second process.
    "lc-audit15p-s3token": {"port": 30717},
    # The dashboard's transfer-state bands (test_audit15q_dashboard_thresholds
    # .py).  Four dashboard faces carrying four pairs of idle/stalled
    # thresholds, and ROOT_PORT's held-open handle is the ONE SHM slot all four
    # read — so the four are asked at one instant and disagree, which is the
    # measurement.  Four ports rather than four locations because the dashboard
    # route table is URI-absolute (module_dispatch.c:76-85): a face mounted
    # anywhere but /brix/ 404s.
    "lc-audit15q-dashbands": {"port": 30718,
                              "extra": {"MID_PORT": 30719,
                                        "SLOW_PORT": 30720,
                                        "DEF_PORT": 30721,
                                        "ROOT_PORT": 30722}},
    # The TPC leg's trust anchor (test_audit15r_webdav_tpc_cadir.py).  Eight
    # WebDAV locations on one listener differing only in which CA directory they
    # are pointed at, and MOCK_PORT is the self-signed TLS pull source they all
    # dial — one source, because the discriminator is the DESTINATION's trust
    # store, not the source's certificate.
    "lc-audit15r-tpccadir": {"port": 30723,
                             "extra": {"MOCK_PORT": 30724}},
    # The authorization audit sink's level (test_audit15s_authdb_audit.py), the
    # first of the value-granularity tranche.  Eight WebDAV locations on ONE
    # listener differing only in the `brix_authdb_audit` token, read out of the
    # ONE error log a single worker writes — a second listener would make line
    # interleaving a variable and buy nothing.
    "lc-audit15s-auditmodes": {"port": 30725},
    # The cluster role at value granularity (test_audit15t_cms_role.py).  Unlike
    # the two files above, this one CANNOT fold onto a single listener: the role
    # is a `server {}`-level directive whose whole observable is the LOGIN Mode
    # word one node sends its manager, so each token needs its own node.  Six
    # nodes, one per arm of the table (`auto`, `auto` + manager_mode, the
    # directive absent, `peer`, `proxy`, and `server` as the control).  The
    # manager peer each one dials is an in-process Python socket on a free_port,
    # not a ledger port.
    "lc-audit15t-role-auto":   {"port": 30726},
    "lc-audit15t-role-automgr": {"port": 30727},
    "lc-audit15t-role-absent": {"port": 30728},
    "lc-audit15t-role-peer":   {"port": 30729},
    "lc-audit15t-role-proxy":  {"port": 30730},
    "lc-audit15t-role-server": {"port": 30731},
    # CRL strictness at value granularity (test_audit15u_crl_mode.py).  Back to
    # one instance: brix_crl_mode is a `server {}`-level directive whose whole
    # observable is a login verdict, so five listeners over ONE hashed CA
    # directory and ONE CRL directory carry the entire table — `off`, `try`,
    # `require`, the directive absent (the merge default), and `try` with no
    # brix_crl, which is the half of the token that arms nothing.  Sharing the
    # store source across the five is the point: it is what proves the
    # config-parse store cache is keyed on the mode and not on the paths.
    "lc-audit15u-crlmode": {"port": 30732, "extra": {"TRY_PORT": 30733,
                                                     "REQ_PORT": 30734,
                                                     "DEF_PORT": 30735,
                                                     "NOCRL_PORT": 30736}},
    # signing_policy strictness at value granularity
    # (test_audit15v_signing_policy.py).  Same shape as the row above and for
    # the same reason: brix_signing_policy is a `server {}`-level directive
    # whose whole observable is a login verdict, so four listeners over ONE
    # hashed CA directory carry the table — `off`, `on`, `require` and the
    # directive absent (the merge default).  The four deliberately name an
    # IDENTICAL brix_trusted_ca: that is what proves the config-parse store
    # cache is keyed on the mode and not on the path.
    "lc-audit15v-sigpolicy": {"port": 30737, "extra": {"ON_PORT": 30738,
                                                       "REQ_PORT": 30739,
                                                       "DEF_PORT": 30740}},
    # brix_security_level at value granularity
    # (test_audit15w_security_level.py).  Six listeners on one instance — one
    # per token plus the absent directive — because the level is a `server {}`
    # directive whose observables are a per-connection advertisement byte and a
    # per-request verdict, so the whole gradient is drivable from one process.
    # All six are auth none (the unsignable session the policy is written
    # against) and all six set brix_signing_required on, which is what turns
    # the level into a verdict rather than a log line.
    "lc-audit15w-seclevel": {"port": 30741, "extra": {"CMP_PORT": 30742,
                                                      "STD_PORT": 30743,
                                                      "INT_PORT": 30744,
                                                      "PED_PORT": 30745,
                                                      "DEF_PORT": 30746}},
    # brix_backend_delegation at value granularity
    # (test_audit15x_backend_delegation.py).  Twelve WebDAV locations on ONE
    # listener — the mode is a location-level directive and the observable is
    # what the ORIGIN was asked for, so every mode can share a port as long as
    # it does not share a URI.  ORIGIN_PORT is the capturing http:// origin the
    # test runs in-process: it records the Authorization header of every
    # request, which is the only way to see whether the caller's own credential
    # reached the backend leg or was dropped on the way.
    "lc-audit15x-deleg": {"port": 30747, "extra": {"ORIGIN_PORT": 30748}},
    # The CVMFS origin-policy enums at value granularity
    # (test_audit15y_cvmfs_origin_policy.py).  TWO cvmfs locations on ONE
    # listener is the whole subject: brix_cvmfs_origin_http_version and
    # brix_cvmfs_fill_retry_policy are location-level directives whose merge
    # writes a process-wide global, so a second location is the only thing that
    # can show which one actually decides.  MOCK_PORT carries the python mock
    # Stratum-1 the fills come from.  DEAD_PORT is reserved and NEVER bound: it
    # is the unreachable half of the DEAD|LIVE origin set the retry policy is
    # measured over, and holding a ledger slot for it is what stops another
    # suite from making it answer.
    "lc-audit15y-cvpolicy": {"port": 30749,
                             "extra": {"MOCK_PORT": 30750, "DEAD_PORT": 30751}},
    # The five never-written disabling tokens at value granularity
    # (test_audit15z_disable_tokens.py).  One process, three servers: the
    # question is always "does writing the off/none token differ from writing
    # nothing", and a single server cannot answer it — brix_seccomp's effect is
    # a process-global that only ratchets up, so SECOND_PORT carries the sibling
    # whose token decides for both, and the primary carries the one whose token
    # is under test.  GSI_PORT is a brix_auth gsi listener: brix_gsi_signed_dh
    # off is visible in the kXR_login sec token ("v:10000" vs "v:10600") before
    # any certificate is exchanged, so the arm needs a GSI face but no Grid PKI.
    "lc-audit15z-disable": {"port": 30752,
                            "extra": {"SECOND_PORT": 30753, "GSI_PORT": 30754}},
    # The five never-written tokens that restate a default
    # (test_audit15aa_default_tokens.py).  Two instances, because the subject is
    # a process-global and a control for one cannot live in the same process as
    # the case:
    #   lc-audit15aa-default — PORT is the WebDAV front carrying both the
    #     checksum-format pair and the three redirect-scheme locations.
    #     MEMBER_PORT/CMS_PORT are the same pair nginx_audit15n_cors.conf uses:
    #     webdav_redirect_dataserver() DECLINES to a local serve while the CMS
    #     registry is empty, so a member must register before any Location
    #     header exists to read a scheme out of.  SSI_PORT / SSI2_PORT are two
    #     cta faces differing only in brix_ssi_cta_executor, and the pair is the
    #     whole point: the executor is pushed into a per-worker global on every
    #     SSI open, so one face can only be shown to retarget the other's
    #     in-flight request while both live in one worker.
    #   lc-audit15aa-clean — a WebDAV face in a SEPARATE process that writes
    #     `text` and nothing else.  brix_webdav_checksum_xattr_format's merge
    #     writes a process-wide global, so the control that proves `text` is
    #     reachable at all cannot share a process with the `xrdcks` location.
    "lc-audit15aa-default": {"port": 30755,
                             "extra": {"MEMBER_PORT": 30756, "CMS_PORT": 30757,
                                       "SSI_PORT": 30758, "SSI2_PORT": 30759}},
    "lc-audit15aa-clean": {"port": 30760},
    # The OCSP flag pair at value granularity (test_audit16a_ocsp_flags.py) —
    # the 16th tranche, which re-runs the audit's Method over the 128
    # `ngx_conf_set_flag_slot` directives one (directive, VALUE) at a time.
    # brix_ocsp_enable / brix_ocsp_soft_fail are `server {}` flags whose whole
    # observable is a GSI login verdict, so four listeners on ONE instance carry
    # the table: `enable off`, `enable on` + `soft_fail on`, `enable on` +
    # `soft_fail off`, and `enable on` with soft_fail ABSENT (the merge
    # default).  RESP_PORT carries the controllable OCSP responder
    # (tests/lib/ocsp_responder.py) that the AIA extension of every credential
    # points at — the suite had none, which is why no test had ever entered the
    # revocation branch.  DEAD_PORT is reserved and NEVER bound: it is the
    # responder-unreachable half of the table, and holding a ledger slot for it
    # is what stops another suite from making it answer.
    "lc-audit16a-ocsp": {"port": 30761,
                         "extra": {"ON_PORT": 30762, "HARD_PORT": 30763,
                                   "DEF_PORT": 30764, "RESP_PORT": 30765,
                                   "DEAD_PORT": 30766}},
    # The third OCSP flag, same tranche (test_audit16b_ocsp_stapling.py).
    # brix_ocsp_stapling is a TLS-context property rather than a login verdict,
    # so its three arms are three root:// listeners with `brix_tls on` and no
    # auth: stapling off, stapling on, and stapling ABSENT for the merge
    # default.  One process is enough — SSL_CTX_set_tlsext_status_cb is
    # per-server-block, and three contexts in one worker is exactly what proves
    # the callback is not process-global.
    "lc-audit16b-staple": {"port": 30767,
                           "extra": {"ON_PORT": 30768, "DEF_PORT": 30769}},
    # brix_http_query_token, same tranche (test_audit16c_query_token.py), the
    # fourth of the seven directives whose BOTH arms are unwritten.  One http
    # listener is enough and one is required: the three arms (on, off, absent)
    # are three WebDAV locations, and the finding is what reaches the ONE access
    # log the shared server writes — a second process could not compare them.
    "lc-audit16c-qtoken": {"port": 30770},
    # brix_cvmfs_origin_reuse_conn, same tranche
    # (test_audit16d_origin_reuse.py), the fifth of the seven directives whose
    # BOTH arms are unwritten.  TWO cvmfs locations on ONE listener, for the
    # same reason lc-audit15y-cvpolicy needs them: the merge writes a
    # process-wide global (cvmfs_module_merge.c:270), so a second location is
    # the only thing that can show which one actually decides.  MOCK_PORT
    # carries a KEEP-ALIVE mock Stratum-1 — the flag's whole effect is
    # CURLOPT_FORBID_REUSE|FRESH_CONNECT, so the origin's accept count is the
    # measurement and an HTTP/1.0 origin (this mock's default) would read as
    # "no reuse" on both arms.
    "lc-audit16d-reuse": {"port": 30771, "extra": {"MOCK_PORT": 30772}},
    # brix_krb5_ip_check, same tranche (test_audit16e_krb5_ip_check.py), the
    # sixth of the seven directives whose BOTH arms are unwritten.  Three stream
    # listeners in ONE process — ip_check on, off, and absent — because unlike
    # lc-audit16d-reuse this flag really is per-server (srv_conf, not a global),
    # and three planes off one keytab is what says so.  RELAY_PORT is not bound
    # by nginx at all: it is the in-process TCP relay the test runs, whose only
    # job is to connect onward from a SECOND loopback address so the server's
    # peer differs from the address the ticket was issued for — the AP-REQ
    # address check has no other observable.  METRICS_PORT is the http face
    # carrying brix_auth_total, which is where a refusal is counted.
    "lc-audit16e-ipcheck": {"port": 30773,
                            "extra": {"OFF_PORT": 30774, "ABSENT_PORT": 30775,
                                      "RELAY_PORT": 30776,
                                      "METRICS_PORT": 30777}},
    # The five S3 LOCATION flags whose `off` arm was never written anywhere —
    # brix_s3_verify_chunk_signatures, brix_s3_allow_unsigned_session_token,
    # brix_s3_token, brix_s3_list_cache, brix_s3_zip_access — same tranche
    # (test_audit16f_s3_location_flags.py).  ONE port for sixteen locations:
    # every arm is a location on a single http listener, which is forced rather
    # than chosen — s3_parse_uri() reads the bucket out of the first URI
    # segment, so an arm needs its own bucket and its own location prefix
    # spelling that bucket, and locations are free while listeners are not.
    # /metrics rides the same listener (brix_s3_auth_total{result=...} is where
    # a refusal is counted), so the whole file costs a single slot.
    "lc-audit16f-s3flags": {"port": 30778},
    # The six pmark flags whose `off` arm was never written anywhere —
    # brix_pmark, brix_pmark_firefly, brix_pmark_flowlabel,
    # brix_pmark_scitag_cgi, brix_pmark_firefly_origin, brix_pmark_http_plain —
    # same tranche (test_audit16g_pmark_flags.py).  ONE port for thirteen WebDAV
    # locations — eighteen arms (three per flag) collapsed onto thirteen, since
    # the reference arm writes only the master switch and http_plain and is
    # therefore the `absent` arm of the other four at the same time — plus
    # /metrics: a pmark arm is a
    # brix_pmark_conf_t, which is per-location, so an arm costs a location and
    # not a listener.  The SAME port is also bound on the IPv6 loopback when the
    # host has one (the flow-label technique only exists over real IPv6), which
    # is a second listen on one slot, not a second slot.  The firefly collector
    # is an in-process UDP sink on an ephemeral port (the documented exemption
    # test_pmark.py already uses) and the origin report is fixed at 10514 inside
    # pmark.h, so neither is a ledger port.
    "lc-audit16g-pmark": {"port": 30779},
    # The six shared-http flags whose `off` arm was never written anywhere —
    # brix_read_only, brix_verify_write, brix_compress, brix_strict_security,
    # brix_session_log, brix_backend_krb5_forwardable — same tranche
    # (test_audit16h_shared_http_flags.py).  ONE port for twenty-two WebDAV
    # locations across FIVE server_name vhosts: all six are BRIX_HTTP_ALL_CONF,
    # so half the subject is what a child location can take back from a value its
    # server wrote, and a server-level arm needs a whole server{} — which on one
    # listen is another `server_name`, selected with a Host: header rather than
    # with a port.  ORIGIN_PORT is an http:// origin the test runs itself: §C
    # needs a backend that hands back something other than what it stored, which
    # is the fault a write-verification read-back exists to catch, and no posix
    # export can lie.
    "lc-audit16h-shared": {"port": 30780, "extra": {"ORIGIN_PORT": 30781}},
    # The nine CVMFS resilience flags whose `off` arm was never written anywhere —
    # brix_cvmfs_bundle, _dict, _delta, _scrub, _learn, _swarm, _unified_origin,
    # _trace and brix_scvmfs — same tranche
    # (test_audit16i_cvmfs_resilience_flags.py).  ONE nginx port: every arm is a
    # separate INSTANCE on the lane's single ledger port, because three of the nine
    # (_scrub, _learn, _swarm) register their service per cvmfs EXPORT and every
    # cvmfs cache location in a config shares the export "/", and a fourth
    # (_trace) writes a process-wide latch — so two arms in one process do not
    # measure two arms, they measure whichever merged last.  MOCK_PORT is the live
    # Stratum-1 every fill comes from.  DEAD_PORT is reserved in the ledger and
    # never bound: it is the unreachable authority §G's unified_origin proxy face
    # is aimed at, and the dead half of §F's seed ring and §J's origin pair.
    "lc-audit16i-cvmfs": {"port": 30782,
                          "extra": {"MOCK_PORT": 30783, "DEAD_PORT": 30784}},
    # The five node-capability flags whose `off` arm was never written anywhere —
    # brix_metadata_only, brix_supervisor, brix_virtual_redirector,
    # brix_collapse_redir, brix_recover_writes — same tranche
    # (test_audit16j_root_caps_flags.py).  TEN stream servers in ONE process, and
    # therefore ten ports: all five are NGX_STREAM_SRV_CONF, and a stream server
    # is selected by the port it listens on — there is no `server_name` to pick
    # one out of a shared listen the way the http-plane files above do, so an arm
    # costs a listener.  One process rather than ten is deliberate: these are
    # srv_conf flags, so ten verdicts from one worker is also the statement that
    # the scope really is per-server.  PORT is the reference (none of the five
    # written) and OFF_PORT is the same server plus all five `off`; SUPER_PORT
    # isolates brix_supervisor from brix_manager_mode, which the suite's only
    # other supervisor config entangles it with; WRTS_PORT carries the per-handle
    # kXR_recoverWrts journal; MAP_PORT is a static manager_map holding the two
    # subjects that cannot interfere (vrdr `off` and metadata_only `on`);
    # COLLON_PORT and COLLOFF_PORT are the collapse-cache arms, which need
    # brix_manager_mode to reach the cache at all, and CMS_PORT + DS_PORT are the
    # registration listener and the data node that make the manager registry
    # non-empty — without them the dynamic path declines and neither arm consults
    # the cache.  ROLE_PORT is `brix_cms_role supervisor` without
    # `brix_supervisor`, the other spelling of the same word.
    "lc-audit16j-caps": {"port": 30785,
                         "extra": {"OFF_PORT": 30786, "SUPER_PORT": 30787,
                                   "WRTS_PORT": 30788, "MAP_PORT": 30789,
                                   "COLLON_PORT": 30790, "COLLOFF_PORT": 30791,
                                   "CMS_PORT": 30792, "DS_PORT": 30793,
                                   "ROLE_PORT": 30794}},
    # The five location-scoped WebDAV flags whose `off` arm was never written
    # anywhere — brix_webdav, brix_webdav_upload_resume, brix_delegation_endpoint,
    # brix_webdav_cors_credentials, brix_webdav_tape_rest — same tranche
    # (test_audit16n_webdav_module_flag_arms.py).  ONE port for twenty locations
    # across FIVE server_name vhosts.  All five are NGX_HTTP_LOC_CONF and nothing
    # else (webdav/module_commands.c:50, :271, :304, :378, :295), so there is no
    # server-level arm to buy a listener for; the vhosts exist because two of the
    # five gate an ABSOLUTE URI prefix (/api/v1/ for tape_rest, and the
    # /.well-known/brix-delegation/ gridsite form) and a URI space holds exactly
    # one arm per server — so `on`, `off`, absent and one mixed attribution
    # control are four `location /` blocks that cannot share a server_name.
    "lc-audit16n-webdav": {"port": 30795},
    # The three MAIN|SRV|LOC WebDAV flags whose `off` arm was never written
    # anywhere — brix_webdav_zip_access, brix_webdav_require_digest,
    # brix_webdav_dig — same tranche
    # (test_audit16o_webdav_scoped_flag_arms.py).  ONE port for eleven locations
    # across SEVEN server_name vhosts.  All three are declared in three scopes
    # (webdav/module_commands.c:405, :440, :454), which is what makes the reading
    # this file owns exist: `on` at SERVER scope with `off` in one location beneath
    # it, an opt-out absence cannot express.  Still no listener to buy — none of
    # the three touches TLS or the socket — but `brix_webdav_dig` gates the
    # ABSOLUTE prefix /.well-known/dig/, so its four arms are four `location /`
    # blocks that cannot share a server_name.
    "lc-audit16o-webdav-scoped": {"port": 30796},
    # brix_webdav_proxy_certs, the last arm-gap of brix_webdav_commands and the
    # only one that needs a socket — same tranche (test_audit16p_proxy_certs.py).
    # THREE TLS listeners rather than three vhosts: the flag's entire effect is
    # X509_V_FLAG_ALLOW_PROXY_CERTS on ONE SSL_CTX (webdav/postconfig.c:247-256),
    # and an SSL_CTX belongs to a LISTENING server — the verify parameters are in
    # place before the ClientHello, so no Host header can pick between two arms the
    # way seven vhosts share 30796's port.  `on` at server scope, `off` at server
    # scope (reconfigured in place for the ABSENT arm, which therefore buys no
    # fourth port), and `on` written inside a `location{}` — a placement the
    # declaration allows (module_commands.c:229) and the postconfig hook cannot
    # see, since it reads the SERVER's loc_conf.  That third listener is the file's
    # finding, not a spare arm.
    "lc-audit16p-proxy-certs": {"port": 30797,
                                "extra": {"OFF_PORT": 30798,
                                          "LOC_PORT": 30799}},
    # The three acc-engine flags of root/stream/directives_auth.h whose `off` arm
    # was never written anywhere — brix_acc_pgo, brix_acc_resolve_hosts,
    # brix_acc_encoding — same tranche
    # (test_audit16q_acc_engine_flag_arms.py).  THREE root:// listeners plus one
    # http listener in one process.  The three root:// ports are not three
    # features: they are `off`, `on` and absent standing side by side, which is
    # the only arrangement that can tell a per-server flag from a process-wide
    # one — and one of these three turns out to be the latter, since
    # brix_acc_build() installs it into a global (acc/config.c:47) once per
    # engine-carrying server.  The http port is the other plane's declaration of
    # the same three names (webdav/module_commands.c:103, :111, :119), whose
    # tables are built LAZILY by the first request, so it is the only way to
    # make a REQUEST change what the root:// servers do.
    "lc-audit16q-acc-engine": {"port": 30800,
                               "extra": {"B_PORT": 30801,
                                         "C_PORT": 30802,
                                         "HTTP_PORT": 30803}},
    # Four root:// acceptors over ONE export for the two CSI integrity flags of
    # root/stream/directives_auth.h at value granularity (tranche 16, file 18;
    # test_audit16r_csi_flag_arms.py).  brix_csi_require and brix_csi_trust_fs
    # are read out of the per-server conf on every kXR_open
    # (read/open_resolved_file_finalize.c:70-88), so four arms in one worker ARE
    # four arms — and the export has to be shared, because the reading is what
    # the SAME file does through different acceptors: one tags it, one verifies
    # it, one trusts it, one demands a record.
    "lc-audit16r-csi": {"port": 30804,
                        "extra": {"B_PORT": 30805,
                                  "C_PORT": 30806,
                                  "D_PORT": 30807}},
    # Three krb5 acceptors over ONE keytab and ONE export for the last arm-gap of
    # root/stream/directives_auth.h (tranche 16, file 19;
    # test_audit16s_krb5_delegate_arms.py): brix_krb5_delegate on, the arm the
    # corpus never wrote (off), and the directive absent.  The gate is
    # `conf->krb5.delegate` read per connection (auth/krb5/deleg_capture.c:25),
    # so three arms in one worker are three arms — and one keytab is the point:
    # the same principal, the same client and the same ccache have to reach all
    # three, or a difference in rounds could be a difference in credentials.
    # Same shape as lc-audit16e-ipcheck one entry up, for the same reasons:
    # RELAY_PORT is bound by the test, not by nginx — here it counts the
    # kXR_authmore rounds on the wire, which is the only place the extra
    # round-trip `on` costs a client is directly visible — and METRICS_PORT is
    # the http face carrying brix_auth_total, the counter that says whether an
    # operator can see a delegation that failed.
    "lc-audit16s-krb5deleg": {"port": 30808,
                              "extra": {"OFF_PORT": 30809,
                                        "ABSENT_PORT": 30810,
                                        "RELAY_PORT": 30811,
                                        "METRICS_PORT": 30812}},
    # Four root:// acceptors over ONE export for the inline-compression pair of
    # root/stream/directives_security.h (tranche 16, file 20;
    # test_audit16t_compress_flag_arms.py): brix_read_compress and
    # brix_write_compress, whose `off` arm the corpus never wrote — every
    # existing test_compression_*.py runs against nginx_shared.conf, where both
    # are on, so what `off` RESTORES had never been read.  Four rather than three
    # because these two flags are independent: the direction is chosen per
    # kXR_open by `enabled = is_write ? conf->write_compress : conf->read_compress`
    # (read/open_request_opaque.c:71), so the reading needs a both-on acceptor, a
    # both-off one, one with the pair unwritten, and a MIXED one that proves the
    # two slots are not secretly the same bit.  One export because the reading is
    # what the SAME bytes do through different acceptors — a difference in
    # negotiated codec must not be a difference in file.  No METRICS_PORT: this
    # pair has no counter anywhere in src/observability, and its whole
    # operator-visible face is the kXR_open reply plus `query config`.
    "lc-audit16t-compress": {"port": 30813,
                             "extra": {"OFF_PORT": 30814,
                                       "ABSENT_PORT": 30815,
                                       "MIXED_PORT": 30816}},
    # Four GSI acceptors plus a controllable responder for the last unentered
    # branch of the OCSP family (tranche 16, file 21;
    # test_audit16u_ocsp_nonce.py): brix_ocsp_require_nonce, which reaches NO
    # config in the corpus in EITHER arm — the replay guard (CWE-294) added with
    # the flag has only ever been source-pinned, as test_ocsp_require_nonce.py
    # says in its own docstring ("Live OCSP negatives need a controllable
    # responder that this suite does not stand up").  It does now:
    # lib/ocsp_responder.py already ships --omit-nonce for exactly this case.
    # Four planes because the flag composes with soft_fail: on/hard, off/hard,
    # unwritten/hard, and on/SOFT — the last asking whether the fail-open
    # performance flag masks a deny the replay guard raised, which is the shape
    # #93 already found once on this tranche.
    #
    # THREE responder ports, not one, and they are bound by the test's own
    # subprocesses rather than by nginx.  The responder's behaviour is fixed at
    # startup (--omit-nonce is an argv switch) while the responder a login talks
    # to is baked into the CREDENTIAL — brix_ocsp_check_cert reads the URL out
    # of the leaf's AIA extension (X509_get1_ocsp(leaf), ocsp.c:143), so a
    # certificate cannot change its mind about which port to ask.  One responder
    # per behaviour is therefore the only way to hold the plane and the answer
    # independent: RESP_PORT echoes the nonce (the control), NONCELESS_PORT
    # never does (the subject), BADNONCE_PORT echoes a DIFFERENT one — the
    # boundary that proves the flag's scope is "missing", not "checked at all",
    # since OCSP_check_nonce reports a mismatch as 0 and ocsp_request.c:236
    # denies that in BOTH arms.
    "lc-audit16u-ocspnonce": {"port": 30817,
                              "extra": {"OFF_PORT": 30818,
                                        "ABSENT_PORT": 30819,
                                        "SOFT_PORT": 30820,
                                        "RESP_PORT": 30821,
                                        "NONCELESS_PORT": 30822,
                                        "BADNONCE_PORT": 30823}},
    # Six planes for the densest entry in the flag-arm census (tranche 16, file
    # 22; test_audit16v_tpc_off_arms.py): src/protocols/root/stream/
    # directives_tpc.h has SEVEN flags whose disarming arm is written nowhere in
    # the corpus — allow_local/source_guard/require_pgwrite/outbound_tls/
    # require_source_size/delegate `off`, and outbound_passthrough `on`.  Six and
    # not two because the arms fall into three groups that cannot share a plane:
    # the two egress gates need a plane where each is armed alone (ARMED,
    # ORDER_PORT) to tell their refusals apart, the transfer-time arms need a
    # destination that can actually reach a loopback source (PULL_PORT) while the
    # all-disarmed plane by construction cannot (OFF_PORT), and the tap-proxy
    # override needs its own listener because it is the one plane whose subject
    # is what postconfiguration did to the value (DELEG_PORT).  ABSENT_PORT is
    # the control every one of them is read against: four of the seven tokens
    # spell the compiled default, so the file has to measure that the token and
    # the omission agree before it can attribute anything to either.
    "lc-audit16v-tpcoff": {"port": 30824,
                           "extra": {"OFF_PORT": 30825,
                                     "ABSENT_PORT": 30826,
                                     "PULL_PORT": 30827,
                                     "ORDER_PORT": 30828,
                                     "DELEG_PORT": 30829}},
    # 2026-08-18 (16th tranche, 23rd file): the WebDAV plane's egress-policy
    # OFF arms (test_audit16w_webdav_tpc_egress_off_arms.py).  Thirteen
    # locations over ONE listener — every directive in the subject is
    # NGX_HTTP_LOC_CONF, so one server carries the whole cross and the planes
    # cannot drift apart on anything but the knob under test.  MOCK_PORT is the
    # capturing TLS source: it answers a pull, sinks a push, and reports which
    # credential (if any) travelled — the only witness for a refusal that must
    # happen BEFORE any outbound leg.
    "lc-audit16w-wdegress": {"port": 30830, "extra": {"MOCK_PORT": 30831}},
    # 2026-08-18 (16th tranche, 24th file): every arm-gap left in
    # root/stream/directives_security.h (test_audit16x_stream_security_off_arms.py).
    # Four flags, and all four are NGX_STREAM_SRV_CONF, so an arm cannot share a
    # listener with its twin the way a location-scoped one can: each of the four
    # gets the written OFF token, the omission, and the armed control, which is
    # twelve acceptors in one worker over one export.  Twelve rather than four
    # because three of the four merge the token and the omission to the same
    # value, and that equality is the thing the corpus asserts everywhere and has
    # never measured.
    "lc-audit16x-secoff": {"port": 30832,
                           "extra": {"ZIP_ABS_PORT":  30833,
                                     "ZIP_ON_PORT":   30834,
                                     "SCR_OFF_PORT":  30835,
                                     "SCR_ABS_PORT":  30836,
                                     "SCR_ON_PORT":   30837,
                                     "ZTN_OFF_PORT":  30838,
                                     "ZTN_ABS_PORT":  30839,
                                     "ZTN_ON_PORT":   30840,
                                     "TLS_OFF_PORT":  30841,
                                     "TLS_ABS_PORT":  30842,
                                     "TLS_ON_PORT":   30843}},
    # 16y: the outbound redirector TLS leg driven live.  Eight nginx planes —
    # verification is server-scoped, and so are the CA and the pinned name, so
    # every trust cell needs its own `listen` — plus three gotoTLS stub
    # upstreams, one per certificate the planes are asked to believe.
    "lc-audit16y-uptls": {"port": 30844,
                          "extra": {"ON_PORT":         30845,
                                    "EVIL_PORT":       30846,
                                    "NOCA_OFF_PORT":   30847,
                                    "CA_OFF_PORT":     30848,
                                    "HOSTPIN_PORT":    30849,
                                    "IP_PIN_PORT":     30850,
                                    "FALLBACK_PORT":   30851,
                                    "STUB_GOOD_PORT":  30852,
                                    "STUB_EVIL_PORT":  30853,
                                    "STUB_OTHER_PORT": 30854}},
    # 16z: the WebDAV mirror's auth policy and its divergence NOTICE, both
    # driven live.  One nginx with seven locations one directive apart, plus two
    # recording shadows — one that agrees with the primary and one that never
    # does, because a divergence is a disagreement between two statuses and you
    # cannot manufacture one with a single upstream.
    "lc-audit16z-mirror": {"port": 30855,
                           "extra": {"SHADOW_OK_PORT":   30856,
                                     "SHADOW_MISS_PORT": 30857}},
    # 16aa: the manager-side redirect-to-dataserver flag, both arms on ONE
    # manager.  The `off` arm only means something when the `on` arm really
    # redirects, and that needs a populated CMS registry — hence a stream
    # manager port and a CMS server port next to the WebDAV front, plus a
    # recording data server on the port the Location is built to name.
    "lc-audit16aa-rdr": {"port": 30858,
                         "extra": {"CMS_PORT":     30859,
                                   "HTTP_PORT":    30860,
                                   "DS_HTTP_PORT": 30861}},
    # 16ab: the two arm-gaps of the dashboard module's command table — the
    # admin factor combiner and the VFS export browser.  ONE port for fourteen
    # planes: both directives are location-scoped and both endpoints live at a
    # fixed URI, so the planes are `server_name` vhosts sharing one `listen`.
    "lc-audit16ab-admin": {"port": 30862},
    # 16ac: the last never-`off` flag of the root/stream command table,
    # brix_manager_mode — the directive that decides whether a node redirects
    # or serves.  EIGHT ports because every plane is a `listen`: the flag is
    # NGX_STREAM_SRV_CONF, so `on`, `off` and absent are three servers, the
    # dynamic redirect needs a CMS listener and a data node to select out of,
    # the auto-derivation `brix_cms_server on` performs needs its own pair
    # (derived, and derived-then-overridden), and the export census that reads
    # brix_server_has_runtime_export() from outside the process is an HTTP
    # dashboard on the same instance.
    "lc-audit16ac-mgrmode": {"port": 30863,
                             "extra": {"OFF_PORT": 30864, "ABS_PORT": 30865,
                                       "CMS_PORT": 30866, "DS_PORT": 30867,
                                       "AUTO_PORT": 30868, "OVER_PORT": 30869,
                                       "HTTP_PORT": 30870}},
    # 16ad: the configuration surface that parses, merges, allocates and is
    # then never read — the five brix_webdav_open_file_cache* directives and
    # brix_backend_passthrough_persist.  ONE port for eight planes: every
    # subject is NGX_HTTP_LOC_CONF (or below), the WebDAV resolver already puts
    # each location's URI prefix on its own subtree of the one export, and an
    # arm that changes nothing needs a control beside it far more than it needs
    # a listener of its own.
    "lc-audit16ad-inert": {"port": 30871},
    # 16ae: the three gridftp gates whose DISARMING arm no config has written —
    # brix_gridftp_verify_write, _require_allo_size and _gsi.  All three are
    # NGX_STREAM_SRV_CONF, so a plane is a `listen`: five write planes (both
    # tokens written, neither written, both armed, and the two crosses) and
    # three GSI planes (off, absent, on) that all carry the same certificate,
    # key and CA so the flag is measured apart from its material.
    "lc-audit16ae-ftpgates": {"port": 30872,
                              "extra": {"ABS_PORT": 30873, "ON_PORT": 30874,
                                        "VONLY_PORT": 30875, "AONLY_PORT": 30876,
                                        "GOFF_PORT": 30877, "GABS_PORT": 30878,
                                        "GON_PORT": 30879}},
    # 16af: the two OCI flags whose SECURING arm no config has written —
    # brix_oci_registry_allow_anonymous (`on` in configs/oci_registry.conf; the
    # authenticating leg of oci/registry_lane.py passes anonymous=False, which
    # renders the slot EMPTY) and brix_oci_mirror_insecure (`on` in two configs
    # and nowhere `off`).  The mirror flag needs no port: the field it merges
    # into is read nowhere, so its whole subject is `nginx -t`.  Anonymity needs
    # SEVEN — four cleartext registries (open, the written `off`, its omission,
    # and the issuers-plus-open composition no lane has ever built) and three
    # TLS listeners, because the load-time gate accepts ssl_verify_client `on`,
    # `optional` and `optional_no_ca` as the same "authenticated context" and
    # only a listener each can say what that acceptance is worth.
    "lc-audit16af-ociarms": {"port": 30880,
                             "extra": {"OFF_PORT": 30881, "ABS_PORT": 30882,
                                       "BOTH_PORT": 30883, "VON_PORT": 30884,
                                       "VOPT_PORT": 30885, "TLS_PORT": 30886}},
    # 16ag: the two httpguard flags whose unwritten arm is the one an operator
    # reaches for — brix_guard (`on` in eleven configs, `off` in none: every
    # "the WAF is not running" control in the tree is rendered as ABSENCE) and
    # brix_guard_default_signatures (`off` in nginx_guard_knobs.conf, the one
    # place the token appears anywhere; `on` — which is also the merge default —
    # in none).  EIGHT faces because the guard classifies the whole r->uri and
    # compares grammar prefixes against its head, so sibling locations would
    # measure the location prefix as much as the arm: six single-location
    # listeners for the arm matrix, plus two that write the inheritance in both
    # directions (server-level on with a location opting out, and the mirror).
    # The three NGX_STREAM_SRV_CONF flags whose control arm no config writes
    # (test_audit16ah_frm_hc_arms.py).  Two instances: the registryless process
    # (eight fronts) and the one server block that stands the process-singleton
    # stage registry up (four fronts).  Every front is a `listen` because all
    # three subjects are stream-server-scoped — there is no location to fold on.
    # 16ai: brix_gridftp_allow_write, the fourth GridFTP gate and the one file
    # 31 left.  Thirty-one configs write `on`; the token `off` appears in NO
    # config in the tree — nginx_gridftp_metrics.conf's own header says its
    # {RO_PORT} server writes it and the server block simply omits the line,
    # and nginx_gridftp_plain_ev_ro.conf is an absence by construction.  FOUR
    # gateways: the writable control, the written `off`, the same server with
    # the line deleted, and `off` beside an armed brix_gridftp_verify_write —
    # plus one HTTP face, because the transfer gate books a `forbidden` op row
    # and the five command-level gates book nothing, which is only visible on a
    # /metrics scrape of the shared process-wide zone.
    # 16aj: brix_cache_store_endpoint, the one directive declared under a
    # single name on BOTH planes — webdav/module_commands.c:74 (MAIN|SRV|LOC,
    # custom setter, writes the WebDAV *and* S3 loc-confs) and
    # root/stream/module.c:239 (STREAM_SRV, stock flag slot).  The corpus wrote
    # `on` in ONE stream server and nowhere else, in any scope, on either plane;
    # the token `off` appears in no config in the tree.  Nine http vhosts over
    # TWO listeners: the arms have to be compared over the same export bytes and
    # a WebDAV location maps its URI straight under the backend, so two prefixes
    # would be two files — but WebDAV and S3 cannot share a `listen` (a
    # load-time refusal, "one brix protocol per port"), so the five WebDAV
    # vhosts and the four S3 vhosts get one listener each.  Plus three stream
    # listeners, because the stream declaration is server-scoped and has no
    # location to fold onto.
    "lc-audit16aj-storeep": {"port": 30912,
                             "extra": {"OFF_PORT": 30913, "ABS_PORT": 30914,
                                       "HTTP_PORT": 30915, "S3_PORT": 30916}},
    "lc-audit16ai-ftpwrite": {"port": 30907,
                              "extra": {"OFF_PORT": 30908, "ABS_PORT": 30909,
                                        "VER_PORT": 30910, "HTTP_PORT": 30911}},
    "lc-audit16ah-frmhc": {"port": 30895,
                           "extra": {"HCABS_PORT": 30896, "HCON_PORT": 30897,
                                     "HCZERO_PORT": 30898, "FRMOFF_PORT": 30899,
                                     "FRMABS_PORT": 30900, "FRMNOC_PORT": 30901,
                                     "ASYNC_PORT": 30902}},
    "lc-audit16ah-frmreg": {"port": 30903,
                            "extra": {"BLEED_PORT": 30904,
                                      "SECOND_PORT": 30905,
                                      "ABS_PORT": 30906}},
    "lc-audit16ag-guardarms": {"port": 30887,
                               "extra": {"ABS_PORT": 30888, "ON_PORT": 30889,
                                         "DEFON_PORT": 30890,
                                         "DEFOFF_PORT": 30891,
                                         "BARE_PORT": 30892,
                                         "SRVON_PORT": 30893,
                                         "SRVOFF_PORT": 30894}},
    # Private empty redirector for test_redirector_no_server.py.  It must not
    # share cluster-redir: the full fast session boots cluster-ds for other
    # tests, which would populate that redirector's CMS registry.
    "lc-redirector-no-server": {"port": 30697},
    # 30506/30507/30508 are the cachemx matrix's S3-over-TLS, remote-origin
    # WebDAV and HTTP-TPC WebDAV planes; they live in the "lc-cachemx" extras
    # block above, out of numeric order because that entry predates them.
}
