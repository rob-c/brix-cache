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
    # 30506/30507/30508 are the cachemx matrix's S3-over-TLS, remote-origin
    # WebDAV and HTTP-TPC WebDAV planes; they live in the "lc-cachemx" extras
    # block above, out of numeric order because that entry predates them.
}
