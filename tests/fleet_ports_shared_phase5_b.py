# fleet_ports_shared_phase5_b.py — ledger entries split off for the 600-line cap;
# merged back via split_continuation.load (.update on LIFECYCLE_SHARED_PORTS_PHASE5).

LIFECYCLE_SHARED_PORTS_PHASE5.update({
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
})
