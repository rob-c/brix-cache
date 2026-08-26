# fleet_ports_shared_phase5_rest.py — the second half of the Phase-5 shared
# port ledger, split off for the 600 logical-line cap and merged back via
# split_continuation.load (.update on the dict the first half defines).

LIFECYCLE_SHARED_PORTS_PHASE5.update({
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
})

from split_continuation import load as _load_fleet_ports_shared_phase5_rest_b
_load_fleet_ports_shared_phase5_rest_b(globals(), __file__, "fleet_ports_shared_phase5_rest_b.py")
