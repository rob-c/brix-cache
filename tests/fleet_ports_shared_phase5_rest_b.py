# fleet_ports_shared_phase5_rest_b.py — ledger entries split off for the 600-line cap;
# merged back via split_continuation.load (.update on LIFECYCLE_SHARED_PORTS_PHASE5).

LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-audit16n-webdav": {"port": 30795},
    # The three MAIN|SRV|LOC WebDAV flags whose `off` arm was never written
    # anywhere — brix_zip_access, brix_webdav_require_digest,
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
    # brix_verify_write, _require_allo_size and _gsi.  All three are
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
    # 16ai: brix_allow_write, the fourth GridFTP gate and the one file
    # 31 left.  Thirty-one configs write `on`; the token `off` appears in NO
    # config in the tree — nginx_gridftp_metrics.conf's own header says its
    # {RO_PORT} server writes it and the server block simply omits the line,
    # and nginx_gridftp_plain_ev_ro.conf is an absence by construction.  FOUR
    # gateways: the writable control, the written `off`, the same server with
    # the line deleted, and `off` beside an armed brix_verify_write —
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
    # --- phase-101 per-feature subjects (seeds are historical; rebased at import) ---
    # xrdfs multi-path operands (test_xrdfs_multipath.py): per-test writable
    # anon posix root server; serialised under xdist_group("lc-xrdfs-multipath").
    "lc-xrdfs-multipath": {"port": 30531},
    # kXR_dirlist kXR_online filter (test_dirlist_online.py): per-test pblock
    # ?nearline=1 lab; serialised under xdist_group("lc-dirlist-online").
    "lc-dirlist-online": {"port": 30532},
    # brix_chkpnt_maxsz cap postures (test_chkpnt_maxsz.py): per-test throwaway
    # posix root server; serialised under xdist_group("lc-chkpnt-maxsz").
    "lc-chkpnt-maxsz": {"port": 30533},
    # HTTP-TPC 202 perf-marker RemoteConnections destination
    # (test_tpc_marker_remoteconn.py); xdist_group("lc-tpc-markers").
    "lc-tpc-markers": {"port": 30534},
    # xrdfs prepare stock-flag wire capture (test_xrdfs_prepare_flags.py);
    # xdist_group("lc-xrdfs-prepflags").
    "lc-xrdfs-prepflags": {"port": 30535},
    # operator cache-evict command postures (test_cache_evict_cmd.py);
    # xdist_group("lc-cache-evict").
    "lc-cache-evict": {"port": 30536},
    # brix_ztn_maxsz size-gate postures (test_ztn_maxsz.py);
    # xdist_group("lc-ztn-maxsz").
    "lc-ztn-maxsz": {"port": 30537},
    # brix_oss_maxsize create-size cap postures (test_oss_maxsize.py);
    # xdist_group("lc-oss-maxsize").
    "lc-oss-maxsize": {"port": 30538},
    # WebDAV GET-on-directory HTML listing postures
    # (test_webdav_html_listing.py); xdist_group("lc-html-listing").
    "lc-html-listing": {"port": 30539},
    # brix_oss_cgroup Qspace reporting (test_oss_cgroup.py);
    # xdist_group("lc-oss-cgroup").
    "lc-oss-cgroup": {"port": 30540},
    # brix_fsoverload_stall budget-overload backoff (test_fsoverload_stall.py);
    # xdist_group("lc-fsoverload").
    "lc-fsoverload": {"port": 30541},
    # kXR_Qspace driver-space seam + sd_xroot forwarding (test_qspace_driver.py);
    # xdist_group("lc-qspace").
    "lc-qspace-pblock": {"port": 30542},
    "lc-qspace-fwd-origin": {"port": 30543},
    "lc-qspace-fwd-proxy": {"port": 30544},
    "lc-qspace-posix": {"port": 30545},
    # phase-107 C1 writer reorder spill (test_vfs_writer_spill.py);
    # xdist_group("lc-p107-spill").  One instance, four root fronts over the
    # two staged-only drivers (brix_upload_resume off on every front, so the
    # kXR writes land in the VFS staged writer, not the protocol's own resume
    # partial):
    #   PORT              root front over http:// (sd_http), spill ON
    #   REMOTE_PORT       root front over s3:// (sd_remote), spill ON
    #   CAPPED_PORT       http front with brix_vfs_spill_max 1m
    #   RO_PORT           http front, writes disabled — EROFS before any spill
    #   HTTP_ORIGIN_PORT  WebDAV posix origin the http fronts commit to
    #   S3_PORT           brix_s3 posix origin the remote front commits to
    "lc-p107-spill": {"port": 30918,
                      "extra": {"REMOTE_PORT": 30919,
                                "CAPPED_PORT": 30920,
                                "RO_PORT": 30921,
                                "HTTP_ORIGIN_PORT": 30922,
                                "S3_PORT": 30923}},
    # phase-107 C5 declared-size reserve (test_vfs_reserve.py);
    # xdist_group("lc-p107-reserve").  One instance, four root fronts + one
    # origin:
    #   PORT         posix front, writable — preallocation + the oversized
    #                oss.asize -> kXR_NoSpace AT OPEN rows
    #   QUOTA_PORT   posix front, brix_oss_maxsize 64k — a lying declaration
    #                must not move the quota boundary
    #   RO_PORT      posix front, writes disabled — EROFS before any reserve
    #   REMOTE_PORT  root front over s3:// (sd_remote) — the 200 GB
    #                declaration that used to be past the multipart ceiling
    #   S3_PORT      brix_s3 posix origin the remote front commits to
    "lc-p107-reserve": {"port": 30924,
                        "extra": {"QUOTA_PORT": 30925,
                                  "RO_PORT": 30926,
                                  "REMOTE_PORT": 30927,
                                  "S3_PORT": 30928}},
    # phase-107 C4 DeleteObjects batch (test_s3_delete_objects_batch.py);
    # xdist_group("lc-p107-bulkdel").  One instance, four S3 fronts + one
    # logged origin:
    #   PORT            S3 front over s3:// (sd_remote) — 1,000 keys, ONE
    #                   upstream ?delete
    #   POSIX_PORT      S3 front over posix — the mixed-batch vocabulary
    #   RO_PORT         S3 front, writes disabled — EROFS for the whole batch
    #   DEADFRONT_PORT  S3 front over s3://DEAD_PORT — the transport arm
    #   DEAD_PORT       allocated, never bound: the dead origin itself
    #   ORIGIN_PORT     brix_s3 posix origin whose access log counts trips
    #   METRICS_PORT    brix_vfs_bulk_delete_{batches,keys}_total
    "lc-p107-bulkdel": {"port": 30929,
                        "extra": {"ORIGIN_PORT": 30930,
                                  "POSIX_PORT": 30931,
                                  "RO_PORT": 30932,
                                  "DEADFRONT_PORT": 30933,
                                  "DEAD_PORT": 30934,
                                  "METRICS_PORT": 30935}},
    # phase-107 C4 windowed rmtree walk (test_vfs_rmtree.py);
    # xdist_group("lc-p107-rmtree").  One instance, two WebDAV fronts + two
    # logged origins:
    #   PORT             WebDAV front over http:// (sd_http, no batch verb)
    #   REMOTE_PORT      WebDAV front over s3:// (sd_remote, CAP_BULK_DELETE)
    #   DAV_ORIGIN_PORT  WebDAV posix origin — the child-before-parent witness
    #   S3ORIGIN_PORT    brix_s3 posix origin — batches vs per-key DELETEs
    #   METRICS_PORT     the batch metric pair
    "lc-p107-rmtree": {"port": 30936,
                       "extra": {"DAV_ORIGIN_PORT": 30937,
                                 "S3ORIGIN_PORT": 30938,
                                 "REMOTE_PORT": 30939,
                                 "METRICS_PORT": 30940}},
    # phase-107 C2 / W6 (test_prepare_recall.py + test_vfs_evict.py, one serial
    # xdist_group("lc-prepare-recall")): the kXR_prepare stage/evict arms
    # through brix_vfs_recall/brix_vfs_evict.  A writable frm://exec + durable
    # stage-registry subject, its brix_allow_write-off twin (the kXR_fsReadOnly
    # negative), and a posix + registry subject whose recall-less backend keeps
    # records QUEUED for the FRM-1 ownership negatives.
    "lc-prepare-recall": {"port": 30941},
    "lc-prepare-recall-ro": {"port": 30942},
    "lc-prepare-own": {"port": 30943},
    # phase-107 C7 / W8 (test_cross_protocol_locks.py,
    # xdist_group("lc-p107-locks")): the VFS lock gate proven across planes.
    # ONE posix export dir shared by four fronts — a lock taken over WebDAV
    # must refuse the same file over every other plane — plus three
    # single-front exports because brix_lock_enforcement registers per
    # canonical export root (root_prepare.c), so each mode needs its own dir:
    #   PORT          root:// front, strict (default) — kXR_FileLocked
    #   DAV_PORT      WebDAV front — LOCK/UNLOCK edge, 423, If: token
    #   S3_PORT       brix_s3 front (anonymous) — 409 OperationAborted
    #   FTP_PORT      cleartext GridFTP front — 450
    #   ADV_PORT      root front, brix_lock_enforcement advisory (own export)
    #   OFF_PORT      root front, brix_lock_enforcement off (own export)
    #   RO_PORT       root front, writes disabled (own export) — EROFS
    #                 precedes EBUSY; expired locks are never reaped
    #   METRICS_PORT  brix_vfs_lock_refused_total{proto=...}
    "lc-p107-locks": {"port": 30944,
                      "extra": {"DAV_PORT": 30945,
                                "S3_PORT": 30946,
                                "FTP_PORT": 30947,
                                "ADV_PORT": 30948,
                                "OFF_PORT": 30949,
                                "RO_PORT": 30950,
                                "METRICS_PORT": 30951}},
    # Ultra-parallel breaking-point storms (test_ultra_parallel_breaking_point.py,
    # xdist_group("lc-ultra-parallel"), slow tier): FTS-shaped
    # connect+login+stat+open+read+close job ladders driven to breaking point.
    # ONE port: every test starts its own arm (plain / concurrency-capped)
    # sequentially inside the serial group, so the port is reused, never
    # contended.  The official-xrootd comparison leg is not a lifecycle spec —
    # it draws from the mock range like the other stock daemons.
    "lc-ultra-parallel": {"port": 30952},
    # §1.4 cross-worker kXR_bind migration (test_bind_migration.py,
    # xdist_group("lc-bind-migration")): a dedicated 2-worker reuseport
    # instance — the shared fleet is 1-worker and cannot scatter binds.
    # Migrated from an inline self-managed config (registry-lint offender).
    #   METRICS_PORT  brix_io_offload_total witness
    "lc-bind-migration": {"port": 30953,
                          "extra": {"METRICS_PORT": 30954}},
    # phase-105 W4.3 HTTP JWKS refresh parity
    # (test_http_jwks_refresh.py, xdist_group("lc-http-jwks-refresh")): one
    # worker owns a WebDAV and an S3 bearer front over distinct protocol-owned
    # key arrays.  Both watch the same atomically replaced JWKS file, which is
    # the cross-plane contract under test.
    "lc-http-jwks-refresh": {"port": 30955,
                             "extra": {"S3_PORT": 30956}},
    # Phase-81 final ordinary-fixture migration.  Each family owns one
    # idempotent instance at a time and is serialized by its matching
    # xdist_group; offload also owns its metrics listener.
    "lc-admin-socket": {"port": 30957},
    "lc-checksum-default": {"port": 30958},
    "lc-frm-dirlist": {"port": 30959},
    "lc-locate-prefname": {"port": 30960},
    "lc-login-fullurl": {"port": 30961},
    "lc-mirage-backend": {"port": 30962},
    "lc-offload-metric": {"port": 30963,
                           "extra": {"METRICS_PORT": 30964}},
    "lc-oss-quota": {"port": 30965},
    "lc-oss-quota-enforce": {"port": 30966},
    "lc-qconfig-sitename": {"port": 30967},
    "lc-s3-native-authz": {"port": 30968},
    # Phase-91 outbound FTP/GSIFTP storage-driver conformance.  The Python
    # origin is a separately owned proc so a wedged protocol peer cannot wedge
    # pytest; the nginx instance exposes writable and read-only WebDAV fronts.
    "lc-gsiftp-backend-origin": {"port": 30969},
    "lc-gsiftp-backend": {"port": 30970,
                           "extra": {"RO_PORT": 30971}},
    "lc-gsiftp-voms-backend": {
        "port": 30972,
        "extra": {
            "PLAIN_PORT": 30973,
            "CMS_PORT": 30974,
            "ORIGIN_PORT": 30975,
        },
    },
})
