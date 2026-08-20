"""Contiguous, relocatable ladder for central Python test infrastructure.

Set ``TEST_PORT_START`` to the number immediately below the first allocated
port.  For example, ``TEST_PORT_START=10000`` allocates 10001..11039.

The old values remain beside their owning constants/ledger entries in
``settings.py``, ``fleet_lifecycle_ports.py`` and ``fleet_ports.py``.  They are
the historical ports used while each test was developed; this module only
translates those named allocations onto a compact per-run lane.
"""

from __future__ import annotations

import os


PORT_START = int(os.environ.get("TEST_PORT_START", "10000"))

# Stable category offsets.  Width changes are intentional compatibility events:
# a caller uses PORT_COUNT to choose the next non-overlapping lane.
SETTINGS_OFFSET, SETTINGS_WIDTH = 0, 178
# 2026-08-09: 523 -> 531 for the CMS parity wave + HTTP redirect lifecycle
# subjects (test_cms_parity_wave.py: lc-cms-parity-mgr(+CMS_PORT)/-node;
# test_webdav_redirect_ds.py: lc-webdav-redirect-mgr(+HTTP+CMS)/-ds(+HTTP)).
# 2026-08-10: 531 -> 534 for the gridftp unified-metrics subject
# (test_gridftp_metrics.py: lc-gridftp-metrics + HTTP_PORT + RO_PORT).  Every
# offset below shifts by the same 3.
# 2026-08-15: 534 -> 541 for the combinatorial-coverage-audit closure subjects
# (test_audit15_*.py: lc-audit15-throttle, three lc-audit15-readonly-*, two
# lc-audit15-guard-*, lc-audit15-mac-rotation).  Every offset below shifts
# by the same 7.
# 2026-08-15 pm: 541 -> 551 for the second audit tranche (test_audit15b_*.py:
# two lc-audit15b-vrdr-*, guard-copy, subs-tls, two lc-audit15b-tpc-*,
# webdav-tokcfg, and srr-cache + its ORIGIN_PORT/SRR_PORT extras).  Every
# offset below shifts by the same 10.
# 2026-08-15 (3rd tranche): 551 -> 564 for the deferred-but-mockable audit
# residuals (test_audit15c_*.py: introspect + IDP_PORT, dash-users, four
# tpcx-* + MOCK_PORT, two ssi-*, zipcaps + CTRL_PORT/HTTP_PORT).  Every
# offset below shifts by the same 13.
# 2026-08-15 (4th tranche): 564 -> 570 for the last locally-drivable audit
# residuals (test_audit15d_*.py: three lc-audit15d-tlstpc-*, inherit, and
# ckstage + its ORIGIN_PORT extra).  Every offset below shifts by the same 6.
# 2026-08-15 (5th tranche): 570 -> 587 for the audit tier/cluster crosses
# (test_audit15e_*.py: async + ORIGIN_PORT, uring + STAGE/ORIGIN, pt +
# ORIGIN, cks3 + ORIGIN, cmsmgr, srrcms + SRR_PORT, cmsmgr2, cmsact +
# ORIGIN/TPC/SRC).  Every offset below shifts by the same 17.
# 2026-08-15 (6th tranche): 587 -> 592 for the WebDAV TPC tuning and
# credential-forwarding subjects (test_audit15f_webdav_tpc_tuning.py:
# lc-audit15f-tpctune + the capturing TLS mock source's MOCK_PORT and the
# token endpoint's IDP_PORT; test_audit15f_tpc_cred_forward.py:
# lc-audit15f-credfwd + MOCK_PORT).  Every offset below shifts by the same 5.
# 2026-08-15 (6th tranche, cont.): 592 -> 602 for the host-auth crosses
# (test_audit15f_host_auth_crosses.py: lc-audit15f-hostmgr, and lc-audit15f-
# hostx + its DENY/ORIGIN/CACHE/STAGE/TPC/SRC/SRCHOST/CMS planes).  Every
# offset below shifts by the same 10.
# 2026-08-15 (6th tranche, cont.): 602 -> 608 for the sigver crosses
# (test_audit15f_sigver_crosses.py: lc-audit15f-sigx + its LAX/SRC/SRCSIG/
# BIND/BINDLAX planes).  Every offset below shifts by the same 6.
# 2026-08-15 (6th tranche, cont.): 608 -> 611 for the cache-admission subjects
# (test_audit15f_cache_admission_and_staging.py: lc-audit15f-cacheorigin, and
# lc-audit15f-cacheadm + its L1_PORT plane).  Every offset below shifts by the
# same 3.
# 2026-08-15 (6th tranche, cont.): 611 -> 617 for the cluster-tuning subjects
# (test_audit15f_cluster_tuning.py: lc-audit15f-cltune + its CMS_PORT and two
# dashboard faces; test_audit15f_cms_node_legs.py: lc-audit15f-clnode + its
# METRICS_PORT).  Every offset below shifts by the same 6.
# 2026-08-15 (6th tranche, cont.): 617 -> 618 for the fifth token-exchange
# destination (test_audit15c_tpc_token_exchange.py: lc-audit15c-tpcx-scope,
# the brix_tpc_outbound_scope arm).  Every offset below shifts by the same 1.
# 2026-08-15 (6th tranche, cont.): 618 -> 619 for the macaroon issuance policy
# subject (test_audit15f_macaroon_issue_policy.py: lc-audit15f-macpol — one
# server, two locations).  Every offset below shifts by the same 1.
# 2026-08-15 (6th tranche, cont.): 619 -> 620 for the acc OS-group resolution
# subject (test_audit15f_acc_group_resolution.py: lc-audit15f-accgrp — one
# port, one process per arm).  Every offset below shifts by the same 1.
# 2026-08-15 (7th tranche): 620 -> 625 for the first two §C mid-transfer
# subjects (test_audit15g_unlink_during_transfer.py: lc-audit15g-unlink + its
# CACHE_PORT tier plane; test_audit15g_evict_during_read.py: lc-audit15g-evict
# + its COLD_PORT reaper plane) and the lc-audit15g-mtorigin origin they share.
# Every offset below shifts by the same 5.
# 2026-08-15 (7th tranche, cont.): 625 -> 637 for the rest of §C — the two
# http://-origin planes (lc-audit15g-fill and lc-audit15g-sdhttp, each with the
# MOCK_PORT its paced Python origin listens on) and the eight-port
# lc-audit15g-tpcx instance carrying TPC x {cache_store, non-posix backend,
# authdb}.  Every offset below shifts by the same 12.
# 2026-08-15 (7th tranche, cont.): 637 -> 639 for the authdb load-failure
# subject (test_audit15g_authdb_load_failure.py: lc-audit15g-badacc + the
# REFRESH_PORT plane that re-reads its authdb on a timer instead of only at
# worker start).  Every offset below shifts by the same 2.
# 2026-08-15 (7th tranche, cont.): 639 -> 640 for the `--verify` verdict-policy
# subject (test_audit15g_verify_strict.py: lc-audit15g-verify — one plain
# writable plane; the subject is the client).  Every offset below shifts by 1.
# 2026-08-16 (8th tranche): 640 -> 644 for the TPC lifetime kill-switches
# (test_audit15h_tpc_lifetime.py: lc-audit15h-tpclife — the capped destination
# plus its SRC_PORT source, the uncapped FREE_PORT control and the DASH_PORT
# dashboard that reads the shared TPC registry).  Every offset below shifts
# by the same 4.
# 2026-08-16 (8th tranche, cont.): 644 -> 647 for dashboard session-TTL expiry
# (test_audit15h_dashboard_session_ttl.py: lc-audit15h-dashttl — the
# single-password plane plus the users-file MU_PORT and the DEF_PORT plane that
# carries no TTL directive).  Every offset below shifts by the same 3.
# 2026-08-16 (8th tranche, cont.): 647 -> 650 for krb5 x TLS
# (test_audit15h_krb5_tls.py: lc-audit15h-krb5tls — the TLS plane, the
# PLAIN_PORT cleartext control and the TLSREQ_PORT plane that gates login on
# TLS).  Every offset below shifts by the same 3.
# 2026-08-16 (8th tranche, cont.): 650 -> 653 for the abandoned TLS-upgrade
# crash pin (test_audit15h_tls_upgrade_abort.py: lc-audit15h-tlsabort — the TLS
# plane whose worker dies, the CLEAR_PORT control and the AUTHED_PORT gsi
# plane).  Every offset below shifts by the same 3.
# 2026-08-16 (8th tranche, cont.): 653 -> 657 for authdb x delegated identity
# (test_audit15h_authdb_delegation.py: lc-audit15h-authdeleg — the EEC-rule
# plane, the LEAF_PORT plane whose rules name the proxy DN, the OPEN_PORT
# no-authdb control and the METRICS_PORT Prometheus face).  Every offset below
# shifts by the same 4.
# 2026-08-16 (8th tranche, cont.): 657 -> 659 for macaroon x VOMS/delegation
# (test_audit15h_macaroon_voms.py: lc-audit15h-macvoms — the authdb-gated
# WebDAV face and the FREE_PORT face without an authdb that attributes its
# denials).  Every offset below shifts by the same 2.
# 2026-08-16 (8th tranche, cont.): 659 -> 667 for native TPC x TLS x GSI
# (test_audit15h_tpc_gsi_tls.py: lc-audit15h-tpcgsitls-src carries the gsi+TLS
# face, the GSIONLY_PORT cleartext gsi control and the ARM_PORT rendezvous face;
# -good/-notls/-nocred/-rogueca/-noca are the five outbound destinations).
# Every offset below shifts by the same 8.
# 2026-08-16 (8th tranche, cont.): 667 -> 670 for TPC x sss
# (test_audit15h_tpc_sss.py: lc-audit15h-tpcsss-src is the sss-guarded pull
# source, -open the anonymous attribution control, -dst the destination whose
# client face is sss).  Every offset below shifts by the same 3.
# 2026-08-16 (8th tranche, cont.): 670 -> 676 for the WebDAV GSI/delegation PUSH
# leg (test_audit15h_webdav_gsi_push.py: lc-audit15h-wdpush carries four
# initiator faces — default / FWDOFF_PORT / NOCERT_PORT / ROGUECA_PORT — and the
# two DN-logging peers, PEER_PORT and STRICT_PORT).  Every offset below shifts by
# the same 6.
# 2026-08-16 (8th tranche, cont.): 676 -> 679 for cvmfs × gridftp co-residence
# (test_audit15h_cvmfs_gridftp.py: lc-audit15h-cvmfsftp is one nginx carrying an
# http{} Stratum-0 front on the spec port plus the two stream{} GridFTP faces,
# FTPRW_PORT and FTPRO_PORT, over the same export root).  Every offset below
# shifts by the same 3.
# 2026-08-16 (9th tranche): 679 -> 682 for the §B2.13 isolation arm
# (test_audit15i_staged_writev.py: lc-audit15i-stagewv is one nginx carrying an
# http{} WebDAV posix origin on ORIGIN_PORT, a ring-free stream{} staged writer
# over it on the spec port, and a bare posix stream{} front on POSIX_PORT as the
# universality control).  Every offset below is a running sum of the widths
# above it, so they all move by the same 3.
# 2026-08-16 (11th tranche): 683 -> 684 for the private empty redirector
# regression fixture (single listener; the no-CMS template has no second bind)
# (test_audit15j_zero_coverage_stragglers.py: lc-audit15j-audgate is one
# cleartext WebDAV nginx whose two locations differ only in whether
# brix_backend_token_audience_ok is present).  Every offset below is a running
# sum of the widths above it, so they all move by the same 1.
# 2026-08-16 (11th tranche, cont.): 684 -> 685 for the S3 co-residency block
# (test_audit15k_s3_coresidency.py: lc-audit15k-s3cores is one cleartext nginx
# whose single server block carries every S3 security option the pairwise
# matrix had only ever seen in separate files).  Every offset below is a
# running sum of the widths above it, so they all move by the same 1.
# 2026-08-16 (12th tranche): 685 -> 688 for the HTTP co-residency block
# (test_audit15l_http_coresidency.py: lc-audit15l-httpcores is one nginx with
# three server blocks — the subject face, the origin its remote tiers fetch
# from, and the CVMFS face that one-protocol-per-port forces onto its own
# listener), so three slots, and every offset below moves by the same 3.
# 2026-08-16 (13th tranche): 688 -> 696 for the stream co-residency nginx
# (test_audit15m_stream_coresidency.py: lc-audit15m-streamcores carries the tap
# proxy, the origin it fronts, the gridftp door, an http-backed cluster member,
# that member's http origin, the manager's two faces, and the mirrored block
# that proves the shadowing is decided by directive order), so eight slots, and
# every offset below moves by the same 8.
# 2026-08-17 (14th tranche): 696 -> 699 for the WebDAV response surface
# (test_audit15n_webdav_cors.py: lc-audit15n-cors is one http listener carrying
# the CORS trio and both redirect signing windows, plus the stream member and
# CMS face that give brix_srv_select() something to select), so three slots, and
# every offset below moves by the same 3.
# 2026-08-17 (14th tranche, 2nd file): 699 -> 703 for the CMS timing plane
# (test_audit15o_cms_windows.py: lc-audit15o-cmswindows is one nginx carrying a
# fast manager, a slow manager differing only in the three window/cap
# directives, the CMS registration face both log into, and a metadata-only
# server), so four slots, and every offset below moves by the same 4.
# 2026-08-17 (14th tranche, 3rd file): 703 -> 704 for the S3 bearer gate's time
# window (test_audit15p_s3_token.py: lc-audit15p-s3token is one http listener
# whose four locations differ only in brix_s3_token_clock_skew and the JWKS
# they trust, so one token gets four verdicts from one port), so one slot, and
# every offset below moves by the same 1.
# 2026-08-17 (14th tranche, 4th file): 704 -> 709 for the dashboard's transfer-
# state bands (test_audit15q_dashboard_thresholds.py: lc-audit15q-dashbands is
# four dashboard faces on four ports — the route table is URI-absolute, so a
# face cannot be a second location — plus the ROOT_PORT data server whose
# held-open handle is the one slot all four read), so five slots, and every
# offset below moves by the same 5.
# 2026-08-17 (14th tranche, 5th file): 709 -> 711 for the TPC trust anchor
# (test_audit15r_webdav_tpc_cadir.py: lc-audit15r-tpccadir is one nginx whose
# eight locations differ only in which CA directory they trust, plus MOCK_PORT
# for the self-signed TLS pull source they all dial), so two slots, and every
# offset below moves by the same 2.
# 2026-08-17 (15th tranche, 1st file): 711 -> 712 for the authorization audit
# sink's level (test_audit15s_authdb_audit.py: lc-audit15s-auditmodes is one
# nginx whose eight locations differ only in the brix_authdb_audit token and are
# all read out of the single error log its single worker writes), so one slot,
# and every offset below moves by the same 1.
# 2026-08-17 (15th tranche, 2nd file): 712 -> 718 for the cluster role's value
# table (test_audit15t_cms_role.py: six lc-audit15t-role-* nodes, one per token
# of brix_cms_role plus the absent-directive control, because the role is a
# server-level directive whose observable is the LOGIN Mode word a node sends —
# it cannot be folded onto one listener), so six slots, and every offset below
# moves by the same 6.
# 2026-08-17 (15th tranche, 3rd file): 718 -> 723 for CRL strictness
# (test_audit15u_crl_mode.py: lc-audit15u-crlmode carries all five arms of
# brix_crl_mode on one instance — `off`, TRY_PORT, REQ_PORT, DEF_PORT for the
# absent directive and NOCRL_PORT for `try` with no CRL source — because the
# five deliberately share one CA and one CRL directory), so five slots, and
# every offset below moves by the same 5.
# 2026-08-17 (15th tranche, 4th file): 723 -> 727 for signing_policy strictness
# (test_audit15v_signing_policy.py: lc-audit15v-sigpolicy carries all four arms
# of brix_signing_policy on one instance — `off`, ON_PORT, REQ_PORT and DEF_PORT
# for the absent directive — over ONE hashed CA directory, because the three
# tokens are only distinguishable across issuers that differ in what they
# publish), so four slots, and every offset below moves by the same 4.
# 2026-08-17 (15th tranche, 5th file): 727 -> 733 for the signing level's value
# table (test_audit15w_security_level.py: lc-audit15w-seclevel carries all five
# tokens of brix_security_level plus DEF_PORT for the absent directive on one
# instance — the level's observables are a per-connection advertisement byte and
# a per-request verdict, both drivable from one process), so six slots, and
# every offset below moves by the same 6.
# 2026-08-17 (15th tranche, 6th file): 733 -> 735 for the backend-delegation
# value table (test_audit15x_backend_delegation.py: lc-audit15x-deleg puts all
# six tokens of brix_backend_delegation on ONE listener, because the mode is a
# location-level directive, plus ORIGIN_PORT for the in-process http:// origin
# that records which credential each mode actually forwarded), so two slots, and
# every offset below moves by the same 2.
# 2026-08-17 (15th tranche, 7th file): 735 -> 738 for the cvmfs origin-policy
# value table (test_audit15y_cvmfs_origin_policy.py: lc-audit15y-cvpolicy needs
# the listener, MOCK_PORT for the Stratum-1 mock its fills come from, and a
# DEAD_PORT that is reserved precisely so nothing ever binds it — the retry
# policy is only readable over an origin set with an unreachable half), so
# three slots, and every offset below moves by the same 3.
# 2026-08-17 (15th tranche, 8th file): 738 -> 741 for the disabling-token table
# (test_audit15z_disable_tokens.py: lc-audit15z-disable runs THREE servers in one
# process — two anonymous root:// listeners whose only difference is the token
# under test, plus SECOND_PORT for the sibling that shows a process-global
# ratchet, plus GSI_PORT for the brix_auth gsi listener whose login sec token
# carries the advertised GSI version), so three slots, and every offset below
# moves by the same 3.
# 2026-08-17 (15th tranche, 9th file): 741 -> 747 for the default-restating
# token table (test_audit15aa_default_tokens.py).  Two instances, because two of
# the five tokens are read through process-globals and a control cannot share a
# process with its case: lc-audit15aa-default takes five slots (the WebDAV front,
# MEMBER_PORT/CMS_PORT for the cluster member that has to register before a 307
# exists at all, and SSI_PORT / SSI2_PORT for the two cta faces whose executors
# alias each other), and
# lc-audit15aa-clean takes one http-only slot as the separate-process control for
# brix_webdav_checksum_xattr_format.  So six slots, and every offset below moves
# by the same 6.
# 2026-08-17 (16th tranche, 1st file): 747 -> 753 for the OCSP flag table
# (test_audit16a_ocsp_flags.py: lc-audit16a-ocsp runs FOUR GSI listeners in one
# process — brix_ocsp_enable off, on+soft_fail on, on+soft_fail off, and on with
# soft_fail absent for the merge default — plus RESP_PORT for the controllable
# responder tests/lib/ocsp_responder.py that the suite never had, plus a
# DEAD_PORT reserved precisely so nothing ever binds it: "the responder is
# unreachable" is one of the two arms brix_ocsp_soft_fail decides between), so
# six slots, and every offset below moves by the same 6.
# 2026-08-17 (16th tranche, 2nd file): 753 -> 756 for the stapling flag
# (test_audit16b_ocsp_stapling.py: lc-audit16b-staple runs three `brix_tls on`
# root:// listeners in one process — stapling off, on, and absent — because
# SSL_CTX_set_tlsext_status_cb is installed per server block and three TLS
# contexts in one worker is what shows the callback is not process-global), so
# three slots, and every offset below moves by the same 3.
# 2026-08-17 (16th tranche, 3rd file): 756 -> 757 for the URL-token flag
# (test_audit16c_query_token.py: lc-audit16c-qtoken is a single http listener
# carrying the three arms as three WebDAV locations, because the assertion that
# matters is what reaches the ONE access log they share), so one slot, and every
# offset below moves by the same 1.
# 2026-08-17 (16th tranche, 4th file): 757 -> 759 for the CVMFS origin
# connection-reuse flag (test_audit16d_origin_reuse.py: lc-audit16d-reuse is one
# listener carrying two cvmfs locations, plus MOCK_PORT for the keep-alive mock
# Stratum-1 whose accept count IS the measurement), so two slots, and every
# offset below moves by the same 2.
# 2026-08-17 (16th tranche, 5th file): 759 -> 764 for the krb5 AP-REQ source-IP
# check (test_audit16e_krb5_ip_check.py: lc-audit16e-ipcheck carries the three
# arms as three stream listeners — ip_check on, off and absent — plus RELAY_PORT
# for the in-process TCP relay that moves the client's SOURCE address, which is
# the only way to make the peer differ from the address the ticket was issued
# for, plus METRICS_PORT for the http face that exposes brix_auth_total), so
# five slots, and every offset below moves by the same 5.
# 2026-08-17 (16th tranche, 6th file): 764 -> 765 for the five S3 location flags
# whose `off` arm was never written (test_audit16f_s3_location_flags.py:
# lc-audit16f-s3flags is a SINGLE http listener carrying sixteen S3 locations —
# three arms x five flags, plus a nested pair and /metrics — because an S3 arm
# needs its own bucket and s3_parse_uri() takes the bucket from the first URI
# segment, which makes the arm a location and not a listener), so one slot, and
# every offset below moves by the same 1.
# 2026-08-17 (16th tranche, 7th file): 765 -> 766 for the six pmark flags whose
# `off` arm was never written (test_audit16g_pmark_flags.py: lc-audit16g-pmark is
# a SINGLE listener carrying thirteen WebDAV locations — eighteen arms, three per
# flag, collapsed onto thirteen because the reference arm is simultaneously the
# `absent` arm of the four flags it does not write — plus /metrics, because
# brix_pmark_conf_t is per-location; the same port is also
# bound on the IPv6 loopback when the host has one, since the flow-label
# technique only exists over real IPv6, and a second listen is not a second
# slot), so one slot, and every offset below moves by the same 1.
# 2026-08-17 (16th tranche, 8th file): 766 -> 768 for the six shared-http flags
# whose `off` arm was never written (test_audit16h_shared_http_flags.py:
# lc-audit16h-shared is a SINGLE listener carrying twenty-two WebDAV locations
# across five `server_name` vhosts — all six directives are BRIX_HTTP_ALL_CONF,
# so a server-level arm is part of the subject and another vhost is cheaper than
# another listen — plus ORIGIN_PORT for the test's own lying http:// origin,
# which §C needs because no posix export can hand back something other than what
# it stored), so two slots, and every offset below moves by the same 2.
# 2026-08-17 (16th tranche, 9th file): 768 -> 771 for the nine CVMFS resilience
# flags whose `off` arm was never written (test_audit16i_cvmfs_resilience_flags.py:
# lc-audit16i-cvmfs is ONE nginx port restarted per arm — eight of the nine
# directives are merged per cvmfs EXPORT and two of them reach a process-wide
# latch, so two arms sharing one process measure one arm — plus MOCK_PORT for the
# live mock Stratum-1 and DEAD_PORT, which is reserved precisely so nothing
# answers on it), so three slots, and every offset below moves by the same 3.
# 2026-08-17 (16th tranche, 10th file): 771 -> 781 for the five node-capability
# flags whose `off` arm was never written (test_audit16j_root_caps_flags.py:
# lc-audit16j-caps is TEN stream servers in ONE process, so ten ports — all five
# directives are NGX_STREAM_SRV_CONF and a stream server is selected by its
# listen port, so unlike the http-plane files above an arm cannot be another
# `server_name` on a shared listen; two of the ten are the CMS registration
# listener and the data node that make the manager registry non-empty, without
# which the collapse-redir cache is unreachable on both of its arms), so ten
# slots, and every offset below moves by the same 10.
# 2026-08-17 (16th tranche, 14th file): 781 -> 782 for the five location-scoped
# WebDAV flags whose `off` arm was never written
# (test_audit16n_webdav_module_flag_arms.py: lc-audit16n-webdav is ONE http
# listener carrying twenty locations across five `server_name` vhosts — all five
# directives are NGX_HTTP_LOC_CONF and nothing else, so unlike the stream-plane
# file above there is no server-level arm to buy a second listener for; the vhosts
# exist because two of the five gate an ABSOLUTE URI prefix rather than the
# location they are written in, and a URI space holds exactly one arm per server),
# so one slot, and every offset below moves by the same 1.
# 2026-08-17 (16th tranche, 15th file): 782 -> 783 for the three MAIN|SRV|LOC
# WebDAV flags whose `off` arm was never written
# (test_audit16o_webdav_scoped_flag_arms.py: lc-audit16o-webdav-scoped is ONE http
# listener carrying eleven locations across seven `server_name` vhosts — three
# legal scopes per directive is what makes the file's subject exist, but a scope is
# not a listener, so `on` at server scope and `off` in a child location still cost
# one port between them; the vhost count is again set by an ABSOLUTE prefix,
# /.well-known/dig/ for brix_webdav_dig), so one slot, and every offset below moves
# by the same 1.
# 2026-08-17 (16th tranche, 16th file): 783 -> 786 for brix_webdav_proxy_certs, the
# last arm-gap of brix_webdav_commands and the only one that needs a socket
# (test_audit16p_proxy_certs.py: lc-audit16p-proxy-certs is THREE TLS listeners —
# `on` at server scope, `off` at server scope, and `on` written in a `location{}`).
# Three ports rather than three vhosts because the flag's whole effect is one
# X509_VERIFY_PARAM flag on ONE SSL_CTX (webdav/postconfig.c:247-256) and an
# SSL_CTX belongs to a listening server: the verify parameters are in place before
# the ClientHello, so no Host header can pick between two arms.  The ABSENT arm is
# a reconfigure of the `off` listener in place and buys nothing.  Three slots, and
# every offset below moves by the same 3.
# 2026-08-17 (16th tranche, 17th file): 786 -> 790 for the three acc-engine flags
# of the stream plane, whose `off` arm was never written
# (test_audit16q_acc_engine_flag_arms.py: lc-audit16q-acc-engine is THREE root://
# listeners plus one http listener in ONE process).  Three stream slots because a
# root:// server is the scope these flags are declared at, and holding all three
# arms side by side in one process is simultaneously how a per-server flag is
# measured and how a process-wide one is caught pretending to be per-server
# (auth/authz/acc/config.c:47).  The fourth slot is http: the same three names are
# declared again for that plane and their tables are built LAZILY, on a request
# (acc/config.c:209-217), so the http arm is a RUNTIME event and needs a listener
# sharing the process rather than a second configuration.  Four slots, and every
# offset below moves by the same 4.
# 2026-08-17 (16th tranche, 18th file): 790 -> 794 for the two CSI integrity flags
# of the stream plane, whose `off` arm was never written
# (test_audit16r_csi_flag_arms.py: lc-audit16r-csi is FOUR root:// listeners over
# ONE export in ONE process).  Four rather than three because these two flags
# compose: the reading needs a tagging acceptor, a verifying one, a trusting one
# and a demanding one all reachable against the SAME bytes on disk, and both
# flags are consulted per kXR_open out of the per-server conf
# (read/open_resolved_file_finalize.c:70-88), so four acceptors in one worker are
# four independent arms.  Four slots, and every offset below moves by the same 4.
# 2026-08-17 (16th tranche, 19th file): 794 -> 797 for the last arm-gap of the same
# header, brix_krb5_delegate's never-written `off`
# (test_audit16s_krb5_delegate_arms.py: lc-audit16s-krb5deleg is THREE krb5
# acceptors — on, off, absent — over ONE keytab and ONE export in ONE process, so
# the same client and the same ccache reach all three arms and a difference in
# rounds cannot be a difference in credentials).  Three slots, and every offset
# below moves by the same 3.
# 2026-08-18 (16th tranche, 20th file): 797 -> 801 for the inline-compression pair
# of root/stream/directives_security.h, whose `off` arm was never written
# (test_audit16t_compress_flag_arms.py: lc-audit16t-compress is FOUR root://
# acceptors over ONE export in ONE process).  Four rather than three because the
# two flags are independent — the direction is picked per kXR_open out of the
# per-server conf (read/open_request_opaque.c:71) — so the reading needs both-on,
# both-off, unwritten AND a mixed acceptor to show the slots are not one bit.
# Four slots, and every offset below moves by the same 4.
# 2026-08-18 (16th tranche, 21st file): 803 -> 810 for brix_ocsp_require_nonce,
# whose BOTH arms are unwritten — a branch nothing in the corpus has ever entered
# (test_audit16u_ocsp_nonce.py: lc-audit16u-ocspnonce is FOUR GSI acceptors plus
# THREE controllable responders).  Seven slots: four planes, and one responder
# per nonce behaviour, because a responder's behaviour is fixed at startup while
# the responder a login reaches is baked into the credential's AIA — a
# kernel-chosen port cannot be minted into a certificate, and a certificate
# cannot change which port it names.  Every offset below moves by the same 7.
# 2026-08-18 (16th tranche, 22nd file): 810 -> 816 for the seven flags in
# directives_tpc.h whose DISARMING arm is written nowhere in the corpus
# (test_audit16v_tpc_off_arms.py: lc-audit16v-tpcoff is six planes over one
# export).  Six slots for seven flags: the two egress gates need a plane each
# where only one of them is armed, the transfer-time arms need a destination
# that can still reach a loopback source, the all-disarmed plane by construction
# cannot, and the tap-proxy override is a config-time verdict on its own
# listener.  Every offset below moves by the same 6.
# 2026-08-18 (16th tranche, 23rd file): 816 -> 818 for the WebDAV plane's
# egress-policy off arms (test_audit16w_webdav_tpc_egress_off_arms.py:
# lc-audit16w-wdegress is THIRTEEN locations over one listener).  Two slots for
# thirteen planes because every directive in the subject is location-scoped, so
# the whole cross fits under one `listen`; the second slot is the capturing TLS
# source, which is the only witness that a refused transfer never dialled out.
# Every offset below moves by the same 2.
# 2026-08-18 (16th tranche, 24th file): 818 -> 830 for the last arm-gaps in
# root/stream/directives_security.h (test_audit16x_stream_security_off_arms.py:
# lc-audit16x-secoff).  Twelve slots for four flags, and the arithmetic is the
# declaration rather than the subject: every one of the four is
# NGX_STREAM_SRV_CONF, so the written `off`, the omission and the armed control
# each need a `listen` of their own — a server-scoped flag has no smaller unit
# to vary.  Every offset below moves by the same 12.
# 2026-08-18 (16th tranche, 25th file): 830 -> 841 for the outbound redirector
# TLS leg driven live (test_audit16y_upstream_tls_verify_live.py:
# lc-audit16y-uptls).  Eleven slots: eight nginx planes, because the CA, the
# pinned name and `brix_upstream_tls_verify` are all NGX_STREAM_SRV_CONF and a
# trust decision cannot be varied below a `listen`; plus three gotoTLS stub
# upstreams, one per certificate the planes are asked to believe, since which
# certificate a leg meets is fixed by which port it dials.  Every offset below
# moves by the same 11.
# 2026-08-18 (16th tranche, 26th file): 841 -> 844 for the WebDAV mirror's auth
# policy and its divergence NOTICE, both driven live
# (test_audit16z_webdav_mirror_arms.py: lc-audit16z-mirror).  Only three slots
# for seven arms: `brix_mirror_strip_auth`, `brix_mirror_token` and
# `brix_mirror_log_diverge` are all NGX_HTTP_LOC_CONF, so seven `location`
# blocks vary under one `listen`.  The other two are recording shadows, and
# there have to be two: a divergence is a disagreement between the primary's
# status and the shadow's, so one upstream that always agrees and one that never
# does is the smallest pair that can produce one on demand.  Every offset below
# moves by the same 3.
# 2026-08-18 (16th tranche, 27th file): 844 -> 848 for the last arm-gap in
# webdav/directives_net.h (test_audit16aa_webdav_redirect_arms.py:
# lc-audit16aa-rdr).  Four slots for one flag, and three of them are the price
# of making its `off` arm mean anything: `brix_webdav_redirect_dataserver off`
# is only observable against an `on` that really redirects, which needs a CMS
# registry with a node in it — a stream manager listen, a CMS server listen, and
# the WebDAV front.  The fourth is a recording data server on the port the
# Location is built to name.  Every offset below moves by the same 4.
# 2026-08-19 (16th tranche, 28th file): 848 -> 849 for the two arm-gaps of the
# dashboard module's command table (test_audit16ab_admin_factor_arms.py:
# lc-audit16ab-admin).  ONE slot for fourteen planes, which is the declaration
# again: brix_admin_require_both is NGX_HTTP_LOC_CONF and the endpoint it gates
# lives at a fixed URI, so a plane cannot be a path — it is a `server_name`
# vhost, and fourteen of them share one `listen`.  Every offset below moves by
# the same 1.
# 2026-08-19 (16th tranche, 29th file): 849 -> 857 for the root/stream command
# table's last never-`off` flag (test_audit16ac_manager_mode_arms.py:
# lc-audit16ac-mgrmode + OFF/ABS/CMS/DS/AUTO/OVER/HTTP).  Eight slots because
# brix_manager_mode is NGX_STREAM_SRV_CONF: a plane here is a `listen`, not a
# location, and the redirect arm is only a redirect if there is a registry with
# a data node in it.  Every offset below moves by the same 8.
# 2026-08-19 (16th tranche, 30th file): 857 -> 858 for the inert configuration
# surface (test_audit16ad_inert_config_surface.py: lc-audit16ad-inert).  ONE
# slot for eight planes, which is what the subject is: every directive under
# test is location-scoped, the WebDAV resolver already gives each location its
# own subtree of the one export, and an arm that changes nothing is measured
# against the control next to it rather than against a listener of its own.
# Every offset below moves by the same 1.
# 2026-08-19: 858 -> 866 for the gridftp gate off-arms subject
# (test_audit16ae_gridftp_gate_off_arms.py: lc-audit16ae-ftpgates + its
# ABS/ON/VONLY/AONLY write planes and its GOFF/GABS/GON security planes).
# Every one of the three subjects is NGX_STREAM_SRV_CONF, so a plane is a
# `listen` and cannot be folded onto the shared port the way 16ad's eight
# locations were.  Every offset below shifts by the same 8.
# 2026-08-19: 866 -> 873 for the two OCI security flags whose securing arm no
# config had written (test_audit16af_oci_security_arms.py: lc-audit16af-ociarms
# + its OFF/ABS/BOTH cleartext planes and its VON/VOPT/TLS listeners).
# brix_oci_mirror_insecure contributes none of the seven: the field it merges
# into is read nowhere, so it is a parse-tier subject entirely.  Every offset
# below shifts by the same 7.
# 2026-08-19: 873 -> 881 for the two httpguard flags whose unwritten arm is the
# one an operator reaches for (test_audit16ag_guard_arms.py:
# lc-audit16ag-guardarms + its ABS/ON/DEFON/DEFOFF/BARE arm faces and its
# SRVON/SRVOFF inheritance faces).  The guard classifies the whole r->uri, so a
# face is a `listen` and cannot be folded onto sibling locations the way 16ad's
# eight were.  Every offset below shifts by the same 8.
# 2026-08-19: 881 -> 893 for the three stream flags whose control arm no config
# had written (test_audit16ah_frm_hc_arms.py: lc-audit16ah-frmhc's eight
# registryless fronts + lc-audit16ah-frmreg's four registry fronts).  The two
# instances cannot be folded into one: brix_stage_registry_init is a first-wins
# process singleton, so "enabled with no registry" and "enabled beside someone
# else's registry" are two processes by construction.  Every offset below shifts
# by the same 12.
# 2026-08-19 (16th tranche, 36th file): 893 -> 898 for the five slots
# lc-audit16ai-ftpwrite adds (test_audit16ai_gridftp_write_gate.py: four FTP
# gateways — writable, the written `off`, the same server with the line deleted,
# and `off` beside an armed verify_write — plus the HTTP face that scrapes the
# process-wide metrics zone they all share).  Every offset below shifts by 5.
# 2026-08-19 (16th tranche, 37th file): 898 -> 903 for the five slots
# lc-audit16aj-storeep adds (test_audit16aj_cache_store_endpoint_arms.py:
# three root:// listeners for the stream declaration's three arms, plus TWO
# http listeners for its nine http vhosts — five WebDAV and four S3, which
# cannot share a `listen` because config_merge refuses "brix_webdav and
# brix_s3 both enabled under listen port N - one brix protocol per port").
# Every offset below shifts by 5.
LIFECYCLE_SHARED_OFFSET, LIFECYCLE_SHARED_WIDTH = 178, 903
# 2026-08-09: 137 -> 140 for the three audit-fix lifecycle subjects
# (test_audit_fixes_2026_08_09.py: only-if-cached, cold-purge, signing).
# Every offset below shifts by the same 3 — the ladder is packed, so a width
# change is an intentional compatibility event (see the note above).
# 2026-08-16: repacked against LIFECYCLE_SHARED_WIDTH.  The audit tranches grew
# the shared lane by 145 slots (534 -> 679) but only carried 103 of that through
# to the lanes below, so the shared lane had been overlapping this one by 42
# since it passed 637 — caught by test_fleet_ports.py's band check.  Every
# offset from here down is now recomputed as a running sum of the widths above
# it (815 -> 857 and so on); that sum, not a hand-carried delta, is the rule.
# 2026-08-17 (16th tranche): repacked again as that running sum, 925 -> 934, for
# the tranche's nine shared slots (747 -> 756).  The two width bumps above landed
# without it and the shared lane overlapped this one by 9 for exactly as long as
# it took test_fleet_ports.py's band check to say so — which is the reason the
# rule is a running sum and not a delta anyone carries by hand.
# 2026-08-17 (16th tranche, 7th file): 943 -> 944, the running sum again, for the
# pmark slot above (765 -> 766).
# 2026-08-17 (16th tranche, 8th file): 944 -> 946, the running sum again, for the
# two shared-http-flag slots above (766 -> 768).
# 2026-08-17 (16th tranche, 9th file): 946 -> 949, the running sum again, for the
# three CVMFS resilience-flag slots above (768 -> 771).
# 2026-08-17 (16th tranche, 10th file): 949 -> 959, the running sum again, for the
# ten node-capability-flag slots above (771 -> 781).
# 2026-08-17 (16th tranche, 14th file): 959 -> 960, the running sum again, for the
# one location-scoped-WebDAV-flag slot above (781 -> 782).  Files 11-13 of the
# tranche added none: two reused this file's own vhost trick and the third reused
# test_stream_guard.py's three relay slots outright.
# 2026-08-17 (16th tranche, 15th file): 960 -> 961, the running sum again, for the
# one MAIN|SRV|LOC-WebDAV-flag slot above (782 -> 783).
# 2026-08-17 (16th tranche, 16th file): 961 -> 964, the running sum again, for the
# three proxy-cert TLS-listener slots above (783 -> 786).
# 2026-08-17 (16th tranche, 17th file): 964 -> 968, the running sum again, for the
# four acc-engine slots above (786 -> 790).
# 2026-08-17 (16th tranche, 18th file): 968 -> 972, the running sum again, for the
# four CSI integrity-flag slots above (790 -> 794).
# 2026-08-17 (16th tranche, 19th file): 972 -> 975, the running sum again, for the
# three krb5-delegation-arm slots above (794 -> 797).
# 2026-08-18 (16th tranche, 20th file): 975 -> 979, the running sum again, for the
# four inline-compression-arm slots above (797 -> 801).
# 2026-08-18 (16th tranche, 21st file): 981 -> 988, the running sum again, for the
# seven OCSP-nonce slots above (803 -> 810).
# 2026-08-18 (16th tranche, 22nd file): 988 -> 994, the running sum again, for the
# six TPC-guard-off-arm slots above (810 -> 816).
# 2026-08-18 (16th tranche, 23rd file): 994 -> 996, the running sum again, for the
# two WebDAV-egress-off-arm slots above (816 -> 818).
# 2026-08-18 (16th tranche, 24th file): 996 -> 1008, the running sum again, for
# the twelve stream-security-off-arm slots above (818 -> 830).
# 2026-08-18 (16th tranche, 25th file): 1008 -> 1019, the running sum again, for
# the eleven live upstream-TLS-verify slots above (830 -> 841).
# 2026-08-18 (16th tranche, 26th file): 1019 -> 1022, the running sum again, for
# the three live WebDAV-mirror slots above (841 -> 844).
# 2026-08-18 (16th tranche, 27th file): 1022 -> 1026, the running sum again, for
# the four redirect-to-dataserver slots above (844 -> 848).
# 2026-08-19 (16th tranche, 28th file): 1026 -> 1027, the running sum again, for
# the single dashboard-arm slot above (848 -> 849).
# 2026-08-19 (16th tranche, 29th file): 1027 -> 1035, the running sum again, for
# the eight manager-mode slots above (849 -> 857).
# 2026-08-19 (16th tranche, 30th file): 1035 -> 1036, the running sum again, for
# the single inert-config-surface slot above (857 -> 858).
# 2026-08-19 (16th tranche, 32nd file): 1036 -> 1044, the running sum again, for
# the eight gridftp-gate slots above (858 -> 866).
# 2026-08-19 (16th tranche, 33rd file): 1044 -> 1051, the running sum again, for
# the seven OCI-security slots above (866 -> 873).
# 2026-08-19 (16th tranche, 34th file): 1051 -> 1059, the running sum again, for
# the eight httpguard-arm slots above (873 -> 881).
# 2026-08-19 (16th tranche, 35th file): 1059 -> 1071, the running sum again, for
# the twelve FRM/health-check slots above (881 -> 893).
# 2026-08-19 (16th tranche, 36th file): 1071 -> 1076, the running sum again, for
# the five GridFTP write-gate slots above (893 -> 898).
# 2026-08-19 (16th tranche, 37th file): 1076 -> 1081, the running sum again,
# for the five cache-store-endpoint slots above (898 -> 903).
LIFECYCLE_EXCLUSIVE_OFFSET, LIFECYCLE_EXCLUSIVE_WIDTH = 1081, 140
# 2026-08-19: 205 -> 211 for the six-port root_readonly_gateway block (origin +
# read-only gateway + allow_write-override gateway + writable control +
# data-substreams gateway + read_only_public gateway).  The config-time
# role-conflict check needs no port: it listens on a unix socket, because
# `nginx -t` opens the listening sockets and a TCP port would race the lane.
CMDSCRIPTS_OFFSET, CMDSCRIPTS_WIDTH = 1221, 211
CMS_MESH_OFFSET, CMS_MESH_WIDTH = 1432, 83
HYBRID_MESH_OFFSET, HYBRID_MESH_WIDTH = 1515, 23
PLACEHOLDERS_OFFSET, PLACEHOLDERS_WIDTH = 1538, 2
# CVMFS conformance mock-Stratum-1 + nginx port blocks (cvmfs/conformance_common.py
# PORT_BLOCKS): 26 files x a 20-port block.  Anchored into the ladder so every
# port stays within TEST_PORT_START+2000 and a second suite on a different
# TEST_PORT_START draws a disjoint range (replaces the old absolute 13100+ tiling).
# 27 file blocks x 20 ports = 540, plus a 48-port matrix sub-range for the
# concurrent fuse-trust mock origins (see conformance_common.matrix_port).
CVMFS_CONFORMANCE_OFFSET, CVMFS_CONFORMANCE_WIDTH = 1540, 588
# Differential-interop per-file fixed ports (official_interop_lib.worker_port):
# one slot per distinct conformance base (61 today), anchored here so they stay
# in the contiguous ladder within TEST_PORT_START+2000 instead of the old
# absolute 30000-49925 per-worker band.  The owning module is pinned to one xdist
# worker (conftest auto-xdist_group), so a fixed port per file suffices.
INTEROP_WORKER_OFFSET, INTEROP_WORKER_WIDTH = 2128, 61
PORT_COUNT = 2189
PORT_FIRST = PORT_START + 1
PORT_LAST = PORT_START + PORT_COUNT

# Python mock listeners and differential upstreams are not registry servers,
# but they still must not ask the kernel to choose a port.  They receive slots
# from this session-shared range through ``ephemeral_port.free_port`` (kept as
# a compatibility spelling).  Keeping this pool after the named ledger means
# the full range is still controlled by TEST_PORT_START while static ledger
# checks retain their exact, contiguous PORT_FIRST..PORT_LAST contract.
MOCK_PORT_OFFSET, MOCK_PORT_WIDTH = PORT_COUNT, 16384
MOCK_PORT_FIRST = PORT_START + MOCK_PORT_OFFSET + 1
MOCK_PORT_LAST = PORT_START + MOCK_PORT_OFFSET + MOCK_PORT_WIDTH
TOTAL_PORT_COUNT = MOCK_PORT_OFFSET + MOCK_PORT_WIDTH

if not 1024 <= PORT_FIRST <= MOCK_PORT_LAST <= 65535:
    raise ValueError(
        f"TEST_PORT_START={PORT_START} yields invalid test port range "
        f"{PORT_FIRST}..{MOCK_PORT_LAST}; choose a base whose complete "
        f"{TOTAL_PORT_COUNT}-port lane fits within 1024..65535"
    )


def _port(offset: int, index: int) -> int:
    return PORT_START + offset + index + 1


def rebase_settings(namespace: dict) -> None:
    """Rebase settings ``*_PORT`` constants in source-definition order.

    ``XRDHTTP_HTTPS_PORT`` was historically an alias of
    ``XRDHTTP_HTTP_PORT`` (original port 11113) and remains an alias rather than
    consuming a second socket slot.
    """
    names = [
        name for name, value in namespace.items()
        if "_PORT" in name
        and name != "TEST_PORT_START"
        and isinstance(value, int)
    ]
    aliases = {"XRDHTTP_HTTPS_PORT": "XRDHTTP_HTTP_PORT"}
    owners = [name for name in names if name not in aliases]
    if len(owners) != SETTINGS_WIDTH:
        raise RuntimeError(
            f"settings port ladder expected {SETTINGS_WIDTH} allocations, "
            f"found {len(owners)}; update port_ladder.py intentionally"
        )
    for index, name in enumerate(owners):
        namespace[name] = _port(SETTINGS_OFFSET, index)
    for alias, owner in aliases.items():
        namespace[alias] = namespace[owner]
    # Config renderers and non-Python helpers historically consume the
    # unprefixed names, while some subprocesses import settings through the
    # TEST_* compatibility variables.  Publish one centrally assigned value to
    # both spellings so every child receives the same lane.
    for name in names:
        value = str(namespace[name])
        os.environ[name] = value
        os.environ[f"TEST_{name}"] = value


def rebase_lifecycle_ledger(ledger: dict, *, shared: bool) -> None:
    """Rebase a lifecycle ledger while preserving its insertion order."""
    offset = LIFECYCLE_SHARED_OFFSET if shared else LIFECYCLE_EXCLUSIVE_OFFSET
    expected = LIFECYCLE_SHARED_WIDTH if shared else LIFECYCLE_EXCLUSIVE_WIDTH
    slots = []
    for entry in ledger.values():
        slots.append((entry, "port"))
        slots.extend((entry["extra"], key) for key in entry.get("extra", {}))
    if len(slots) != expected:
        kind = "shared" if shared else "exclusive"
        raise RuntimeError(
            f"{kind} lifecycle ladder expected {expected} allocations, "
            f"found {len(slots)}; update port_ladder.py intentionally"
        )
    for index, (container, key) in enumerate(slots):
        container[key] = _port(offset, index)


def rebase_cmdscripts(blocks: dict[str, tuple[int, int]]) -> dict[str, tuple[int, int]]:
    """Return command-suite blocks packed contiguously in declaration order."""
    total = sum(span for _original, span in blocks.values())
    if total != CMDSCRIPTS_WIDTH:
        raise RuntimeError(
            f"cmdscripts ladder expected {CMDSCRIPTS_WIDTH} allocations, found "
            f"{total}; update port_ladder.py intentionally"
        )
    rebased = {}
    index = 0
    for name, (_original, span) in blocks.items():
        rebased[name] = (_port(CMDSCRIPTS_OFFSET, index), span)
        index += span
    return rebased


def rebase_named_ports(ports: dict[str, int], *, category: str) -> dict[str, int]:
    """Pack a registry-owned external orchestrator's named listeners."""
    categories = {
        "cms-mesh": (CMS_MESH_OFFSET, CMS_MESH_WIDTH),
        "hybrid-mesh": (HYBRID_MESH_OFFSET, HYBRID_MESH_WIDTH),
    }
    offset, expected = categories[category]
    if len(ports) != expected or len(set(ports.values())) != expected:
        raise RuntimeError(
            f"{category} ladder expected {expected} unique allocations, found "
            f"{len(ports)} names/{len(set(ports.values()))} values; update "
            "port_ladder.py intentionally"
        )
    return {name: _port(offset, index) for index, name in enumerate(ports)}


def placeholder_port(index: int) -> int:
    if not 0 <= index < PLACEHOLDERS_WIDTH:
        raise IndexError(index)
    return _port(PLACEHOLDERS_OFFSET, index)
