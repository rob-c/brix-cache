# Final port-ladder segments, continued from port_ladder_offsets.py.
# Loaded into port_ladder.py's namespace so public constant imports are stable.
#
# 2026-09-06: LIFECYCLE_EXCLUSIVE moved here from port_ladder_offsets.py,
# which its ledger history had pushed past the 600-line cap.  The value is
# unchanged and the segments below still run in ascending offset order.

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
# 2026-08-27: 1105 -> 1106, the running sum again, for the one
# lc-pblock-quota-qspace slot above (927 -> 928).
# 2026-08-31: 1106 -> 1111, the running sum, for the five phase-106 slots.
# 2026-09-05: 1179 -> 1191, the running sum, for the twelve phase-115 W2.4 slots;
# 1191 -> 1195 for the four W3.2 tape-purge slots.
# 2026-09-06: 1195 -> 1197 for the two W3.1 tape-archiver slots.
# 2026-09-06: 1197 -> 1203 for the six phase-116 runtime-DNS slots.
# 2026-09-06: 1203 -> 1205 for the W3.1 recall-gate and W3.3 space-group slots.
# 2026-09-06: 1205 -> 1207 for the two phase-116 W5.2 mirror slots.
# 2026-09-06: exclusive lane 142 -> 144 for the two phase-115 serve-while-
# filling slots (lc-cache-swf and its verifying security negative).
# 2026-09-07: 1232 -> 1236, the running sum, for the four phase-115 W5.4
# same-origin server-copy slots above (one origin plus one nginx carrying
# the read/write, read-only and deeper-root fronts that all reach it).
# 2026-09-07: 1236 -> 1239, the running sum, for the three phase-115 W7.2a
# per-caller sss identity slots above (one instance per keytab shape).
# 2026-09-07: 1239 -> 1247, the running sum, for the eight phase-115 W8.2
# credential-renewal slots above.
# 2026-09-07: 1247 -> 1251, the running sum, for the four phase-115 W8.3
# CMS admin-socket slots above.
# 2026-09-07: 1272 -> 1273, the running sum, for the one phase-115 W8.6
# cross-worker CTA queue slot above.
# 2026-09-07: 1273 -> 1275, the running sum, for the two phase-115 W4.3 §5
# refusal-SHAPE slots in the shared lane above (1094 -> 1096).  Those two
# landed width-only, so the shared lane overlapped this one by 2 until
# test_fleet_ports.py's band check said so — the same failure the 2026-08-16
# and 2026-08-17 notes above describe, and the reason the rule is a running
# sum of the widths above it rather than a delta anyone carries by hand.
# 2026-09-07: 1275 -> 1277, the running sum, for the two phase-115 W5.2
# FEAT-decoy slots in the shared lane above (1096 -> 1098).
# 2026-09-07: +23 for the 2.0-readiness axis-(e) metrics labs (F6 RAM-store
# rows, F10 health family, F12 three-tier CMS, F13 dashboard cross-validation,
# F14 cardinality, F15 VO/authdb auth_total) — nine instances, 23 slots,
# 144 -> 167; the running sum re-applied to every lane above.
# 2026-09-07: 167 -> 168 for the F6 posix origin (lc-r20-ram-origin) the
# RAM-cached export reads through once the lab moved to the 2.0 tier grammar
# (`brix_storage_backend root://` + `brix_cache_store ram:`).
# 2026-09-07: 168 -> 170 for the F8 site-checksum-plugin lab (lc-r20-cks-plugin:
# root:// + WebDAV listeners).
# 2026-09-08: 170 -> 171 for the F1 brix_frm_* engine-knob lab (lc-r20-frm-knobs,
# one root:// listener).
# 2026-09-08: 1277, 171 -> 1277, 172 for the F2 brix_frm_stagemsg StageEvents lab (lc-r20-frm-stagemsg, one root:// listener).
# 2026-09-08: +1 for the F3 OssArc backup-queue lab (lc-r20-arc-seal, one root:// listener).
# 2026-09-08: +1 for the F4 purge-policy lab (lc-r20-purge-policy, one root:// listener).
# 2026-09-08: +9 for the two F7 native-TPC labs (lc-r20-tpc-multihop, five listeners; lc-r20-tpc-streams, four listeners).
# 2026-09-09: +7 for the two F9 SSS entity labs (lc-r20-sss-entity, three listeners; lc-r20-sss-proxied, four listeners).
# 2026-09-09: +3 for the two F5 labs (lc-r20-fwd-origin + lc-r20-fwd-proxy,
# one listener each; lc-r20-urlcgi-opaque, one listener).
# 2026-09-09: +5 for the F16 native-TPC-push lab (lc-r20-tpc-push, five
# listeners: push source, single-stream cap, dialect-off face, destination
# and egress-guarded source); the running sum re-applied to every lane above.
# 2026-09-09: +5 for the F17 cms.fsxeq operator-program lab
# (test_release20_cms_fsxeq.py, five one-listener data nodes: every op named,
# only mkdir named, failing/hanging programs, no thread pool, read-only
# export); the running sum re-applied to every lane below.
# 2026-09-09: +7 for the F18 TPC identity-matrix lab (lc-r20-tpcmx, seven
# listeners: an unconfigured source and destination, one destination per
# fail-closed stage (allow/require/restrict), a source carrying `require dest`
# and a destination whose host-plane guard denies while its matrix permits);
# the running sum re-applied to every lane below.
# 2026-09-09: +2 for the F18 WebDAV-plane gate lab (lc-r20-tpcmx-dav: one
# listener plus the TLS mock source a permitted arm must actually reach) in the
# exclusive lane (210 -> 212); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F19 xrd.tlsca residual lab (lc-r20-tlsca, seven
# listeners: scope all / scope last / scope absent, verify_log all,
# verify_log failure, a malformed-CRL plane under `require`, and an
# unreadable-CRL plane under `try`); the running sum re-applied to every
# lane below.
# 2026-09-10: +1 for the F20 native-authdb grammar residual lab
# (lc-r20-authdb-f20, one root:// listener carrying the compound `v`/`l`
# selectors and the `x` privilege); the running sum re-applied to every lane
# below (219 -> 220).
# 2026-09-10: +1 for the F20 lab's own /metrics face (its INVARIANT-8 arm
# scrapes the label set the role-bearing identity produces); the running sum
# re-applied to every lane below (220 -> 221).
# 2026-09-18: 1277 -> 1287, the running sum, for the shared lane's 1098 -> 1108.
# Eight of those ten were the 2026-09-16 gsi-legacy-proxy slots, which landed
# width-only: the shared lane had overlapped this one by 8 ever since, and
# test_fleet_ports.py's band check was failing on it.  The remaining two are the
# impgm WebDAV arms.  Same lesson as the 2026-08-16/2026-08-17/2026-09-07 notes
# above — the rule is a running sum of the widths above, never a hand-carried
# delta on one constant.
# 2026-09-19: 1294 -> 1295, the running sum, for the shared lane's 1115 -> 1116
# (lc-policy-rule-scope).  Every offset below moves with it, for the same reason
# the notes above give: the sum of the widths ABOVE a lane is its offset, and a
# width bumped without re-applying that sum leaves this lane overlapping the one
# it follows until test_fleet_ports.py's band check notices.
LIFECYCLE_EXCLUSIVE_OFFSET, LIFECYCLE_EXCLUSIVE_WIDTH = 1295, 221


# 2026-08-19: 205 -> 211 for the six-port root_readonly_gateway block (origin +
# read-only gateway + allow_write-override gateway + writable control +
# data-substreams gateway + read_only_public gateway).  The config-time
# role-conflict check needs no port: it listens on a unix socket, because
# `nginx -t` opens the listening sockets and a TCP port would race the lane.
# 2026-09-03: 211 -> 213 for cvmfs_verify's mock Stratum-1 and cache-front
# listeners.  It previously used absolute ports, defeating per-run isolation.
# 2026-09-07: 1444 -> 1445, the running sum, for the F6 posix-origin slot in
# the exclusive lane above (167 -> 168).
# 2026-09-07: +2, the running sum, for the F8 plugin lab in the exclusive lane
# above (168 -> 170).
# 2026-09-08: +1, the running sum, for the F1 frm-knob lab in the exclusive
# lane above (170 -> 171).
# 2026-09-08: 1448 -> 1449 for the F2 brix_frm_stagemsg StageEvents lab (lc-r20-frm-stagemsg, one root:// listener).
# 2026-09-08: +1 for the F3 OssArc backup-queue lab (lc-r20-arc-seal, one root:// listener).
# 2026-09-08: +1 for the F4 purge-policy lab (lc-r20-purge-policy, one root:// listener).
# 2026-09-08: +9 for the two F7 native-TPC labs (lc-r20-tpc-multihop, five listeners; lc-r20-tpc-streams, four listeners).
# 2026-09-09: +7 for the two F9 SSS entity labs (lc-r20-sss-entity, three listeners; lc-r20-sss-proxied, four listeners).
# 2026-09-09: +3, the running sum, for the three F5 lab slots in the
# lifecycle-exclusive lane above (190 -> 193).
# 2026-09-09: 213 -> 216 for cvmfs_live's three-listener scenarios (mock
# Stratum-1 + cache front + control).  Same defect as cvmfs_verify above: it
# used absolute ports 12851-12898, defeating per-run isolation — and two of its
# own scenarios (connection-reuse, keepalive) both claimed 12896.
# 2026-09-09: +5 for the F16 native-TPC-push lab (lc-r20-tpc-push, five
# listeners: push source, single-stream cap, dialect-off face, destination
# and egress-guarded source); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F18 TPC identity-matrix lab (lc-r20-tpcmx, seven
# listeners) in the exclusive lane (203 -> 210); the running sum re-applied
# to every lane above.
# 2026-09-09: +2 for the F18 WebDAV-plane gate lab (lc-r20-tpcmx-dav: one
# listener plus the TLS mock source a permitted arm must actually reach) in the
# exclusive lane (210 -> 212); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F19 xrd.tlsca residual lab (lc-r20-tlsca, seven
# listeners: scope all / scope last / scope absent, verify_log all,
# verify_log failure, a malformed-CRL plane under `require`, and an
# unreadable-CRL plane under `try`); the running sum re-applied to every
# lane below.
CMDSCRIPTS_OFFSET, CMDSCRIPTS_WIDTH = 1516, 216
# 2026-09-07: 1657 -> 1658, the running sum, for the F6 posix-origin slot in
# the exclusive lane above (167 -> 168).
# 2026-09-07: +2, the running sum, for the F8 plugin lab in the exclusive lane
# above (168 -> 170).
# 2026-09-08: 1661 -> 1662 for the F2 brix_frm_stagemsg StageEvents lab (lc-r20-frm-stagemsg, one root:// listener).
# 2026-09-08: +1 for the F3 OssArc backup-queue lab (lc-r20-arc-seal, one root:// listener).
# 2026-09-08: +1 for the F4 purge-policy lab (lc-r20-purge-policy, one root:// listener).
# 2026-09-08: +9 for the two F7 native-TPC labs (lc-r20-tpc-multihop, five listeners; lc-r20-tpc-streams, four listeners).
# 2026-09-09: +7 for the two F9 SSS entity labs (lc-r20-sss-entity, three listeners; lc-r20-sss-proxied, four listeners).
# 2026-09-09: +3, the running sum, for the three F5 lab slots in the
# lifecycle-exclusive lane above (190 -> 193).
# 2026-09-09: +3, the running sum, for the cvmfs_live block above (213 -> 216).
# 2026-09-09: +5 for the F16 native-TPC-push lab (lc-r20-tpc-push, five
# listeners: push source, single-stream cap, dialect-off face, destination
# and egress-guarded source); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F18 TPC identity-matrix lab (lc-r20-tpcmx, seven
# listeners) in the exclusive lane (203 -> 210); the running sum re-applied
# to every lane above.
# 2026-09-09: +2 for the F18 WebDAV-plane gate lab (lc-r20-tpcmx-dav: one
# listener plus the TLS mock source a permitted arm must actually reach) in the
# exclusive lane (210 -> 212); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F19 xrd.tlsca residual lab (lc-r20-tlsca, seven
# listeners: scope all / scope last / scope absent, verify_log all,
# verify_log failure, a malformed-CRL plane under `require`, and an
# unreadable-CRL plane under `try`); the running sum re-applied to every
# lane below.
CMS_MESH_OFFSET, CMS_MESH_WIDTH = 1732, 83
# 2026-09-07: 1740 -> 1741, the running sum, for the F6 posix-origin slot in
# the exclusive lane above (167 -> 168).
# 2026-09-07: +2, the running sum, for the F8 plugin lab in the exclusive lane
# above (168 -> 170).
# 2026-09-08: 1744 -> 1745 for the F2 brix_frm_stagemsg StageEvents lab (lc-r20-frm-stagemsg, one root:// listener).
# 2026-09-08: +1 for the F3 OssArc backup-queue lab (lc-r20-arc-seal, one root:// listener).
# 2026-09-08: +1 for the F4 purge-policy lab (lc-r20-purge-policy, one root:// listener).
# 2026-09-08: +9 for the two F7 native-TPC labs (lc-r20-tpc-multihop, five listeners; lc-r20-tpc-streams, four listeners).
# 2026-09-09: +7 for the two F9 SSS entity labs (lc-r20-sss-entity, three listeners; lc-r20-sss-proxied, four listeners).
# 2026-09-09: +3, the running sum, for the three F5 lab slots in the
# lifecycle-exclusive lane above (190 -> 193).
# 2026-09-09: +3, the running sum, for the cvmfs_live block (213 -> 216).
# 2026-09-09: +5 for the F16 native-TPC-push lab (lc-r20-tpc-push, five
# listeners: push source, single-stream cap, dialect-off face, destination
# and egress-guarded source); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F18 TPC identity-matrix lab (lc-r20-tpcmx, seven
# listeners) in the exclusive lane (203 -> 210); the running sum re-applied
# to every lane above.
# 2026-09-09: +2 for the F18 WebDAV-plane gate lab (lc-r20-tpcmx-dav: one
# listener plus the TLS mock source a permitted arm must actually reach) in the
# exclusive lane (210 -> 212); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F19 xrd.tlsca residual lab (lc-r20-tlsca, seven
# listeners: scope all / scope last / scope absent, verify_log all,
# verify_log failure, a malformed-CRL plane under `require`, and an
# unreadable-CRL plane under `try`); the running sum re-applied to every
# lane below.
HYBRID_MESH_OFFSET, HYBRID_MESH_WIDTH = 1815, 23
# 2026-09-07: 1763 -> 1764, the running sum, for the F6 posix-origin slot in
# the exclusive lane above (167 -> 168).
# 2026-09-07: +2, the running sum, for the F8 plugin lab in the exclusive lane
# above (168 -> 170).
# 2026-09-08: 1767 -> 1768 for the F2 brix_frm_stagemsg StageEvents lab (lc-r20-frm-stagemsg, one root:// listener).
# 2026-09-08: +1 for the F3 OssArc backup-queue lab (lc-r20-arc-seal, one root:// listener).
# 2026-09-08: +1 for the F4 purge-policy lab (lc-r20-purge-policy, one root:// listener).
# 2026-09-08: +9 for the two F7 native-TPC labs (lc-r20-tpc-multihop, five listeners; lc-r20-tpc-streams, four listeners).
# 2026-09-09: +7 for the two F9 SSS entity labs (lc-r20-sss-entity, three listeners; lc-r20-sss-proxied, four listeners).
# 2026-09-09: +3, the running sum, for the three F5 lab slots in the
# lifecycle-exclusive lane above (190 -> 193).
# 2026-09-09: +3, the running sum, for the cvmfs_live block (213 -> 216).
# 2026-09-09: +5 for the F16 native-TPC-push lab (lc-r20-tpc-push, five
# listeners: push source, single-stream cap, dialect-off face, destination
# and egress-guarded source); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F18 TPC identity-matrix lab (lc-r20-tpcmx, seven
# listeners) in the exclusive lane (203 -> 210); the running sum re-applied
# to every lane above.
# 2026-09-09: +2 for the F18 WebDAV-plane gate lab (lc-r20-tpcmx-dav: one
# listener plus the TLS mock source a permitted arm must actually reach) in the
# exclusive lane (210 -> 212); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F19 xrd.tlsca residual lab (lc-r20-tlsca, seven
# listeners: scope all / scope last / scope absent, verify_log all,
# verify_log failure, a malformed-CRL plane under `require`, and an
# unreadable-CRL plane under `try`); the running sum re-applied to every
# lane below.
PLACEHOLDERS_OFFSET, PLACEHOLDERS_WIDTH = 1838, 2

# CVMFS conformance mock-Stratum-1 + nginx port blocks (cvmfs/conformance_common.py
# PORT_BLOCKS): 26 files x a 20-port block. Anchored into the ladder so every
# port stays within TEST_PORT_START+2000 and a second suite on a different
# TEST_PORT_START draws a disjoint range (replaces the old absolute 13100+ tiling).
# 27 file blocks x 20 ports = 540, plus a 48-port matrix sub-range for the
# concurrent fuse-trust mock origins (see conformance_common.matrix_port).
# 2026-09-07: 1765 -> 1766, the running sum, for the F6 posix-origin slot in
# the exclusive lane above (167 -> 168).
# 2026-09-07: +2, the running sum, for the F8 plugin lab in the exclusive lane
# above (168 -> 170).
# 2026-09-08: 1769 -> 1770 for the F2 brix_frm_stagemsg StageEvents lab (lc-r20-frm-stagemsg, one root:// listener).
# 2026-09-08: +1 for the F3 OssArc backup-queue lab (lc-r20-arc-seal, one root:// listener).
# 2026-09-08: +1 for the F4 purge-policy lab (lc-r20-purge-policy, one root:// listener).
# 2026-09-08: +9 for the two F7 native-TPC labs (lc-r20-tpc-multihop, five listeners; lc-r20-tpc-streams, four listeners).
# 2026-09-09: +7 for the two F9 SSS entity labs (lc-r20-sss-entity, three listeners; lc-r20-sss-proxied, four listeners).
# 2026-09-09: +3, the running sum, for the three F5 lab slots in the
# lifecycle-exclusive lane above (190 -> 193).
# 2026-09-09: +3, the running sum, for the cvmfs_live block (213 -> 216).
# 2026-09-09: +5 for the F16 native-TPC-push lab (lc-r20-tpc-push, five
# listeners: push source, single-stream cap, dialect-off face, destination
# and egress-guarded source); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F18 TPC identity-matrix lab (lc-r20-tpcmx, seven
# listeners) in the exclusive lane (203 -> 210); the running sum re-applied
# to every lane above.
# 2026-09-09: +2 for the F18 WebDAV-plane gate lab (lc-r20-tpcmx-dav: one
# listener plus the TLS mock source a permitted arm must actually reach) in the
# exclusive lane (210 -> 212); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F19 xrd.tlsca residual lab (lc-r20-tlsca, seven
# listeners: scope all / scope last / scope absent, verify_log all,
# verify_log failure, a malformed-CRL plane under `require`, and an
# unreadable-CRL plane under `try`); the running sum re-applied to every
# lane below.
CVMFS_CONFORMANCE_OFFSET, CVMFS_CONFORMANCE_WIDTH = 1840, 588

# Differential-interop per-file fixed ports (official_interop_lib.worker_port):
# one slot per distinct conformance base (65 today), anchored here so they stay
# in the contiguous ladder within TEST_PORT_START+3000 instead of the old
# absolute 30000-49925 per-worker band. The owning module is pinned to one xdist
# worker, so a fixed port per file suffices.
# 2026-08-26: 61 -> 65 — four conformance bases were registered in
# _INTEROP_BASES without the matching width bump (caught by
# test_fleet_ports.py: worker slots 12216-12219 fell past PORT_LAST).
# 2026-09-07: 2353 -> 2354, the running sum, for the F6 posix-origin slot in
# the exclusive lane above (167 -> 168).
# 2026-09-07: +2, the running sum, for the F8 plugin lab in the exclusive lane
# above (168 -> 170).
# 2026-09-08: 2357 -> 2358 for the F2 brix_frm_stagemsg StageEvents lab (lc-r20-frm-stagemsg, one root:// listener).
# 2026-09-08: +1 for the F3 OssArc backup-queue lab (lc-r20-arc-seal, one root:// listener).
# 2026-09-08: +1 for the F4 purge-policy lab (lc-r20-purge-policy, one root:// listener).
# 2026-09-08: +9 for the two F7 native-TPC labs (lc-r20-tpc-multihop, five listeners; lc-r20-tpc-streams, four listeners).
# 2026-09-09: +7 for the two F9 SSS entity labs (lc-r20-sss-entity, three listeners; lc-r20-sss-proxied, four listeners).
# 2026-09-09: +3, the running sum, for the three F5 lab slots in the
# lifecycle-exclusive lane above (190 -> 193).
# 2026-09-09: +3, the running sum, for the cvmfs_live block (213 -> 216).
# 2026-09-09: +5 for the F16 native-TPC-push lab (lc-r20-tpc-push, five
# listeners: push source, single-stream cap, dialect-off face, destination
# and egress-guarded source); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F18 TPC identity-matrix lab (lc-r20-tpcmx, seven
# listeners) in the exclusive lane (203 -> 210); the running sum re-applied
# to every lane above.
# 2026-09-09: +2 for the F18 WebDAV-plane gate lab (lc-r20-tpcmx-dav: one
# listener plus the TLS mock source a permitted arm must actually reach) in the
# exclusive lane (210 -> 212); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F19 xrd.tlsca residual lab (lc-r20-tlsca, seven
# listeners: scope all / scope last / scope absent, verify_log all,
# verify_log failure, a malformed-CRL plane under `require`, and an
# unreadable-CRL plane under `try`); the running sum re-applied to every
# lane below.
INTEROP_WORKER_OFFSET, INTEROP_WORKER_WIDTH = 2428, 65

# 2026-08-31 (phase-106): shared lane +5 for the five nginx-integration nodes;
# every lane below shifts by 5. Packed ladder — an intentional compatibility
# event, per the note above.
# 2026-09-01/02 (phase-107): shared lane +34, PORT_COUNT 2225 -> 2259. The C7
# +8 first landed width-only — the shared/exclusive overlap the 2026-08-16
# band check exists for; every lane re-summed 2026-09-02.
# 2026-09-02 (phase-109 merge): shared lane +3 for lc-walk-offload,
# PORT_COUNT 2259 -> 2262 (running sum re-applied across both waves).
# 2026-09-03 (phase-105 W4.3): shared lane +2 for the WebDAV+S3
# HTTP JWKS-refresh parity worker.
# 2026-09-04 (phase-81): shared lane +12 for the ordinary-fixture close-out.
# 2026-09-04 (phase-91): +7 for the FTP origin, two gateway listeners and the
# VOMS carry lab's origin plus three WebDAV fronts.
# 2026-09-05 (phase-115): +7 for the W2.1 CMS select-then-proxy lab and +8 for
# the W2.4 transparent-upstream GSI lab plus +4 for its cache-origin half,
# PORT_COUNT 2295 -> 2307 (running sum re-applied to every lane below the
# shared one); +4 for the W3.2 tape-purge lab, PORT_COUNT 2307 -> 2311.
# 2026-09-06: +2 for the W3.1 tape dataset archiver lab, PORT_COUNT 2311 -> 2313.
# 2026-09-06: 2313 -> 2319 for the six phase-116 runtime-DNS slots.
# 2026-09-06: 2319 -> 2321 for the W3.1 recall-gate and W3.3 space-group slots.
# 2026-09-06: 2321 -> 2323 for the two phase-116 W5.2 mirror slots.
# 2026-09-06: 2323 -> 2325 for the two phase-115 serve-while-filling slots.
# 2026-09-06: 2325 -> 2326 for NGINX_RAM_CACHE_PORT, the phase-115 W4.2
# dedicated RAM-cache-store role.  It is a FIXED port (18459), not a ladder
# derivative, but the settings lane counts allocations, not addresses, so
# the settings width grows with it and every offset here shifts by +1.
# 2026-09-07: 2326 -> 2337 for the eleven phase-115 W5.1 GridFTP
# data-channel slots; the running sum re-applied to every lane above.
# 2026-09-07: 2337 -> 2342 for the four phase-115 W5.2 ERET slots and the one
# phase-116 dns-bridge slot; the running sum re-applied to every lane above.
# 2026-09-07: 2342 -> 2350 for the eight phase-115 W5.3 SPAS slots (three
# origins — striped, silent, and one that advertises a stripe on an address it
# does not own — plus one nginx carrying five fronts); the running sum
# re-applied to every lane above.
# 2026-09-07: 2350 -> 2354 for the four phase-115 W5.4 server-copy slots;
# the running sum re-applied to every lane above.
# 2026-09-07: 2354 -> 2357 for the three phase-115 W7.2a sss-identity slots;
# the running sum re-applied to every lane above.
# 2026-09-07: 2377 -> 2385 for the eight phase-115 W8.2 credential-renewal
# slots; the running sum re-applied to every lane above.
# 2026-09-07: 2385 -> 2389 for the four phase-115 W8.3 CMS admin-socket
# slots; the running sum re-applied to every lane above.
# 2026-09-07: 2389 -> 2390 for the one phase-115 W8.6 native-SSI-client
# slot; the running sum re-applied to every lane above.
# 2026-09-07: 2390 -> 2391 for the one phase-115 W8.6 cross-worker CTA queue
# slot; the running sum re-applied to every lane above.
# 2026-09-07: 2391 -> 2393 for the two phase-115 W4.3 §5 refusal-SHAPE slots;
# the running sum re-applied to every lane above.
# 2026-09-07: 2393 -> 2395 for the two phase-115 W5.2 FEAT-decoy slots; the
# +2 reaches cvmfs-conformance (1740 -> 1742) and interop-worker (2328 -> 2330)
# as well.  Those two sit BELOW the placeholders and were missed on the first
# pass, which is the same "running sum" mistake the exclusive-lane note above
# already records: every lane below a widened one moves, not just the next.
# 2026-09-07: 2395 -> 2418 for the 23 axis-(e) 2.0-readiness metrics-lab
# slots in the exclusive lane; the running sum re-applied to every lane above.
# 2026-09-07: 2418 -> 2419 for the F6 posix origin slot in the exclusive lane.
# 2026-09-08: 2421 -> 2422 for the F1 brix_frm_* engine-knob lab in the
# exclusive lane (170 -> 171); the running sum re-applied to every lane above.
# 2026-09-08: 2422 -> 2423 for the F2 brix_frm_stagemsg StageEvents lab (lc-r20-frm-stagemsg, one root:// listener).
# 2026-09-08: +1 for the F3 OssArc backup-queue lab (lc-r20-arc-seal, one root:// listener).
# 2026-09-08: +1 for the F4 purge-policy lab (lc-r20-purge-policy, one root:// listener).
# 2026-09-08: +9 for the two F7 native-TPC labs (2425 -> 2434).
# 2026-09-09: +7 for the two F9 SSS entity labs (2434 -> 2441).
# 2026-09-09: +3 for the three F5 lab slots -- lc-r20-fwd-origin,
# lc-r20-fwd-proxy, lc-r20-urlcgi-opaque -- in the exclusive lane
# (190 -> 193); the running sum re-applied to every lane above.
# 2026-09-09: +3 for the cvmfs_live cmdscripts block (213 -> 216); it had run
# on absolute ports 12851-12898, outside the lane entirely.
# 2026-09-09: +5 for the F16 native-TPC-push lab (lc-r20-tpc-push, five
# listeners: push source, single-stream cap, dialect-off face, destination
# and egress-guarded source); the running sum re-applied to every lane above.
# 2026-09-09: +5 for the F17 cms.fsxeq operator-program lab
# (test_release20_cms_fsxeq.py, five one-listener data nodes) in the exclusive
# lane (198 -> 203); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F18 TPC identity-matrix lab (lc-r20-tpcmx, seven
# listeners) in the exclusive lane (203 -> 210); the running sum re-applied
# to every lane above.
# 2026-09-09: +2 for the F18 WebDAV-plane gate lab (lc-r20-tpcmx-dav: one
# listener plus the TLS mock source a permitted arm must actually reach) in the
# exclusive lane (210 -> 212); the running sum re-applied to every lane above.
# 2026-09-09: +7 for the F19 xrd.tlsca residual lab (lc-r20-tlsca, seven
# listeners: scope all / scope last / scope absent, verify_log all,
# verify_log failure, a malformed-CRL plane under `require`, and an
# unreadable-CRL plane under `try`); the running sum re-applied to every
# lane below.
# 2026-09-10: +1 for the F20 native-authdb grammar residual lab
# (lc-r20-authdb-f20, one root:// listener) in the exclusive lane
# (219 -> 220); the running sum re-applied to every lane below it.
# 2026-09-10: +1 for the F20 lab's /metrics face, PORT_COUNT 2474 -> 2475.
# 2026-09-19: +4 for the MU fleet's missing cache/direct halves (see the
# matching note on LIFECYCLE_SHARED_WIDTH); the running sum is re-applied to
# every lane in this file, PORT_COUNT 2485 -> 2489; +1 more for mu-root_write,
# 2489 -> 2490; +2 for the impgm broker-hold arms, 2490 -> 2492.
# 2026-09-19: +1 for lc-policy-rule-scope, the remote-backed webdav export that
# pins a policy rule's path scope when root_canon is "/", 2492 -> 2493.
PORT_COUNT = 2493
