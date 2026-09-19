# fleet_ports_shared_phase5_rest_c.py — ledger entries split off for the 600-line
# cap; merged back via split_continuation.load (.update on
# LIFECYCLE_SHARED_PORTS_PHASE5).
#
# The numbers below are DECLARATION-ORDER placeholders, not addresses.
# port_ladder.rebase_lifecycle_ledger() repacks the whole shared band
# contiguously from LIFECYCLE_SHARED_OFFSET, so what a slot actually costs is one
# allocation in LIFECYCLE_SHARED_WIDTH — which is why adding one here is an
# intentional compatibility event that re-sums every lane below the shared one in
# port_ladder_offsets_tail.py, and why picking a "free" number here proves
# nothing on its own.

# Phase-115 W5.1 (tests/test_phase115_gridftp_mode_e.py): the GridFTP MODE E
# data channel on the outbound FTP driver.  Two Python origins — one that can
# speak extended block mode (and emits a non-conforming block stream when the
# retrieved NAME says so, so every refusal costs a seed file rather than a whole
# second origin) and one that answers `MODE E` 504 — plus one nginx with three
# WebDAV fronts over them: `mode=e`, the MODE S control over the SAME origin (so
# a byte-exactness difference is attributable to the mode and not to the lab),
# and a `mode=e` front aimed at the origin that cannot do it.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-mode-e-origin": {"port": 31013},
    "lc-p115-mode-e-plain-origin": {"port": 31014},
    "lc-p115-mode-e": {"port": 31015,
                       "extra": {"STREAM_PORT": 31016, "REFUSE_PORT": 31017}},
})

# Phase-115 W5.1 (tests/test_phase115_gridftp_prot_p.py): the protected outbound
# GridFTP data channel.  Four WebDAV fronts that differ only in whether their
# store line says `prot=p` and which origin it names — the fourth reaches the
# unsecured origin over plain ftp:// and DOES serve the file, which is what
# makes the protected front's refusal a statement about protection rather than
# about a broken origin.
#
# The two stream GridFTP origins are a SECOND instance rather than two more
# servers inside the front's: the gsiftp driver's WRITE path still runs its
# blocking FTP conversation on the worker, so a front whose origin shares that
# worker cannot upload at all.  The ports stay where they were — the origin
# instance takes the two that already named the origins.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-prot-p": {"port": 31018,
                       "extra": {"CLEAR_PORT": 31019,
                                 "REFUSE_PORT": 31020,
                                 "PLAIN_OK_PORT": 31021}},
    "lc-p115-prot-p-origin": {"port": 31022,
                              "extra": {"PLAIN_ORIGIN_PORT": 31023}},
})

# phase-115 W5.2 — the ERET partial-retrieve lab: two origins that differ only
# in whether they advertise ERET, and one nginx whose two fronts carry the SAME
# store line (see configs/nginx_lc_gsiftp_eret.conf).
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-eret-origin": {"port": 31024},
    "lc-p115-eret-plain-origin": {"port": 31025},
    "lc-p115-eret": {"port": 31026, "extra": {"PLAIN_PORT": 31027}},
})

# phase-115 W5.3 — the SPAS striped-passive lab.  THREE origins, because the
# three outcomes a SPAS reply can have are properties of the ORIGIN and not of
# anything an operator writes: one that stripes, one that never advertises, and
# one that advertises a stripe on an address it does not own (the FTP-bounce
# negative).  One nginx carries five fronts over them — see
# configs/nginx_lc_gsiftp_spas.conf.  The stripe DATA listeners are ephemeral,
# as EPSV's already are; only the control ports are ledgered.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-spas-origin": {"port": 31029},
    "lc-p115-spas-plain-origin": {"port": 31030},
    "lc-p115-spas-bounce-origin": {"port": 31031},
    "lc-p115-spas": {"port": 31032,
                     "extra": {"UNSTRIPED_PORT": 31033,
                               "PLAIN_PORT": 31034,
                               "BUDGET_PORT": 31035,
                               "BOUNCE_PORT": 31036}},
})

# phase-115 W5.4 — same-origin server copy: ONE origin under three exports
# (read/write, read-only, and a deeper root), because the point of the suite is
# that all three reach the same origin instance.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-copy-origin": {"port": 31037},
    "lc-p115-copy": {"port": 31038,
                     "extra": {"RO_PORT": 31039,
                               "SUB_PORT": 31040}},
})

# phase-116 (owned by another lane) — a single http front, no extras; declared
# here because an unledgered lifecycle spec raises rather than falling back to
# an ephemeral port.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p116-dns-bridge": {"port": 31028},
})

# phase-115 W7.2a (tests/test_phase115_fuse_caller_identity.py): three stream
# instances that differ ONLY in the keytab they load, because the identity a
# proposed name resolves to is decided by the key's own u:/g:/n: fields at
# config-parse time and cannot be varied on a live server.  `any` issues
# u:anybody (the proposed name becomes the identity), `svc` issues a fixed user
# (the security negative: a proposed name must not move it), and `plus` is the
# anybody key with a `+` name suffix, whose BRIX_SSS_OPT_NOIPCK is parsed and
# then read nowhere — inert, and pinned live rather than by grep.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-sss-ident-any": {"port": 31041},
    "lc-p115-sss-ident-svc": {"port": 31042},
    "lc-p115-sss-ident-plus": {"port": 31043},
})

# phase-115 W2.4 (tests/test_phase115_cache_origin_gsi.py): a fourth read cache
# carrying the rogue anchor at SERVER level as `brix_trusted_ca` instead of
# inside the credential.  It exists to hold still the discovery that the two
# spellings are not equivalent on the xroot cache->origin leg — the synthetic
# srv_conf never consults the server-level directive — so it must be a real
# second instance rather than a reconfiguration of the credential-anchored one.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-co-outerca": {"port": 31044},
})

# phase-115 W4.3 (tests/test_phase115_pgread_verify.py): one WebDAV read node
# per verify_pages shape.  They cannot share an instance because the policy is
# a store-line parameter fixed at config-parse time, and each node points at a
# throwaway Python origin (PgOrigin), which binds its own ephemeral port and
# needs no ledger row of its own.
#
# TRAP (2026-09-07): these had no ledger rows at all.  Every one of them reaches
# `lifecycle.start()`, which raises RuntimeError on an unledgered spec — so the
# suite was green only for a caller running it with TEST_SKIP_SERVER_SETUP=1
# (its own Run: line) and halted the fleet lane the first time it was reached.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-pgv-ok-req": {"port": 31045},
    "lc-p115-pgv-ok-be": {"port": 31046},
    "lc-p115-pgv-range": {"port": 31047},
    "lc-p115-pgv-default": {"port": 31048},
    "lc-p115-pgv-corrupt": {"port": 31049},
    "lc-p115-pgv-corrupt-be": {"port": 31050},
    "lc-p115-pgv-badoff": {"port": 31051},
    "lc-p115-pgv-empty": {"port": 31052},
    "lc-p115-pgv-noadv-req": {"port": 31053},
    "lc-p115-pgv-noadv-be": {"port": 31054},
    "lc-p115-pgv-refuse-req": {"port": 31055},
    "lc-p115-pgv-refuse-be": {"port": 31056},
    # W4.3 §5 SHAPE: the two rows that pin what a refusal looks like ON THE
    # WIRE, not merely that it happened.  31057-31062 belong to the CMS block
    # below, so these take the next free pair above it.
    "lc-p115-pgv-shape-bytes": {"port": 31078},
    "lc-p115-pgv-shape-abort": {"port": 31079},
})

# phase-115 W2.2/W2.3 (test_phase115_cms_space_floor.py,
# test_phase115_cms_locate_entry_types.py, _test_phase115_cms_coalesce_helpers.py):
# the two-faced CMS managers those suites start through `_mgr()`.  Each carries
# a root face (`port`) and a CMS face (`CMS_PORT`), the same shape as
# lc-cms-parity-mgr; the FakeNode data servers are pure Python and bind their
# own ephemeral ports.  Same TRAP as the pgv block above — unledgered, so
# test_phase115_cms_space_floor.py halted rhB34 at 52%.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-cms-space-mgr": {"port": 31057, "extra": {"CMS_PORT": 31058}},
    "lc-p115-cms-loctype-mgr": {"port": 31059, "extra": {"CMS_PORT": 31060}},
    "lc-p115-cms-coalesce-mgr": {"port": 31061, "extra": {"CMS_PORT": 31062}},
})

# tests/test_pblock_group_multiuser.py:291 — a GSI/gridmap pblock-group node
# registered with no `port=`.  It is latent rather than failing today only
# because the suite it belongs to is root-only and skips for an unprivileged
# runner; as root it reaches the same `RuntimeError: no fixed port` the pgv and
# CMS blocks above did.  Reported by guard #14
# (tools/ci/check_lifecycle_spec_ledger.py), which judges specs statically and
# so sees it whether or not the suite runs here.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "pbgm-gsi": {"port": 31063},
})

# phase-115 W8.2 (tests/test_phase115_tpc_cred_renew.py): the mid-transfer
# delegated-credential renewal lab.  One token-DEMANDING source — the only
# instance here with `brix_auth token`, and the only setting in which the
# destination presents a ztn credential at all, which is what makes renewal
# reachable — plus five destinations that differ only in their outbound
# credential shape: renew_lead wider than the issuer's lifetime, no lead at all
# (the pre-W8.2 shape), a lead inside the lifetime, an issuer that mints once
# and then fails, and the default passthrough-opt mode carrying a bearer file it
# has no authority to re-mint (twice, for renew_strict off and on).
#
# They cannot be collapsed: `brix_tpc_outbound_renew_lead` and
# `brix_tpc_outbound_renew_strict` are config-parse-time server values, so each
# arm is a distinct instance rather than a per-test reconfiguration.  The
# destinations run `brix_auth none`, so `lc-p115-renew-off` doubles as the
# ANONYMOUS pull source for the `cred_presented` security-negative and needs no
# row of its own.  MOCK_PORT is the in-test minting IdP (a Python
# ThreadingHTTPServer), one for the whole lab.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-renew-src": {"port": 31064},
    "lc-p115-renew-dst": {"port": 31065, "extra": {"MOCK_PORT": 31066}},
    "lc-p115-renew-off": {"port": 31067},
    "lc-p115-renew-ample": {"port": 31068},
    "lc-p115-renew-once": {"port": 31069},
    "lc-p115-renew-lax": {"port": 31070},
    "lc-p115-renew-strict": {"port": 31071},
})

# phase-115 W8.3 (tests/test_phase115_cms_admin_socket.py): the CMS admin
# socket lab.  A manager carrying BOTH admin sockets — §1.16's session socket
# and §2.x's new cluster socket — plus two CMS nodes that register into the
# manager's SHM node registry.
#
# Two nodes, not one: `nodes` listing a single row cannot show that the listing
# is per-node rather than per-connection, and drain/undrain of one node cannot
# show that the OTHER node is left alone — which is the property an operator
# actually relies on when draining a box mid-incident.  The manager needs its
# CMS_PORT as a second listener (`brix_cms_server on`) because the registry is
# only populated by real CMS logins; there is no way to seed it from outside,
# and seeding it would test the socket against a fiction.
#
# NODE_A_PORT / NODE_B_PORT are ADVERTISED-only: the two nodes are Python
# FakeNodes (_test_cms_parity_wave_helpers) that name these as their kYR_login
# dPort, so the registry keys — and therefore every `drain <host:port>` operand
# — are ladder-owned and cannot collide with another lane's real listener.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-cmsadm-mgr": {"port": 31072, "extra": {"CMS_PORT": 31073,
                                                    "NODE_A_PORT": 31074,
                                                    "NODE_B_PORT": 31075}},
})

# phase-115 W8.6 (tests/test_phase115_ssi_client.py): the native SSI client
# lab.  One throwaway root:// server with `brix_ssi on;` and NO
# `brix_ssi_service` line — the directive gates only the CTA tape service, and
# the suite's point is that the built-in reference services resolve without it.
#
# A single port, not one per service: every test drives the same seven built-in
# services through the same listener, and the driver holds one connection for
# the length of one invocation, so nothing here needs an instance of its own.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-ssi-client": {"port": 31076},
})

# phase-115 W8.6 (tests/test_phase115_cta_shm_queue.py): the cross-worker CTA
# queue lab.  ONE instance, deliberately carrying `worker_processes 2;` — the
# defect this row exists to prove gone (a per-process `static brix_cta_queue_t
# *g_cta_queue`, whose next_id restarted in every worker) is invisible with a
# single worker, because one process never collides with itself.
#
# It cannot share `lc-p115-ssi-client`: that instance runs the default worker
# count and names no journal, and the ids here are only observable through the
# journal the instance writes.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-cta-shm": {"port": 31077},
})

# phase-115 W5.2, the FEAT-terminator finding: an origin that advertises rows
# CONTAINING "ERET"/"SPAS" without advertising either feature, and a front over
# it.  It cannot reuse `lc-p115-eret-plain-origin` — that one advertises nothing
# at all, so it proves the driver is quiet when there is nothing to see, while
# this one proves the probe reads a TOKEN and not a substring.  Ledgered late
# rather than in the W5.2 block above because 31028 was already spent; the
# front is a third listen on the W5.2 nginx, so the three fronts still carry
# one identical store line and the origins remain the only variable.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-p115-eret-decoy-origin": {"port": 31247},
})
LIFECYCLE_SHARED_PORTS_PHASE5["lc-p115-eret"]["extra"]["DECOY_PORT"] = 31248

# brix_gsi_legacy_proxy at value granularity (tests/test_gsi_legacy_proxy.py):
# pre-RFC 3820 (GT2) proxy acceptance, `off` | `on` | `full-only` | absent, on
# BOTH planes from ONE instance.  The directive is a `server {}`-level switch on
# the stream plane and a location-merged one on the http plane, and its whole
# observable is a login verdict — so four root:// listeners and four davs://
# listeners over ONE trust anchor carry the (mode x plane x credential) table,
# and one error log carries both planes' NOTICE/WARN lines.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-gsi-legacy-proxy": {"port": 31324,
                            "extra": {"ON_PORT": 31325, "FULL_PORT": 31326,
                                      "DEF_PORT": 31327, "HTTP_PORT": 31328,
                                      "HTTP_ON_PORT": 31329,
                                      "HTTP_FULL_PORT": 31330,
                                      "HTTP_DEF_PORT": 31331}},
})

# The two WebDAV arms of test_impersonation_gridmap_root.py (group impgm).  The
# three root:// arms of that module — impgm-single, impgm-s3, impgm-root-gsi —
# were ledgered with the rest of the root-only families; these two were not, and
# a root run died on `lifecycle spec 'impgm-wd-squash' has no fixed port` before
# either fixture could start.  They are separate instances rather than one: the
# whole observable is a grid-mapfile verdict, and `squash` (an unmapped
# principal lands on brixgm_squash) and `deny` (no brix_idmap_default_user, so
# the same principal fails closed) are two values of ONE server-level directive,
# which a single nginx cannot hold at once.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "impgm-wd-squash": {"port": 31332},
    "impgm-wd-deny": {"port": 31333},
})

# Two more impgm arms, for what the privileged broker still HOLDS after the
# double-fork rather than for what it maps.  They are separate instances because
# each is measured in a state the other cannot be in: impgm-sealed must stay up
# while its descriptor table is read, and impgm-rebind is stopped mid-test so the
# port it was bound to can be claimed by something else.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "impgm-sealed": {"port": 31345},
    "impgm-rebind": {"port": 31346},
})

# One instance for test_policy_rule_scope.py: a webdav export with a REMOTE
# backend, which is what makes its root_canon "/" and sends every policy rule
# through the resolver branch that used to drop the rule's path.  It is its own
# server because no other lifecycle instance is both remote-backed and carrying
# brix_require_vo — the combination IS the condition under test.
LIFECYCLE_SHARED_PORTS_PHASE5.update({
    "lc-policy-rule-scope": {"port": 31347},
})
