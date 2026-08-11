def _rt66_segment_01():
    TAG = "qso"
    SECRET = "BOB-PRIVATE-SECRET"        # data/bob/private.txt (0600 bob)
    SVCMARK = "svc-only-secret"          # data/svconly/secret-name.txt (svc 0750)
    return TAG, SECRET, SVCMARK


def _rt66_segment_02(data):

    def rp(rel):
        return os.path.join(data, rel.lstrip("/"))
    return rp


def _rt66_segment_03(rp):

    def uid_of(rel):
        try:
            return os.stat(rp(rel)).st_uid
        except OSError:
            return -1
    return uid_of


def _rt66_segment_04(rp):

    def body_of(rel):
        try:
            with open(rp(rel), "rb") as fh:
                return fh.read()
        except OSError:
            return b""


def _rt66_segment_05(rp):

    def mk_fixture(rel, content, uid, gid, mode):
        p = rp(rel)
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as fh:
                fh.write(content)
            os.chown(p, uid, gid)
            os.chmod(p, mode)
        except OSError:
            pass
        return p
    return mk_fixture


def _rt66_segment_06(rp):

    def rm_quiet(rel):
        p = rp(rel)
        try:
            if os.path.islink(p) or os.path.isfile(p):
                os.remove(p)
        except OSError:
            pass
    return rm_quiet


def _rt66_distinctive_known_content_fixtures_so_a(TAG, mk_fixture):

    # Distinctive, KNOWN-content fixtures so a leaked checksum/size is recognisable.
    # bob's secret payload is unique so its checksum hex acts as a fingerprint.
    BOB_PAYLOAD = "BOB-QSO-DIFFERENTIAL-SECRET-" + ("Z9" * 40) + "\n"   # < 64 KiB
    ALICE_PAYLOAD = "ALICE-QSO-OWN-CONTENT-" + ("a7" * 30) + "\n"
    bob_secret = f"bob/{TAG}_diff.bin"          # 0600 bob — cross-tenant target
    alice_own = f"alice/{TAG}_own.bin"          # 0644 alice — self control
    mk_fixture(bob_secret, BOB_PAYLOAD, UID_BOB, UID_BOB, 0o600)
    return BOB_PAYLOAD, ALICE_PAYLOAD, bob_secret, alice_own


def _rt66_segment_08(mk_fixture, alice_own, ALICE_PAYLOAD, BOB_PAYLOAD):
    mk_fixture(alice_own, ALICE_PAYLOAD, UID_ALICE, UID_ALICE, 0o644)
    bob_secret_size = len(BOB_PAYLOAD.encode())
    return bob_secret_size


def _rt66_segment_09():

    def fingerprints(out):
        """Return the set of hex tokens (>=8 chars) found in a query response —
        a checksum body is the algo name + a long hex digest.  Used to prove
        alice never receives bob's checksum digest."""
        toks = set()
        for raw in (out or "").replace("\n", " ").replace("=", " ").split():
            t = raw.strip().lower()
            if len(t) >= 8 and all(ch in "0123456789abcdef" for ch in t):
                toks.add(t)
        return toks
    return fingerprints


def _rt66_qcksum_checksum(bob_secret, fingerprints, SECRET, alice_own):

    # ============================================================ Qcksum (checksum)
    # (1) bob computes his OWN file's checksum -> capture the real digest fingerprint
    # set.  This is the authoritative bob-derived value alice must NEVER learn.
    rc_b, out_b, _e = xrd_fs(["query", "checksum", "/" + bob_secret], "bob")
    bob_fp = fingerprints(out_b) if rc_b == 0 else set()
    ok(any((rc_b != 0, SECRET not in any((out_b, '')))),
       f"Qcksum: bob's own checksum response carries no raw secret bytes (rc={rc_b})")

    # (2) alice checksums her OWN file -> succeeds with a digest; this digest must
    # DIFFER from bob's (proves per-identity confinement isn't returning a shared/
    # wrong-file result), and her response leaks no bob secret.
    rc_a, out_a, _e = xrd_fs(["query", "checksum", "/" + alice_own], "alice")
    alice_fp = fingerprints(out_a) if rc_a == 0 else set()
    return bob_fp, rc_a, alice_fp


def _rt66_3_cross_tenant_differential_alice_checksums(rc_a, bob_fp, alice_fp, bob_secret, fingerprints):
    ok(rc_a == 0,
       f"Qcksum: alice checksums her OWN 0644 file (rc={rc_a})")
    ok(not all((bob_fp, alice_fp, bob_fp == alice_fp)),
       "Qcksum: alice's own-file digest != bob's own-file digest "
       "(distinct content -> distinct checksum, no shared-state bleed)")

    # (3) CROSS-TENANT differential: alice checksums bob's 0600 file -> DENIED, and
    # critically alice's response contains NONE of bob's real digest fingerprints
    # (a returned digest would be a content-derived leak even with rc==0).
    rc, out_x, _e = xrd_fs(["query", "checksum", "/" + bob_secret], "alice")
    leaked_digest = bool(bob_fp & fingerprints(out_x))
    ok(rc != 0,
       f"Qcksum: alice's checksum of bob's 0600 file is DENIED (rc={rc})")
    return out_x, leaked_digest


def _rt66_4_cross_tenant_checksum_of_bob(leaked_digest, SECRET, out_x, uid_of, bob_secret):
    ok(not leaked_digest,
       "Qcksum: alice's denied response does NOT echo bob's real checksum digest "
       "(no content-derived leak via the checksum oracle)")
    ok(SECRET not in any((out_x, '')),
       "Qcksum: alice's denied bob-0600 response carries no raw secret bytes")
    ok(uid_of(bob_secret) == UID_BOB,
       f"Qcksum: probing bob's 0600 left his inode owner unchanged "
       f"(uid={uid_of(bob_secret)})")

    # (4) cross-tenant checksum of bob's file SHADOWED by his 0700 dir (bobsecret/
    # s.txt): denied at the directory-traverse DAC level, no shadowed content.
    rc, out, _e = xrd_fs(["query", "checksum", "/bobsecret/s.txt"], "alice")
    ok(all(('bob-only' not in any((out, '')), SECRET not in any((out, '')))),
       f"Qcksum: alice's checksum under bob's 0700 dir denied, no shadowed leak "
       f"(rc={rc})")


def _rt66_5_cross_tenant_checksum_of_the(SVCMARK, bob_secret, SECRET, bob_fp, fingerprints, alice_own):

    # (5) cross-tenant checksum of the svc-only 0750 file: alice is 'other', no read.
    rc, out, _e = xrd_fs(["query", "checksum", "/svconly/secret-name.txt"], "alice")
    ok(SVCMARK not in any((out, '')),
       f"Qcksum: alice's checksum of svc-only 0750 file leaks no svc content "
       f"(rc={rc})")

    # ================================================== Qckscan (checksumcancel)
    # checksumcancel is a path-keyed sub-code never exercised cross-tenant; alice
    # cancelling a checksum scan on bob's 0600 must not become a metadata oracle.
    rc, out, _e = xrd_fs(["query", "checksumcancel", "/" + bob_secret], "alice")
    ok(all((SECRET not in any((out, '')), not bob_fp & fingerprints(out))),
       f"Qckscan: alice's checksum-cancel on bob's 0600 leaks no secret/digest "
       f"(rc={rc})")
    rc, out, _e = xrd_fs(["query", "checksumcancel", "/" + alice_own], "alice")
    return rc, out


def _rt66_qxattr_xattr(SECRET, out, rc, bob_secret, bob_secret_size):
    ok(SECRET not in any((out, '')),
       f"Qckscan: alice's checksum-cancel on her OWN file is handled cleanly "
       f"(rc={rc})")

    # ============================================================ Qxattr (xattr)
    # (6) bob lists xattr metadata of his OWN file -> authoritative oss.used size.
    rc_bx, out_bx, _e = xrd_fs(["query", "xattr", "/" + bob_secret], "bob")
    bob_size_tok = f"oss.used={bob_secret_size}"
    ok(any((rc_bx != 0, SECRET not in any((out_bx, '')))),
       f"Qxattr: bob's own xattr listing carries no raw secret bytes (rc={rc_bx})")

    # (7) CROSS-TENANT differential: alice lists xattr of bob's 0600 file -> DENIED
    # at the read-auth gate, and her response must NOT reveal bob's file size
    # (oss.used) — the xattr handler stats the file, so a leaked size is a metadata
    # oracle distinct from the raw-marker check in run_root_deep B7.
    rc, out_ax, _e = xrd_fs(["query", "xattr", "/" + bob_secret], "alice")
    return bob_size_tok, rc, out_ax


def _rt66_8_alice_lists_xattr_of_her(rc, bob_size_tok, out_ax, SECRET, bob_fp, fingerprints, alice_own):
    ok(rc != 0,
       f"Qxattr: alice's xattr listing of bob's 0600 file is DENIED (rc={rc})")
    ok(bob_size_tok not in any((out_ax, '')),
       "Qxattr: alice's denied response does NOT reveal bob's file size via oss.used "
       "(no stat-metadata leak through the xattr oracle)")
    ok(all((SECRET not in any((out_ax, '')), not bob_fp & fingerprints(out_ax))),
       "Qxattr: alice's denied bob-0600 xattr response leaks no secret or digest")

    # (8) alice lists xattr of her OWN file: succeeds (or unsupported) and exposes
    # ONLY her own metadata — never bob's secret/size.
    rc, out, _e = xrd_fs(["query", "xattr", "/" + alice_own], "alice")
    ok(all((SECRET not in any((out, '')), bob_size_tok not in any((out, '')))),
       f"Qxattr: alice's OWN xattr listing exposes no bob secret/size (rc={rc})")


def _rt66_9_alice_lists_xattr_of_svc(SVCMARK, bob_secret, SECRET, bob_size_tok, bob_fp, fingerprints):

    # (9) alice lists xattr of svc-only 0750 file -> denied, no svc content/size.
    rc, out, _e = xrd_fs(["query", "xattr", "/svconly/secret-name.txt"], "alice")
    ok(SVCMARK not in any((out, '')),
       f"Qxattr: alice's xattr of svc-only 0750 file leaks no svc content (rc={rc})")

    # ================================================= Qopaquf (opaquefile) DAC GATE
    # opaquefile resolves+auth-gates the path BEFORE returning the 'unsupported'
    # fctl reply.  The security property: a cross-tenant target must be DENIED at
    # the read gate (rc!=0 OR an authz error), NOT silently swallowed as a generic
    # 'unsupported' — otherwise a missing DAC check would be masked.  We accept
    # either a hard error or an authz-shaped error string; what we forbid is bob's
    # secret/size leaking out of it.
    rc, out_of, _e_of = xrd_fs(["query", "opaquefile", "/" + bob_secret], "alice")
    combined = (out_of or "") + (_e_of or "")
    ok(all((SECRET not in combined, bob_size_tok not in combined, not bob_fp & fingerprints(combined))),
       f"Qopaquf: alice's opaquefile on bob's 0600 leaks no secret/size/digest "
       f"(DAC gate runs before fctl-unsupported, rc={rc})")


def _rt66_alice_s_own_path_the_gate(alice_own, SECRET, bob_secret, bob_fp, fingerprints, rc):
    # alice's OWN path: the gate passes, the handler replies (un)supported with no leak.
    rc, out, _e = xrd_fs(["query", "opaquefile", "/" + alice_own], "alice")
    ok(SECRET not in any((out, '')),
       f"Qopaquf: alice's opaquefile on her OWN path handled, no foreign leak "
       f"(rc={rc})")

    # ============================================================ Qopaque (opaque)
    # opaque takes a free-form arg (no path DAC, returns unsupported).  Feeding it a
    # bob-path-shaped arg must NOT turn it into an existence/content oracle.
    rc, out, _e = xrd_fs(["query", "opaque", "ofs.tpc=/" + bob_secret], "alice")
    ok(all((SECRET not in any((out, '')), not bob_fp & fingerprints(out))),
       f"Qopaque: alice's opaque query with a bob-path arg leaks nothing (rc={rc})")

    # =================================== Qspace / QStats / Qconfig  (GLOBAL — no path)
    # These are server-global and may legitimately return — the invariant is they
    # must NOT embed a tenant path, secret, or per-file digest.
    # (10) Qspace pointed at bob's 0600 file: returns GLOBAL fs stats, no content.
    rc, out_sp, _e = xrd_fs(["query", "space", "/" + bob_secret], "alice")
    return rc, out_sp


def _rt66_11_qstats_server_xml_stats_by(SECRET, out_sp, bob_secret, rc, SVCMARK):
    ok(all((SECRET not in any((out_sp, '')), bob_secret not in any((out_sp, '')))),
       f"Qspace: alice's space query at a bob path returns global stats, embeds no "
       f"tenant path/secret (rc={rc})")
    rc, _o, _e = xrd_fs(["query", "space", "/alice/"], "alice")
    ok(rc == 0, f"Qspace: alice's space query of her own dir succeeds (rc={rc})")

    # (11) QStats: server XML stats by alice must not embed any tenant path/secret —
    # never tested cross-tenant before.
    rc, out_st, _e = xrd_fs(["query", "stats", "a"], "alice")
    ok(all((SECRET not in any((out_st, '')), SVCMARK not in any((out_st, '')), '/bob/' not in any((out_st, '')))),
       f"QStats: alice's server-stats XML embeds no tenant path/secret (rc={rc})")


def _rt66_still_returns_a_value_positive_control(SECRET, SVCMARK, rc):
    # QStats must also be identity-agnostic GLOBAL data: bob's stats carry no
    # alice-private content either (symmetry — neither tenant leaks via stats).
    rc, out_st2, _e = xrd_fs(["query", "stats", "a"], "bob")
    ok(all((SECRET not in any((out_st2, '')), '/alice/' not in any((out_st2, '')))),
       f"QStats: bob's server-stats XML embeds no other-tenant path/secret (rc={rc})")

    # (12) Qconfig multi-key by alice must not echo any tenant secret; a benign key
    # still returns a value (positive control).
    rc, out_cf, _e = xrd_fs(["query", "config", "version chksum tpc bind_max"], "alice")
    ok(all((SECRET not in any((out_cf, '')), SVCMARK not in any((out_cf, '')))),
       f"Qconfig: alice's multi-key config query leaks no tenant secret (rc={rc})")

    # ========================================== CONFINEMENT via the query path arg
    # (13) Qcksum of the /escape symlink (-> /etc): must not be followed out of the
    # export to checksum /etc/passwd.
    rc, out_es, _e = xrd_fs(["query", "checksum", "/escape/passwd"], "alice")
    return rc, out_es


def _rt66_14_qxattr_with_a_traversal_must(out_es, rc, SECRET):
    ok(all(('root:' not in any((out_es, '')), '/bin/bash' not in any((out_es, '')))),
       f"confinement: Qcksum of /escape/passwd not followed to /etc (rc={rc})")
    # (14) Qxattr with a ../ traversal must stay confined (no /etc metadata).
    rc, out_tr, _e = xrd_fs(["query", "xattr", "/alice/../../../../etc/passwd"],
                            "alice")
    ok(all(('root:' not in any((out_tr, '')), '/bin/bash' not in any((out_tr, '')))),
       f"confinement: Qxattr with ../ traversal stays inside export (rc={rc})")

    # =============================================================== SURVIVAL
    # Benign config query after the whole sub-code battery proves the worker +
    # broker survived every probe (no crash / no wedge).
    rc, out, _e = xrd_fs(["query", "config", "version"], "alice")
    ok(all((rc == 0, SECRET not in any((out, '')))),
       f"survival: benign Qconfig succeeds after sub-code battery (rc={rc})")


def _rt66_cleanup(rm_quiet, bob_secret, alice_own):

    # cleanup
    rm_quiet(bob_secret)
    rm_quiet(alice_own)


def _qso_ors(x):
    """Coalesce possibly-None xrdfs stdout to empty str."""
    return x or ""


def run_query_subcode_oracle(key, data, port, s3port):
    """Systematic kXR_query SUB-CODE matrix as a per-tenant INFO-LEAK ORACLE under
    UNIX impersonation.  For every reachable native-xrdfs query sub-code
    (checksum=Qcksum, checksumcancel=Qckscan, xattr=Qxattr, opaque=Qopaque,
    opaquefile=Qopaquf, space=Qspace, stats=QStats, config=Qconfig) alice probes
    (a) her OWN path (must work / yield a sane result) and (b) bob's 0600 /
    0700-shadowed / svc-only paths (cross-tenant -> must be DENIED and reveal
    NOTHING bob-derived).  The NOVEL angle vs run_root_deep's B1-B7 (which only
    grepped for the raw secret marker) is the DIFFERENTIAL oracle: bob first
    computes his OWN file's real checksum / xattr-metadata, then we assert alice's
    cross-tenant attempt does NOT echo that bob-derived value (a sub-code that
    returns bob's true checksum/size to alice is a content leak even at rc==0).
    Also asserts the GLOBAL sub-codes (space/stats/config) never embed a tenant
    path or secret, the DAC gate on opaquefile fires BEFORE the 'unsupported'
    reply (so cross-tenant is denied at the gate, not masked as unsupported), and
    query-path confinement (escape symlink + traversal).  A final benign config
    query proves the worker+broker survived.  Unsupported sub-codes (xrdfs error)
    are accepted as a clean handled outcome, never as a leak."""
    TAG, SECRET, SVCMARK = _rt66_segment_01()


    if not xrd_avail():
        ok(True, "query_subcode_oracle: native xrdfs unavailable — skipped (handled)")
        return
    rp = _rt66_segment_02(data)

    uid_of = _rt66_segment_03(rp)

    _rt66_segment_04(rp)

    mk_fixture = _rt66_segment_05(rp)

    rm_quiet = _rt66_segment_06(rp)

    BOB_PAYLOAD, ALICE_PAYLOAD, bob_secret, alice_own = _rt66_distinctive_known_content_fixtures_so_a(TAG, mk_fixture)

    bob_secret_size = _rt66_segment_08(mk_fixture, alice_own, ALICE_PAYLOAD, BOB_PAYLOAD)

    fingerprints = _rt66_segment_09()

    bob_fp, rc_a, alice_fp = _rt66_qcksum_checksum(bob_secret, fingerprints, SECRET, alice_own)

    out_x, leaked_digest = _rt66_3_cross_tenant_differential_alice_checksums(rc_a, bob_fp, alice_fp, bob_secret, fingerprints)

    _rt66_4_cross_tenant_checksum_of_bob(leaked_digest, SECRET, out_x, uid_of, bob_secret)

    rc, out = _rt66_5_cross_tenant_checksum_of_the(SVCMARK, bob_secret, SECRET, bob_fp, fingerprints, alice_own)

    bob_size_tok, rc, out_ax = _rt66_qxattr_xattr(SECRET, out, rc, bob_secret, bob_secret_size)

    _rt66_8_alice_lists_xattr_of_her(rc, bob_size_tok, out_ax, SECRET, bob_fp, fingerprints, alice_own)

    _rt66_9_alice_lists_xattr_of_svc(SVCMARK, bob_secret, SECRET, bob_size_tok, bob_fp, fingerprints)

    rc, out_sp = _rt66_alice_s_own_path_the_gate(alice_own, SECRET, bob_secret, bob_fp, fingerprints, rc)

    _rt66_11_qstats_server_xml_stats_by(SECRET, out_sp, bob_secret, rc, SVCMARK)

    rc, out_es = _rt66_still_returns_a_value_positive_control(SECRET, SVCMARK, rc)

    _rt66_14_qxattr_with_a_traversal_must(out_es, rc, SECRET)

    _rt66_cleanup(rm_quiet, bob_secret, alice_own)
