"""
Phase 28 — adversarial-hardening residuals (P90-28.6): source-contract checks.

Coverage (3-test ritual per change):
  C3 OCSP max-staleness — check_ocsp_response() now bounds the response's
     thisUpdate..nextUpdate validity window via OCSP_check_validity():
       1. success shape: the check + both bound constants are present/wired;
       2. error: a stale/not-yet-valid response degrades to UNKNOWN (rc=1,
          soft_fail policy decides), never to GOOD, and is checked after
          find_status but before the status switch;
       3. security-neg: REVOKED is never overridden by staleness.
  D3 authdb ADMIN ('k') bit — explicit-grant-only, rule/path-scoped, and a
     repo-wide consumer census so no future code can add an "admin ⇒
     allow-all" shortcut unreviewed.
  D4 pwd user-enumeration timing — unknown user burns the same PBKDF2 cost
     as a wrong password against a fixed dummy entry:
       1. success shape: the dummy verify sits in the lookup-failure branch;
       2. error: both post-decrypt failure modes funnel to ONE uniform wire
          message ("invalid password") — no "no such user" divergence;
       3. security-neg: the real compare stays constant-time (CRYPTO_memcmp)
          and the dummy hash satisfies the hashlen gate so the KDF actually
          runs (a short dummy would early-return and defeat the fix).

These are contract assertions on the checked-in sources — no fleet needed.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _read(rel):
    return (ROOT / rel).read_text()


# ---------------------------------------------------------------------------
# C3 — OCSP response max-staleness
# ---------------------------------------------------------------------------

class TestC3OcspMaxStaleness:

    def test_validity_check_present(self):
        req = _read("src/auth/crypto/ocsp_request.c")
        hdr = _read("src/auth/crypto/ocsp_internal.h")
        assert "OCSP_check_validity(thisupd, nextupd" in req
        assert "BRIX_OCSP_VALIDITY_SKEW_SEC" in req
        assert "BRIX_OCSP_VALIDITY_MAX_AGE_SEC" in req
        assert "#define BRIX_OCSP_VALIDITY_SKEW_SEC" in hdr
        assert "#define BRIX_OCSP_VALIDITY_MAX_AGE_SEC" in hdr

    def test_stale_degrades_to_unknown_not_good(self):
        req = _read("src/auth/crypto/ocsp_request.c")
        gate = req.index("OCSP_check_validity(thisupd, nextupd")
        # Ordering: after the status extraction, before the GOOD/REVOKED map.
        assert req.index("OCSP_resp_find_status(bresp, id") < gate
        assert gate < req.index("case V_OCSP_CERTSTATUS_GOOD:")
        # The stale branch returns the UNKNOWN code for the soft_fail policy,
        # and says so in the operator-facing log line.
        block = req[gate:gate + 700]
        assert "return 1;" in block
        assert "outside its validity window" in block

    def test_revoked_never_overridden_by_staleness(self):
        req = _read("src/auth/crypto/ocsp_request.c")
        gate = req.index("OCSP_check_validity(thisupd, nextupd")
        block = req[gate:gate + 400]
        assert "status != V_OCSP_CERTSTATUS_REVOKED" in block, (
            "stale REVOKED evidence must still deny — the staleness gate may "
            "only downgrade GOOD/UNKNOWN outcomes")


# ---------------------------------------------------------------------------
# E1 — tamper-evident (hash-chained) admin audit log
# ---------------------------------------------------------------------------

class TestE1AuditHashChain:

    def test_chain_present_and_wired(self):
        adm = _read("src/observability/dashboard/api_admin.c")
        hdr = _read("src/observability/dashboard/dashboard_http.h")
        assert "uint8_t     audit_chain[32];" in hdr
        assert "uint64_t    audit_seq;" in hdr
        assert "brix_sha256(msg, 32 + canon_len, digest)" in adm
        assert "seq=%uL" in adm
        assert "ngx_hex_dump(hex, digest, 16)" in adm

    def test_crypto_failure_never_drops_the_audit_line(self):
        adm = _read("src/observability/dashboard/api_admin.c")
        fail = adm.index('"%*s chain=-"')
        # The unchained fallback logs the same canonical text and returns
        # WITHOUT committing the chain state.
        assert adm.index("brix_sha256(msg") < fail
        assert fail < adm.index("ngx_memcpy(conf->audit_chain, digest, 32)")

    def test_each_line_commits_to_prior_digest_and_own_seq(self):
        adm = _read("src/observability/dashboard/api_admin.c")
        # prev digest is prefixed to the hashed message …
        assert "ngx_memcpy(msg, conf->audit_chain, 32)" in adm
        assert "ngx_memcpy(msg + 32, canon, canon_len)" in adm
        # … the canonical text embeds the sequence number (reorder/delete
        # detection), and state is committed before the line is emitted.
        canon = adm.index('result=%s seq=%uL"')
        commit = adm.index("ngx_memcpy(conf->audit_chain, digest, 32)")
        emit = adm.index('"%*s chain=%*s"')
        assert canon < commit < emit
        # Genesis + verifier recipe are documented for operators.
        hdr = _read("src/observability/dashboard/dashboard_http.h")
        assert "32 zero bytes" in hdr
        assert "prev = digest" in adm


# ---------------------------------------------------------------------------
# D3 — authdb ADMIN ('k') bit: explicit, path-scoped, no global bypass
# ---------------------------------------------------------------------------

class TestD3AdminBitPathScope:

    def test_admin_bit_never_implicit(self):
        parse = _read("src/auth/authz/authdb_parse.c")
        # Exactly one grant site, and it is the explicit 'k' case — no other
        # privilege letter may fold ADMIN in.
        assert parse.count("BRIX_AUTH_ADMIN") == 1
        k_case = parse.index("case 'k':")
        assert "BRIX_AUTH_ADMIN" in parse[k_case:k_case + 60]
        # The neighbours stay non-admin: append folds to UPDATE, read to
        # READ|LOOKUP.
        assert "case 'a': privs |= BRIX_AUTH_UPDATE" in parse
        assert "case 'r': privs |= BRIX_AUTH_READ | BRIX_AUTH_LOOKUP" in parse

    def test_admin_census_no_new_consumer_without_review(self):
        # Ratchet: the ADMIN bit is consumed in exactly these places — the
        # define, the 'k' parse case, and the acc-op mapping.  Any new file
        # touching BRIX_AUTH_ADMIN must update this census consciously (and
        # must not introduce an "admin ⇒ allow-all" shortcut).
        expected = {
            "src/core/types/config.h",
            "src/auth/authz/authdb_parse.c",
            "src/auth/authz/auth_gate.c",
        }
        found = set()
        for p in (ROOT / "src").rglob("*.[ch]"):
            if "BRIX_AUTH_ADMIN" in p.read_text(errors="replace"):
                found.add(str(p.relative_to(ROOT)))
        assert found == expected, f"ADMIN-bit census drifted: {found ^ expected}"

    def test_admin_is_rule_scoped_and_maps_to_specific_acc_op(self):
        authdb = _read("src/auth/authz/authdb.c")
        find_rule = _read("src/auth/authz/find_rule.c")
        gate = _read("src/auth/authz/auth_gate.c")
        # Grants live on per-path rules: sufficiency is bit-subset on the
        # longest boundary-aware prefix match, deny when no rule matches —
        # ADMIN gets no other lookup path, so it cannot act off-prefix.
        assert "(rule[i].privs & needed_privs) == needed_privs" in authdb
        assert "brix_path_prefix_match" in find_rule
        # The one consumer maps ADMIN to the specific acc CHMOD operation,
        # never to an unconditional allow.
        admin_line = next(l for l in gate.splitlines()
                          if "auth_level & BRIX_AUTH_ADMIN" in l)
        assert "BRIX_AOP_CHMOD" in admin_line


# ---------------------------------------------------------------------------
# D4 — pwd auth user-enumeration timing
# ---------------------------------------------------------------------------

class TestD4PwdUniformTiming:

    def test_dummy_verify_on_unknown_user(self):
        auth = _read("src/auth/pwd/auth.c")
        look = auth.index("brix_pwd_file_lookup(pwdpath")
        block = auth[look:look + 1200]
        assert "(void) brix_pwd_verify(creds, creds_len, dummy_salt" in block
        assert "dummy_hash" in block

    def test_uniform_wire_message_for_both_failures(self):
        auth = _read("src/auth/pwd/auth.c")
        # Lookup-fail and verify-fail must funnel into the single
        # `if (!verified)` deny with one wire string; the dummy branch must
        # not mint its own error message or early-return.
        assert auth.count('kXR_NotAuthorized, "invalid password"') == 1
        look = auth.index("brix_pwd_file_lookup(pwdpath")
        deny = auth.index('kXR_NotAuthorized, "invalid password"')
        dummy = auth.index("(void) brix_pwd_verify(creds, creds_len, dummy_salt")
        assert look < dummy < deny
        assert "return" not in auth[dummy:auth.index("}", dummy)], (
            "dummy-verify branch must fall through to the shared deny")

    def test_real_compare_stays_ct_and_dummy_passes_hashlen_gate(self):
        pwdfile = _read("src/auth/pwd/pwdfile.c")
        auth = _read("src/auth/pwd/auth.c")
        assert "CRYPTO_memcmp(derived, hash, BRIX_PWD_HASH_LEN)" in pwdfile
        assert "hashlen != BRIX_PWD_HASH_LEN" in pwdfile
        # The dummy hash must be exactly BRIX_PWD_HASH_LEN so brix_pwd_verify
        # reaches PKCS5_PBKDF2_HMAC_SHA1 instead of early-returning.
        assert "dummy_hash[BRIX_PWD_HASH_LEN]" in auth
