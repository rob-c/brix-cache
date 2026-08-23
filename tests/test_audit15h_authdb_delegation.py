"""
test_audit15h_authdb_delegation.py — authdb rules against a delegated identity
(audit §B1.7: "authdb × delegation").

THE GAP, precisely.  ``brix_authdb`` has plenty of coverage — user rules, group
rules, host rules, CIDR rules, refresh, load failure — but every ``u`` rule the
suite has ever written is ``u *`` (``test_authdb.py``'s rule file is the
canonical example, and the multi-user and cache-node configs copy it).  A
wildcard matches whatever identity the server happens to hand it, so no test in
the tree has ever asked the question this row is about: **which** distinguished
name is a proxy login authorized as?

A grid proxy chain offers two answers, and they are not interchangeable:

  * the **leaf** DN, which is the End-Entity subject with a fresh RFC 3820
    ``/CN=<serial>`` appended — a different string every time the user runs
    ``xrdgsiproxy init``;
  * the **EEC** subject underneath it, which is what the user's certificate
    actually says and what an operator reads off ``openssl x509 -subject``.

Key authorization on the leaf and every rule an operator writes stops working
the next morning, silently, with a "not authorized" that names a DN nobody put
in the file.  Key it on the EEC and the rule survives re-delegation.  The
product chose the EEC (``brix_gsi_extract_eec_dn``, ``gsi_verify.c:163``, and
``brix_gsi_complete_auth`` prefers ``login.eec_dn`` when it is set) — this file
is the test that says so, from both sides.

WHY THE ROW STAYED OPEN.  It needs a real delegated identity: a CA, an
End-Entity certificate, and a proxy minted from it by the same tool a user
would run.  A mock identity cannot exhibit the property at issue, because the
property IS the relationship between two certificates in one verified chain.
The suite already has the machinery (``_test_gsi_handshake_helpers``' CA,
signing and ``xrdgsiproxy`` wrappers, plus ``voms-proxy-fake`` for the group
half), so what this file adds is the pairing, not the tooling.

THE ATTRIBUTION CONTROL.  ``OPEN_PORT`` is the same gsi acceptor with no
``brix_authdb`` at all.  Every denial below is asserted together with the
identical operation succeeding there on the identical credential, so "refused"
can never be a broken handshake wearing a policy's clothes — with one
deliberate exception, the impostor, which must fail on BOTH and is asserted
that way for exactly that reason.

DEFECT CANDIDATE #24 — the identity that is counted is not the identity that
is authorized.  ``brix_gsi_complete_auth`` hands the stable EEC DN to the
authorization identity and, four lines later, hands the PROXY LEAF DN to
``brix_track_unique_user`` and ``brix_session_register``
(``src/auth/gsi/auth.c:81`` vs ``:90``/``:109``).  So one user who re-mints a
proxy three times is one identity to every rule in the authdb and three
distinct users to ``brix_unique_users_total`` — measured below, and asserted
against the authdb's verdict on the very same logins so the disagreement is
shown rather than inferred.  It is not a label-cardinality breach (invariant 8
is safe: the table is a bounded 1024-slot LRU hashed with FNV-1a, and no DN
reaches the exposition), which is what makes it a metrics-correctness defect
rather than a memory one: ``brix_unique_users_current`` is documented as
"currently tracked unique user identities", a site with hourly proxy renewal
sees it climb to the cap, and ``brix_user_evictions_total`` then starts
throwing out real users to make room for the same one arriving again.
**FLIP IT WHEN THE COUNTER IS FIXED**: the correct delta is 1, and the
assertion below already spells out both numbers.

Cases:
  * success       — a rule naming the EEC subject authorizes a proxy login
  * success       — a second, freshly minted proxy (different leaf DN) gets the
                    identical verdict: the rule survives re-delegation
  * error         — a rule naming the proxy leaf DN authorizes nothing, even
                    for the very proxy whose DN it names
  * error         — another user's proxy under the same CA is refused
  * error         — a path no rule covers is refused (default-deny)
  * error         — the `w` bit is enforced against the delegated identity
  * success/error — a VOMS `g` rule matches the FQAN the proxy carries, and a
                    proxy without the attribute certificate is refused
  * sec-negative  — an untrusted chain bearing the granted subject verbatim is
                    refused at the handshake, never reaching the rules
  * sec-negative  — no credential at all is refused
  * defect        — the counted identity disagrees with the authorized one
"""

import os
import shutil
import subprocess
import urllib.request

import pytest

from server_registry import NginxInstanceSpec
from settings import BIND_HOST, NGINX_BIN
from _test_gsi_handshake_helpers import (_ca_hash_link, _make_ca,
                                         _make_voms_proxy, _make_vomsdir,
                                         _make_voms_signing_cert, _mint_proxy,
                                         _signed)

def _check_test_the_counted_identity_disagrees_with_the_authorized_one_2(leaves):
    assert len(leaves) == RENEWALS, \
        f"the renewals share leaf DNs; nothing was re-delegated: {leaves}"

def _check_test_the_counted_identity_disagrees_with_the_authorized_one_4(delta):
    assert delta == RENEWALS, (
        f"expected the defect's {RENEWALS} (one per delegation), saw {delta}; "
        f"if this is now 1 the counter has been keyed on the EEC DN — flip "
        f"the expectation and remove DEFECT CANDIDATE #24 from the audit")

def _check_test_the_counted_identity_disagrees_with_the_authorized_one_1(out, env, pki, index):
    assert _mint_proxy(pki["granted_cert"], pki["granted_key"], out,
                       pki["certs"], env), f"could not mint renewal {index}"

def _check_test_the_counted_identity_disagrees_with_the_authorized_one_3(result, index):
    assert result.returncode == 0, \
        (f"renewal {index} was not authorized, so the counter reading "
         f"below would not be about one authorized identity: {result.stderr}")


pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15h-authdeleg")]

NAME = "lc-audit15h-authdeleg"
CONNECT_HOST = "localhost"  # net-literal-allow: Kerberos/GSI service test identity

# Subjects with no whitespace, deliberately: an authdb line is four
# whitespace-separated fields (`adb_scan_field`, authdb_parse.c:205), so a DN
# containing a space would be truncated at the space and the rule would be
# about a different identity than the one the test thinks it wrote.
GRANTED_CN = "audit15h-granted"
OTHER_CN = "audit15h-other"
VO = "audit15h"
FQAN = f"/{VO}/Role=NULL/Capability=NULL"

# The three trees the rules speak about, plus one they do not.
RO_DIR, RW_DIR, VO_DIR, UNRULED = "/eec", "/eecrw", "/vo", "/nowhere"
SEED = b"authdb delegation seed\n"

SYS_XRDFS = shutil.which("xrdfs")
SYS_XRDCP = shutil.which("xrdcp")

# How many fresh proxies the counter probe mints from the one certificate.
RENEWALS = 3


# --------------------------------------------------------------------------- #
# PKI — one CA, two users, one impostor, and the proxies minted from them
# --------------------------------------------------------------------------- #

def _subject(pem):
    """The certificate subject in X509_NAME_oneline form — the same rendering
    the server puts in ``login.dn``/``login.eec_dn``, so a string written into
    an authdb rule here is byte-comparable with what the rule matcher sees."""
    out = subprocess.run(
        ["openssl", "x509", "-in", pem, "-noout", "-subject",
         "-nameopt", "compat"],
        check=True, capture_output=True, text=True, timeout=30).stdout
    return out.strip().split("=", 1)[1].strip()


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A trusted CA, a host cert, two user EECs, an untrusted look-alike, and
    proxies minted from each with the tool a real user runs.

    A hard requirement, not a skip: the row exists to prove that a *real*
    delegated identity is authorized correctly, so missing openssl or
    xrdgsiproxy is a failure of the environment, not a reason to pass."""
    assert shutil.which("openssl"), "openssl is required to build the chain"
    assert shutil.which("xrdgsiproxy"), \
        "xrdgsiproxy is required to mint a real proxy"
    base = str(tmp_path_factory.mktemp("a15hauthdeleg"))

    ca_key, ca_pem = _make_ca(base, "/O=XrdTest/CN=audit15h-deleg-CA")
    certs = os.path.join(base, "certs")
    os.makedirs(certs, exist_ok=True)
    _ca_hash_link(ca_pem, certs)
    os.chmod(certs, 0o755)          # XrdCl refuses a group-writable CA dir

    host_key = os.path.join(base, "hostkey.pem")
    host_cert = os.path.join(base, "hostcert.pem")
    _signed(ca_key, ca_pem, CONNECT_HOST, host_key, host_cert, base)
    os.chmod(host_key, 0o600)

    def _user(cn, tag):
        key = os.path.join(base, f"{tag}key.pem")
        cert = os.path.join(base, f"{tag}cert.pem")
        _signed(ca_key, ca_pem, cn, key, cert, base)
        os.chmod(key, 0o600)
        return cert, key

    granted_cert, granted_key = _user(GRANTED_CN, "granted")
    other_cert, other_key = _user(OTHER_CN, "other")

    def _proxy(cert, key, tag, store=certs):
        out = os.path.join(base, f"{tag}proxy.pem")
        env = dict(os.environ, X509_CERT_DIR=store, X509_USER_PROXY=out)
        assert _mint_proxy(cert, key, out, store, env), \
            f"xrdgsiproxy could not mint the {tag} proxy"
        return out

    # Two proxies from ONE certificate.  Different leaf DNs (asserted below),
    # the same EEC underneath: this pair is the whole row in two files.
    granted = _proxy(granted_cert, granted_key, "granted")
    renewed = _proxy(granted_cert, granted_key, "renewed")
    other = _proxy(other_cert, other_key, "other")

    # The impostor: a DIFFERENT certificate authority issuing an EEC whose
    # subject is byte-identical to the granted user's.  Knowing a DN is public
    # information; being able to present it is not.
    rogue_home = os.path.join(base, "rogue")
    os.makedirs(rogue_home, exist_ok=True)
    rogue_key, rogue_pem = _make_ca(rogue_home,
                                    "/O=XrdTest/CN=audit15h-rogue-CA")
    rogue_certs = os.path.join(base, "roguecerts")
    os.makedirs(rogue_certs, exist_ok=True)
    _ca_hash_link(rogue_pem, rogue_certs)
    os.chmod(rogue_certs, 0o755)
    imp_key = os.path.join(base, "impkey.pem")
    imp_cert = os.path.join(base, "impcert.pem")
    _signed(rogue_key, rogue_pem, GRANTED_CN, imp_key, imp_cert, base)
    os.chmod(imp_key, 0o600)
    impostor = _proxy(imp_cert, imp_key, "impostor", store=rogue_certs)

    # A trust store holding BOTH anchors, for the impostor's client only.  With
    # the trusted CA alone the CLIENT would reject its own chain and the test
    # would prove nothing about the server; with the rogue CA alone the client
    # could not verify the server's host cert.  Handing it both leaves the
    # server as the only party with a reason to say no.
    both = os.path.join(base, "bothcerts")
    os.makedirs(both, exist_ok=True)
    _ca_hash_link(ca_pem, both)
    _ca_hash_link(rogue_pem, both)
    os.chmod(both, 0o755)

    # The VOMS half: a signing cert under the trusted CA, an LSC directory that
    # names it, and an attribute certificate asserting membership of VO.
    voms_cert, voms_key = _make_voms_signing_cert(ca_key, ca_pem, base)
    vomsdir = os.path.join(base, "vomsdir")
    os.makedirs(vomsdir, exist_ok=True)
    _make_vomsdir(vomsdir, voms_cert, VO)
    voms_proxy = os.path.join(base, "vomsproxy.pem")
    assert _make_voms_proxy(granted_cert, granted_key, certs,
                            voms_cert, voms_key, VO, FQAN, voms_proxy), \
        "voms-proxy-fake could not mint the VO proxy"

    return {"ca": ca_pem, "certs": certs, "vomsdir": vomsdir,
            "cert": host_cert, "key": host_key,
            "granted_cert": granted_cert, "granted_key": granted_key,
            "eec_dn": _subject(granted_cert), "other_dn": _subject(other_cert),
            "granted": granted, "renewed": renewed, "other": other,
            "impostor": impostor, "both": both,
            "voms": voms_proxy, "base": base}


# --------------------------------------------------------------------------- #
# The three planes, off one CA
# --------------------------------------------------------------------------- #

def _write_authdb(path, user_dn):
    """The same four rules, keyed on whichever DN the caller names.

    `rl` on the read tree and `rwl` on the write tree so the privilege bits are
    separable: a denial under RW_DIR would be a missing UPDATE, a denial under
    RO_DIR is the rule doing its job."""
    with open(path, "w") as handle:
        handle.write("# audit15h §B1.7 — authdb x a delegated identity\n")
        handle.write(f"u {user_dn} {RO_DIR} rl\n")
        handle.write(f"u {user_dn} {RW_DIR} rwl\n")
        handle.write(f"g {VO} {VO_DIR} rl\n")


@pytest.fixture
def authdeleg(lifecycle, tmp_path, pki):
    if SYS_XRDFS is None or SYS_XRDCP is None:
        pytest.skip("stock xrdfs/xrdcp not on PATH")
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    for tree in (RO_DIR, RW_DIR, VO_DIR, UNRULED):
        (data / tree.lstrip("/")).mkdir(parents=True)
        (data / tree.lstrip("/") / "seed.txt").write_bytes(SEED)

    # The leaf plane's rules name the granted proxy's OWN leaf DN, so a grant
    # there could not be blamed on naming the wrong proxy.
    eec_db = str(tmp_path / "authdb")
    leaf_db = str(tmp_path / "authdb-leaf")
    _write_authdb(eec_db, pki["eec_dn"])
    _write_authdb(leaf_db, _subject(pki["granted"]))

    tmp = tmp_path / "ngxtmp"
    tmp.mkdir()

    yield lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15h_authdeleg.conf",
        protocol="root",
        readiness="tcp",
        data_root=str(data),
        template_values={"CERT": pki["cert"], "KEY": pki["key"],
                         "CA": pki["ca"], "CERTS": pki["certs"],
                         "VOMSDIR": pki["vomsdir"], "TMP_DIR": str(tmp),
                         "AUTHDB": eec_db, "LEAF_AUTHDB": leaf_db},
        reason="audit-15h authdb x delegated identity (§B1.7)")), data


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #

def _env(pki, proxy, *, certs=None):
    """Drive the stock client to one specific proxy and trust store.

    XrdSecPROTOCOL is pinned to gsi so a stray ticket in the ambient
    environment can never satisfy a login this file believes it authenticated
    with a certificate."""
    env = os.environ.copy()
    env["XrdSecPROTOCOL"] = "gsi"
    env["X509_CERT_DIR"] = certs or pki["certs"]
    if proxy is None:
        for name in ("X509_USER_PROXY", "X509_USER_CERT", "X509_USER_KEY"):
            env.pop(name, None)
    else:
        env["X509_USER_PROXY"] = proxy
    env.pop("KRB5CCNAME", None)
    return env


def _xrdfs(pki, port, *args, proxy, certs=None):
    return subprocess.run(
        [SYS_XRDFS, f"root://{CONNECT_HOST}:{port}", *args],
        capture_output=True, text=True, timeout=90,
        env=_env(pki, proxy, certs=certs))


def _cat(pki, port, path, *, proxy, certs=None):
    return _xrdfs(pki, port, "cat", path, proxy=proxy, certs=certs)


def _upload(pki, port, src, dest, *, proxy):
    return subprocess.run(
        [SYS_XRDCP, "-f", str(src), f"root://{CONNECT_HOST}:{port}/{dest}"],
        capture_output=True, text=True, timeout=90,
        env=_env(pki, proxy))


def _metric(endpoint, name):
    url = f"http://{BIND_HOST}:{endpoint.extra_ports['METRICS_PORT']}/metrics"
    with urllib.request.urlopen(url, timeout=20) as response:
        body = response.read().decode("utf-8", "replace")
    for line in body.splitlines():
        if line.startswith(f"{name} "):
            return float(line.split(None, 1)[1])
    raise AssertionError(f"{name} absent from the exposition")


# --------------------------------------------------------------------------- #
# success — the rule an operator would actually write
# --------------------------------------------------------------------------- #

def test_a_rule_naming_the_eec_subject_grants_a_proxy_login(authdeleg, pki):
    """The row's core claim.  The authdb names the End-Entity subject — the DN
    printed by `openssl x509 -subject` on the user's certificate — and the
    client presents a PROXY minted from it, whose own subject is a strict
    extension of that string.  The read is granted, and the bytes are the
    file's, so this is a completed authorization and not merely a login."""
    endpoint, _ = authdeleg

    assert _subject(pki["granted"]).startswith(pki["eec_dn"] + "/CN="), \
        ("the proxy leaf is not an extension of the EEC subject; the premise "
         f"of the row does not hold: {_subject(pki['granted'])!r}")

    result = _cat(pki, endpoint.port, f"{RO_DIR}/seed.txt",
                  proxy=pki["granted"])
    assert result.returncode == 0, result.stderr
    assert SEED.decode() in result.stdout, result.stdout


def test_a_freshly_minted_proxy_is_the_same_identity(authdeleg, pki):
    """Re-delegation must not change the verdict.

    ``renewed`` came out of the same certificate and the same tool as
    ``granted``, minutes apart; its leaf DN differs (asserted, because if the
    two serials collided this test would pass vacuously).  The authdb file is
    untouched between the two logins, so a difference in outcome could only
    come from the server keying authorization on something that moved."""
    endpoint, _ = authdeleg
    assert _subject(pki["renewed"]) != _subject(pki["granted"]), \
        "the two proxies share a leaf DN — re-delegation was not exercised"

    for tag, proxy in (("granted", pki["granted"]), ("renewed", pki["renewed"])):
        result = _cat(pki, endpoint.port, f"{RO_DIR}/seed.txt", proxy=proxy)
        assert result.returncode == 0, f"{tag}: {result.stderr}"


# --------------------------------------------------------------------------- #
# error — the identity the rules must NOT be keyed on
# --------------------------------------------------------------------------- #

def test_a_rule_naming_the_proxy_leaf_dn_authorizes_nothing(authdeleg, pki):
    """The other side of the same claim, and the one that makes it falsifiable.

    LEAF_PORT carries the identical rules with the granted proxy's own leaf DN
    substituted for the EEC subject.  If the server authorized on the leaf,
    this would be the most specific rule imaginable and the read would succeed;
    it is refused, and the same credential reads the same path on the plane
    with no authdb, so the refusal is the rule's and not the handshake's."""
    endpoint, _ = authdeleg

    denied = _cat(pki, endpoint.extra_ports["LEAF_PORT"],
                  f"{RO_DIR}/seed.txt", proxy=pki["granted"])
    assert denied.returncode != 0, \
        ("a rule keyed on the proxy leaf DN granted access — authorization "
         "drifts with the proxy serial")

    control = _cat(pki, endpoint.extra_ports["OPEN_PORT"],
                   f"{RO_DIR}/seed.txt", proxy=pki["granted"])
    assert control.returncode == 0, \
        f"the credential itself is not usable: {control.stderr}"


def test_another_users_proxy_is_refused_on_the_granted_path(authdeleg, pki):
    """The rule is about one subject, not about "any proxy from this CA".  The
    other user's chain verifies just as well — proven on OPEN_PORT — and is
    still not the identity the rule names."""
    endpoint, _ = authdeleg
    assert pki["other_dn"] != pki["eec_dn"]

    denied = _cat(pki, endpoint.port, f"{RO_DIR}/seed.txt",
                  proxy=pki["other"])
    assert denied.returncode != 0, \
        "a rule for one EEC subject admitted a different user"

    control = _cat(pki, endpoint.extra_ports["OPEN_PORT"],
                   f"{RO_DIR}/seed.txt", proxy=pki["other"])
    assert control.returncode == 0, \
        f"the other user's credential is not usable at all: {control.stderr}"


def test_a_path_no_rule_covers_is_refused(authdeleg, pki):
    """Default-deny, asserted against the delegated identity rather than the
    wildcard every existing authdb test uses.  A rule set that granted the EEC
    subject everything below `/` would pass every test above and fail here."""
    endpoint, _ = authdeleg

    denied = _cat(pki, endpoint.port, f"{UNRULED}/seed.txt",
                  proxy=pki["granted"])
    assert denied.returncode != 0, \
        f"{UNRULED} is in no rule and was served anyway"

    control = _cat(pki, endpoint.extra_ports["OPEN_PORT"],
                   f"{UNRULED}/seed.txt", proxy=pki["granted"])
    assert control.returncode == 0, control.stderr


def test_the_write_bit_is_enforced_against_the_delegated_identity(authdeleg,
                                                                  pki,
                                                                  tmp_path):
    """Privilege bits, not just path matching.  The same identity holds `rl`
    under RO_DIR and `rwl` under RW_DIR, and `brix_allow_write on` is set on
    every plane — invariant 3 puts that gate BEFORE authorization, so without
    it the refusal below would prove nothing about the authdb."""
    endpoint, data = authdeleg
    payload = tmp_path / "upload.bin"
    payload.write_bytes(b"delegated write\n" * 64)

    refused = _upload(pki, endpoint.port, payload, f"{RO_DIR}/pushed.bin",
                      proxy=pki["granted"])
    assert refused.returncode != 0, \
        "a read-only rule permitted a write for the delegated identity"
    assert not (data / RO_DIR.lstrip("/") / "pushed.bin").exists(), \
        "the write was refused on the wire but the file landed anyway"

    allowed = _upload(pki, endpoint.port, payload, f"{RW_DIR}/pushed.bin",
                      proxy=pki["granted"])
    assert allowed.returncode == 0, allowed.stderr
    assert (data / RW_DIR.lstrip("/") / "pushed.bin").read_bytes() == \
        payload.read_bytes()


# --------------------------------------------------------------------------- #
# the group half — a delegated identity that carries an attribute certificate
# --------------------------------------------------------------------------- #

def test_a_group_rule_matches_the_fqan_the_proxy_carries(authdeleg, pki):
    """`g <vo>` is matched against the VO list extracted from the proxy's VOMS
    attribute certificate, which is a property of the DELEGATION and not of the
    certificate underneath it: the same End-Entity issues both proxies here,
    and only one of them carries the AC.  Both directions are asserted, because
    a server that ignored the VO list entirely would grant both."""
    endpoint, _ = authdeleg

    member = _cat(pki, endpoint.port, f"{VO_DIR}/seed.txt", proxy=pki["voms"])
    assert member.returncode == 0, \
        f"a proxy carrying {FQAN} was refused by `g {VO}`: {member.stderr}"

    plain = _cat(pki, endpoint.port, f"{VO_DIR}/seed.txt",
                 proxy=pki["granted"])
    assert plain.returncode != 0, \
        ("a proxy with no attribute certificate satisfied a group rule — the "
         "VO list is not being consulted")


# --------------------------------------------------------------------------- #
# security-negative
# --------------------------------------------------------------------------- #

def test_an_untrusted_chain_bearing_the_granted_subject_is_refused(authdeleg,
                                                                   pki):
    """The attack the EEC-keyed design invites, and the one it must survive.

    A DN is public: it is printed in logs, in the authdb file itself, and by
    every tool that touches the certificate.  The impostor here holds a chain
    whose End-Entity subject is byte-identical to the granted user's, issued by
    a CA the server does not trust.  It must be refused, and — unlike every
    other denial in this file — refused on the OPEN_PORT plane too: a
    credential that gets no further than the handshake never reaches a rule, so
    the authdb is not what is protecting the data here, and asserting the
    control succeeds would be asserting the wrong thing.

    The client is given a trust store containing both anchors, so it is
    perfectly happy with its own chain and with the server's host cert: the
    only party left with a reason to refuse is the server."""
    endpoint, _ = authdeleg
    assert _subject(pki["impostor"]).startswith(pki["eec_dn"] + "/CN="), \
        "the impostor does not actually carry the granted subject"

    for plane, port in (("authdb", endpoint.port),
                        ("no-authdb", endpoint.extra_ports["OPEN_PORT"])):
        result = _cat(pki, port, f"{RO_DIR}/seed.txt",
                      proxy=pki["impostor"], certs=pki["both"])
        assert result.returncode != 0, \
            f"{plane}: an untrusted CA's chain was accepted for the granted DN"


def test_no_credential_at_all_is_refused(authdeleg, pki):
    """The floor.  With X509_USER_PROXY unset there is nothing to delegate, and
    the gsi acceptor has nothing to authorize — asserted on the plane with no
    authdb so it cannot be a rule declining an empty DN."""
    endpoint, _ = authdeleg

    result = _cat(pki, endpoint.extra_ports["OPEN_PORT"], f"{RO_DIR}/seed.txt",
                  proxy=None)
    assert result.returncode != 0, "an anonymous client was served by gsi"


# --------------------------------------------------------------------------- #
# DEFECT CANDIDATE #24 — FLIP THIS WHEN THE COUNTER IS FIXED
# --------------------------------------------------------------------------- #

def test_the_counted_identity_disagrees_with_the_authorized_one(authdeleg,
                                                                pki):
    """One user, three delegations, three "unique users".

    Every proxy here is minted from the one certificate, so the authdb sees one
    identity — asserted, on the very same logins, so the two numbers come from
    the same traffic rather than from two separate stories.
    ``brix_unique_users_total`` counts the proxy leaf DN instead, and moves by
    one per delegation.

    ``brix_unique_users_current`` is a bounded 1024-slot LRU, so this is a
    correctness defect and not a leak: what it costs a real site is that a user
    renewing hourly consumes a slot an hour, ``brix_user_evictions_total``
    starts discarding genuine users to make room, and the gauge documented as
    "currently tracked unique user identities" becomes a count of live
    credentials.

    The correct delta is 1.  When ``brix_gsi_complete_auth`` passes
    ``login.eec_dn`` to ``brix_track_unique_user`` the way it already passes it
    to ``brix_identity_set_dn``, change the expected value below and delete the
    defect note."""
    endpoint, _ = authdeleg
    before = _metric(endpoint, "brix_unique_users_total")

    fresh = []
    for index in range(RENEWALS):
        out = os.path.join(pki["base"], f"renew{index}.pem")
        env = dict(os.environ, X509_CERT_DIR=pki["certs"], X509_USER_PROXY=out)
        _check_test_the_counted_identity_disagrees_with_the_authorized_one_1(out, env, pki, index)
        fresh.append(out)

    leaves = {_subject(proxy) for proxy in fresh}
    _check_test_the_counted_identity_disagrees_with_the_authorized_one_2(leaves)

    for index, proxy in enumerate(fresh):
        result = _cat(pki, endpoint.port, f"{RO_DIR}/seed.txt", proxy=proxy)
        _check_test_the_counted_identity_disagrees_with_the_authorized_one_3(result, index)

    delta = _metric(endpoint, "brix_unique_users_total") - before
    _check_test_the_counted_identity_disagrees_with_the_authorized_one_4(delta)
