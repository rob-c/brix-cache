"""
test_audit15h_macaroon_voms.py — macaroons minted for, and used in place of, an
identity that came from a VOMS proxy chain (audit §B1.10: "macaroon × voms /
macaroon × delegation — macaroon minting for an identity established via
VOMS/proxy chain: zero units").

THE GAP, precisely.  Every macaroon file in the tree — the rotation suite, the
issuance-policy suite, the OAuth2 endpoint suite — authenticates its own
issuance request with ANOTHER macaroon (`make_macaroon` into an Authorization
header).  That is a closed loop: a bearer token asks for a bearer token.  The
endpoint's other caller has never been driven at all, and it is the caller a
real site has: a user with an X.509 proxy in `/tmp`, a VO membership in an
attribute certificate, and no token to start from.  The two callers do not take
the same path through the code — `mac_authorize` (macaroon_endpoint.c:156)
opens with `if (!ctx->token_auth) { return NGX_OK; }` — so nothing that has ever
been asserted about issuance applies to them.

WHAT THIS FILE STANDS UP.  One WebDAV server, two faces off one PKI:

  * PORT      — `brix_webdav_authdb` + `brix_webdav_vomsdir`.  The minting user
                is authorized here by DN on two trees, by VO on a third, by the
                `u *` wildcard on a fourth, and by nothing at all on a fifth.
  * FREE_PORT — the same face with no authdb.  It is the attribution control:
                a credential refused on PORT and served here was a good
                credential that a RULE declined, never a token the server could
                not read.  Every 403 below is asserted together with its 200.

DEFECT CANDIDATE #25 — WebDAV authorizes the proxy LEAF; root:// authorizes the
EEC.  `webdav_finish_verified_cert` (auth_cert.c:433) sets the request identity
from `X509_NAME_oneline(X509_get_subject_name(leaf))` — the RFC 3820 proxy
certificate on top of the chain.  `brix_gsi_complete_auth` (auth.c:81) sets it
from `brix_gsi_extract_eec_dn`, the End-Entity subject underneath.  Both faces
read the SAME `brix_authdb` file, and `access_apply_authdb` exists precisely to
give WebDAV "native authdb + VO ACL read parity with root://" (access.c:275).
The parity is broken at the identity: a `u <EEC subject>` rule that authorizes
this user over root:// — proven in test_audit15h_authdb_delegation.py, whose
whole subject is that pairing — refuses them over WebDAV, and the `u <proxy
leaf>` rule that works over WebDAV stops working the moment the user re-mints.
Both halves are measured below, on one server, with one authdb, so the
disagreement is shown rather than argued.  Note also that
`webdav_verify_proxy_cert` passes a `brix_gsi_verify_result_t` to
`brix_gsi_verify_chain` and never reads it — the EEC subject is computed on
this very code path and discarded.
**FLIP TESTS 6 AND 7 WHEN THE IDENTITY IS FIXED**: the correct outcome is /eec
200 and /leaf 403, and the assertions below already name both numbers.

WHAT A MACAROON CARRIES.  Nothing about its minter.  `mac_make_identifier`
emits `v=1;t=<unix>;n=<16-hex-random>` and `macaroon_parse.c:39` copies those
bytes into `claims->sub`, so the identity a macaroon presents is a nonce.  The
consequence is measured here and it is not academic: the `targetWithMacaroon`
URL this server hands back — the entire point of the dCache API — is 403 on the
authdb-gated face that minted it, because the authdb sees the nonce as the DN,
and 200 on the face with no authdb.  It fails closed, so it is a broken
delegation rather than a hole; a site whose exports are authdb-gated cannot use
macaroons at all, and one that adds `u *` to make them work has made every
macaroon equivalent to every other.

THE ISSUANCE BOUND.  A certificate caller's request IS bounded — but at the
request URI, by the authdb read gate, and not at the `path:` caveat it asks
for.  So the same caller who is refused a macaroon AT /nowhere is issued one
FOR /nowhere by asking at /pub, with UPLOAD, DELETE and MANAGE attached.  The
bearer caller beside it cannot even reach the endpoint without write scope.
That asymmetry is the row in one line: the token caller is measured against
what it holds, the certificate caller against where it knocked.

Cases:
  * success       — a VOMS proxy identity is issued a macaroon at all
  * success       — that macaroon then authenticates a request carrying no
                    certificate whatsoever
  * error         — the macaroon records neither the DN nor the VO, and two
                    users' macaroons differ only in the nonce
  * error         — it does not carry the minter's authdb identity
  * error         — it does not delegate VO membership
  * defect        — WebDAV authorizes the proxy leaf, not the EEC subject
  * defect        — so a renewed proxy silently loses what it had
  * error         — the caveat path escapes the gate the URI is subject to
  * sec-negative  — a read-only bearer cannot reach the endpoint at all
  * sec-negative  — an unauthenticated issuance request is refused
  * sec-negative  — an untrusted chain cannot obtain a macaroon
  * sec-negative  — a DOWNLOAD-only macaroon cannot upload
"""

import base64
import json
import os
import re
import shutil
import subprocess

import pytest

from server_registry import NginxInstanceSpec
from settings import HOST, NGINX_BIN
from test_token_macaroon import make_macaroon
from _test_gsi_handshake_helpers import (_ca_hash_link, _make_ca,
                                         _make_voms_proxy, _make_vomsdir,
                                         _make_voms_signing_cert, _mint_proxy,
                                         _signed, _split_for_curl)

def _check_probe_1(done):
    assert done.returncode == 0, f"curl failed: {done.stderr.strip()}"


pytestmark = [pytest.mark.timeout(300),
              pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15h-macvoms")]

NAME = "lc-audit15h-macvoms"

# Deliberately disjoint strings: test 3 asserts that NEITHER appears anywhere in
# an issued macaroon, and a VO that were a substring of the CN could make that
# assertion pass for the wrong reason.
MINTER_CN = "macvoms-minter"
OTHER_CN = "macvoms-bystander"
VO = "brixvo"
FQAN = f"/{VO}/Role=NULL/Capability=NULL"

# The five trees.  /eec and /leaf carry the same privilege for the same user
# under two different spellings of "who that user is"; /vo is reached by the
# attribute certificate; /pub by the wildcard every real authdb has; /nowhere by
# nothing at all.
EEC_DIR, LEAF_DIR, VO_DIR, PUB_DIR, UNRULED = ("/eec", "/leaf", "/vo",
                                               "/pub", "/nowhere")
SEED = b"macaroon voms seed\n"

SECRET_HEX = "b12ac0de" * 8
SECRET = bytes.fromhex(SECRET_HEX)
MACAROON_REQUEST = "application/macaroon-request"
IDENTIFIER_RE = re.compile(rb"identifier v=1;t=\d+;n=[0-9a-f]{16}\n")


# --------------------------------------------------------------------------- #
# PKI — one CA, a VOMS attribute certificate, and the proxies minted from it
# --------------------------------------------------------------------------- #

def _subject(pem):
    """The subject of a PEM's FIRST certificate in X509_NAME_oneline form.

    That is the proxy leaf for a grid-proxy file and the certificate itself for
    an End-Entity file — the two spellings this file is about — and it is the
    same rendering both `webdav_finish_verified_cert` and the authdb matcher
    use, so a string written into a rule here is byte-comparable with what the
    server sees."""
    out = subprocess.run(
        ["openssl", "x509", "-in", pem, "-noout", "-subject",
         "-nameopt", "compat"],
        check=True, capture_output=True, text=True, timeout=30).stdout
    return out.strip().split("=", 1)[1].strip()


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    """A trusted CA, a host cert, two users, a VO attribute certificate, and
    the proxies — including one from an untrusted CA and one renewal.

    A hard requirement rather than a skip: the row exists to prove that a REAL
    delegated identity is minted for correctly, so a missing openssl or
    xrdgsiproxy is a broken environment, not a reason to pass."""
    assert shutil.which("openssl"), "openssl is required to build the chain"
    assert shutil.which("xrdgsiproxy"), \
        "xrdgsiproxy is required to mint a real proxy"
    base = str(tmp_path_factory.mktemp("a15hmacvoms"))

    ca_key, ca_pem = _make_ca(base, "/O=XrdTest/CN=macvoms-CA")
    certs = os.path.join(base, "certs")
    os.makedirs(certs, exist_ok=True)
    _ca_hash_link(ca_pem, certs)
    os.chmod(certs, 0o755)

    host_key = os.path.join(base, "hostkey.pem")
    host_cert = os.path.join(base, "hostcert.pem")
    _signed(ca_key, ca_pem, "localhost", host_key, host_cert, base)  # net-literal-allow: certificate SAN subject
    os.chmod(host_key, 0o600)

    def _user(cn, tag, ca_k=ca_key, ca_p=ca_pem):
        key = os.path.join(base, f"{tag}key.pem")
        cert = os.path.join(base, f"{tag}cert.pem")
        _signed(ca_k, ca_p, cn, key, cert, base)
        os.chmod(key, 0o600)
        return cert, key

    minter_cert, minter_key = _user(MINTER_CN, "minter")
    other_cert, other_key = _user(OTHER_CN, "other")

    # The VO half: a signing cert under the trusted CA, an LSC directory naming
    # it, and an attribute certificate asserting membership.  This is the
    # credential the row is about — the identity is established by a chain AND
    # carries a VO, so both halves of "macaroon x voms" have something to lose.
    voms_cert, voms_key = _make_voms_signing_cert(ca_key, ca_pem, base)
    vomsdir = os.path.join(base, "vomsdir")
    os.makedirs(vomsdir, exist_ok=True)
    _make_vomsdir(vomsdir, voms_cert, VO)

    minter = os.path.join(base, "minterproxy.pem")
    assert _make_voms_proxy(minter_cert, minter_key, certs,
                            voms_cert, voms_key, VO, FQAN, minter), \
        "voms-proxy-fake could not mint the VO proxy"

    def _plain_proxy(cert, key, tag, store=certs):
        out = os.path.join(base, f"{tag}proxy.pem")
        env = dict(os.environ, X509_CERT_DIR=store, X509_USER_PROXY=out)
        assert _mint_proxy(cert, key, out, store, env), \
            f"xrdgsiproxy could not mint the {tag} proxy"
        return out

    # The renewal: the same certificate, a new proxy, therefore a new leaf DN.
    # Nothing about the user changed; test 7 asks whether the server agrees.
    renewed = _plain_proxy(minter_cert, minter_key, "renewed")
    other = _plain_proxy(other_cert, other_key, "other")

    # An untrusted CA issuing a certificate with the minter's subject verbatim.
    # Knowing a DN is public information; presenting one is not.
    rogue_home = os.path.join(base, "rogue")
    os.makedirs(rogue_home, exist_ok=True)
    rogue_key, rogue_pem = _make_ca(rogue_home, "/O=XrdTest/CN=macvoms-rogueCA")
    rogue_certs = os.path.join(base, "roguecerts")
    os.makedirs(rogue_certs, exist_ok=True)
    _ca_hash_link(rogue_pem, rogue_certs)
    os.chmod(rogue_certs, 0o755)
    imp_cert, imp_key = _user(MINTER_CN, "imp", rogue_key, rogue_pem)
    impostor = _plain_proxy(imp_cert, imp_key, "impostor", store=rogue_certs)

    eec_dn = _subject(minter_cert)
    leaf_dn = _subject(minter)
    # An authdb line is four whitespace-separated fields (adb_scan_field,
    # authdb_parse.c:205), so a DN carrying a space would be truncated and the
    # rule would silently be about a different identity than the one this file
    # believes it wrote.  Fail loudly here instead of mysteriously there.
    for label, dn in (("EEC", eec_dn), ("proxy leaf", leaf_dn)):
        assert not re.search(r"\s", dn), \
            f"the {label} DN contains whitespace and cannot be an authdb id: {dn!r}"
    assert leaf_dn != eec_dn, (
        "the proxy leaf and the EEC have the same subject — voms-proxy-fake "
        "did not append an RFC 3820 CN, so this file cannot tell the two "
        f"identities apart: {leaf_dn!r}")
    assert _subject(renewed) != leaf_dn, (
        "the renewal has the same leaf DN as the original proxy, so 'a renewed "
        "proxy is a different string' is not true in this environment")

    return {"ca": ca_pem, "certs": certs, "vomsdir": vomsdir,
            "cert": host_cert, "key": host_key, "base": base,
            "eec_dn": eec_dn, "leaf_dn": leaf_dn,
            "minter": minter, "renewed": renewed, "other": other,
            "impostor": impostor}


# --------------------------------------------------------------------------- #
# The two faces
# --------------------------------------------------------------------------- #

def _write_authdb(path, eec_dn, leaf_dn):
    """Both spellings of one user, side by side in one file.

    /eec names the End-Entity subject — the DN an operator reads off
    `openssl x509 -subject`, and the one root:// authorizes.  /leaf names the
    proxy certificate on top of it.  Exactly one of them can be the identity
    WebDAV uses, and the pair says which."""
    with open(path, "w") as handle:
        handle.write("# audit15h §B1.10 — macaroon x voms / x delegation\n")
        handle.write(f"u {eec_dn} {EEC_DIR} rl\n")
        handle.write(f"u {leaf_dn} {LEAF_DIR} rl\n")
        handle.write(f"g {VO} {VO_DIR} rl\n")
        handle.write(f"u * {PUB_DIR} rl\n")


@pytest.fixture
def macvoms(lifecycle, tmp_path, pki):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx binary not executable: {NGINX_BIN}")
    if shutil.which("curl") is None:
        pytest.skip("curl is not on PATH")

    data = tmp_path / "data"
    for tree in (EEC_DIR, LEAF_DIR, VO_DIR, PUB_DIR, UNRULED):
        (data / tree.lstrip("/")).mkdir(parents=True)
        (data / tree.lstrip("/") / "seed.txt").write_bytes(SEED)

    authdb = str(tmp_path / "authdb")
    _write_authdb(authdb, pki["eec_dn"], pki["leaf_dn"])

    tmp = tmp_path / "ngxtmp"
    tmp.mkdir()

    return lifecycle.start(NginxInstanceSpec(
        name=NAME,
        template="nginx_audit15h_macvoms.conf",
        protocol="https",
        readiness="webdav",
        data_root=str(data),
        template_values={"CERT": pki["cert"], "KEY": pki["key"],
                         "CA": pki["ca"], "CERTS": pki["certs"],
                         "VOMSDIR": pki["vomsdir"], "TMP_DIR": str(tmp),
                         "AUTHDB": authdb, "SECRET_HEX": SECRET_HEX},
        reason="audit-15h macaroon x voms/delegation (§B1.10)"))


# --------------------------------------------------------------------------- #
# Client — curl, because a proxy chain has to be split before it can be sent
# --------------------------------------------------------------------------- #

def _client_pair(pki, proxy):
    """A grid proxy as curl wants it: every certificate in one file, proxy
    first, and the key in another."""
    tag = os.path.basename(proxy).replace(".pem", "")
    cert, key = _split_for_curl(proxy, pki["base"], f"mv_{tag}")
    assert cert and key, f"could not split {proxy} for curl"
    return cert, key


def _option(value, flag, rendered=None):
    """Return one curl option when its value was supplied."""
    if value is None:
        return []
    return [flag, value if rendered is None else rendered]


def _proxy_options(pki, proxy):
    if proxy is None:
        return []
    cert, key = _client_pair(pki, proxy)
    return ["--cert", cert, "--key", key]


def _probe_options(pki, proxy, token, ctype, body, upload, method):
    options = _proxy_options(pki, proxy)
    options += _option(token, "-H", f"Authorization: Bearer {token}")
    options += _option(ctype, "-H", f"Content-Type: {ctype}")
    options += _option(body, "--data-binary")
    options += _option(upload, "-T")
    options += _option(method, "-X")
    return options


def _probe_url(port, path, query):
    base = f"https://{HOST}:{port}{path}"
    return f"{base}?{query}" if query else base


def _probe(pki, port, path, *, proxy=None, token=None, method=None,
           body=None, ctype=None, upload=None, query=None):
    """One request; returns (http_code, body_text).

    `-k` because the host certificate carries no SAN and this file is not about
    server verification: every identity assertion here is about the CLIENT's
    credential, which curl sends regardless."""
    cmd = ["curl", "-sS", "-k", "--max-time", "30", "-w", "\n%{http_code}"]
    cmd += _probe_options(pki, proxy, token, ctype, body, upload, method)
    cmd.append(_probe_url(port, path, query))
    done = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    _check_probe_1(done)
    text, _, code = done.stdout.rpartition("\n")
    return code.strip(), text


def _get(pki, port, path, *, proxy=None, token=None):
    """A read, with the token in the query string when there is one — the
    `?authz=` form is what `targetWithMacaroon` hands out, so it is the form a
    delegated reader actually uses."""
    return _probe(pki, port, path, proxy=proxy,
                  query=(f"authz={token}" if token else None))


def _issue(pki, port, path, caveats, *, proxy=None, token=None):
    """POST a dCache macaroon-request; returns (http_code, body_text)."""
    return _probe(pki, port, path, proxy=proxy, token=token,
                  body=json.dumps({"caveats": caveats}),
                  ctype=MACAROON_REQUEST)


def _minted(pki, port, path, caveats, *, proxy):
    """Issue and unwrap, asserting the dCache envelope on the way through."""
    code, text = _issue(pki, port, path, caveats, proxy=proxy)
    assert code == "200", f"issuance at {path} refused ({code}): {text}"
    return json.loads(text)["macaroon"]


def _decode(token):
    return base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))


def _caveats(raw):
    """Stable first-party caveats, excluding server-issued expiry timestamps."""
    return {c for c in re.findall(rb"cid ([^\n]+)\n", raw)
            if not c.startswith(b"before:")}


def _bearer(caveats, port, subject="bystander"):
    """A macaroon minted OUTSIDE the server, to drive the bearer-caller path.

    Its location is this face; nothing pins it (no brix_webdav_token_issuer),
    which is what lets one credential be compared against another.  The
    `before:` caveat is not decoration — validation treats a macaroon with no
    expiry as unusable, and an authentication failure would answer 401 where
    this file needs to see an authorization verdict."""
    return make_macaroon(SECRET, subject,
                         [*caveats, "before:2099-12-31T23:59:59Z"],
                         location=f"https://{HOST}:{port}")


def _free(endpoint):
    return endpoint.extra_ports["FREE_PORT"]


# --------------------------------------------------------------------------- #
# The row: a certificate identity reaches the issuance endpoint
# --------------------------------------------------------------------------- #

def test_a_voms_proxy_identity_is_issued_a_macaroon(macvoms, pki):
    """success: the endpoint's other caller.  `mac_gate_and_read_body` asks for
    `ctx->verified`, which a verified proxy chain satisfies exactly as a bearer
    token does, so a user with nothing but an X.509 proxy gets the full dCache
    envelope back."""
    code, text = _issue(pki, macvoms.port, f"{PUB_DIR}/seed.txt",
                        ["activity:DOWNLOAD,LIST", "path:/"],
                        proxy=pki["minter"])
    assert code == "200", f"a VOMS proxy was refused a macaroon ({code}): {text}"
    body = json.loads(text)
    assert body["macaroon"], body
    assert body["uri"]["targetWithMacaroon"].endswith(body["macaroon"]), body
    assert _decode(body["macaroon"]).startswith(b"00"), "not a macaroon"


def test_the_issued_macaroon_authenticates_a_request_with_no_certificate(
        macvoms, pki):
    """success: the delegation works where the authdb says `u *`.  No client
    certificate is presented at all — the whole credential is the query-string
    token the server just handed out."""
    token = _minted(pki, macvoms.port, f"{PUB_DIR}/seed.txt",
                    ["activity:DOWNLOAD,LIST", "path:/"], proxy=pki["minter"])
    code, text = _get(pki, macvoms.port, f"{PUB_DIR}/seed.txt", token=token)
    assert code == "200", f"the minted macaroon was refused ({code}): {text}"
    assert text == SEED.decode()


# --------------------------------------------------------------------------- #
# What the macaroon carries: nothing about its minter
# --------------------------------------------------------------------------- #

def test_the_macaroon_records_neither_the_dn_nor_the_vo(macvoms, pki):
    """error: the issued token identifies no one.  `mac_make_identifier` emits
    a timestamp and sixteen random hex digits, and that string is what
    `macaroon_parse.c:39` later presents as `claims->sub` — so two different
    users' macaroons, minted at the same URI with the same caveats, differ only
    in the nonce and the signature it seeds."""
    caveats = ["activity:DOWNLOAD,LIST", "path:/"]
    mine = _decode(_minted(pki, macvoms.port, f"{PUB_DIR}/seed.txt", caveats,
                           proxy=pki["minter"]))
    theirs = _decode(_minted(pki, macvoms.port, f"{PUB_DIR}/seed.txt", caveats,
                             proxy=pki["other"]))

    assert IDENTIFIER_RE.search(mine), f"unexpected identifier form: {mine!r}"
    for needle in (MINTER_CN.encode(), VO.encode(), b"macvoms-CA"):
        assert needle not in mine, f"{needle!r} leaked into the macaroon: {mine!r}"
    assert _caveats(mine) == _caveats(theirs), (
        "the two users' caveats differ, so something about the minter DID "
        f"survive: {_caveats(mine)} vs {_caveats(theirs)}")
    assert IDENTIFIER_RE.sub(b"", mine) != mine


def test_the_macaroon_does_not_carry_the_minters_authdb_identity(macvoms, pki):
    """error: the `targetWithMacaroon` URL the server returns is 403 on the
    export that minted it.  The authdb matches `u` rules against
    `brix_identity_dn_cstr`, which for a macaroon-authenticated request is the
    nonce, so no rule naming a person can ever match one.  Served on the face
    without an authdb, so this is a rule declining a good token."""
    token = _minted(pki, macvoms.port, f"{PUB_DIR}/seed.txt",
                    ["activity:DOWNLOAD,LIST", "path:/"], proxy=pki["minter"])

    mine, _ = _get(pki, macvoms.port, f"{LEAF_DIR}/seed.txt",
                   proxy=pki["minter"])
    assert mine == "200", f"the proxy itself cannot read {LEAF_DIR}: {mine}"

    delegated, text = _get(pki, macvoms.port, f"{LEAF_DIR}/seed.txt",
                           token=token)
    assert delegated == "403", (
        f"the macaroon now carries its minter's identity ({delegated}) — the "
        "identifier records a DN; retire defect candidate #25's second half")

    free, body = _get(pki, _free(macvoms), f"{LEAF_DIR}/seed.txt", token=token)
    assert free == "200", f"the token is not readable at all ({free}): {body}"
    assert body == SEED.decode()


def test_the_macaroon_does_not_delegate_vo_membership(macvoms, pki):
    """error: the VO half.  The proxy reaches a `g <vo>` tree because its
    attribute certificate asserts membership; the macaroon it mints carries no
    VO at all, so `brix_identity_vo_csv_cstr` is empty and the group rule
    cannot match.  A macaroon is not a delegation of who you are with."""
    token = _minted(pki, macvoms.port, f"{PUB_DIR}/seed.txt",
                    ["activity:DOWNLOAD,LIST", "path:/"], proxy=pki["minter"])

    vo_read, _ = _get(pki, macvoms.port, f"{VO_DIR}/seed.txt",
                      proxy=pki["minter"])
    assert vo_read == "200", (
        f"the VOMS proxy cannot read the `g {VO}` tree ({vo_read}) — the "
        "attribute certificate did not survive, so nothing below is about "
        "macaroons")

    delegated, _ = _get(pki, macvoms.port, f"{VO_DIR}/seed.txt", token=token)
    assert delegated == "403", (
        f"the macaroon now carries the VO ({delegated}) — retire this pin")

    free, body = _get(pki, _free(macvoms), f"{VO_DIR}/seed.txt", token=token)
    assert free == "200", f"the same token is unreadable without rules: {free}"
    assert body == SEED.decode()


# --------------------------------------------------------------------------- #
# DEFECT CANDIDATE #25 — which of the two DNs WebDAV authorizes
# --------------------------------------------------------------------------- #

def test_webdav_authorizes_the_proxy_leaf_not_the_eec_subject(macvoms, pki):
    """defect: one authdb, one user, two rules — and the wrong one wins.

    `u <EEC subject> /eec` is the rule an operator writes and the rule root://
    honours (test_audit15h_authdb_delegation.py proves that half on the same
    kind of chain).  `u <proxy leaf> /leaf` is the rule that names a string
    which will not exist tomorrow.  WebDAV serves /leaf and refuses /eec,
    because `webdav_finish_verified_cert` takes the subject of the LEAF.  Both
    trees are readable on the face without an authdb, so this is authorization
    and not the chain."""
    eec, _ = _get(pki, macvoms.port, f"{EEC_DIR}/seed.txt", proxy=pki["minter"])
    leaf, _ = _get(pki, macvoms.port, f"{LEAF_DIR}/seed.txt",
                   proxy=pki["minter"])

    assert leaf == "200", (
        f"the rule naming the proxy leaf did not grant ({leaf}) — WebDAV is "
        "keyed on neither DN and this pin describes the wrong defect")
    assert eec == "403", (
        f"the rule naming the EEC subject now grants ({eec}) — WebDAV has been "
        "moved onto the End-Entity subject; flip this test and its neighbour "
        "and retire defect candidate #25")

    for tree in (EEC_DIR, LEAF_DIR):
        code, body = _get(pki, _free(macvoms), f"{tree}/seed.txt",
                          proxy=pki["minter"])
        assert code == "200", f"{tree} is unreadable without an authdb: {code}"
        assert body == SEED.decode()


def test_a_renewed_proxy_loses_the_authorization_it_had(macvoms, pki):
    """defect, consequence: the same certificate, a new proxy, no access.

    Because the rule that works names the leaf, it names a serial.  A user who
    re-runs `xrdgsiproxy init` — hourly, on every real site — is a different
    principal to this authdb from one minute to the next, and the denial names
    a DN nobody put in the file.  The original proxy is re-read in the same
    test so the tree cannot be blamed."""
    original, _ = _get(pki, macvoms.port, f"{LEAF_DIR}/seed.txt",
                       proxy=pki["minter"])
    renewed, _ = _get(pki, macvoms.port, f"{LEAF_DIR}/seed.txt",
                      proxy=pki["renewed"])

    assert original == "200", f"the original proxy stopped working: {original}"
    assert renewed == "403", (
        f"the renewal is now authorized ({renewed}) — authorization survives "
        "re-delegation, so WebDAV has been moved onto the EEC subject")

    free, _ = _get(pki, _free(macvoms), f"{LEAF_DIR}/seed.txt",
                   proxy=pki["renewed"])
    assert free == "200", f"the renewed proxy does not authenticate at all: {free}"


# --------------------------------------------------------------------------- #
# The issuance bound
# --------------------------------------------------------------------------- #

def test_the_caveat_path_escapes_the_gate_the_uri_is_subject_to(macvoms, pki):
    """error: a certificate caller is bounded by WHERE IT KNOCKED, not by what
    it asked for.  POSTing at /nowhere is refused by the authdb read gate (POST
    is not in the WebDAV operation table, so `access_apply_authdb` treats it as
    a read of the request URI).  The identical authority — /nowhere, with every
    write activity — is granted when the same caller knocks at /pub instead,
    because `mac_authorize` returns early for a non-token caller and nothing
    else looks at the `path:` caveat."""
    refused, _ = _issue(pki, macvoms.port, f"{UNRULED}/seed.txt",
                        ["activity:DOWNLOAD", "path:/"], proxy=pki["minter"])
    assert refused == "403", (
        f"the authdb no longer gates the issuance URI ({refused}) — this test "
        "compares two doors and one of them is missing")

    token = _minted(pki, macvoms.port, f"{PUB_DIR}/seed.txt",
                    [f"activity:UPLOAD,DELETE,MANAGE", f"path:{UNRULED}"],
                    proxy=pki["minter"])
    raw = _decode(token)
    assert f"cid path:{UNRULED}\n".encode() in raw, raw
    assert b"cid activity:UPLOAD,DELETE,MANAGE\n" in raw, raw


def test_a_read_only_bearer_cannot_reach_the_endpoint_at_all(macvoms, pki):
    """security-negative, and the control for the test above: the OTHER caller
    is measured against what it holds.  An issuance POST is classified
    BRIX_TOKEN_OP_WRITE by `webdav_token_op_class`, so a DOWNLOAD-only macaroon
    is refused in the access phase before `mac_authorize` is even reached —
    while the certificate caller, whose authdb rules grant `rl` and nothing
    else, is issued the same macaroon from the same URI."""
    body = ["activity:UPLOAD,DELETE,MANAGE", "path:/"]
    reader = _bearer(["activity:DOWNLOAD,LIST", "path:/"], macvoms.port)

    denied, _ = _issue(pki, macvoms.port, f"{PUB_DIR}/seed.txt", body,
                       token=reader)
    assert denied == "403", (
        f"a read-only bearer minted a write macaroon ({denied}) — the scope "
        "gate on the issuance POST is gone")

    granted, text = _issue(pki, macvoms.port, f"{PUB_DIR}/seed.txt", body,
                           proxy=pki["minter"])
    assert granted == "200", (
        f"the certificate caller was refused too ({granted}): {text} — the "
        "asymmetry this test is about no longer exists")
    assert json.loads(text)["macaroon"]


# --------------------------------------------------------------------------- #
# Security negatives
# --------------------------------------------------------------------------- #

def test_an_unauthenticated_issuance_request_is_refused(macvoms, pki):
    """security-negative: no certificate, no token, no macaroon.  `brix_webdav_auth
    required` stops it in the access phase, and `mac_gate_and_read_body` would
    stop it again on `ctx->verified` — anonymous callers cannot obtain
    credentials from either door."""
    code, text = _issue(pki, macvoms.port, f"{PUB_DIR}/seed.txt",
                        ["activity:DOWNLOAD", "path:/"])
    assert code in ("401", "403"), f"anonymous issuance returned {code}: {text}"
    assert "macaroon" not in text, f"a macaroon leaked to an anonymous caller: {text}"


def test_an_untrusted_chain_cannot_obtain_a_macaroon(macvoms, pki):
    """security-negative: a certificate bearing the minter's subject verbatim,
    issued by a CA this server does not trust.  `brix_gsi_verify_chain` refuses
    it against `conf->ca_store`, so the string equality that would satisfy the
    authdb is never reached — and no macaroon is minted for a name the caller
    merely knows."""
    code, text = _issue(pki, macvoms.port, f"{PUB_DIR}/seed.txt",
                        ["activity:DOWNLOAD", "path:/"], proxy=pki["impostor"])
    assert code in ("401", "403"), f"an untrusted chain got {code}: {text}"
    assert "macaroon" not in text, f"a macaroon leaked to an impostor: {text}"

    free, _ = _issue(pki, _free(macvoms), f"{PUB_DIR}/seed.txt",
                     ["activity:DOWNLOAD", "path:/"], proxy=pki["impostor"])
    assert free in ("401", "403"), (
        f"the face without an authdb minted for the impostor ({free}) — the "
        "refusal above was a rule, not the chain check")


def test_a_download_only_macaroon_cannot_upload(macvoms, pki, tmp_path):
    """security-negative: the activity caveats bind.  Both PUTs are made on the
    face with no authdb and `brix_allow_write on`, so the only thing that can
    separate them is the token's own scope — `webdav_check_token_scope` maps
    PUT to a write and `macaroon_scope_for_activity` gives DOWNLOAD only
    `storage.read`."""
    payload = tmp_path / "upload.bin"
    payload.write_bytes(b"macvoms upload\n")

    reader = _minted(pki, macvoms.port, f"{PUB_DIR}/seed.txt",
                     ["activity:DOWNLOAD,LIST", "path:/"], proxy=pki["minter"])
    writer = _minted(pki, macvoms.port, f"{PUB_DIR}/seed.txt",
                     ["activity:DOWNLOAD,UPLOAD", "path:/"], proxy=pki["minter"])

    denied, text = _probe(pki, _free(macvoms), f"{PUB_DIR}/ro.bin",
                          token=reader, upload=str(payload))
    assert denied == "403", f"a DOWNLOAD-only macaroon uploaded ({denied}): {text}"

    allowed, text = _probe(pki, _free(macvoms), f"{PUB_DIR}/rw.bin",
                           token=writer, upload=str(payload))
    assert allowed in ("200", "201", "204"), (
        f"an UPLOAD macaroon could not upload either ({allowed}): {text} — the "
        "refusal above is not the activity caveat")
