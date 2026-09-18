"""
tests/_test_voms_corner_helpers.py — PKI, vomsdir and harness plumbing for
tests/test_voms_corner_cases.py (re-exported there via split_continuation).

What lives here
---------------
  make_pki(root)        a throwaway PKI built with openssl: a self-signed test
                        CA (installed as certdir/<hash>.0), a user certificate,
                        VOMS signing certificates on RSA, EC P-256 and Ed25519
                        keys (all with subjectKeyIdentifier), an EXPIRED RSA
                        signer, a REVOKED RSA signer (the CA's CRL revoking it is
                        written as certdir/<hash>.r0) and a ROGUE signer no LSC
                        names.
  make_vomsdir(pki)     vomsdir/<vo>/ for cms (two LSC files: the RSA and the
                        Ed25519 signer), atlas (the EC signer in RFC 2253 form,
                        CRLF endings, a comment), dteam (a 4-line chain LSC:
                        signer, CA, CA, CA) and vo.example.org (legacy: a PEM
                        copy of the RSA signer, no LSC).
  build_harness(out)    compiles shared/voms/voms_ac_check.c once.
  run_check(...)        runs it and parses the `status:` / `ac[i]:` contract.
  mint(...)             utils/voms_proxy_fake.py with extra knobs.
"""

import datetime
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FAKE = os.path.join(REPO, "utils", "voms_proxy_fake.py")
HARNESS_SRC = os.path.join(REPO, "shared", "voms", "voms_ac_check.c")
ENGINE_SRCS = ["voms_ac_check.c", "voms_asn1.c", "voms_decode.c", "voms_verify.c", "voms_lsc.c"]
BASE_DN = "/DC=test/DC=corner"
SIGNERS = ("rsa", "ec", "ed25519", "expired", "revoked", "rogue")
_KEY_KIND = {"rsa": "rsa", "ec": "ec", "ed25519": "ed25519", "expired": "rsa",
             "revoked": "rsa", "rogue": "rsa"}
_EXPIRED_WINDOW = ("-not_before", "20200101000000Z", "-not_after", "20200102000000Z")


def _run(argv, **kw):
    return subprocess.run(argv, check=True, capture_output=True, text=True, **kw)


def _openssl(*argv):
    return _run(["openssl", *argv])


# ---------------------------------------------------------------------------
# PKI
# ---------------------------------------------------------------------------

@dataclass
class Pki:
    root: str
    certdir: str
    ca_cert: str
    ca_key: str
    user_cert: str
    user_key: str
    certs: dict = field(default_factory=dict)   # signer name -> cert path
    keys: dict = field(default_factory=dict)    # signer name -> key path
    vomsdir: str = ""


def _gen_key(path: str, kind: str) -> None:
    if kind == "rsa":
        _openssl("genrsa", "-out", path, "2048")
    elif kind == "ec":
        _openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", path)
    else:
        _openssl("genpkey", "-algorithm", "ed25519", "-out", path)


def _write_ext_conf(path: str) -> None:
    """End-entity extensions: every signer carries a subjectKeyIdentifier so the
    AC's authorityKeyIdentifier has something to agree with."""
    with open(path, "w") as fh:
        fh.write("[v3]\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always\n"
                 "basicConstraints = CA:FALSE\nkeyUsage = digitalSignature,keyEncipherment\n")


def _write_req_conf(path: str) -> None:
    """A req config forcing PrintableString DN attributes (OpenSSL 3 defaults to
    UTF8String), so the user certificate's CN is PrintableString and the
    -holder-utf8 knob really exercises the canonical name compare."""
    with open(path, "w") as fh:
        fh.write("[req]\ndistinguished_name = dn\nstring_mask = pkix\nprompt = no\n"
                 "[dn]\nDC = test\n1.DC = corner\nCN = Corner User\n")


def _make_ca(root: str) -> tuple[str, str]:
    ca_key, ca_cert = os.path.join(root, "ca.key"), os.path.join(root, "ca.pem")
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", ca_key,
             "-out", ca_cert, "-subj", f"{BASE_DN}/CN=Corner CA", "-days", "30",
             "-extensions", "v3", "-config", os.path.join(root, "ca_req.conf"))
    return ca_cert, ca_key


def _write_ca_req_conf(root: str) -> None:
    ext = os.path.join(root, "ca_req.conf")
    with open(ext, "w") as fh:
        fh.write("[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = Corner CA\n"
                 "[v3]\nbasicConstraints = critical,CA:TRUE\n"
                 "keyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\n")


def _issue(pki: Pki, name: str, kind: str, cn: str, *extra) -> None:
    """Key + CSR + CA-signed certificate for signer `name` (or the user)."""
    key = os.path.join(pki.root, f"{name}.key")
    cert = os.path.join(pki.root, f"{name}.pem")
    csr = os.path.join(pki.root, f"{name}.csr")
    ext = os.path.join(pki.root, "ee_ext.conf")
    _gen_key(key, kind)
    _openssl("req", "-new", "-key", key, "-subj", f"{BASE_DN}/CN={cn}", "-out", csr)
    _openssl("x509", "-req", "-in", csr, "-CA", pki.ca_cert, "-CAkey", pki.ca_key,
             "-CAcreateserial", "-out", cert, "-days", "30", "-extensions", "v3",
             "-extfile", ext, *extra)
    pki.certs[name] = cert
    pki.keys[name] = key


def _issue_user(pki: Pki) -> None:
    conf = os.path.join(pki.root, "user_req.conf")
    _write_req_conf(conf)
    _gen_key(pki.user_key, "rsa")
    csr = os.path.join(pki.root, "user.csr")
    _openssl("req", "-new", "-key", pki.user_key, "-config", conf, "-out", csr)
    _openssl("x509", "-req", "-in", csr, "-CA", pki.ca_cert, "-CAkey", pki.ca_key,
             "-CAcreateserial", "-out", pki.user_cert, "-days", "30", "-extensions", "v3",
             "-extfile", os.path.join(pki.root, "ee_ext.conf"))


def subject_hash(pem: str) -> str:
    return _openssl("x509", "-in", pem, "-noout", "-subject_hash").stdout.strip()


def dn(pem: str, field_name: str, nameopt: str = "compat") -> str:
    """Subject or issuer DN in OpenSSL one-line ('compat') or RFC 2253 form."""
    out = _openssl("x509", "-in", pem, "-noout", f"-{field_name}", "-nameopt", nameopt)
    return out.stdout.strip().split("=", 1)[1].strip()


def _write_crl(pki: Pki, revoked_pem: str) -> None:
    """The CA's CRL revoking `revoked_pem`, as certdir/<hash>.r0 (PEM)."""
    with open(pki.ca_cert, "rb") as fh:
        ca = x509.load_pem_x509_certificate(fh.read())
    with open(pki.ca_key, "rb") as fh:
        ca_key = serialization.load_pem_private_key(fh.read(), password=None)
    with open(revoked_pem, "rb") as fh:
        revoked = x509.load_pem_x509_certificate(fh.read())
    now = datetime.datetime.now(datetime.timezone.utc)
    entry = (x509.RevokedCertificateBuilder().serial_number(revoked.serial_number)
             .revocation_date(now - datetime.timedelta(minutes=5)).build())
    crl = (x509.CertificateRevocationListBuilder().issuer_name(ca.subject)
           .last_update(now - datetime.timedelta(minutes=5))
           .next_update(now + datetime.timedelta(days=30))
           .add_revoked_certificate(entry).sign(ca_key, hashes.SHA256()))
    with open(os.path.join(pki.certdir, f"{subject_hash(pki.ca_cert)}.r0"), "wb") as fh:
        fh.write(crl.public_bytes(serialization.Encoding.PEM))


def make_pki(root: str) -> Pki:
    os.makedirs(root, exist_ok=True)
    certdir = os.path.join(root, "certificates")
    os.makedirs(certdir, exist_ok=True)
    _write_ca_req_conf(root)
    ca_cert, ca_key = _make_ca(root)
    pki = Pki(root, certdir, ca_cert, ca_key, os.path.join(root, "user.pem"),
              os.path.join(root, "user.key"))
    shutil.copy(ca_cert, os.path.join(certdir, f"{subject_hash(ca_cert)}.0"))
    _write_ext_conf(os.path.join(root, "ee_ext.conf"))
    _issue_user(pki)
    for name in SIGNERS:
        extra = _EXPIRED_WINDOW if name == "expired" else ()
        _issue(pki, name, _KEY_KIND[name], f"voms-{name}.test.local", *extra)
    _write_crl(pki, pki.certs["revoked"])
    return pki


# ---------------------------------------------------------------------------
# vomsdir
# ---------------------------------------------------------------------------

def _write_lsc(path: str, lines, newline: str = "\n") -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="") as fh:
        fh.write(newline.join(lines) + newline)


def make_vomsdir(pki: Pki) -> str:
    vomsdir = os.path.join(pki.root, "vomsdir")
    rsa, ec, ed = (pki.certs[n] for n in ("rsa", "ec", "ed25519"))
    _write_lsc(os.path.join(vomsdir, "cms", "voms-rsa.test.local.lsc"),
               [dn(rsa, "subject"), dn(rsa, "issuer")])
    _write_lsc(os.path.join(vomsdir, "cms", "voms-ed25519.test.local.lsc"),
               [dn(ed, "subject"), dn(ed, "issuer")])
    _write_lsc(os.path.join(vomsdir, "atlas", "voms-ec.test.local.lsc"),
               ["# the EC signer, RFC 2253 spelling", "",
                dn(ec, "subject", "RFC2253") + "  ", dn(ec, "issuer", "RFC2253")],
               newline="\r\n")
    ca_dn = dn(pki.ca_cert, "subject")
    _write_lsc(os.path.join(vomsdir, "dteam", "voms-rsa.test.local.lsc"),
               [dn(rsa, "subject"), ca_dn, ca_dn, ca_dn])
    legacy = os.path.join(vomsdir, "vo.example.org")
    os.makedirs(legacy, exist_ok=True)
    shutil.copy(rsa, os.path.join(legacy, "voms-rsa.test.local.pem"))
    pki.vomsdir = vomsdir
    return vomsdir


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------

def _openssl_flags() -> list[str]:
    prefix = "/usr/local/opt/openssl@3"
    if os.path.isdir(os.path.join(prefix, "include")):
        return [f"-I{prefix}/include", f"-L{prefix}/lib"]
    return []


def build_harness(out: str) -> str:
    """Compile shared/voms/voms_ac_check.c (the contract in the brief)."""
    srcs = [os.path.join(REPO, "shared", "voms", n) for n in ENGINE_SRCS]
    _run(["cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror",
          "-I", os.path.join(REPO, "shared"), *_openssl_flags(), *srcs, "-lcrypto", "-o", out])
    return out


@dataclass
class Verdict:
    status: str
    acs: list            # one dict per ac[i]: vo, verdict, uri, digest, fqans, carrier, fqan, attr
    stdout: str
    returncode: int


_AC_LINE = re.compile(r"^ac\[(\d+)\]: (.*)$")


def _parse_ac(rest: str) -> dict:
    ac = dict(kv.split("=", 1) for kv in rest.split(" "))
    ac["fqan"] = []
    ac["attr"] = []
    return ac


def _absorb_line(line: str, out: Verdict) -> None:
    stripped = line.strip()
    match = _AC_LINE.match(stripped)
    if stripped.startswith("status: "):
        out.status = stripped[len("status: "):]
    elif match:
        out.acs.append(_parse_ac(match.group(2)))
    elif stripped.startswith("fqan: "):
        out.acs[-1]["fqan"].append(stripped[len("fqan: "):])
    elif stripped.startswith("attr: "):
        out.acs[-1]["attr"].append(stripped[len("attr: "):])


def parse_verdict(stdout: str, returncode: int) -> Verdict:
    out = Verdict("", [], stdout, returncode)
    for line in stdout.splitlines():
        _absorb_line(line, out)
    return out


def run_check(harness: str, proxy: str, certdir: str | None = None,
              vomsdir: str | None = None, skew: int | None = None,
              now: int | None = None) -> Verdict:
    argv = [harness]
    for flag, value in (("--certdir", certdir), ("--vomsdir", vomsdir),
                        ("--skew", skew), ("--now", now)):
        if value is not None:
            argv += [flag, str(value)]
    r = subprocess.run(argv + [proxy], capture_output=True, text=True, timeout=30)
    return parse_verdict(r.stdout + r.stderr, r.returncode)


# ---------------------------------------------------------------------------
# minting
# ---------------------------------------------------------------------------

def _vo_fqan_pairs(vo, fqan) -> list[tuple[str, str]]:
    """`vo` a name or a list; `fqan` None (Role=NULL/Capability=NULL per VO),
    one string, or a list paired positionally."""
    vos = [vo] if isinstance(vo, str) else list(vo)
    if fqan is None:
        return [(v, f"/{v}/Role=NULL/Capability=NULL") for v in vos]
    fqans = [fqan] if isinstance(fqan, str) else list(fqan)
    return list(zip(vos, fqans))


def mint(pki: Pki, out: str, signer: str = "rsa", vo="cms", fqan=None, *extra) -> str:
    """utils/voms_proxy_fake.py for `vo` (a name or a list, paired with `fqan`)
    signed by `signer`, plus any extra knobs."""
    argv = [sys.executable, FAKE, "-cert", pki.user_cert, "-key", pki.user_key,
            "-certdir", pki.certdir, "-hostcert", pki.certs[signer],
            "-hostkey", pki.keys[signer], "-uri", f"voms-{signer}.test.local:15000",
            "-out", out, "-hours", "24", "-cacert", pki.ca_cert]
    for v, f in _vo_fqan_pairs(vo, fqan):
        argv += ["-voms", v, "-fqan", f]
    _run(argv + list(extra))
    return out
