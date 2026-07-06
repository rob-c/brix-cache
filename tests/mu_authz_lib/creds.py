"""Per-principal credential factory: GSI cert + RFC 3820 proxy, VOMS proxy, WLCG token, S3 key.

The GSI proxy is built inline (utils/make_proxy.py only handles the single default user), but
byte-for-byte matching its format: proxyCertInfo (id-ppl-inheritAll, critical), KeyUsage
digital_signature (critical), subject = user DN + CN=<serial>, file = proxy_cert + user_cert +
proxy_key. VOMS proxies delegate to utils/voms_proxy_fake.py against a self-contained VOMS
signing cert + vomsdir. Tokens use utils/make_token.TokenIssuer.
"""
import datetime
import hashlib
import os
import subprocess
import sys
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import ports

_REPO = Path(__file__).resolve().parents[2]
_UTILS = _REPO / "utils"
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))


def _user_dir() -> Path:
    d = Path(ports.MU.PKI_DIR) / "user"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _fresh(*paths: str) -> None:
    """Remove any pre-existing outputs so a regenerate can't fail on a 0400 file."""
    for p in paths:
        try:
            os.remove(p)
        except FileNotFoundError:
            pass


def _serial_for(name: str) -> str:
    """A stable, positive 63-bit serial derived from `name` (decimal string)."""
    return str(int(hashlib.sha256(name.encode()).hexdigest()[:15], 16) | 1)


def _ca_paths() -> "tuple[str, str]":
    return os.path.join(ports.MU.CA_DIR, "ca.pem"), os.path.join(ports.MU.CA_DIR, "ca.key")


# --------------------------------------------------------------------------- #
# GSI user cert + RFC 3820 proxy                                              #
# --------------------------------------------------------------------------- #

def gen_user_cert(dn: str, name: str) -> "tuple[str, str]":
    """Generate a user cert with the given DN, signed by the test CA. Returns (cert, key)."""
    ud = _user_dir()
    cert = str(ud / f"{name}_usercert.pem")
    key = str(ud / f"{name}_userkey.pem")
    ca_cert, ca_key = _ca_paths()

    _fresh(key, cert)
    subprocess.run(["openssl", "genrsa", "-out", key, "2048"], check=True, capture_output=True)
    os.chmod(key, 0o400)
    csr = cert.replace(".pem", ".csr")
    subprocess.run(["openssl", "req", "-new", "-key", key, "-subj", dn, "-out", csr],
                   check=True, capture_output=True)
    ext = cert.replace(".pem", ".ext")
    # keyUsage critical incl. keyEncipherment is required for XrdCrypto proxy delegation.
    Path(ext).write_text("keyUsage=critical,digitalSignature,keyEncipherment\n"
                         "extendedKeyUsage=clientAuth\n")
    # -set_serial (a stable per-name serial), NOT -CAcreateserial: the shared test CA's
    # ca.srl is also used by the running fleet, and -CAcreateserial mutates it
    # non-atomically -> a race. A fixed serial per name avoids touching ca.srl entirely.
    subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
                    "-set_serial", _serial_for(name), "-out", cert, "-days", "3650",
                    "-sha256", "-extfile", ext], check=True, capture_output=True)
    return cert, key


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, (n >> 8) & 0xFF, n & 0xFF])


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_len(len(value)) + value


def _encode_oid(oid_str: str) -> bytes:
    parts = [int(x) for x in oid_str.split(".")]
    out = [40 * parts[0] + parts[1]]
    for part in parts[2:]:
        if part == 0:
            out.append(0)
            continue
        chunks = []
        while part > 0:
            chunks.append(part & 0x7F)
            part >>= 7
        chunks.reverse()
        for i in range(len(chunks) - 1):
            chunks[i] |= 0x80
        out.extend(chunks)
    return bytes(out)


def _proxy_cert_info_der() -> bytes:
    """proxyCertInfo with id-ppl-inheritAll (matches utils/make_proxy.py)."""
    policy_oid = _der_tlv(0x06, _encode_oid("1.3.6.1.5.5.7.21.1"))
    proxy_policy = _der_tlv(0x30, policy_oid)
    return _der_tlv(0x30, proxy_policy)


def gen_gsi_proxy(cert_path: str, key_path: str, name: str) -> str:
    """Build an RFC 3820 proxy from a user cert/key; write proxy+cert+key bundle."""
    out = str(_user_dir() / f"{name}_proxy.pem")
    with open(cert_path, "rb") as f:
        user_cert = x509.load_pem_x509_certificate(f.read())
    with open(key_path, "rb") as f:
        user_key = serialization.load_pem_private_key(f.read(), password=None)

    proxy_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    serial = 12346
    proxy_subject = x509.Name(list(user_cert.subject)
                              + [x509.NameAttribute(NameOID.COMMON_NAME, str(serial))])
    now = datetime.datetime.now(datetime.timezone.utc)
    proxy_cert = (x509.CertificateBuilder()
                  .subject_name(proxy_subject)
                  .issuer_name(user_cert.subject)
                  .public_key(proxy_key.public_key())
                  .serial_number(serial)
                  .not_valid_before(now - datetime.timedelta(minutes=5))
                  .not_valid_after(now + datetime.timedelta(hours=12))
                  .add_extension(x509.UnrecognizedExtension(
                      x509.ObjectIdentifier("1.3.6.1.5.5.7.1.14"), _proxy_cert_info_der()),
                      critical=True)
                  .add_extension(x509.KeyUsage(
                      digital_signature=True, content_commitment=False, key_encipherment=False,
                      data_encipherment=False, key_agreement=False, key_cert_sign=False,
                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
                  .sign(user_key, hashes.SHA256()))

    proxy_key_pem = proxy_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    _fresh(out)
    with open(out, "wb") as f:
        f.write(proxy_cert.public_bytes(serialization.Encoding.PEM))
        with open(cert_path, "rb") as uc:
            f.write(uc.read())
        f.write(proxy_key_pem)
    os.chmod(out, 0o400)
    return out


# --------------------------------------------------------------------------- #
# VOMS proxy (self-contained VOMS signing cert + vomsdir)                      #
# --------------------------------------------------------------------------- #

def _voms_signing_cert() -> "tuple[str, str]":
    """Create (idempotent) a VOMS signing key+cert signed by the test CA."""
    vdir = Path(ports.MU.PKI_DIR) / "voms"
    vdir.mkdir(parents=True, exist_ok=True)
    cert = str(vdir / "voms_cert.pem")
    key = str(vdir / "voms_key.pem")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    ca_cert, ca_key = _ca_paths()
    subprocess.run(["openssl", "genrsa", "-out", key, "2048"], check=True, capture_output=True)
    csr = cert.replace(".pem", ".csr")
    subprocess.run(["openssl", "req", "-new", "-key", key,
                    "-subj", "/DC=test/DC=xrootd/CN=voms.test.local", "-out", csr],
                   check=True, capture_output=True)
    ext = cert.replace(".pem", "_ext.conf")
    Path(ext).write_text("[voms_ext]\nsubjectKeyIdentifier = hash\n"
                         "authorityKeyIdentifier = keyid:always\nbasicConstraints = CA:FALSE\n")
    subprocess.run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
                    "-set_serial", _serial_for("voms-signing"), "-out", cert, "-days", "365",
                    "-extensions", "voms_ext", "-extfile", ext], check=True, capture_output=True)
    return cert, key


def _voms_dn(pem: str, field: str) -> str:
    r = subprocess.run(["openssl", "x509", "-in", pem, "-noout", f"-{field}", "-nameopt", "compat"],
                       check=True, capture_output=True, text=True)
    return r.stdout.strip().split("=", 1)[1].strip()


def _ensure_vomsdir(vo: str) -> None:
    voms_cert, _ = _voms_signing_cert()
    subject = _voms_dn(voms_cert, "subject")
    issuer = _voms_dn(voms_cert, "issuer")
    vo_dir = Path(ports.MU.VOMSDIR) / vo
    vo_dir.mkdir(parents=True, exist_ok=True)
    (vo_dir / "voms.test.local.lsc").write_text(f"{subject}\n{issuer}\n")


def gen_voms_proxy(cert_path: str, key_path: str, name: str, vo: str) -> str:
    """Create a fake VOMS proxy for `vo` from a user cert/key."""
    _ensure_vomsdir(vo)
    voms_cert, voms_key = _voms_signing_cert()
    out = str(_user_dir() / f"{name}_voms_{vo}.pem")
    _fresh(out)
    subprocess.run([sys.executable, str(_UTILS / "voms_proxy_fake.py"),
                    "-cert", cert_path, "-key", key_path, "-certdir", ports.MU.CA_DIR,
                    "-hostcert", voms_cert, "-hostkey", voms_key, "-voms", vo,
                    "-fqan", f"/{vo}/Role=NULL/Capability=NULL",
                    "-uri", "voms.test.local:15000", "-out", out, "-hours", "24"],
                   check=True, capture_output=True)
    os.chmod(out, 0o400)
    return out


# --------------------------------------------------------------------------- #
# WLCG token + S3 key                                                         #
# --------------------------------------------------------------------------- #

def mint_token(sub: str, scope: str, name: str, *, issuer=None, audience=None,
               expired: bool = False) -> str:
    """Mint a WLCG JWT for (sub, scope); write to TOKENS_DIR/<name>.jwt; return the path."""
    from utils.make_token import TokenIssuer
    os.makedirs(ports.MU.TOKENS_DIR, exist_ok=True)
    iss = TokenIssuer(token_dir=ports.MU.TOKENS_DIR)
    if not os.path.exists(iss.key_path):
        iss.init_keys()
    if expired:
        tok = iss.generate_expired(sub=sub, scope=scope)
    else:
        tok = iss.generate(sub=sub, scope=scope,
                           issuer=issuer or TokenIssuer.DEFAULT_ISSUER,
                           audience=audience or TokenIssuer.DEFAULT_AUDIENCE, lifetime=3600)
    path = os.path.join(ports.MU.TOKENS_DIR, f"{name}.jwt")
    Path(path).write_text(tok)
    return path


def s3_key_for(name: str) -> "tuple[str, str]":
    """Deterministic (access_key, secret_key) per principal name."""
    ak = "AKIA" + hashlib.sha256(("ak:" + name).encode()).hexdigest()[:12].upper()
    sk = hashlib.sha256(("sk:" + name).encode()).hexdigest()
    return ak, sk
