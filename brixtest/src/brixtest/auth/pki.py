"""OpenSSL-backed disposable CA, CRL, host, client, and VOMS certificates."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Dict, Iterable, Mapping, Optional

from brixtest.errors import SpecError

__all__ = ["OpenSSL", "create_pki"]


class OpenSSL:
    """Shell-free OpenSSL command runner with complete failure diagnostics."""

    def __init__(self, executable: str = "openssl") -> None:
        self.executable = shutil.which(executable) or ""
        if not self.executable:
            raise SpecError("TLS recipe", executable, "OpenSSL is not installed or not on PATH")

    def run(self, *args: str, input_text: str = "") -> str:
        try:
            result = subprocess.run(
                [self.executable, *args], input=input_text or None,
                capture_output=True, text=True, timeout=30.0, check=False,
                env={**os.environ, "RANDFILE": "/dev/null"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SpecError("OpenSSL", " ".join(args), str(exc)) from exc
        if result.returncode:
            raise SpecError(
                "OpenSSL", " ".join(args),
                (result.stderr or result.stdout or "command failed").strip(),
            )
        return result.stdout.strip()


def _safe_subject(value: str, field: str) -> str:
    if not value or any(char in value for char in "/\n\r\x00"):
        raise SpecError(field, value, "must be a safe X.509 common name")
    return value


def _configuration(root: Path, hostnames: Iterable[str], days: int) -> str:
    alt_names = "\n".join(
        "DNS.%d = %s" % (index, hostname)
        for index, hostname in enumerate(hostnames, 1)
    )
    return """[ ca ]
default_ca = CA_default

[ CA_default ]
dir = {root}
database = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate = $dir/ca.pem
private_key = $dir/ca.key
serial = $dir/serial
crlnumber = $dir/crlnumber
default_days = {days}
default_crl_days = {days}
default_md = sha256
policy = policy_any
unique_subject = no
copy_extensions = none

[ policy_any ]
commonName = supplied

[ server_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ client_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

[ alt_names ]
{alt_names}
""".format(root=root, days=days, alt_names=alt_names)


def _certificate(
    openssl: OpenSSL, root: Path, name: str, common_name: str, extension: str,
    key_bits: int,
) -> Mapping[str, Path]:
    key = root / (name + ".key")
    request = root / (name + ".csr")
    certificate = root / (name + ".pem")
    openssl.run(
        "req", "-new", "-newkey", "rsa:%d" % key_bits, "-nodes",
        "-keyout", str(key), "-out", str(request),
        "-subj", "/CN=%s" % _safe_subject(common_name, name + ".common_name"),
    )
    openssl.run(
        "ca", "-batch", "-config", str(root / "openssl.cnf"),
        "-extensions", extension, "-in", str(request), "-out", str(certificate),
    )
    key.chmod(stat.S_IRUSR | stat.S_IWUSR)
    request.unlink()
    return {name + "_key": key, name + "_cert": certificate}


def _subject(openssl: OpenSSL, certificate: Path) -> str:
    value = openssl.run("x509", "-in", str(certificate), "-noout", "-subject", "-nameopt", "compat")
    return value.split("=", 1)[1].strip() if "=" in value else value.strip()


def create_pki(
    root: Path, *, authority_name: str, hostnames: Iterable[str], client_name: str,
    days: int = 2, key_bits: int = 2048, voms_name: Optional[str] = None,
    openssl: Optional[OpenSSL] = None,
) -> Mapping[str, Path]:
    """Create an isolated test CA with CRL and role-specific leaf certificates."""
    runner = openssl or OpenSSL()
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    (root / "newcerts").mkdir()
    (root / "index.txt").write_text("")
    (root / "serial").write_text("1000\n")
    (root / "crlnumber").write_text("1000\n")
    names = tuple(dict.fromkeys(hostnames))
    if not names:
        raise SpecError("TLS hostnames", names, "must contain at least one hostname")
    (root / "openssl.cnf").write_text(_configuration(root, names, days))
    ca_key, ca_cert = root / "ca.key", root / "ca.pem"
    runner.run(
        "req", "-x509", "-newkey", "rsa:%d" % key_bits, "-nodes",
        "-keyout", str(ca_key), "-out", str(ca_cert), "-days", str(days),
        "-subj", "/CN=%s" % _safe_subject(authority_name, "authority_name"),
        "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
    )
    ca_key.chmod(stat.S_IRUSR | stat.S_IWUSR)
    files: Dict[str, Path] = {"ca_key": ca_key, "ca_cert": ca_cert}
    files.update(_certificate(runner, root, "host", names[0], "server_cert", key_bits))
    files.update(_certificate(runner, root, "client", client_name, "client_cert", key_bits))
    if voms_name is not None:
        files.update(_certificate(runner, root, "voms", voms_name, "server_cert", key_bits))
    crl = root / "ca.crl"
    runner.run("ca", "-batch", "-config", str(root / "openssl.cnf"), "-gencrl", "-out", str(crl))
    files["crl"] = crl
    trust = root / "certificates"
    trust.mkdir()
    cert_hash = runner.run("x509", "-in", str(ca_cert), "-noout", "-hash")
    crl_hash = runner.run("crl", "-in", str(crl), "-noout", "-hash")
    shutil.copy2(ca_cert, trust / (cert_hash + ".0"))
    shutil.copy2(crl, trust / (crl_hash + ".r0"))
    files["trust_dir"] = trust
    subjects = root / "subjects.txt"
    lines = ["ca=%s" % _subject(runner, ca_cert), "host=%s" % _subject(runner, files["host_cert"])]
    if voms_name is not None:
        lines.append("voms=%s" % _subject(runner, files["voms_cert"]))
    subjects.write_text("\n".join(lines) + "\n")
    files["subjects"] = subjects
    return files
