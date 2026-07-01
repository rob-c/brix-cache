"""Helpers for rebuilding the local test PKI from scratch."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from settings import CA_CERT, CA_DIR, CA_KEY, PKI_DIR, SERVER_CERT, SERVER_KEY, USER_CERT, USER_KEY

ROOT_DIR = Path(__file__).resolve().parents[1]
MAKE_PROXY = ROOT_DIR / "utils" / "make_proxy.py"
MAKE_CRL = ROOT_DIR / "utils" / "make_crl.py"

CA_SUBJECT = "/DC=test/DC=xrootd/CN=Test XRootD CA"
SERVER_SUBJECT = "/DC=test/DC=xrootd/CN=localhost"
USER_SUBJECT = "/DC=test/DC=xrootd/CN=Test User/CN=12345"


def _run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed: {' '.join(cmd)}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result.stdout.strip()


def _symlink(target: str, link_path: Path) -> None:
    if link_path.exists() or link_path.is_symlink():
        link_path.unlink()
    link_path.symlink_to(target)


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def blitz_test_pki() -> None:
    """Replace the local test PKI with a clean, canonical layout."""
    pki_dir = Path(PKI_DIR)
    ca_dir = Path(CA_DIR)
    server_dir = Path(SERVER_CERT).parent
    user_dir = Path(USER_CERT).parent

    if pki_dir.exists():
        shutil.rmtree(pki_dir)

    for subdir in ("ca", "server", "user", "voms", "vomsdir"):
        (pki_dir / subdir).mkdir(parents=True, exist_ok=True)

    # CA certificate, hash links, and signing-policy files.
    _run(["openssl", "genrsa", "-out", CA_KEY, "4096"])
    os.chmod(CA_KEY, 0o400)
    _run(
        [
            "openssl",
            "req",
            "-new",
            "-x509",
            "-key",
            CA_KEY,
            "-out",
            CA_CERT,
            "-days",
            "3650",
            "-sha256",
            "-subj",
            CA_SUBJECT,
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "subjectKeyIdentifier=hash",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]
    )

    new_hash = _run(["openssl", "x509", "-in", CA_CERT, "-noout", "-subject_hash"])
    old_hash = _run(["openssl", "x509", "-in", CA_CERT, "-noout", "-subject_hash_old"])

    signing_policy = ca_dir / "signing-policy"
    _write(
        signing_policy,
        "\n".join(
            [
                f"access_id_CA    X509    '{CA_SUBJECT}'",
                "pos_rights      globus  CA:sign",
                "cond_subjects   globus  '\"/DC=test/DC=xrootd/*\"'",
                "",
            ]
        ),
    )

    for hash_name in {new_hash, old_hash}:
        _symlink("ca.pem", ca_dir / f"{hash_name}.0")
        _symlink("signing-policy", ca_dir / f"{hash_name}.signing_policy")

    # Host certificate and compatibility symlink for older helper scripts.
    _run(["openssl", "genrsa", "-out", SERVER_KEY, "2048"])
    os.chmod(SERVER_KEY, 0o400)
    _run(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            SERVER_KEY,
            "-out",
            str(server_dir / "host.csr"),
            "-subj",
            SERVER_SUBJECT,
        ]
    )
    # Sign the server cert WITH a subjectAltName covering every address a client
    # reaches it by — name (localhost), IPv4 loopback (127.0.0.1) and IPv6
    # loopback (::1).  Without a SAN the cert only carries CN=localhost, so a
    # client connecting to https://127.0.0.1 fails TLS hostname verification
    # (curl exit 60) even though the cert chain is valid.  The reference XrdHttp
    # server and several tests address the server by literal 127.0.0.1.
    # keyUsage/extendedKeyUsage mirror a real IGTF host certificate: a TLS
    # server needs digitalSignature (handshake signing) + keyEncipherment (RSA
    # key transport), and serverAuth/clientAuth so the host can act as both the
    # TLS server and — for TPC/proxying — a TLS client.
    san_ext = server_dir / "san.ext"
    san_ext.write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n"
    )
    _run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(server_dir / "host.csr"),
            "-CA",
            CA_CERT,
            "-CAkey",
            CA_KEY,
            "-CAcreateserial",
            "-out",
            SERVER_CERT,
            "-days",
            "3650",
            "-sha256",
            "-extfile",
            str(san_ext),
        ]
    )
    _symlink("hostkey.pem", server_dir / "host.key")

    # User certificate and compatibility symlink for older helper scripts.
    _run(["openssl", "genrsa", "-out", USER_KEY, "2048"])
    os.chmod(USER_KEY, 0o400)
    _run(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            USER_KEY,
            "-out",
            str(user_dir / "user.csr"),
            "-subj",
            USER_SUBJECT,
        ]
    )
    # An IGTF end-entity certificate carries a critical keyUsage with
    # digitalSignature (+ keyEncipherment).  This is not cosmetic: GSI X.509
    # proxy *delegation* signs a proxy request against the delegator's chain,
    # and XrdCrypto's cryptossl_X509SignProxyReq rejects the request unless the
    # signing chain carries keyUsage ("wrong extensions in request").  A
    # keyUsage-less EEC therefore makes every delegation/TPC-lite test fail at
    # the crypto step regardless of the rest of the setup.  The clientAuth EKU
    # matches a real user certificate presented over TLS.
    user_ext = user_dir / "user.ext"
    user_ext.write_text(
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=clientAuth\n"
    )
    _run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(user_dir / "user.csr"),
            "-CA",
            CA_CERT,
            "-CAkey",
            CA_KEY,
            "-CAcreateserial",
            "-out",
            USER_CERT,
            "-days",
            "3650",
            "-sha256",
            "-extfile",
            str(user_ext),
        ]
    )
    _symlink("userkey.pem", user_dir / "user.key")

    _run([sys.executable, str(MAKE_PROXY), PKI_DIR])

    if MAKE_CRL.exists():
        _run([sys.executable, str(MAKE_CRL), PKI_DIR])
