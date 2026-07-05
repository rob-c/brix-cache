"""images — docker build/run helpers for the image + mega-config e2e tests.

Subprocess-backed (there is no first-class Python docker in this repo's stack).
Only used under ``-m e2e`` — needs a working docker daemon.
"""
from __future__ import annotations

import base64
from pathlib import Path

from .shell import run

LAB_DIR = Path(__file__).resolve().parents[2]
REPO = LAB_DIR.parent
SERVER_IMAGE = "brix-server:dev"
AUTHORITY_IMAGE = "brix-authority:dev"


def build(tag, dockerfile, context=REPO):
    """docker build -t <tag> -f <dockerfile> <context> ; return CompletedProcess."""
    return run(["docker", "build", "-t", tag, "-f", str(dockerfile), str(context)],
               timeout=1800)


def run_(image, argv, env=None):
    """docker run --rm [-e K=V ...] <image> <argv...> ; return CompletedProcess."""
    cmd = ["docker", "run", "--rm"]
    for k, v in (env or {}).items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [image, *argv]
    return run(cmd, timeout=300)


def _authority_blob(script):
    """Run a one-liner in the authority image and return its stdout."""
    return run_(AUTHORITY_IMAGE, ["bash", "-lc", script]).stdout


def nginx_t_mega():
    """Validate the mega config with `nginx -t` in the server image (real
    JWKS + CRL from the authority image). Returns the nginx exit code.

    Port of mega_config.bats' 'validates with nginx -t' test.
    """
    conf = LAB_DIR / "charts" / "topology-role" / "configs" / "fleet-mega.conf"
    jwks = _authority_blob(
        "cd /opt/brix && TEST_ROOT=/w python3 utils/make_token.py init /w/tok "
        ">/dev/null 2>&1 && cat /w/tok/jwks.json")
    crl = _authority_blob(
        "cd /opt/brix && TEST_ROOT=/w python3 -c "
        "'import sys;sys.path.insert(0,\"tests\");from pki_helpers import "
        "blitz_test_pki;blitz_test_pki()' >/dev/null 2>&1; cat /w/pki/ca/test-user.crl.pem")
    env = {
        "C": base64.b64encode(conf.read_bytes()).decode(),
        "J": base64.b64encode(jwks.encode()).decode(),
        "CRL": base64.b64encode(crl.encode()).decode(),
    }
    script = r"""
      mkdir -p /var/log/brix /data/xrootd/cache /etc/grid-security/certificates \
               /etc/grid-security/vomsdir /etc/brix/crl /etc/brix/jwks
      echo "$C"   | base64 -d > /etc/brix/nginx.conf
      echo "$J"   | base64 -d > /etc/brix/jwks/jwks.json
      echo "$CRL" | base64 -d > /etc/brix/crl/crl.pem
      openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout /etc/grid-security/hostkey.pem -out /etc/grid-security/hostcert.pem \
        -days 1 -subj /CN=t >/dev/null 2>&1
      cp /etc/grid-security/hostcert.pem /etc/grid-security/certificates/ca.pem
      nginx -t -c /etc/brix/nginx.conf
    """
    return run_(SERVER_IMAGE, ["bash", "-lc", script], env=env).returncode
