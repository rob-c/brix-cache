"""Per-protocol verdict measurement → Verdict (spec §7, §8.6).

Each adapter presents a principal's credential for the given protocol, performs the
operation, and maps the outcome to a Verdict(decision, reason, tier). root:// uses a
per-call subprocess so credentials (cached inside the XRootD client process) don't leak
between measurements; WebDAV/S3 use `requests`.
"""
import json
import os
import re
import subprocess
import sys

import requests

from . import ports
from .verdict import Verdict

# --------------------------------------------------------------------------- #
# root:// (XRootD client, per-call subprocess for credential isolation)       #
# --------------------------------------------------------------------------- #

_ROOT_PROBE = r'''
import json, sys
from XRootD import client
from XRootD.client.flags import OpenFlags
url, path, op = sys.argv[1], sys.argv[2], sys.argv[3]
if op == "stat":
    st, _ = client.FileSystem(url).stat(path)
else:
    f = client.File()
    st, _ = f.open(url + "//" + path, OpenFlags.READ)
    if st.ok:
        if op == "read":
            st, _ = f.read(0, 4096)
        f.close()
print(json.dumps({"ok": bool(st.ok), "errno": int(st.errno), "message": st.message or ""}))
'''


def _root_env(principal) -> dict:
    env = os.environ.copy()
    env["X509_CERT_DIR"] = ports.MU.CA_DIR
    # Clear any inherited credential so an unauthenticated measurement is truly anonymous.
    for k in ("X509_USER_PROXY", "BEARER_TOKEN", "BEARER_TOKEN_FILE", "XrdSecPROTOCOL"):
        env.pop(k, None)
    if principal is None:
        return env
    if getattr(principal, "proxy", ""):
        env["X509_USER_PROXY"] = principal.proxy
        env["XrdSecPROTOCOL"] = "gsi"
    elif getattr(principal, "token", ""):
        env["BEARER_TOKEN_FILE"] = principal.token
        env["XrdSecPROTOCOL"] = "ztn"
    return env


def measure_root(url: str, path: str, op: str, *, principal=None) -> Verdict:
    r = subprocess.run([sys.executable, "-c", _ROOT_PROBE, url, path, op],
                       env=_root_env(principal), capture_output=True, text=True, timeout=30)
    for line in r.stdout.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        return Verdict.allow() if d["ok"] else Verdict.deny(d["message"])
    return Verdict.deny(f"probe-failed: {r.stderr.strip()[:200]}")


# --------------------------------------------------------------------------- #
# WebDAV (davs:// over https)                                                  #
# --------------------------------------------------------------------------- #

def measure_webdav(url: str, path: str, op: str, *, principal=None) -> Verdict:
    kw: dict = {"timeout": 30, "verify": os.path.join(ports.MU.CA_DIR, "ca.pem")}
    if principal is not None and getattr(principal, "token", ""):
        kw["headers"] = {"Authorization": "Bearer " + open(principal.token).read().strip()}
        kw["verify"] = False
    elif principal is not None and getattr(principal, "proxy", ""):
        kw["cert"] = principal.proxy
        kw["verify"] = False
    method = {"read": "GET", "stat": "HEAD", "list": "PROPFIND"}.get(op, "GET")
    try:
        resp = requests.request(method, url + path, **kw)
    except requests.exceptions.RequestException as e:
        return Verdict.deny(f"request-failed: {e}")
    if resp.status_code in (200, 206, 207):
        return Verdict.allow()
    if resp.status_code in (401, 403):
        return Verdict.deny((resp.reason or "") + " " + resp.text[:200])
    if resp.status_code == 404:
        return Verdict.deny("not found")
    return Verdict.deny(f"http {resp.status_code}")


# --------------------------------------------------------------------------- #
# S3 (SigV4)                                                                   #
# --------------------------------------------------------------------------- #

def measure_s3(url: str, path: str, op: str, *, principal=None) -> Verdict:
    from .s3sig import signed_headers
    host = url.split("://", 1)[1]
    method = {"read": "GET", "stat": "HEAD", "list": "GET"}.get(op, "GET")
    headers = {}
    if principal is not None and getattr(principal, "s3_key", ""):
        headers = signed_headers(method, path, principal.s3_key, principal.s3_secret, host=host)
    try:
        resp = requests.request(method, url + path, headers=headers, timeout=30)
    except requests.exceptions.RequestException as e:
        return Verdict.deny(f"request-failed: {e}")
    if resp.status_code == 200:
        return Verdict.allow()
    m = re.search(r"<Code>([^<]+)</Code>", resp.text or "")
    return Verdict.deny(m.group(1) if m else f"http {resp.status_code}")
