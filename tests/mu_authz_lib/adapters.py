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

# NOTE the lstrip: a root:// URL spells its path with EXACTLY two slashes after
# the authority, and every caller here passes an already-rooted "/cms/x".  Gluing
# "//" onto that made "root://h:p///cms/x", whose logical path is "//cms/x" — a
# different string from "/cms/x" to everything that prefix-matches rather than
# resolves.  The bytes still arrived (the backing path resolves the same), but no
# `u <id> /cms rl` grant and no `brix_require_vo /cms cms` rule applied, so every
# principal was refused by default-deny and the whole differential oracle agreed
# DENY==DENY for a reason that had nothing to do with authorization.
_ROOT_PROBE = r'''
import json, sys
from XRootD import client
from XRootD.client.flags import OpenFlags
url, path, op = sys.argv[1], sys.argv[2], sys.argv[3]
if op == "stat":
    st, _ = client.FileSystem(url).stat(path)
else:
    f = client.File()
    st, _ = f.open(url + "//" + path.lstrip("/"), OpenFlags.READ)
    if st.ok:
        if op == "read":
            st, _ = f.read(0, 4096)
        f.close()
print(json.dumps({"ok": bool(st.ok), "errno": int(st.errno), "message": st.message or ""}))
'''


# XrdCl's defaults make an unreachable endpoint indistinguishable from a slow one:
# ConnectionWindow is 120 s and ConnectionRetry 5, so a connect to a port with
# nothing on it is RETRIED rather than reported, and the probe blocks far past any
# per-test budget.  Every MU measurement then dies as the enclosing pytest-timeout
# — a stack in selectors.poll() that names the harness, not the endpoint — and the
# real fault (a server that did not start, a port the fleet never assigned) is
# invisible.  Bounding the window below the probe's own subprocess timeout, which
# is in turn below the test timeout, makes the innermost layer the one that
# reports: a dead endpoint comes back as a DENY whose reason is the connect error.
# Same knobs, same reason, as test_official_vs_brix_cache_faults.py's fault lane.
_XRD_BUDGET = {
    "XRD_CONNECTIONWINDOW": "5",
    "XRD_CONNECTIONRETRY":  "1",
    "XRD_REQUESTTIMEOUT":   "15",
    "XRD_STREAMTIMEOUT":    "15",
    "XRD_TIMEOUTRESOLUTION": "1",
}


def _root_env(principal) -> dict:
    env = os.environ.copy()
    env.update(_XRD_BUDGET)
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
        # WLCG bearer-token discovery: BEARER_TOKEN_FILE is what the XrdCl ztn
        # plugin reads (matching tests/_test_native_xrdcp_xrdfs_helpers.py). Do NOT
        # force XrdSecPROTOCOL=ztn — forcing it to the sole protocol makes a
        # construction failure fatal ("no protocols left to try"); left unset the
        # client auto-negotiates ztn when the token file is present.
        tok = principal.token
        env["BEARER_TOKEN_FILE"] = tok
        try:
            env["BEARER_TOKEN"] = open(tok).read().strip()
        except OSError:
            pass
    return env


def measure_root(url: str, path: str, op: str, *, principal=None) -> Verdict:
    try:
        r = subprocess.run([sys.executable, "-c", _ROOT_PROBE, url, path, op],
                           env=_root_env(principal), capture_output=True, text=True,
                           timeout=20)
    except subprocess.TimeoutExpired:
        # Deliberately a Verdict, not a raise: the oracle compares verdicts, and a
        # measurement that never finished is a DENY that names itself.  Raising here
        # would surface as a test ERROR with the harness in the traceback and the
        # endpoint nowhere in it.  20 s sits under the 30 s pytest budget and over
        # the XRD window above, so this only fires when the SERVER wedged, not when
        # the connect failed.
        return Verdict.deny(f"probe-timeout: {url} {op} {path}")
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
    kw = _webdav_options(principal)
    method = {"read": "GET", "stat": "HEAD", "list": "PROPFIND"}.get(op, "GET")
    try:
        resp = requests.request(method, url + path, **kw)
    except requests.exceptions.RequestException as e:
        return Verdict.deny(f"request-failed: {e}")
    return _webdav_verdict(resp)


def _webdav_options(principal):
    options: dict = {"timeout": 30, "verify": os.path.join(ports.MU.CA_DIR, "ca.pem")}
    if principal is not None and getattr(principal, "token", ""):
        options["headers"] = {"Authorization": "Bearer " + open(principal.token).read().strip()}
        options["verify"] = False
    elif principal is not None and getattr(principal, "proxy", ""):
        options["cert"] = principal.proxy
        options["verify"] = False
    return options


def _webdav_verdict(response):
    if response.status_code in (200, 206, 207):
        return Verdict.allow()
    if response.status_code in (401, 403):
        return Verdict.deny((response.reason or "") + " " + response.text[:200])
    if response.status_code == 404:
        return Verdict.deny("not found")
    return Verdict.deny(f"http {response.status_code}")


# --------------------------------------------------------------------------- #
# S3 (SigV4)                                                                   #
# --------------------------------------------------------------------------- #

def measure_s3(url: str, path: str, op: str, *, principal=None) -> Verdict:
    from .s3sig import signed_headers
    host = url.split("://", 1)[1]
    method = {"read": "GET", "stat": "HEAD", "list": "GET"}.get(op, "GET")
    headers = _s3_headers(signed_headers, method, path, principal, host)
    try:
        resp = requests.request(method, url + path, headers=headers, timeout=30)
    except requests.exceptions.RequestException as e:
        return Verdict.deny(f"request-failed: {e}")
    return _s3_verdict(resp)


def _s3_headers(signer, method, path, principal, host):
    """Authenticate one S3 request AS `principal` — bearer first, SigV4 second.

    The order is the whole measurement.  `brix_s3` carries a SINGLE
    access-key/secret pair (src/protocols/s3/module.c), so a per-principal SigV4
    identity is not expressible: signing with each principal's own key made
    everyone but the service account fail at the SIGNATURE, which is an
    authentication verdict where root:// reaches an authorization one, and the
    parity cells recorded a tier mismatch that no configuration could close.

    `brix_s3_token on` is how this plane does express per-principal identity: the
    verified token's `sub` lands in the same identity field the authdb is keyed
    on (brix_identity_set_token_claims), so S3 answers root://'s question off
    root://'s record.  SigV4 stays as the fallback for a principal holding only
    an S3 key — the service account, and the signature-negative cells."""
    if principal is None:
        return {}
    token = getattr(principal, "token", "")
    if token:
        with open(token) as fh:
            return {"Authorization": "Bearer " + fh.read().strip()}
    if not getattr(principal, "s3_key", ""):
        return {}
    return signer(method, path, principal.s3_key, principal.s3_secret, host=host)


def _s3_verdict(response):
    if response.status_code == 200:
        return Verdict.allow()
    match = re.search(r"<Code>([^<]+)</Code>", response.text or "")
    if match:
        return Verdict.deny(match.group(1))
    return Verdict.deny(f"http {response.status_code}")
