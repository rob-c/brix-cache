"""No-root verification of upload staging temp-file modes (stage-private / publish-intended).

A staged upload is written to a temp file that is later atomically renamed onto the namespace
object. Because rename preserves the temp's mode, the temp mode IS the final served mode — so a
naive "make the temp 0600" would ship every object 0600 and break VO-shared impersonated reads.
The fix keeps the temp PRIVATE (0600) during the write (a peer mapped uid cannot read an
in-progress upload) and restores the client-intended mode (0644) at commit.

This test drives a real WebDAV write server (impersonation off) over GSI and stats the on-disk
artifacts:
  * a completed PUT commits at 0644 (publish-intended — NOT over-tightened to 0600);
  * an in-flight resumable-PUT partial is 0600 (stage-private) while incomplete, then the
    completed object is 0644.

Run: PYTHONPATH=tests pytest tests/test_mu_stage_modes.py -v   (no root needed)
"""
import os
import socket
import stat
import subprocess
import time

import pytest
import requests

from mu_authz_lib import creds, fleet, ports, principals

_PORT = ports.MU.WEBDAV_STAGE
_URL = f"https://{ports.MU.HOST}:{_PORT}"


def _port_open(p):
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect((ports.MU.HOST, p))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.fixture(scope="module")
def stage_env():
    principals.build_cast()
    os.makedirs(os.path.join(ports.MU.DATA_ROOT, "stage"), exist_ok=True)
    for dd in (ports.MU.CONFIG_DIR, ports.MU.LOG_DIR, os.path.join(ports.MU.LOG_DIR, "nginx_tmp")):
        os.makedirs(dd, exist_ok=True)
    subst = fleet._base_subst()
    src = os.path.join(fleet._CFG_SRC, "webdav_stage_noimp.conf")
    text = open(src).read()
    for k, v in subst.items():
        text = text.replace(k, v)
    dst = os.path.join(ports.MU.CONFIG_DIR, "webdav_stage_noimp.conf")
    with open(dst, "w") as f:
        f.write(text)
    pidf = os.path.join(ports.MU.MU_ROOT, "webdav_stage.pid")
    subprocess.run([fleet.NGINX, "-c", dst, "-g", f"pid {pidf};"], check=True, capture_output=True)
    deadline = time.time() + 15
    while time.time() < deadline and not _port_open(_PORT):
        time.sleep(0.2)
    if not _port_open(_PORT):
        raise TimeoutError(f"webdav stage server never listened on {_PORT}")
    try:
        yield _URL
    finally:
        try:
            os.kill(int(open(pidf).read().strip()), 15)
        except (ProcessLookupError, ValueError, FileNotFoundError):
            pass


@pytest.fixture(scope="module")
def alice_proxy():
    cert = os.path.join(ports.MU.PKI_DIR, "user", "alice_usercert.pem")
    key = os.path.join(ports.MU.PKI_DIR, "user", "alice_userkey.pem")
    return creds.gen_gsi_proxy(cert, key, "stage_alice")


def test_completed_put_commits_at_client_mode(stage_env, alice_proxy):
    """A completed PUT publishes the object at its client-intended 0644 — the temp's private
    0600 must NOT leak onto the committed namespace file (that would break VO-shared reads)."""
    url = stage_env
    dest = os.path.join(ports.MU.DATA_ROOT, "stage", "committed.bin")
    if os.path.exists(dest):
        os.remove(dest)
    r = requests.put(url + "/stage/committed.bin", data=b"C" * 4096,
                     cert=alice_proxy, verify=False, timeout=30)
    assert r.status_code in (200, 201, 204), f"PUT failed: {r.status_code} {r.text[:200]}"
    assert os.path.exists(dest), "committed object missing on disk"
    assert _mode(dest) == 0o644, (
        f"committed object mode {oct(_mode(dest))} != 0o644 — the private staging mode leaked "
        f"onto the served file (would break impersonated cross-user reads)")


def test_inflight_resume_partial_is_private_then_publishes(stage_env, alice_proxy):
    """An in-flight resumable-PUT partial is 0600 (a peer mapped uid cannot read the in-progress
    upload); once completed the object is published at 0644."""
    url = stage_env
    final = os.path.join(ports.MU.DATA_ROOT, "stage", "resumable.bin")
    if os.path.exists(final):
        os.remove(final)
    payload = b"R" * 4096

    # First chunk: bytes 0-2047/4096 — incomplete, so the server holds a persistent partial.
    r1 = requests.put(url + "/stage/resumable.bin", data=payload[:2048],
                      headers={"Content-Range": "bytes 0-2047/4096"},
                      cert=alice_proxy, verify=False, timeout=30)
    assert r1.status_code in (200, 201, 202, 204, 308), \
        f"partial PUT failed: {r1.status_code} {r1.text[:200]}"
    assert not os.path.exists(final), "object committed before the upload completed"

    # The partial lives under the export (identity-keyed). Find it and assert it is private.
    partials = []
    for root, _dirs, files in os.walk(ports.MU.DATA_ROOT):
        for fn in files:
            fp = os.path.join(root, fn)
            if os.path.samefile(root, os.path.dirname(final)) and fn == "resumable.bin":
                continue
            if os.path.getsize(fp) > 0 and fp != final:
                partials.append(fp)
    # the freshly written partial is the one holding our 2048 in-flight bytes
    inflight = [p for p in partials if os.path.getsize(p) == 2048]
    assert inflight, f"could not locate the in-flight resume partial (saw {partials})"
    for p in inflight:
        assert _mode(p) == 0o600, (
            f"in-flight resume partial {p} mode {oct(_mode(p))} != 0o600 — a peer mapped uid "
            f"could read the in-progress upload")

    # Second chunk completes the upload → atomic commit at the client-intended mode.
    r2 = requests.put(url + "/stage/resumable.bin", data=payload[2048:],
                      headers={"Content-Range": "bytes 2048-4095/4096"},
                      cert=alice_proxy, verify=False, timeout=30)
    assert r2.status_code in (200, 201, 204), \
        f"completing PUT failed: {r2.status_code} {r2.text[:200]}"
    assert os.path.exists(final), "object not committed after completion"
    assert _mode(final) == 0o644, (
        f"completed resumable object mode {oct(_mode(final))} != 0o644 (publish-intended failed)")
