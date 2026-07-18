"""
test_frm_control_locality.py — MSS residency locality semantics.

Rewritten 2026-07-18 onto the live tape://exec backend that replaced the removed
control-dir xattr-stub residency model.  Residency is now driven by the exec MSS
adapter and reported through the real WLCG Tape REST surface (POST
/api/v1/archiveinfo), which maps the probe to {exists, onDisk, locality}:

  * object materialised in the online buffer  → exists, onDisk, ONLINE
  * object on tape only (`exists` verb == 0)   → exists, !onDisk, NEARLINE
  * object nowhere (`exists` verb != 0)        → exists=false, NONE

The load-bearing property is unchanged from the original test's intent: a
not-resident object is only reported present when it truly exists on the backend,
never a blanket "no marker ⇒ online".

Self-provisioned http WebDAV + tape://exec; skips cleanly without nginx.
"""

import json
import os
import urllib.error
import urllib.request

import pytest

from settings import NGINX_BIN, HOST, BIND_HOST, free_port
from server_registry import NginxInstanceSpec
from server_launcher import RegistryCommandFailure

pytestmark = pytest.mark.uses_lifecycle_harness


def _stagecmd(tape):
    """Minimal exec MSS adapter: $BRIX_FRM_STAGECMD <verb> <key> <online>.  Only
    the `exists` residency verb matters for archiveinfo (no recall is issued); the
    tape dir is baked in (nginx rewrites its environ, so a spawned command sees
    only argv + BRIX_FRM_STAGECMD)."""
    return (
        "#!/bin/bash\n"
        'verb="$1"; key="${2#/}"; online="$3"\n'
        f"tape='{tape}'\n"
        'case "$verb" in\n'
        '  exists)  [ -f "$tape/$key" ] && exit 0 || exit 1 ;;\n'
        '  recall)  mkdir -p "$(dirname "$online")"; cp "$tape/$key" "$online" ;;\n'
        '  migrate) cp "$online" "$tape/$key" ;;\n'
        '  purge)   rm -f "$online" ;;\n'
        "esac\n"
    )


def _post(http_port, path, obj, timeout=5):
    url = "http://%s:%d%s" % (HOST, http_port, path)
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as e:
        return None, str(e).encode()


@pytest.fixture
def srv(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not found")
    d = tmp_path

    base = d / "base"; base.mkdir()
    online = base / ".online"; online.mkdir()
    tape = d / "tape"; tape.mkdir()
    export = d / "export"; export.mkdir()
    cache = d / "cache"; cache.mkdir()

    # ONLINE: materialised in the online buffer <base>/.online/<key>.
    (online / "online.dat").write_bytes(b"resident\n")
    # NEARLINE: on tape only (the `exists` verb finds it), not in the online buffer.
    (tape / "near.dat").write_bytes(b"nearline bytes\n")
    # /gone.dat: nowhere — not in the online buffer, not on tape → ABSENT/NONE.

    stagecmd = d / "stage.sh"
    stagecmd.write_text(_stagecmd(str(tape)))
    stagecmd.chmod(0o755)

    spec = NginxInstanceSpec(
        name="lc-frm-control-locality",
        template="nginx_lc_frm_control_locality.conf",
        protocol="http",
        template_values={"BIND_HOST": BIND_HOST,
                         "BASE_DIR": str(base),
                         "EXPORT_DIR": str(export),
                         "CACHE_DIR": str(cache)},
        env={"BRIX_FRM_STAGECMD": str(stagecmd)},
        reason="frm control-locality")
    try:
        ep = lifecycle.start(spec)
    except RegistryCommandFailure:
        pytest.skip("nginx build lacks the brix_frm* directive surface "
                    "(removed 2026-06-30)")

    class S:
        pass
    s = S()
    s.http_port = ep.port
    yield s


def _locality(srv, paths):
    st, body = _post(srv.http_port, "/api/v1/archiveinfo", {"paths": paths})
    assert st == 200, "archiveinfo status %r: %s" % (st, body[:200])
    j = json.loads(body.decode())
    assert "files" in j, "no files in archiveinfo: %r" % body[:200]
    return {f["path"]: f for f in j["files"]}


def test_control_dir_resident_is_online(srv):
    f = _locality(srv, ["/online.dat"])["/online.dat"]
    assert f.get("exists") is True, f
    assert f.get("onDisk") is True, f
    assert f["locality"] in ("ONLINE", "ONLINE_AND_NEARLINE"), f


def test_control_dir_stub_is_nearline(srv):
    f = _locality(srv, ["/near.dat"])["/near.dat"]
    assert f.get("exists") is True, f
    assert f.get("onDisk") is False, f
    assert f["locality"] == "NEARLINE", f


def test_control_dir_missing_object_is_lost_not_online(srv):
    """The fix: a missing object with no control stub is LOST (exists=false),
    NOT falsely reported ONLINE just because the control stub is absent."""
    f = _locality(srv, ["/gone.dat"])["/gone.dat"]
    assert f.get("exists") is False, f
    assert f.get("locality") == "NONE", f
    assert f.get("onDisk") in (False, None), f
