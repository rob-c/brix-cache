"""
test_zip_scratch.py — ZIP CONSUME via materialize-to-scratch (Pillar F #3).

ZIP serves a member by random-access pread (+ sendfile for stored members) over
the archive fd — which a storage backend with no kernel fd cannot provide. The
materialize-to-scratch seam copies the archive into a local POSIX scratch and
reads THAT. Exercised on a POSIX export via brix_zip_force_scratch +
brix_zip_stage_dir; the member must still serve byte-exact, and the server logs
that it staged the archive.  Throwaway nginx comes from the registry lifecycle
harness; reuses test_zip_member's raw-wire helpers.
"""

import os
import zipfile
from pathlib import Path

import pytest

from settings import NGINX_BIN, BIND_HOST
from server_registry import NginxInstanceSpec
from test_zip_member import _session, _open, _read, kXR_ok, STORED

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-zip-scratch")]


def _start(lifecycle, tmp_path, name, force_scratch):
    if not os.path.exists(NGINX_BIN):
        pytest.skip("nginx binary not built")
    stage = tmp_path / "stage"; stage.mkdir()

    zip_dirs = ""
    if force_scratch:
        zip_dirs = (f"brix_zip_stage_dir {stage}; "
                    "brix_zip_force_scratch on; ")
    endpoint = lifecycle.start(NginxInstanceSpec(
        name=name,
        template="nginx_zip_scratch.conf",
        template_values={"BIND_HOST": BIND_HOST, "ZIP_DIRECTIVES": zip_dirs},
        reason="ZIP materialize-to-scratch member serving"))
    with zipfile.ZipFile(Path(endpoint.data_root, "a.zip"), "w") as z:
        z.writestr("stored.txt", STORED, compress_type=zipfile.ZIP_STORED)

    class Ctx:
        pass
    ctx = Ctx()
    ctx.port = endpoint.port
    ctx.errlog = str(Path(endpoint.prefix, "logs", "err.log"))
    return ctx


def _read_member(port, member):
    s = _session(port)
    try:
        st, body = _open(s, f"/a.zip?xrdcl.unzip={member}")
        assert st == kXR_ok, f"open failed status={st}"
        st, data = _read(s, body[:4], 0, 65536)
        assert st == kXR_ok
        return data
    finally:
        s.close()


def test_zip_member_served_via_scratch(lifecycle, tmp_path):
    ctx = _start(lifecycle, tmp_path, "lc-zip-scratch", force_scratch=True)
    # served byte-exact even though the archive was read from a staged copy
    assert _read_member(ctx.port, "stored.txt") == STORED
    # proof the materialize-to-scratch path ran
    log = open(ctx.errlog).read()
    assert "archive staged to scratch" in log, \
        "force-scratch did not stage the zip archive"


def test_zip_member_in_place_when_not_forced(lifecycle, tmp_path):
    """Control: no force → the archive is read in place (no staging)."""
    ctx = _start(lifecycle, tmp_path, "lc-zip-inplace", force_scratch=False)
    assert _read_member(ctx.port, "stored.txt") == STORED
    log = open(ctx.errlog).read()
    assert "archive staged to scratch" not in log
