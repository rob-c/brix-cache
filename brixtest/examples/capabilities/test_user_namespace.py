"""Opt-in real user-namespace supplementary-group example."""

import os
import sys

import pytest

from brixtest import Placement, binary, case, identity, probe, server

pytestmark = pytest.mark.skipif(
    not (os.environ.get("BRIXTEST_SUBUID") and os.environ.get("BRIXTEST_SUBGID")),
    reason="set BRIXTEST_SUBUID and BRIXTEST_SUBGID to allocated subordinate IDs",
)

PYTHON = binary("userns_python", path=sys.executable)
RUNNER = identity(
    "mapped_root", uid=0, gid=0, groups=(7,), user_namespace=True,
    uid_map=((0, int(os.environ.get("BRIXTEST_SUBUID", "100000")), 2),),
    gid_map=(
        (0, int(os.environ.get("BRIXTEST_SUBGID", "100000")), 1),
        (7, int(os.environ.get("BRIXTEST_SUBGID", "100000")) + 7, 1),
    ),
)
IDENTITY = server(
    "identity_probe",
    command=(
        PYTHON, "-u", "-c",
        "import ctypes,os,pathlib,tempfile,time\n"
        "root=pathlib.Path(tempfile.mkdtemp());private=root/'private';shared=root/'shared'\n"
        "private.write_text('private');shared.write_text('group')\n"
        "os.chmod(private,0o600);os.chown(shared,-1,7);os.chmod(shared,0o040)\n"
        "libc=ctypes.CDLL(None,use_errno=True);assert libc.setfsuid(1)==0\n"
        "try: private.read_text();private_denied=False\n"
        "except PermissionError: private_denied=True\n"
        "group_read=shared.read_text();assert libc.setfsuid(0)==1\n"
        "print(os.geteuid(),os.getegid(),os.getgroups(),private_denied,group_read,flush=True)\n"
        "time.sleep(300)",
    ),
    placement=Placement(identity=RUNNER), probe=probe("none"),
)


@case(RUNNER, IDENTITY, PYTHON, keep="never")
def test_user_namespace_applies_uid_gid_and_supplementary_groups(run):
    assert run.server(IDENTITY).read_log().splitlines()[0] == "0 0 [7] True group"
