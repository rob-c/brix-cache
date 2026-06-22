"""test_e2e_redteam.py — full-stack privilege-escalation red-team for phase-40.

Boots the REAL nginx binary with `xrootd_impersonation map` inside an unprivileged
user namespace and drives it with token-authenticated WebDAV requests as many
identities, trying to break the permissions model (escalate to root/service/low
uid, join a forbidden group, impersonate an unmapped user, escape confinement,
leak credentials under concurrency).  Unlike the micro broker test, this exercises
the WHOLE production chain: real lifecycle (master spawns the broker), real svc-uid
workers connecting, real auth -> identity -> dispatch -> principal hook -> broker.

Skips cleanly when the prerequisites (userns, newuidmap, /etc/subuid, the nginx
binary, the `cryptography` package, a C compiler) are unavailable.
"""

import os
import shutil
import subprocess
import textwrap

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
NGINX = os.environ.get("TEST_NGINX_BIN", "/tmp/nginx-1.28.3/objs/nginx")
CC = os.environ.get("CC", "cc")

FAKE_PASSWD = textwrap.dedent("""\
    root:x:0:0:root:/:/sbin/nologin
    alice:x:1001:1001:alice:/home/alice:/sbin/nologin
    bob:x:1002:1002:bob:/home/bob:/sbin/nologin
    sys100:x:100:100:sys:/:/sbin/nologin
    svc:x:1500:1500:svc:/:/sbin/nologin
    dockerite:x:1007:1007:dockerite:/:/sbin/nologin
    nobody:x:65534:65534:nobody:/:/sbin/nologin
    carol:x:1003:1003:carol:/:/sbin/nologin
    dave:x:1004:1004:dave:/:/sbin/nologin
    erin:x:1005:1005:erin:/:/sbin/nologin
    frank:x:1006:1006:frank:/:/sbin/nologin
    manyu:x:1008:1008:manyu:/:/sbin/nologin
    floor1000:x:1000:1000:floor:/:/sbin/nologin
    lowu:x:999:999:low:/:/sbin/nologin
    badprim:x:1009:50:badprim:/:/sbin/nologin
""")

# Group memberships drive the broker's getgrouplist()/setgroups() path (the core
# supplementary-group DAC mechanism).  staff={alice,carol}, research={bob,dave},
# shared={alice,bob,carol} (3-way), proj={carol,dave,erin}; manyu is a member of 34
# extra groups (the getgrouplist>32 path); badprim's PRIMARY gid (50) is reserved.
FAKE_GROUP = textwrap.dedent("""\
    root:x:0:
    alice:x:1001:
    bob:x:1002:
    svc:x:1500:
    docker:x:1600:dockerite
    nogroup:x:65534:
    carol:x:1003:
    dave:x:1004:
    erin:x:1005:
    frank:x:1006:
    manyu:x:1008:
    floor1000:x:1000:
    lowu:x:999:
    staff:x:2001:alice,carol
    research:x:2002:bob,dave
    shared:x:2003:alice,bob,carol
    proj:x:2004:carol,dave,erin
""") + "".join(f"mg{i:02d}:x:{3000 + i}:manyu\n" for i in range(34))


def _have(cmd):
    return shutil.which(cmd) is not None


@pytest.mark.timeout(180)
def test_impersonation_redteam_e2e(tmp_path):
    if not os.path.isfile(NGINX):
        pytest.skip(f"nginx binary not at {NGINX} (set TEST_NGINX_BIN)")
    if not _have(CC):
        pytest.skip("no C compiler")
    if not (_have("newuidmap") and _have("newgidmap")):
        pytest.skip("newuidmap/newgidmap not installed (uidmap package)")
    try:
        import cryptography  # noqa: F401
    except ImportError:
        pytest.skip("python 'cryptography' package not available")
    # cheap userns pre-flight
    r = subprocess.run(["unshare", "-Ur", "true"], capture_output=True)
    if r.returncode != 0:
        pytest.skip("unprivileged user namespaces unavailable")

    launcher = str(tmp_path / "launcher")
    build = subprocess.run(
        [CC, "-O2", "-D_GNU_SOURCE", "-Wall", "-o", launcher,
         os.path.join(HERE, "c", "userns_exec_launcher.c")],
        capture_output=True, text=True)
    assert build.returncode == 0, f"launcher compile failed:\n{build.stderr}"

    pw = tmp_path / "passwd"
    gr = tmp_path / "group"
    pw.write_text(FAKE_PASSWD)
    gr.write_text(FAKE_GROUP)
    work = tmp_path / "work"
    work.mkdir()

    env = dict(os.environ, TEST_NGINX_BIN=NGINX)
    run = subprocess.run(
        [launcher, str(pw), str(gr),
         "python3", os.path.join(HERE, "e2e_redteam.py"), str(work)],
        capture_output=True, text=True, timeout=160, env=env)
    out = run.stdout + "\n" + run.stderr

    if "SKIP:" in run.stdout and "ALL PASSED" not in run.stdout:
        pytest.skip(f"red-team prerequisites unmet:\n{out}")

    assert run.returncode == 0, f"red-team E2E failed:\n{out}"
    assert "ALL PASSED" in run.stdout, out
    # the security-critical checks must actually have run
    assert "owned by the MAPPED user" in out
    assert "escalate to root" in out
    assert "no setfsuid leak" in out
