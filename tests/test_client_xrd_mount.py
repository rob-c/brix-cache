"""
`xrd mount` / `xrd unmount` — FUSE3 driver + fusermount front-end verbs.

WHAT: `xrd mount [--legacy] <endpoint> <mountpoint> [fuse-opts]` execs the single
      FUSE driver `xrootdfs` (forwarding `--legacy` to it as a flag), in the
      driver's native arg order and resolving a ~/.xrdrc alias for the endpoint.
      `xrd unmount [-z] <mountpoint>` runs fusermount3, then fusermount, then umount.
WHY:  one front-end verb for the whole mount lifecycle (the drivers + fusermount
      are separate tools today).
HOW:  hermetic — no real mount. Copy `xrd` into a sandbox with FAKE sibling drivers
      that echo their argv (exec_tool finds siblings first), and drive `xrd unmount`
      with a FAKE fusermount3/umount on $PATH. Asserts on the forwarded argv.

Run:
    PYTHONPATH=tests pytest tests/test_client_xrd_mount.py -p no:xdist -v
"""
import os
import shutil
import subprocess

import pytest

from cmdscripts import fake_exec

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRD = os.path.join(CLIENT_DIR, "bin", "xrd")


@pytest.fixture(scope="module")
def built():
    r = subprocess.run(["make", "-C", CLIENT_DIR, "xrd"],
                       capture_output=True, text=True, timeout=180)
    if r.returncode != 0 or not os.path.exists(XRD):
        pytest.skip(f"xrd build failed:\n{r.stdout}\n{r.stderr}")
    return XRD


def _sandbox(tmp_path):
    """Copy xrd into an isolated dir alongside fake FUSE drivers (so exec_tool's
    sibling search finds the fakes, not the real built drivers)."""
    d = tmp_path / "bin"
    d.mkdir()
    shutil.copy(XRD, d / "xrd")
    (d / "xrd").chmod(0o755)
    # one unified driver; --legacy is a runtime flag. The fake echoes its
    # identity + each argv element to stdout so the test asserts the forwarded argv.
    fake_exec.install(d, "xrootdfs", echo_tool_argv=True)
    return d


def test_mount_no_args(built, tmp_path):
    # `xrd mount` with no positional args lists current XRootD mounts (mirrors
    # mount(8)); with an empty mountinfo that is a clean, empty success.
    mi = tmp_path / "empty"
    mi.write_text("")
    env = dict(os.environ, XRD_MOUNTINFO_PATH=str(mi))
    r = subprocess.run([built, "mount"], capture_output=True, text=True,
                       env=env, timeout=10)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == ""


def test_mount_bad_driver(built):
    r = subprocess.run([built, "mount", "--driver", "bogus", "ep", "mp"],
                       capture_output=True, text=True, timeout=10)
    assert r.returncode == 50
    assert "unknown driver" in r.stderr


def test_mount_forwards_to_aio(built, tmp_path):
    d = _sandbox(tmp_path)
    r = subprocess.run([str(d / "xrd"), "mount", "root://h//data", "/mnt/x", "-o", "ro"],
                       capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert "TOOL=xrootdfs\n" in r.stdout
    out = r.stdout
    assert "ARG=root://h//data" in out and "ARG=/mnt/x" in out
    assert "ARG=-o" in out and "ARG=ro" in out


def test_mount_legacy_selects_xrootdfs(built, tmp_path):
    # One unified binary: --legacy execs `xrootdfs` and is forwarded to it as a flag.
    d = _sandbox(tmp_path)
    r = subprocess.run([str(d / "xrd"), "mount", "--legacy", "root://h//", "/mnt/x"],
                       capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, r.stderr
    assert "TOOL=xrootdfs\n" in r.stdout
    assert "ARG=--legacy" in r.stdout


def test_mount_resolves_endpoint_alias(built, tmp_path):
    d = _sandbox(tmp_path)
    rc = tmp_path / "xrdrc"
    rc.write_text("[alias lab]\nurl = root://myhost:1094//\n")
    env = dict(os.environ, XRDRC=str(rc))
    r = subprocess.run([str(d / "xrd"), "mount", "lab:/data", "/mnt/x"],
                       capture_output=True, text=True, timeout=10, env=env)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    # the alias must be expanded before reaching the driver
    assert "ARG=root://myhost" in r.stdout, r.stdout
    assert "ARG=lab:/data" not in r.stdout


def test_unmount_no_args(built):
    r = subprocess.run([built, "unmount"], capture_output=True, text=True, timeout=10)
    assert r.returncode == 50


def test_unmount_prefers_fusermount3(built, tmp_path):
    binp = tmp_path / "pbin"
    binp.mkdir()
    log = tmp_path / "fm3.log"
    fake_exec.install(binp, "fusermount3", log_args=str(log))
    env = dict(os.environ, PATH=f"{binp}:{os.environ['PATH']}")
    r = subprocess.run([built, "unmount", "-z", "/mnt/x"],
                       capture_output=True, text=True, timeout=10, env=env)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert log.read_text().strip() == "-u -z /mnt/x"


def test_unmount_falls_back_to_umount(built, tmp_path):
    # PATH with ONLY a fake umount: fusermount3/fusermount aren't found, so the
    # fallback chain reaches umount.
    binp = tmp_path / "obin"
    binp.mkdir()
    log = tmp_path / "um.log"
    fake_exec.install(binp, "umount", log_args=str(log))
    env = dict(os.environ, PATH=str(binp))
    r = subprocess.run([built, "unmount", "/mnt/x"],
                       capture_output=True, text=True, timeout=10, env=env)
    assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
    assert log.read_text().strip() == "/mnt/x"
