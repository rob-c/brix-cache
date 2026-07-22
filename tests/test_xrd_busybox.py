"""
Phase-41 BusyBox-style POSIX verbs on the unified `xrd` front-end:

    xrd head [-c BYTES] [-n LINES] <url>      first bytes/lines
    xrd tail [-n LINES] [-f] <url>            last lines / follow
    xrd df [-h] <url>                         friendly disk-space report (Qspace)
    xrd touch [-c] <url>                       create-if-absent + set times (NO chown)
    xrd ln [-s] <target> <url>                 hard / symbolic link
    xrd readlink <url>                         print a symlink target
    xrd chmod [-R] <url> <octal>               octal chmod (+ recursive)
    xrd mount | xrd mounts                     list active XRootD FUSE mounts

Self-hosts a writable root:// server (the module advertises `xrdfs.ext`
unconditionally, so the link/setattr verbs work end-to-end). The mount-listing
tests need no server — they drive the /proc/self/mountinfo parser via the
XRD_MOUNTINFO_PATH override.

Run:
    TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests pytest tests/test_xrd_busybox.py -v -p no:xdist
"""

import json
import os
import shutil
import signal
import socket
import subprocess
import time

import pytest

from settings import HOST, BIND_HOST, NGINX_BIN
from server_registry import NginxInstanceSpec

pytestmark = [pytest.mark.timeout(120), pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-xrd-busybox")]

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
XRD = os.path.join(CLIENT_DIR, "bin", "xrd")


def _port_up(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def _client_built():
    if shutil.which("cc") is None and shutil.which("gcc") is None:
        pytest.skip("no C compiler")
    subprocess.run(["make", "-C", CLIENT_DIR, "xrd", "xrdfs", "xrdcp"],
                   capture_output=True, text=True, timeout=240)
    for b in ("xrd", "xrdfs"):
        if not os.path.exists(os.path.join(CLIENT_DIR, "bin", b)):
            pytest.skip(f"{b} build failed")


@pytest.fixture()
def rw(lifecycle, _client_built, tmp_path):
    if not os.access(NGINX_BIN, os.X_OK):
        pytest.skip(f"nginx not executable: {NGINX_BIN}")

    data = tmp_path / "data"
    data.mkdir()
    (data / "lines.txt").write_text("".join(f"line{i}\n" for i in range(1, 21)))
    (data / "small.txt").write_text("abcdefghij")
    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-xrd-busybox",
        template="nginx_lc_stream_posix_anon.conf",
        protocol="root",
        template_values={"BIND_HOST": BIND_HOST, "DATA_DIR": str(data)},
        reason="BusyBox-style POSIX verbs against a writable anon root server"))
    return {"port": ep.port, "data": data}


def _url(rw, path=""):
    return f"root://{HOST}:{rw['port']}/{path}"


def _run(*args, **kw):
    return subprocess.run([XRD, *args], capture_output=True, text=True,
                          timeout=kw.pop("timeout", 30), **kw)


# ----------------------------- head -----------------------------------------

def test_head_lines(rw):
    p = _run("head", "-n", "3", _url(rw, "/lines.txt"))
    assert p.returncode == 0, p.stderr
    assert p.stdout == "line1\nline2\nline3\n", repr(p.stdout)


def test_head_bytes_and_overflow(rw):
    p = _run("head", "-c", "5", _url(rw, "/small.txt"))
    assert p.returncode == 0 and p.stdout == "abcde", repr(p.stdout)
    # -c past EOF yields the whole file, no error
    p2 = _run("head", "-c", "9999", _url(rw, "/small.txt"))
    assert p2.returncode == 0 and p2.stdout == "abcdefghij", repr(p2.stdout)


def test_head_missing_path_errors(rw):
    p = _run("head", _url(rw, "/nope_missing.txt"))
    assert p.returncode != 0
    assert "head" in p.stderr.lower()


# ----------------------------- tail -----------------------------------------

def test_tail_lines(rw):
    p = _run("tail", "-n", "2", _url(rw, "/lines.txt"))
    assert p.returncode == 0, p.stderr
    assert p.stdout == "line19\nline20\n", repr(p.stdout)


def test_tail_follow_sees_append_then_sigint(rw):
    target = rw["data"] / "grow.txt"
    target.write_text("a\n")
    proc = subprocess.Popen([XRD, "tail", "-f", "--interval", "0.2",
                             _url(rw, "/grow.txt")],
                            stdout=subprocess.PIPE, text=True)
    try:
        time.sleep(0.4)
        with open(target, "a") as fh:
            fh.write("b\n")
        time.sleep(0.6)
        proc.send_signal(signal.SIGINT)
        out, _ = proc.communicate(timeout=10)
    finally:
        if proc.poll() is None:
            proc.kill()
    assert "a" in out and "b" in out, repr(out)


def test_tail_empty_file(rw):
    (rw["data"] / "empty.txt").write_text("")
    p = _run("tail", "-n", "5", _url(rw, "/empty.txt"))
    assert p.returncode == 0 and p.stdout == "", repr(p.stdout)


# ------------------------------ df ------------------------------------------

def test_df_columns(rw):
    p = _run("df", _url(rw, "/"))
    assert p.returncode == 0, p.stderr
    assert "Size" in p.stdout and "Avail" in p.stdout and "Use%" in p.stdout
    # second (data) row should carry digits
    rows = [r for r in p.stdout.splitlines() if r and "Size" not in r]
    assert rows and any(ch.isdigit() for ch in rows[0]), p.stdout


def test_df_human(rw):
    p = _run("df", "-h", _url(rw, "/"))
    assert p.returncode == 0, p.stderr
    data_row = [r for r in p.stdout.splitlines() if "Size" not in r][0]
    # human units present (one of B/K/M/G/T)
    assert any(u in data_row for u in ("K", "M", "G", "T")), data_row


def test_df_bad_endpoint_errors():
    p = _run("df", "root://nonexistent.invalid:1094//")
    assert p.returncode != 0


# ----------------------------- touch ----------------------------------------

def test_touch_creates_empty(rw):
    p = _run("touch", _url(rw, "/touched.txt"))
    assert p.returncode == 0, p.stderr
    assert (rw["data"] / "touched.txt").exists()
    assert (rw["data"] / "touched.txt").stat().st_size == 0


def test_touch_updates_mtime(rw):
    f = rw["data"] / "ts.txt"
    f.write_text("x")
    os.utime(f, (1_000_000, 1_000_000))
    p = _run("touch", _url(rw, "/ts.txt"))
    assert p.returncode == 0, p.stderr
    assert f.stat().st_mtime > 1_000_000


def test_touch_c_absent_is_noop(rw):
    p = _run("touch", "-c", _url(rw, "/never_created.txt"))
    assert p.returncode == 0, p.stderr
    assert not (rw["data"] / "never_created.txt").exists()


# --------------------------- ln / readlink ----------------------------------

def test_symlink_and_readlink(rw):
    p = _run("ln", "-s", "/lines.txt", _url(rw, "/sym1"))
    assert p.returncode == 0, p.stderr
    link = rw["data"] / "sym1"
    assert link.is_symlink() and os.readlink(link) == "/lines.txt"
    r = _run("readlink", _url(rw, "/sym1"))
    assert r.returncode == 0 and r.stdout.strip() == "/lines.txt", r.stdout


def test_hardlink_shares_content(rw):
    (rw["data"] / "hsrc.txt").write_text("hard\n")
    p = _run("ln", _url(rw, "/hsrc.txt"), _url(rw, "/hdst.txt"))
    assert p.returncode == 0, p.stderr
    assert (rw["data"] / "hdst.txt").read_text() == "hard\n"
    assert (rw["data"] / "hdst.txt").stat().st_ino == (rw["data"] / "hsrc.txt").stat().st_ino


def test_readlink_on_nonsymlink_errors(rw):
    p = _run("readlink", _url(rw, "/small.txt"))
    assert p.returncode != 0


def test_rm_symlink_removes_link_not_target(rw):
    """Regression: rm of a symlink unlinks the link itself (POSIX/lstat semantics),
    leaving the target intact. Earlier the server followed the link's stored absolute
    target into RESOLVE_BENEATH and returned NotFound, so the link was un-removable."""
    (rw["data"] / "rmtgt.bin").write_text("keep-me\n")
    assert _run("ln", "-s", "/rmtgt.bin", _url(rw, "/rmlnk")).returncode == 0
    link = rw["data"] / "rmlnk"
    assert link.is_symlink()
    r = _run("rm", _url(rw, "/rmlnk"))
    assert r.returncode == 0, r.stderr
    assert not os.path.lexists(str(link))                       # the link itself is gone
    assert (rw["data"] / "rmtgt.bin").read_text() == "keep-me\n"  # target untouched
    # a dangling symlink is removable too
    assert _run("ln", "-s", "/no_such_target.bin", _url(rw, "/rmdead")).returncode == 0
    assert _run("rm", _url(rw, "/rmdead")).returncode == 0
    assert not os.path.lexists(str(rw["data"] / "rmdead"))


# ----------------------------- chmod -R -------------------------------------

def test_chmod_octal_and_recursive(rw):
    d = rw["data"] / "tree"
    d.mkdir()
    (d / "a.txt").write_text("a")
    p = _run("chmod", "-R", _url(rw, "/tree"), "700")
    assert p.returncode == 0, p.stderr
    assert (d / "a.txt").stat().st_mode & 0o777 == 0o700
    assert d.stat().st_mode & 0o777 == 0o700


# --------------------------- mount listing (no server) ----------------------

_MOUNTINFO = (
    "36 35 98:0 / /mnt/data rw,noatime master:1 - fuse.xrootdfs "
    "root://store//data rw,user_id=1000\n"
    "40 35 0:50 / /mnt/legacy\\040space rw - fuse.xrootdfs_legacy root://lab:1095//home rw\n"
    "50 35 0:51 / /mnt/ext rw - ext4 /dev/sdb1 rw\n"
)


def test_mount_list_parses_fixture(tmp_path):
    if not os.path.exists(XRD):
        pytest.skip("xrd not built")
    mi = tmp_path / "mountinfo"
    mi.write_text(_MOUNTINFO)
    env = dict(os.environ, XRD_MOUNTINFO_PATH=str(mi))
    p = subprocess.run([XRD, "mount"], capture_output=True, text=True,
                       env=env, timeout=10)
    assert p.returncode == 0, p.stderr
    assert "root://store//data" in p.stdout and "/mnt/data" in p.stdout and "aio" in p.stdout
    # octal-escaped space decoded; ext4 row filtered out
    assert "/mnt/legacy space" in p.stdout
    assert "ext4" not in p.stdout and "/dev/sdb1" not in p.stdout


def test_mount_list_empty(tmp_path):
    if not os.path.exists(XRD):
        pytest.skip("xrd not built")
    mi = tmp_path / "empty"
    mi.write_text("")
    env = dict(os.environ, XRD_MOUNTINFO_PATH=str(mi))
    p = subprocess.run([XRD, "mounts"], capture_output=True, text=True,
                       env=env, timeout=10)
    assert p.returncode == 0
    assert p.stdout.strip() == ""


def test_mount_list_malformed_lines_ignored(tmp_path):
    if not os.path.exists(XRD):
        pytest.skip("xrd not built")
    mi = tmp_path / "bad"
    mi.write_text("garbage\n1 2 3 -\n36 35 98:0 / /mnt/x rw - fuse.xrootdfs root://h//d rw\n")
    env = dict(os.environ, XRD_MOUNTINFO_PATH=str(mi))
    p = subprocess.run([XRD, "mount"], capture_output=True, text=True,
                       env=env, timeout=10)
    assert p.returncode == 0, p.stderr
    assert "/mnt/x" in p.stdout


# ============================ Tier 1: cksum / wc / cmp / xattr ===============

def test_cksum(rw):
    p = _run("cksum", "-a", "adler32", _url(rw, "/small.txt"))
    assert p.returncode == 0, p.stderr
    parts = p.stdout.split()
    assert parts[0] == "adler32" and len(parts[1]) >= 8 and parts[2] == "/small.txt"


def test_cksum_bad_path(rw):
    p = _run("cksum", _url(rw, "/no_such_cksum.txt"))
    assert p.returncode != 0


def test_wc_all_counts(rw):
    # lines.txt = 20 lines "lineN\n", each one word
    p = _run("wc", _url(rw, "/lines.txt"))
    assert p.returncode == 0, p.stderr
    nums = [int(x) for x in p.stdout.split()[:3]]
    assert nums == [20, 20, len("".join(f"line{i}\n" for i in range(1, 21)))], p.stdout


def test_wc_bytes_only_matches_stat(rw):
    p = _run("wc", "-c", _url(rw, "/small.txt"))
    assert p.returncode == 0 and p.stdout.split()[0] == "10", p.stdout


def test_cmp_identical_is_quiet(rw):
    (rw["data"] / "c1.txt").write_text("same-bytes\n")
    (rw["data"] / "c2.txt").write_text("same-bytes\n")
    p = _run("cmp", _url(rw, "/c1.txt"), _url(rw, "/c2.txt"))
    assert p.returncode == 0 and p.stdout.strip() == "", repr(p.stdout)


def test_cmp_differ(rw):
    (rw["data"] / "d1.txt").write_text("alpha\n")
    (rw["data"] / "d2.txt").write_text("beta\n")
    p = _run("cmp", _url(rw, "/d1.txt"), _url(rw, "/d2.txt"))
    assert p.returncode == 1
    assert "differ" in p.stdout, p.stdout


def test_xattr_set_get_ls_rm_roundtrip(rw):
    u = _url(rw, "/small.txt")
    assert _run("xattr", "set", u, "user.color", "blue").returncode == 0
    assert _run("xattr", "set", u, "project", "alpha").returncode == 0
    g = _run("xattr", "get", u, "user.color")
    assert g.returncode == 0 and g.stdout.strip() == "blue", g.stdout
    ls = _run("xattr", "ls", u)
    assert ls.returncode == 0
    names = set(ls.stdout.split())
    assert {"user.color", "project"} <= names, ls.stdout
    # every listed name must be directly gettable (ls/get consistency)
    for n in names:
        assert _run("xattr", "get", u, n).returncode == 0, n
    assert _run("xattr", "rm", u, "user.color").returncode == 0
    assert _run("xattr", "rm", u, "project").returncode == 0


def test_xattr_get_missing_errors(rw):
    p = _run("xattr", "get", _url(rw, "/small.txt"), "user.nope_absent")
    assert p.returncode != 0


# ============================ Tier 2: grep / hexdump =========================

def test_grep_matches_with_lineno(rw):
    (rw["data"] / "g.txt").write_text("apple\nbanana\nApple pie\n")
    p = _run("grep", "-n", "apple", _url(rw, "/g.txt"))
    assert p.returncode == 0
    assert p.stdout == "1:apple\n", repr(p.stdout)


def test_grep_icase_and_no_match(rw):
    (rw["data"] / "g2.txt").write_text("apple\nApple\n")
    p = _run("grep", "-i", "apple", _url(rw, "/g2.txt"))
    assert p.returncode == 0 and p.stdout.count("\n") == 2, p.stdout
    miss = _run("grep", "zzz_absent", _url(rw, "/g2.txt"))
    assert miss.returncode == 1 and miss.stdout == "", repr(miss.stdout)


def test_hexdump(rw):
    p = _run("hexdump", "-n", "10", _url(rw, "/small.txt"))
    assert p.returncode == 0, p.stderr
    assert p.stdout.startswith("00000000 ")
    assert "61 62 63" in p.stdout          # 'a' 'b' 'c'
    assert "|abcdefghij|" in p.stdout


# ============================ Tier 3: stage / evict / ping ===================

def test_stage_and_evict(rw):
    # disk-resident file: stage is a no-op success, evict succeeds
    assert _run("stage", _url(rw, "/small.txt")).returncode == 0
    assert _run("evict", _url(rw, "/small.txt")).returncode == 0


def test_ping(rw):
    p = _run("ping", "-c", "3", f"root://{HOST}:{rw['port']}")
    assert p.returncode == 0, p.stderr
    assert "min/avg/max" in p.stdout and "3/3 ok" in p.stdout


def test_ping_dead_endpoint():
    p = _run("ping", "-c", "2", "root://nonexistent.invalid:1094")
    assert p.returncode != 0


# ============================ sync ==========================================

def test_dd_window(rw, tmp_path):
    blob = bytes(range(256)) * 4096           # 1 MiB of deterministic bytes
    (rw["data"] / "dd.bin").write_bytes(blob * 4)   # 4 MiB
    # skip 1 block, take 2 blocks of 1 MiB
    p = subprocess.run([XRD, "dd", _url(rw, "/dd.bin"),
                        "bs=1M", "skip=1", "count=2"],
                       capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert p.stdout == (blob * 4)[1 << 20: 3 << 20]
    assert b"bytes copied" in p.stderr


def test_dd_rate_limit_paces(rw):
    # 2 MiB at 4 MiB/s should take ~0.5s; assert it is not instant and not absurd
    big = b"z" * (4 << 20)
    (rw["data"] / "ddr.bin").write_bytes(big)
    t0 = time.monotonic()
    p = subprocess.run([XRD, "dd", _url(rw, "/ddr.bin"),
                        "bs=1M", "count=2", "rate=4M"],
                       capture_output=True, timeout=30)
    dt = time.monotonic() - t0
    assert p.returncode == 0 and len(p.stdout) == (2 << 20)
    assert 0.3 < dt < 3.0, f"rate pacing off: {dt:.3f}s"


def test_dd_bad_bs_rejected(rw):
    p = subprocess.run([XRD, "dd", _url(rw, "/small.txt"), "bs=999G"],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode != 0 and "bs" in p.stderr


def test_upload_roundtrip(rw, tmp_path):
    src = tmp_path / "u.bin"
    src.write_bytes(b"upload-me-exactly\n" * 1000)
    p = _run("upload", str(src), _url(rw, "/up_rt.bin"))
    assert p.returncode == 0, p.stderr
    assert (rw["data"] / "up_rt.bin").read_bytes() == src.read_bytes()


def test_upload_rate_and_overwrite(rw, tmp_path):
    src = tmp_path / "u2.bin"
    src.write_bytes(b"x" * (2 << 20))           # 2 MiB
    # first upload, then -f overwrite at a rate cap
    assert _run("upload", str(src), _url(rw, "/up_r.bin")).returncode == 0
    # without -f the existing file must not be clobbered
    again = _run("upload", str(src), _url(rw, "/up_r.bin"))
    assert again.returncode != 0
    t0 = time.monotonic()
    p = _run("upload", "-f", "rate=4M", str(src), _url(rw, "/up_r.bin"))
    dt = time.monotonic() - t0
    assert p.returncode == 0, p.stderr
    assert 0.3 < dt < 3.0, f"upload rate pacing off: {dt:.3f}s"
    assert (rw["data"] / "up_r.bin").read_bytes() == src.read_bytes()


def test_upload_from_stdin(rw):
    p = subprocess.run([XRD, "upload", "-f", "-", _url(rw, "/stdin_up.txt")],
                       input=b"piped-content\n", capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert (rw["data"] / "stdin_up.txt").read_bytes() == b"piped-content\n"


def test_download_roundtrip_and_default_name(rw, tmp_path):
    blob = b"download-me\n" * 5000
    (rw["data"] / "dl_src.bin").write_bytes(blob)
    out = tmp_path / "got.bin"
    p = _run("download", _url(rw, "/dl_src.bin"), str(out))
    assert p.returncode == 0, p.stderr
    assert out.read_bytes() == blob
    # default local name = remote basename, created in cwd
    p2 = subprocess.run([XRD, "download", _url(rw, "/dl_src.bin")],
                        capture_output=True, text=True, cwd=str(tmp_path), timeout=30)
    assert p2.returncode == 0, p2.stderr
    assert (tmp_path / "dl_src.bin").read_bytes() == blob


def test_download_rate_limit_paces(rw):
    (rw["data"] / "dlr.bin").write_bytes(b"q" * (4 << 20))
    t0 = time.monotonic()
    p = _run("download", "-f", "rate=4M", _url(rw, "/dlr.bin"), "-")
    dt = time.monotonic() - t0
    assert p.returncode == 0, p.stderr
    assert len(p.stdout) == (4 << 20)          # "q" bytes decode 1:1 as text
    assert 0.6 < dt < 4.0, f"download rate pacing off: {dt:.3f}s"


def test_download_no_overwrite_without_force(rw, tmp_path):
    (rw["data"] / "dl2.bin").write_bytes(b"data\n")
    out = tmp_path / "exists.bin"
    out.write_bytes(b"old\n")
    p = _run("download", _url(rw, "/dl2.bin"), str(out))
    assert p.returncode != 0
    assert out.read_bytes() == b"old\n"        # untouched


# ===================== diagnostics: caps/whoami/clockskew/certinfo/doctor ====

def test_caps_lists_qconfig(rw):
    p = _run("caps", _url(rw))
    assert p.returncode == 0, p.stderr
    assert "role=server" in p.stdout
    assert "chksum" in p.stdout and "xrdfs.ext" in p.stdout


def test_whoami_anonymous(rw):
    p = _run("whoami", _url(rw))
    assert p.returncode == 0, p.stderr
    assert "anonymous" in p.stdout
    assert "presenting:" in p.stdout


def test_clockskew_in_sync(rw):
    # server is localhost → offset ~0; root:// uses touch+stat (server is writable)
    p = _run("clockskew", _url(rw))
    assert p.returncode == 0, p.stderr
    assert "clock offset:" in p.stdout and "server time:" in p.stdout


def test_certinfo_cleartext_is_clean(rw):
    # the rw fixture is cleartext root:// → no peer cert, reported cleanly (exit 0)
    p = _run("certinfo", _url(rw))
    assert p.returncode == 0, p.stderr
    assert "no server certificate" in p.stdout


def test_certinfo_tls_when_available():
    """If the shared GSI+TLS server (:11096) is up, exercise real cert parsing."""
    if not os.path.exists(XRD):
        pytest.skip("xrd not built")
    if not _port_up(HOST, 11096):
        pytest.skip("no TLS server on :11096")
    p = subprocess.run([XRD, "certinfo", f"roots://{HOST}:11096//"],
                       capture_output=True, text=True, timeout=30)
    assert p.returncode in (0, 1), p.stderr      # 0 valid, 1 expired/not-yet
    assert "server certificate for" in p.stdout
    assert "validity:" in p.stdout and "issuer:" in p.stdout


def _clean_cred_env(tmp_path):
    """Env with no discoverable token/proxy, so doctor's local-cred check (which would
    flag a stray expired ~/x509 proxy on the host) doesn't perturb the exit code."""
    env = dict(os.environ, X509_USER_PROXY=str(tmp_path / "no_such_proxy"))
    for k in ("BEARER_TOKEN", "BEARER_TOKEN_FILE", "XDG_RUNTIME_DIR"):
        env.pop(k, None)
    return env


def test_doctor_human(rw, tmp_path):
    p = subprocess.run([XRD, "doctor", _url(rw)], capture_output=True, text=True,
                       env=_clean_cred_env(tmp_path), timeout=30)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "== endpoint" in p.stdout
    assert "connect:  OK" in p.stdout
    assert "caps:" in p.stdout and "clock:" in p.stdout


def test_doctor_json(rw):
    p = _run("doctor", _url(rw), "--json")
    assert p.returncode == 0, p.stderr
    doc = json.loads(p.stdout)                   # must be valid JSON
    assert doc["connected"] is True
    assert doc["role"] == "server"
    assert doc["port"] == rw["port"]
    assert "chksum" in doc["capabilities"]
    assert doc["capabilities"]["xrdfs.ext"]
    assert doc["clock"] is not None              # root:// touch+stat measured it
    assert "credentials" in doc


def test_doctor_readonly_battery_json(rw):
    """doctor (no --rw) runs the read-only root:// method battery; writes skipped."""
    p = _run("doctor", _url(rw), "--json")
    assert p.returncode == 0, p.stderr
    doc = json.loads(p.stdout)
    assert "tests" in doc and len(doc["tests"]) == 1
    t = doc["tests"][0]
    assert t["protocol"] == "root" and t["reachable"] is True
    names = {c["name"]: c["status"] for c in t["checks"]}
    assert names.get("stat") == "pass" and names.get("dirlist") == "pass"
    assert names.get("path-confinement") == "pass"
    assert names.get("write-suite") == "skip"     # read-only by default


def test_doctor_rw_battery_json(rw, tmp_path):
    """doctor --rw runs the full write/read/verify/checksum/metadata cycle; zero fails
    (the symlink-unlink limitation surfaces as a SKIP, not a FAIL)."""
    p = subprocess.run([XRD, "doctor", _url(rw), "--rw", "--json"],
                       capture_output=True, text=True,
                       env=_clean_cred_env(tmp_path), timeout=60)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    doc = json.loads(p.stdout)
    t = doc["tests"][0]
    assert t["protocol"] == "root" and t["reachable"] is True
    assert t["failed"] == 0, [c for c in t["checks"] if c["status"] == "fail"]
    names = {c["name"]: c["status"] for c in t["checks"]}
    for step in ("write", "read-verify", "readv", "checksum-verify", "rename", "rm"):
        assert names.get(step) == "pass", (step, names)


def test_doctor_rw_human(rw, tmp_path):
    p = subprocess.run([XRD, "doctor", _url(rw), "--rw"], capture_output=True, text=True,
                       env=_clean_cred_env(tmp_path), timeout=60)
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert "== root tests:" in p.stdout
    assert "[PASS] write" in p.stdout and "[PASS] read-verify" in p.stdout
    assert "checksum-verify" in p.stdout


def test_doctor_also_webdav_when_available(rw):
    """If the shared davs endpoint (:8443) is up, --also runs the WebDAV battery."""
    if not _port_up(HOST, 8443):
        pytest.skip("no davs server on :8443")
    p = subprocess.run([XRD, "doctor", _url(rw), "--rw", "--insecure",
                        "--also", f"https://{HOST}:8443/", "--json"],
                       capture_output=True, text=True, timeout=60)
    doc = json.loads(p.stdout)
    web = [t for t in doc["tests"] if t["protocol"] in ("http", "https")]
    assert web and web[0]["reachable"] is True
    names = {c["name"]: c["status"] for c in web[0]["checks"]}
    assert names.get("OPTIONS") == "pass" and names.get("PUT") == "pass"
    assert names.get("GET-verify") == "pass"


def test_doctor_also_s3_when_available(rw):
    """If the shared S3 endpoint (:9001) is up, --also runs the S3 battery."""
    if not _port_up(HOST, 9001):
        pytest.skip("no S3 server on :9001")
    env = dict(os.environ, AWS_ACCESS_KEY_ID="testkey",
               AWS_SECRET_ACCESS_KEY="testsecret", AWS_DEFAULT_REGION="us-east-1")
    p = subprocess.run([XRD, "doctor", _url(rw), "--rw", "--insecure",
                        "--also", f"s3://{HOST}:9001/testbucket", "--json"],
                       capture_output=True, text=True, env=env, timeout=60)
    doc = json.loads(p.stdout)
    s3 = [t for t in doc["tests"] if t["protocol"] == "s3"]
    assert s3 and s3[0]["reachable"] is True
    names = {c["name"]: c["status"] for c in s3[0]["checks"]}
    assert names.get("list-objects") == "pass"
    assert names.get("PUT") == "pass" and names.get("GET-verify") == "pass"


def test_sync_uploads_tree(rw, tmp_path):
    """`xrd sync` mirrors a local tree to a remote dir with rsync-style trailing-
    slash semantics: a source WITHOUT a trailing slash nests the directory itself
    under the destination; a source WITH a trailing slash copies its contents in
    flat."""
    src = tmp_path / "srctree"
    src.mkdir()
    (src / "x.txt").write_text("one\n")
    (src / "y.txt").write_text("two\n")

    # no trailing slash -> nest the source dir under the destination
    p = _run("sync", str(src), _url(rw, "/nested"))
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert (rw["data"] / "nested" / "srctree" / "x.txt").read_text() == "one\n"
    assert (rw["data"] / "nested" / "srctree" / "y.txt").read_text() == "two\n"

    # trailing slash -> flat mirror of the contents into the destination
    p = _run("sync", str(src) + "/", _url(rw, "/flat"))
    assert p.returncode == 0, f"{p.stdout}\n{p.stderr}"
    assert (rw["data"] / "flat" / "x.txt").read_text() == "one\n"
    assert (rw["data"] / "flat" / "y.txt").read_text() == "two\n"
