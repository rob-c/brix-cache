"""
test_fault_proxy_privileged.py — root-gated ("priv") lever tests for
brix-fault-proxy (client/apps/diag/brix_fault_priv.c).

These levers mutate HOST-GLOBAL network state (a `tc netem` qdisc, an `nft`
table, a NIC's MTU), so every test runs the proxy inside a throwaway network
namespace on that namespace's isolated `lo` — the real host NICs are never
touched, and a leaked qdisc/table/MTU can only ever escape into a namespace we
delete in teardown.

The 3-test ritual for the new privileged surface:

* SUCCESS  — with root + --privileged, `priv netem`/`priv cut`/`priv mtu` install
             the expected kernel state, and it is fully restored when the proxy
             exits (SIGTERM) — the auto-teardown contract.
* ERROR    — `priv` without --privileged is refused; --priv-iface without
             --privileged exits 2; a nonexistent/hostile --priv-iface is refused
             before the subsystem arms.
* SECURITY — arming requires root; numeric/interface operands are validated, and
             shell-metacharacter interface names are rejected (defence in depth
             on top of the no-shell execvp() design).

Skips cleanly when not root or when iproute2/nftables are unavailable; the netem
sub-tests additionally skip when the kernel lacks sch_netem.
"""

import os
import shutil
import socket
import subprocess
import time

import pytest

pytestmark = pytest.mark.timeout(120)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
BFP = os.path.join(CLIENT_DIR, "bin", "brix-fault-proxy")

_TOOLS = ["ip", "tc", "nft"]


def _have_tools():
    return all(shutil.which(t) for t in _TOOLS)


needs_root = pytest.mark.skipif(
    os.geteuid() != 0 or not _have_tools(),
    reason="privileged levers need root + iproute2/nftables",
)


# --------------------------------------------------------------------------- #
# Namespace + control helpers                                                 #
# --------------------------------------------------------------------------- #
def _nsrun(ns, *argv, **kw):
    return subprocess.run(["ip", "netns", "exec", ns, *argv],
                          capture_output=True, text=True, timeout=10, **kw)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _ctl(ns, port, cmd):
    """Send one control command to the in-namespace control port, return reply."""
    code = ('import socket,sys;s=socket.socket();s.connect(("127.0.0.1",%d));'
            's.sendall(sys.stdin.buffer.read());sys.stdout.write(s.recv(768)'
            '.decode())' % port)
    r = subprocess.run(["ip", "netns", "exec", ns, "python3", "-c", code],
                       input=(cmd + "\n").encode(), capture_output=True, timeout=6)
    return r.stdout.decode()


@pytest.fixture(scope="module")
def bfp():
    proc = subprocess.run(["make", "-C", CLIENT_DIR, "brix-fault-proxy"],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 or not os.path.exists(BFP):
        pytest.skip(f"brix-fault-proxy build failed:\n{proc.stdout}\n{proc.stderr}")
    return BFP


@pytest.fixture
def netns():
    """A fresh network namespace with `lo` up; deleted (with its pids) on exit."""
    name = "bfp_priv_%d" % os.getpid()
    subprocess.run(["ip", "netns", "del", name],
                   capture_output=True)  # best-effort pre-clean
    subprocess.run(["ip", "netns", "add", name], check=True)
    _nsrun(name, "ip", "link", "set", "lo", "up")
    try:
        yield name
    finally:
        pids = subprocess.run(["ip", "netns", "pids", name],
                              capture_output=True, text=True)
        for pid in pids.stdout.split():
            try:
                os.kill(int(pid), 15)
            except (ProcessLookupError, ValueError):
                pass
        subprocess.run(["ip", "netns", "del", name], capture_output=True)


def _spawn(bfp, ns, extra):
    """Start an armed proxy inside `ns` in front of an in-ns echo target.
    Returns (proc, listen_port, control_port)."""
    listen, ctl, tgt = _free_port(), _free_port(), _free_port()
    proc = subprocess.Popen(
        ["ip", "netns", "exec", ns, bfp, "--listen", str(listen),
         "--target", f"127.0.0.1:{tgt}", "--control", str(ctl),
         "--quiet", "--privileged"] + extra,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        if "on iface" in _ctl(ns, ctl, "priv status") or proc.poll() is not None:
            break
        time.sleep(0.05)
    return proc, listen, ctl


def _netem_supported(ns):
    r = _nsrun(ns, "tc", "qdisc", "add", "dev", "lo", "root", "netem",
               "delay", "1ms")
    if r.returncode == 0:
        _nsrun(ns, "tc", "qdisc", "del", "dev", "lo", "root")
        return True
    return False


# --------------------------------------------------------------------------- #
# SUCCESS                                                                      #
# --------------------------------------------------------------------------- #
@needs_root
def test_netem_installs_and_tears_down(bfp, netns):
    if not _netem_supported(netns):
        pytest.skip("kernel lacks sch_netem")
    proc, _listen, ctl = _spawn(bfp, netns, ["--priv-iface", "lo"])
    try:
        assert "ok" in _ctl(netns, ctl, "priv netem delay 30 10")
        assert "ok" in _ctl(netns, ctl, "priv netem loss 20")
        show = _nsrun(netns, "tc", "qdisc", "show", "dev", "lo").stdout
        assert "netem" in show and "delay 30ms" in show and "loss" in show
    finally:
        proc.terminate()
        proc.wait(timeout=5)
    # Auto-teardown must have removed the qdisc.
    assert "netem" not in _nsrun(netns, "tc", "qdisc", "show", "dev", "lo").stdout


@needs_root
def test_cut_and_mtu_install_and_restore(bfp, netns):
    proc, _listen, ctl = _spawn(bfp, netns, ["--priv-iface", "lo"])
    try:
        # nft RST cut installs a reject rule scoped to our own ports.
        assert "ok" in _ctl(netns, ctl, "priv cut rst down")
        table = _nsrun(netns, "nft", "list", "table", "inet",
                       "brix_fault_proxy").stdout
        assert "reject with tcp reset" in table
        assert "ok" in _ctl(netns, ctl, "priv uncut")
        assert "brix_fault_proxy" not in _nsrun(
            netns, "nft", "list", "tables").stdout

        # MTU shrink then explicit restore.
        base = int(open("/sys/class/net/lo/mtu").read())  # host lo (unused ref)
        assert "ok" in _ctl(netns, ctl, "priv mtu 600")
        assert _nsrun(netns, "cat", "/sys/class/net/lo/mtu").stdout.strip() == "600"
        assert "ok" in _ctl(netns, ctl, "priv mtu restore")
        restored = _nsrun(netns, "cat", "/sys/class/net/lo/mtu").stdout.strip()
        assert restored != "600" and int(restored) >= 600
        assert base > 0
    finally:
        proc.terminate()
        proc.wait(timeout=5)


@needs_root
def test_teardown_restores_nft_and_mtu_on_signal(bfp, netns):
    proc, _listen, ctl = _spawn(bfp, netns, ["--priv-iface", "lo"])
    _ctl(netns, ctl, "priv cut drop both")
    _ctl(netns, ctl, "priv mtu 552")
    assert "brix_fault_proxy" in _nsrun(netns, "nft", "list", "tables").stdout
    proc.terminate()
    proc.wait(timeout=5)
    # Both the nft table and the shrunk MTU must be gone/restored.
    assert "brix_fault_proxy" not in _nsrun(netns, "nft", "list", "tables").stdout
    assert _nsrun(netns, "cat", "/sys/class/net/lo/mtu").stdout.strip() != "552"


# --------------------------------------------------------------------------- #
# ERROR                                                                        #
# --------------------------------------------------------------------------- #
def test_priv_refused_without_optin(bfp):
    """`priv` commands must report 'not enabled' unless --privileged was given."""
    listen, ctl, tgt = _free_port(), _free_port(), _free_port()
    proc = subprocess.Popen(
        [bfp, "--listen", str(listen), "--target", f"127.0.0.1:{tgt}",
         "--control", str(ctl), "--quiet"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.time() + 5
        reply = ""
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", ctl), timeout=0.3) as s:
                    s.sendall(b"priv netem delay 10\n")
                    reply = s.recv(768).decode()
                    break
            except OSError:
                time.sleep(0.05)
        assert "not enabled" in reply
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def test_priv_iface_without_privileged_exits_2(bfp):
    r = subprocess.run(
        [bfp, "--listen", "1", "--target", "127.0.0.1:2", "--control", "3",
         "--priv-iface", "lo"],
        capture_output=True, text=True, timeout=10)
    assert r.returncode == 2
    assert "requires --privileged" in r.stderr


# --------------------------------------------------------------------------- #
# SECURITY                                                                     #
# --------------------------------------------------------------------------- #
@needs_root
def test_hostile_iface_name_refused(bfp):
    """A shell-metacharacter / nonexistent --priv-iface must be refused before
    the subsystem arms (defence in depth atop the no-shell execvp design)."""
    r = subprocess.run(
        [bfp, "--listen", "1", "--target", "127.0.0.1:2", "--control", "3",
         "--privileged", "--priv-iface", "lo; touch /tmp/bfp_pwned"],
        capture_output=True, text=True, timeout=10)
    assert r.returncode == 2
    assert "invalid or nonexistent --priv-iface" in r.stderr
    assert not os.path.exists("/tmp/bfp_pwned")


@needs_root
def test_numeric_operands_validated(bfp, netns):
    proc, _listen, ctl = _spawn(bfp, netns, ["--priv-iface", "lo"])
    try:
        assert "err:" in _ctl(netns, ctl, "priv netem loss 250")     # >100%
        assert "err:" in _ctl(netns, ctl, "priv netem delay abc")    # non-numeric
        assert "err:" in _ctl(netns, ctl, "priv netem rate 1gigabit")  # bad unit
        assert "err:" in _ctl(netns, ctl, "priv cut bogus")          # unknown mode
        assert "err:" in _ctl(netns, ctl, "priv mtu 40")             # < 68 floor
    finally:
        proc.terminate()
        proc.wait(timeout=5)
