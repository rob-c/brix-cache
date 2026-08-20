"""
test_audit15e_cms_active_member.py — CMS mesh members whose data plane is a
PROXY or a native-TPC DESTINATION (audit §B3.16,
testsuite-combinatorial-coverage-audit 2026-08-15: cms×* combinations in the
suite always joined nodes backed by a plain posix export — or by nothing at
all, `return ""` — so "registered with a manager" and "moves other people's
bytes" had never been true of the same node at the same time).

One manager instance (nginx_cms_state_server.conf as lc-audit15e-cmsmgr2) and
one instance hosting four stream planes (nginx_audit15e_cmsact.conf): a TPC
source and an origin that stay OUT of the mesh, plus two members that join it
— a read-only proxy over root:// and a writable native-TPC destination.  Every
assertion is anchored to the member's own registration line ("CMS registered
with ... after N ms (K connect attempt(s), profile)"), so each case is
demonstrably about a node that is IN the mesh, not one that merely carries a
manager directive.

Cases:
  * success — both data roles register as two distinct CMS nodes out of one
    master (the identity gate does not collapse them, and a data-carrying
    server block still joins)
  * success — the proxy member serves the origin's bytes over the raw root
    wire while joined: the backend leg and the control plane coexist
  * success — a native TPC pull lands in the destination member's export and
    the membership survives the transfer
  * error — a pull whose rendezvous key was never armed on the source fails
    closed: no terminal ok, and nothing in the destination export
  * security-negative — a write-open on the read-only proxy member is refused
    and no object appears on the origin behind it
"""

import os
import re
import struct
import time

import pytest

from server_registry import NginxInstanceSpec
from port_ladder import PORT_LAST
from settings import NGINX_BIN, HOST, BIND_HOST
from test_phase25_ratelimit import (KXR_OK, _xrd_login, _xrd_open, _xrd_read,
                                    _xrd_recv_status)
from test_audit15c_tpc_token_exchange import _arm_source, _drive_pull

pytestmark = [pytest.mark.uses_lifecycle_harness,
              pytest.mark.xdist_group("lc-audit15e-cmsact")]

SEED = b"audit15e-tpc-source-payload\n" * 4
ORIGIN_BYTES = b"audit15e-origin-bytes\n" * 6

REGISTERED = re.compile(r"CMS registered with (\S+) after (\d+) ms "
                        r"\((\d+) connect attempt\(s\), (\w+)\)")


@pytest.fixture()
def mesh(lifecycle, tmp_path):
    if not os.path.exists(NGINX_BIN):
        pytest.skip(f"nginx binary not found at {NGINX_BIN}")
    mgr = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15e-cmsmgr2",
        template="nginx_cms_state_server.conf",
        # This fixture owns two throwaway CMS instances.  Keep them outside
        # the shared lifecycle ladder: the fixed ledger slot can be occupied
        # by an interrupted/user-launched suite while this test is starting.
        port=PORT_LAST + 1,
        protocol="root",
        readiness="tcp",
        reason="audit-15e cms manager for the active-member pair"))

    base = tmp_path / "planes"
    src, origin, tpc = base / "src", base / "origin", base / "tpc"
    for d in (src, origin, tpc):
        d.mkdir(parents=True)
    (src / "src.bin").write_bytes(SEED)
    (origin / "hot.bin").write_bytes(ORIGIN_BYTES)
    # The master may run as root; the worker drops privilege and still has to
    # create the checkpoint-recovery lock inside each export.
    for d in (base, src, origin, tpc):
        os.chmod(d, 0o777)

    ep = lifecycle.start(NginxInstanceSpec(
        name="lc-audit15e-cmsact",
        template="nginx_audit15e_cmsact.conf",
        port=PORT_LAST + 2,
        protocol="root",
        readiness="tcp",
        data_root=str(base),
        extra_ports={"ORIGIN_PORT": PORT_LAST + 3,
                     "TPC_PORT": PORT_LAST + 4,
                     "SRC_PORT": PORT_LAST + 5},
        template_values={"BIND_HOST": BIND_HOST,
                         "MANAGER_PORT": str(mgr.port),
                         "SRC_ROOT": str(src),
                         "ORIGIN_ROOT": str(origin),
                         "TPC_ROOT": str(tpc)},
        reason="audit-15e cms members with proxy / TPC-destination roles"))
    return ep, {"src": src, "origin": origin, "tpc": tpc}


def _log(ep):
    try:
        with open(os.path.join(ep.prefix, "logs", "error.log")) as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _wait_registrations(ep, want=2, timeout=10.0):
    """Return the registration lines once `want` of them have appeared (the
    line is emitted once per node, guarded by ever_logged_in), else whatever
    was seen when the window closed."""
    deadline = time.time() + timeout
    seen = []
    while time.time() < deadline:
        seen = REGISTERED.findall(_log(ep))
        if len(seen) >= want:
            return seen
        time.sleep(0.05)
    return seen


def _read(port, path, size):
    s = _xrd_login(HOST, port)
    try:
        status, body = _xrd_open(s, path)
        if status != KXR_OK:
            return status, body
        return _xrd_read(s, body[:4], 0, size)
    finally:
        s.close()


def _open_frame(s, path, flags, mode=0o644):
    payload = path.encode()
    body = struct.pack(">HH12s", mode, flags, b"\x00" * 12)
    s.sendall(struct.pack(">BBH", 0, 1, 3010) + body
              + struct.pack(">I", len(payload)) + payload)
    return _xrd_recv_status(s)


# kXR_new | kXR_open_wrto | kXR_mkpath
WRITE_FLAGS = 0x0008 | 0x4000 | 0x0100


def _pull(dst_port, src_port, dest_path, key, arm=True):
    """Drive a native TPC pull into the destination member; returns the
    terminal (status, body).  With arm=False the rendezvous key is never
    registered on the source, so the pull must not complete."""
    armed = _arm_source(src_port, key) if arm else None
    s = _xrd_login(HOST, dst_port)
    s.settimeout(30)
    try:
        opaque = (f"?tpc.src={HOST}:{src_port}&tpc.key={key}"
                  f"&tpc.lfn=/src.bin&tpc.stage=copy&oss.asize={len(SEED)}")
        status, body = _open_frame(s, dest_path + opaque, WRITE_FLAGS)
        if status != KXR_OK:
            return status, body
        return _drive_pull(s, body[:4])
    finally:
        s.close()
        if armed is not None:
            armed.close()


def _objects(root):
    """Export contents excluding the server's own dotfiles (each export gets a
    .nginx-xrootd-ckp-recovery.lock when the node boots)."""
    return sorted(p.name for p in root.iterdir() if not p.name.startswith("."))


def _wait_bytes(path, want, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists() and path.read_bytes() == want:
            return True
        time.sleep(0.2)
    return False


def test_both_data_roles_join_the_mesh(mesh):
    ep, _roots = mesh
    seen = _wait_registrations(ep)
    assert len(seen) >= 2, (
        "a data-carrying stream block failed to register: expected the proxy "
        "member and the TPC-destination member to join as two CMS nodes\n"
        + _log(ep))
    mgr_names = {row[0] for row in seen}
    assert len(mgr_names) == 1, ("both members must target ONE manager", seen)
    for _mgr, _ms, attempts, profile in seen:
        assert int(attempts) >= 1
        assert profile == "loopback", (profile, seen)
    # The registration line is emitted once per node (ever_logged_in), so the
    # count IS the node count: the identity gate did not collapse the two
    # server blocks into one, nor did extra workers register duplicates.
    assert len(seen) == 2, ("unexpected CMS node count out of one master",
                            seen)


def test_proxy_member_serves_the_origin_while_joined(mesh):
    ep, roots = mesh
    assert len(_wait_registrations(ep)) >= 2
    status, data = _read(ep.port, "/hot.bin", len(ORIGIN_BYTES))
    assert status == KXR_OK, (status, data)
    assert data == ORIGIN_BYTES
    # The member is a proxy: it kept no copy of what it served.
    assert _objects(roots["tpc"]) == []
    assert _objects(roots["origin"]) == ["hot.bin"]
    assert "CMS registered with" in _log(ep), \
        "the control plane died while the backend leg was in flight"


def test_tpc_pull_lands_in_a_mesh_member(mesh):
    ep, roots = mesh
    assert len(_wait_registrations(ep)) >= 2
    tpc_port = ep.extra_ports["TPC_PORT"]
    src_port = ep.extra_ports["SRC_PORT"]
    status, body = _pull(tpc_port, src_port, "/pulled.bin", "a15e-mesh-pull")
    assert status == KXR_OK, ("TPC pull into the mesh member failed", status,
                              body)
    assert _wait_bytes(roots["tpc"] / "pulled.bin", SEED), \
        "the pull reported ok but the destination export never matched"
    # ... and the transfer did not cost the node its mesh membership.
    assert len(REGISTERED.findall(_log(ep))) == 2


def test_pull_with_an_unarmed_key_fails_closed(mesh):
    ep, roots = mesh
    assert len(_wait_registrations(ep)) >= 2
    tpc_port = ep.extra_ports["TPC_PORT"]
    src_port = ep.extra_ports["SRC_PORT"]
    status, body = _pull(tpc_port, src_port, "/unarmed.bin",
                         "a15e-never-armed", arm=False)
    assert status != KXR_OK, \
        ("a pull whose rendezvous key was never armed on the source "
         "completed", status, body)
    assert not (roots["tpc"] / "unarmed.bin").exists() \
        or (roots["tpc"] / "unarmed.bin").read_bytes() != SEED, \
        "the failed pull left the source payload in the destination export"


def test_proxy_member_refuses_write_open(mesh):
    ep, roots = mesh
    assert len(_wait_registrations(ep)) >= 2
    s = _xrd_login(HOST, ep.port)
    try:
        status, body = _open_frame(s, "/intruder.bin", WRITE_FLAGS)
    finally:
        s.close()
    assert status != KXR_OK, \
        ("the read-only proxy member accepted a write-open", status, body)
    assert not (roots["origin"] / "intruder.bin").exists(), \
        "the refused write-open still reached the origin behind the proxy"
    assert _objects(roots["origin"]) == ["hot.bin"]
