"""
tests/test_cms_node_readiness.py — the scripted CMS data node reports when the
manager has registered it, so tests wait on that instead of sleeping.

Race-hunt run 30 halted on test_phase115_cms_select_proxy.py: its ``_settle``
was ``time.sleep(0.4)`` covering TWO node logins on one manager, and the
manager registers a node only when its event loop reaches the LOGIN frame.
``_CmsNode.wait_ready`` (test_cms_locate_have.py) turns the manager's first
inbound frame — sent only after ``brix_srv_register`` — into the signal.

  success       — a manager that speaks after login makes wait_ready True at
                  once, without waiting out the timeout;
  error         — a manager that never speaks makes wait_ready False after the
                  timeout, and the node still closes cleanly;
  security-neg  — no settle in the phase-115 select/proxy suite is a bare
                  sleep any more: every ``_settle`` call names the nodes it
                  waits on, and the helper waits on ``wait_ready``.

Run:
    PYTHONPATH=tests pytest tests/test_cms_node_readiness.py -v
"""
import ast
import re
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from ephemeral_port import free_port
from settings import SERVER_HOST
from test_cms_locate_have import _CmsNode

H = SERVER_HOST
CMS_RR_PING = 4
TESTS = Path(__file__).resolve().parent
SELECT_PROXY = TESTS / "test_phase115_cms_select_proxy.py"


class _ScriptedManager:
    """Accepts one CMS login and, when ``speaks`` is set, answers with a
    single ping frame — the manager's first post-registration word."""

    def __init__(self, speaks: bool):
        self.speaks = speaks
        self._srv = socket.socket()
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.port = free_port(H)
        self._srv.bind((H, self.port))
        self._srv.listen(1)
        self._conn = None
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            self._conn, _peer = self._srv.accept()
            self._conn.settimeout(5)
            hdr = self._conn.recv(8)
            if len(hdr) == 8:
                _sid, _code, _mod, dlen = struct.unpack(">IBBH", hdr)
                while dlen > 0:
                    chunk = self._conn.recv(dlen)
                    if not chunk:
                        return
                    dlen -= len(chunk)
            if self.speaks:
                self._conn.sendall(struct.pack(">IBBH", 1, CMS_RR_PING, 0, 0))
        except OSError:
            return

    def close(self):
        for s in (self._conn, self._srv):
            try:
                if s is not None:
                    s.close()
            except OSError:
                pass
        self._thread.join(timeout=2)


def test_manager_that_speaks_after_login_makes_the_node_ready_at_once():
    mgr = _ScriptedManager(speaks=True)
    node = None
    try:
        node = _CmsNode(mgr.port, 1094, paths=b"r /x")
        t0 = time.monotonic()
        assert node.wait_ready(5.0), "no frame from the manager"
        assert time.monotonic() - t0 < 2.0, "ready arrived only at the timeout"
    finally:
        if node is not None:
            node.close()
        mgr.close()


def test_silent_manager_leaves_the_node_not_ready_after_the_timeout():
    mgr = _ScriptedManager(speaks=False)
    node = None
    try:
        node = _CmsNode(mgr.port, 1094, paths=b"r /x")
        t0 = time.monotonic()
        assert not node.wait_ready(0.4)
        assert time.monotonic() - t0 >= 0.4
        assert not node.ready.is_set()
    finally:
        if node is not None:
            node.close()
        mgr.close()


def _settle_helper(tree: ast.Module) -> ast.FunctionDef:
    for fn in tree.body:
        if isinstance(fn, ast.FunctionDef) and fn.name == "_settle":
            return fn
    pytest.fail("_settle helper is gone from the select/proxy suite")


def test_every_settle_in_the_select_proxy_suite_names_its_nodes():
    src = SELECT_PROXY.read_text()
    tree = ast.parse(src)
    helper = _settle_helper(tree)
    body = ast.get_source_segment(src, helper) or ""
    assert "wait_ready(" in body, "_settle no longer waits on the registry"
    assert "sleep(" not in body, "_settle fell back to a sleep"
    bare = re.findall(r"^\s*_settle\(\)\s*$", src, flags=re.M)
    assert bare == [], f"{len(bare)} _settle() call(s) wait on nothing"
    calls = re.findall(r"^\s*_settle\((.+)\)\s*$", src, flags=re.M)
    assert len(calls) >= 9, calls
