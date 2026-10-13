"""Platform selection for the TCP established-connection observer."""

import lib_py.util as util


def test_established_to_port_prefers_ss(monkeypatch):
    monkeypatch.setattr(util, "have_cmd", lambda name: name == "ss")
    monkeypatch.setattr(util, "_ss_established_to_port", lambda port: 3)

    assert util.established_to_port(10111) == 3


def test_established_to_port_uses_populated_darwin_table(monkeypatch):
    monkeypatch.setattr(util, "have_cmd", lambda name: name in {"netstat", "lsof"})
    monkeypatch.setattr(util, "_darwin_netstat_rows", lambda state: [
        ("127.0.0.1.50000", "127.0.0.1.10111", 42),  # net-literal-allow: synthetic Darwin netstat row
        ("127.0.0.1.10111", "127.0.0.1.50000", 43),  # net-literal-allow: synthetic Darwin netstat row
    ])
    monkeypatch.setattr(
        util, "_lsof_established_to_port",
        lambda port: (_ for _ in ()).throw(AssertionError("unexpected fallback")),
    )

    assert util.established_to_port(10111) == 1


def test_established_to_port_falls_back_when_netstat_capture_is_empty(monkeypatch):
    monkeypatch.setattr(util, "have_cmd", lambda name: name in {"netstat", "lsof"})
    monkeypatch.setattr(util, "_darwin_netstat_rows", lambda state: [])
    monkeypatch.setattr(util, "_lsof_established_to_port", lambda port: 1)

    assert util.established_to_port(10111) == 1
