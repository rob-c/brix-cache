"""The ownership probe must report open, write and close failures honestly."""

import sys
from types import ModuleType, SimpleNamespace

import pytest

from mu_authz_lib.putter import _PUT_PROBE


@pytest.mark.parametrize("failed", [None, "open", "write", "close"])
def test_put_probe_checks_every_result(monkeypatch, failed):
    calls = []

    class File:
        def open(self, *_args):
            calls.append("open")
            return SimpleNamespace(ok=failed != "open"), None

        def write(self, *_args):
            calls.append("write")
            return SimpleNamespace(ok=failed != "write"), None

        def close(self):
            calls.append("close")
            return SimpleNamespace(ok=failed != "close"), None

    package = ModuleType("XRootD")
    package.client = SimpleNamespace(File=File)
    flags = ModuleType("XRootD.client.flags")
    flags.OpenFlags = SimpleNamespace(NEW=1, WRITE=2)
    monkeypatch.setitem(sys.modules, "XRootD", package)
    monkeypatch.setitem(sys.modules, "XRootD.client.flags", flags)
    monkeypatch.setattr(sys, "argv", ["probe", "root://test", "/cms/new.dat", "bytes"])
    with pytest.raises(SystemExit) as outcome:
        exec(_PUT_PROBE, {})
    assert outcome.value.code == (3 if failed else 0)
    assert calls == (["open"] if failed == "open" else ["open", "write", "close"])
