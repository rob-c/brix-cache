"""A clean-room linkage assertion must fail closed without inspector evidence."""
import subprocess

import pytest

from lib_py import util


def test_successful_linkage_inspection_retains_the_native_output(monkeypatch):
    output = "libssl.so.3 => /trusted/libssl.so.3\n"
    monkeypatch.setattr(util, "have_cmd", lambda name: True)
    monkeypatch.setattr(util, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args, 0, output, ""))
    assert util.linked_libraries("binary", check=True) == output


def test_failed_inspector_cannot_prove_clean_linkage(monkeypatch):
    monkeypatch.setattr(util, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args, 1, "", "invalid image"))
    with pytest.raises(subprocess.CalledProcessError):
        util.linked_libraries("broken", check=True)


def test_empty_inspection_cannot_hide_an_unchecked_binary(monkeypatch):
    monkeypatch.setattr(util, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args, 0, "", ""))
    with pytest.raises(ValueError, match="no evidence"):
        util.linked_libraries("uninspected", check=True)
