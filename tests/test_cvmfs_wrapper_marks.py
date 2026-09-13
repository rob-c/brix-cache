"""Split test wrappers must retain helper timeouts and prerequisite gates."""

import importlib

import pytest


def _arguments(marks, name):
    return [mark.args for mark in marks if mark.name == name]


@pytest.mark.parametrize("family,suffix,timeout,skip_count", [
    ("trust", "", 180, 0),
    ("manifest_parse", "", 300, 1),
    ("cache", "", 300, 2),
    ("cache", "_b", 300, 2),
    ("cache", "_c", 300, 2),
    ("catalog", "", None, 1),
    ("catalog", "_b", None, 1),
    ("read", "", None, 1),
    ("read", "_b", None, 1),
    ("posix", "", None, 1),
    ("refresh_failover", "", None, 1),
    ("refresh_failover", "_b", None, 1),
    ("refresh_failover", "_c", None, 1),
])
def test_split_wrapper_keeps_all_runtime_marks(family, suffix, timeout, skip_count):
    module = importlib.import_module(f"test_cvmfs_conformance_fuse_{family}{suffix}")
    marks = module.pytestmark
    assert _arguments(marks, "xdist_group") == [(f"test_cvmfs_conformance_fuse_{family}",)]
    assert len(_arguments(marks, "skipif")) == skip_count
    assert _arguments(marks, "timeout") == ([] if timeout is None else [(timeout,)])
