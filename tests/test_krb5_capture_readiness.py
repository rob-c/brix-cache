"""A credential-capture observer must not confuse creation with serialization."""

import ast
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest


def _observer(statuses):
    """Load the real observer without starting its Kerberos realm or servers."""
    source = Path(__file__).with_name("test_audit16s_krb5_delegate_arms_b.py")
    functions = [node for node in ast.parse(source.read_text()).body
                 if isinstance(node, ast.FunctionDef)
                 and node.name in ("_capture_is_usable", "_capture_while_open")]
    status = iter(statuses)
    scans = iter([set(), {Path("/private/credential")}, {Path("/private/credential")}])
    ticks = iter([0, 1, 2, 3])
    session = SimpleNamespace(stat=lambda: None)
    calls = []

    def klist(command, **kwargs):
        calls.append(command)
        result = next(status)
        if isinstance(result, Exception):
            raise result
        return subprocess.CompletedProcess(command, result)

    namespace = dict(
        subprocess=SimpleNamespace(run=klist, TimeoutExpired=subprocess.TimeoutExpired),
        os=os, SYS_KLIST="klist", KRB5_CONF="/private/krb5.conf",
        DEFAULT_CAPTURE_DIR=Path("/private"), _CAPTURE_TIMEOUT=3, _CAPTURE_TICK=0,
        time=SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _: None),
        _captures=lambda _: next(scans), _Session=lambda *args: session)
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(source), "exec"), namespace)
    return namespace["_capture_while_open"], session, calls


def test_observer_waits_for_a_partial_cache_to_be_serialized():
    """A transient bad-format placeholder cannot become a spurious failure."""
    observer, session, calls = _observer([1, 0])
    assert observer(1094, "ticket") == (Path("/private/credential"), session)
    assert len(calls) == 2


def test_permanently_corrupt_cache_is_never_reported_ready():
    """Security-negative: an existing but unreadable cache is not evidence."""
    observer, session, calls = _observer([1, 1])
    assert observer(1094, "ticket") == (None, session)
    assert len(calls) == 2


@pytest.mark.parametrize("error", [OSError("not readable"),
                                    subprocess.TimeoutExpired("klist", 5)])
def test_observer_does_not_accept_a_failed_verifier(error):
    """Verifier errors remain unready and the caller retains session cleanup."""
    observer, session, _ = _observer([error, error])
    assert observer(1094, "ticket") == (None, session)
