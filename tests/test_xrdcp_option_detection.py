"""Client capability probes recognize diagnostics from both client spellings."""
import subprocess

import pytest

import test_xrdcp_client_options as options


@pytest.mark.parametrize('diagnostic,supported', [
    ("unknown option '--jobs'", False),
    ("xrdcp: Invalid option, '--jobs'.", False),
    ("unrecognized option '--jobs'", False),
    ('missing source and destination operands', True),
])
def test_option_probe_classifies_usage_errors(monkeypatch, diagnostic, supported):
    monkeypatch.setattr(options, '_OPTION_SUPPORT_CACHE', {})
    monkeypatch.setattr(options.subprocess, 'run', lambda command, **_kwargs:
        subprocess.CompletedProcess(command, 2, b'', diagnostic.encode()))
    assert options._xrdcp_supports_option('--jobs') is supported
