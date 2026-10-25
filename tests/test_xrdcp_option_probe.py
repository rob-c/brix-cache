"""Option probing must not mistake a missing operand for a missing feature."""

import subprocess

import test_xrdcp_client_options as options


def test_jobs_probe_supplies_its_required_count(monkeypatch):
    monkeypatch.setattr(options, "_OPTION_SUPPORT_CACHE", {})
    commands = []

    def probe(command, **kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 50, b"usage: xrdcp", b"")

    monkeypatch.setattr(options.subprocess, "run", probe)
    assert options._xrdcp_supports_option("--jobs")
    assert commands == [[options.XRDCP_BIN, "--jobs", "2"]]


def test_a_genuinely_unknown_option_remains_unsupported(monkeypatch):
    monkeypatch.setattr(options, "_OPTION_SUPPORT_CACHE", {})
    monkeypatch.setattr(options.subprocess, "run", lambda *a, **k:
                        subprocess.CompletedProcess([], 50, b"", b"unknown option '--jobs'"))
    assert not options._xrdcp_supports_option("--jobs")


def test_cached_probe_cannot_launch_another_client(monkeypatch):
    monkeypatch.setattr(options, "_OPTION_SUPPORT_CACHE", {"--jobs": True})

    def forbidden(*args, **kwargs):
        raise AssertionError("one probe per option")

    monkeypatch.setattr(options.subprocess, "run", forbidden)
    assert options._xrdcp_supports_option("--jobs")
