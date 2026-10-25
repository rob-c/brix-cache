"""Native coverage prerequisites cannot silently mask malformed fixtures."""
from pathlib import Path
import re

import pytest

import test_endsess_session_scope as endsess
import test_lazy_file_table_preopen as lazy
import test_path_confinement as confinement


@pytest.mark.parametrize('module', [endsess, lazy], ids=['endsess', 'handles'])
def test_overwrite_fixture_flag_matches_authoritative_wire_header(module):
    """Success: both probes use overwrite, never the unrelated force bit."""
    flags = Path(__file__).resolve().parents[1] / 'src/protocols/root/protocol/flags.h'
    value = re.search(r'^#define kXR_delete\s+(0x[0-9a-fA-F]+)', flags.read_text(), re.M)
    assert value is not None
    assert module.kXR_delete == int(value[1], 16) == 0x0002


@pytest.mark.parametrize('available', [True, False])
def test_webdav_readiness_is_checked_at_fixture_execution(monkeypatch, available):
    """A missing listener remains a real skip, but collection never probes it."""
    calls = []
    monkeypatch.setattr(confinement, '_webdav_available', lambda: calls.append(True) or available)
    if available:
        confinement.require_webdav.__wrapped__()
    else:
        with pytest.raises(pytest.skip.Exception, match='not reachable'):
            confinement.require_webdav.__wrapped__()
    assert calls == [True]


def test_traversal_group_requires_runtime_webdav_fixture():
    """Security-negative: traversal checks cannot be discarded at import time."""
    marks = confinement.TestWebDavTraversal.pytestmark
    assert any(mark.name == 'usefixtures' and 'require_webdav' in mark.args for mark in marks)
    assert not any(mark.name == 'skipif' for mark in marks)


def test_cache_evict_uses_canonical_official_client_discovery():
    """FreeBSD's /usr/local/bin tool is independent of BriX's own client path."""
    import official_interop_lib
    import test_cache_evict_cmd

    assert test_cache_evict_cmd.STOCK_XRDFS == official_interop_lib.OFF_XRDFS


def _helm_workflow_command():
    import yaml

    root = Path(__file__).resolve().parents[1]
    workflow = yaml.load((root / '.github/workflows/freebsd.yml').read_text(),
                         Loader=yaml.BaseLoader)
    run = workflow['jobs']['native']['steps'][1]['with']['run']
    command = next(line for line in run.splitlines() if 'go install helm.sh/' in line)
    return run, command


def test_freebsd_chart_renderer_is_pinned_and_on_the_validation_path():
    """Success: clean full CI enables the same native render exercised locally."""
    run, command = _helm_workflow_command()
    assert 'helm.sh/helm/v4/cmd/helm@v4.3.1' in command
    assert 'export PATH="/home/brixvalidate/helm-deps/bin:' in run
    assert run.index(command) > run.index("if [ '${{ inputs.test_level || 'contracts' }}' = full ]; then")


def test_freebsd_chart_renderer_build_failures_are_not_waived():
    """Error: bootstrap and toolchain failures stop the full validation setup."""
    run, command = _helm_workflow_command()
    assert 'set -eu' in run
    assert 'GOTOOLCHAIN=local' in command
    assert not any(fragment in command for fragment in ('||', '@latest', '; true'))


def test_freebsd_chart_renderer_never_builds_as_root_or_without_resource_bounds():
    """Security-negative: only the dedicated identity owns bounded build work."""
    _run, command = _helm_workflow_command()
    assert command.strip().startswith('su -l brixvalidate -c ')
    assert 'GOBIN=/home/brixvalidate/helm-deps/bin' in command
    assert all(value in command for value in ('GOMAXPROCS=2', 'GOMEMLIMIT=2GiB', 'GOFLAGS=-p=2'))
