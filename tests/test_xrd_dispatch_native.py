"""Execute the real umbrella CLI and assert its sibling argv and refusals."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest

from brix_suite.client_build import client_make, client_run
from cmdscripts import fake_exec

pytestmark = [pytest.mark.serial,
              pytest.mark.skipif(sys.platform != 'linux', reason='GNU exec wrapping')]


@pytest.fixture(scope='module')
def dispatch_binary(tmp_path_factory):
    """Link a private CLI with the configured objects and real exec instrumentation."""
    root = Path(__file__).resolve().parents[1]
    output = tmp_path_factory.mktemp('xrd-dispatch-build')
    flags = ['--coverage', '-Wl,-z,relro', '-Wl,-z,now', '-Wl,-z,noexecstack',
             '-Wl,--wrap=execv', '-Wl,--wrap=execvp', '-Wl,--wrap=execve',
             '-Wl,--wrap=_exit',
             '-Wl,-u,__gcov_dump', '-Wl,-u,__gcov_reset',
             str(root / 'tests/c/coverage_exec_finite.c')]
    result = client_make(root / 'client', '-n', 'xrd', f'BINDIR={output}',
                         'LDFLAGS=' + ' '.join(flags),
                         capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stdout + result.stderr
    command = private_link_command(result.stdout, output / 'xrd')
    linked = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert linked.returncode == 0, linked.stdout + linked.stderr
    assert (output / 'xrd').is_file()
    return output / 'xrd'


def private_link_command(plan, binary):
    """Select only the configured private executable link, without rebuilding objects."""
    matches = list(private_link_candidates(plan, binary))
    assert len(matches) == 1, plan
    return matches[0]


def private_link_candidates(plan, binary):
    """Ignore make diagnostics before parsing candidate compiler commands."""
    for line in plan.splitlines():
        if str(binary) not in line:
            continue
        command = shlex.split(line)
        if targets_private_binary(command, binary):
            yield command


def targets_private_binary(command, binary):
    """Distinguish the link recipe from prerequisite compilation commands."""
    return '-o' in command and str(binary) in command and '-c' not in command


def compile_client_contract(root, output, driver, wrappers=()):
    """Link a finite main to the client's configured library and dependency closure."""
    binary = output / 'xrdcksum'
    plan = client_make(root / 'client', '-n', 'xrdcksum', f'BINDIR={output}',
                       capture_output=True, text=True, timeout=120)
    assert plan.returncode == 0, plan.stdout + plan.stderr
    command = private_link_command(plan.stdout, binary)
    command[command.index('apps/cksum/xrdcksum.o')] = str(root / driver)
    command = [argument for argument in command
               if not argument.startswith('apps/cksum/')]
    command += ['-Wl,--wrap=' + name for name in wrappers]
    result = client_run(root / 'client', command, cwd=root / 'client',
                        capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr
    return binary


@pytest.fixture
def private_cli(dispatch_binary, tmp_path):
    """Keep sibling resolution and aliases entirely within each test's directory."""
    binary = tmp_path / 'xrd'
    shutil.copy2(dispatch_binary, binary)
    (tmp_path / 'brix-xrd').symlink_to(binary)
    config = tmp_path / 'xrdrc'
    config.write_text('')
    return tmp_path, dict(os.environ, XRDRC=str(config), PATH=str(tmp_path))


def dispatch(private_cli, arguments, tools=(), prefixed=False):
    """Install explicit argv-recording children, then run the real umbrella."""
    directory, environment = private_cli
    for tool in tools:
        fake_exec.install(directory, tool, echo_tool_argv=True)
    name = 'brix-xrd' if prefixed else 'xrd'
    result = subprocess.run([str(directory / name), *arguments],
                            env=environment, capture_output=True, text=True, timeout=10)
    return result


@pytest.mark.parametrize('arguments,tool,forwarded', [
    (['cp', 'source', 'destination', '--force'], 'xrdcp', ['source', 'destination', '--force']),
    (['copy', 'source', 'destination'], 'xrdcp', ['source', 'destination']),
    (['get', 'source'], 'xrdcp', ['source', '.']),
    (['get', 'source', 'destination'], 'xrdcp', ['source', 'destination']),
    (['put', 'source', 'destination'], 'xrdcp', ['source', 'destination']),
    (['sync', 'source', 'destination', '--verbose'], 'xrdcp',
     ['-r', '--sync', 'source', 'destination', '--verbose']),
    (['diag', 'check', 'endpoint'], 'xrddiag', ['check', 'endpoint']),
    (['replicas', 'endpoint'], 'xrdmapc', ['endpoint']),
    (['inventory', 'backend'], 'xrdstorascan', ['inventory', 'backend']),
    (['verify', 'backend'], 'xrdstorascan', ['verify', 'backend']),
    (['drift', 'backend'], 'xrdstorascan', ['drift', 'backend']),
    (['inspect', 'backend'], 'xrdstorascan', ['inspect', 'backend']),
])
def test_dispatch_preserves_exact_argument_order(private_cli, arguments, tool, forwarded):
    result = dispatch(private_cli, arguments, [tool])
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ['TOOL=' + tool, *['ARG=' + arg for arg in forwarded]]


@pytest.mark.parametrize('scheme,port', [('root', 1094), ('roots', 1094),
                                      ('http', 80), ('https', 443), ('dav', 80), ('davs', 443)])
def test_filesystem_urls_map_to_one_endpoint(private_cli, scheme, port):
    origin = scheme + '://origin.invalid'
    result = dispatch(private_cli, ['mv', origin + '/a', origin + '/b'], ['xrdfs'])
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ['TOOL=xrdfs',
        f'ARG={scheme}://origin.invalid:{port}', 'ARG=mv', 'ARG=/a', 'ARG=/b']


def test_flags_and_bare_endpoints_keep_their_positions(private_cli):
    result = dispatch(private_cli, ['ls', 'origin.invalid:12000', '-l', '/data'], ['xrdfs'])
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ['TOOL=xrdfs', 'ARG=origin.invalid:12000',
                                        'ARG=ls', 'ARG=-l', 'ARG=/data']


@pytest.mark.parametrize('target', ['root://other.invalid/a', 'root://origin.invalid:12000/a',
                                   'https://other.invalid/a'])
def test_cross_endpoint_operands_are_rejected_before_exec(private_cli, target):
    result = dispatch(private_cli, ['mv', 'root://origin.invalid/a', target], ['xrdfs'])
    assert result.returncode == 50 and result.stdout == ''
    assert 'every path must be on the same endpoint' in result.stderr


@pytest.mark.parametrize('tools,expected', [
    (['brix-xrdcp', 'xrdcp'], 'brix-xrdcp'), (['xrdcp'], 'xrdcp'),
])
def test_compat_prefix_prefers_matching_sibling_then_falls_back(private_cli, tools, expected):
    result = dispatch(private_cli, ['cp', 'a', 'b'], tools, prefixed=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ['TOOL=' + expected, 'ARG=a', 'ARG=b']


@pytest.mark.parametrize('arguments', [['get'], ['put', 'only-source'], ['sync', 'only-source'],
                                      ['stat'], ['misspelled-command']])
def test_bad_invocations_do_not_launch_a_child(private_cli, arguments):
    result = dispatch(private_cli, arguments, ['xrdcp', 'xrdfs'])
    assert result.returncode == 50 and result.stdout == ''


def test_missing_sibling_reports_127(private_cli):
    result = dispatch(private_cli, ['cp', 'a', 'b'])
    assert result.returncode == 127
    assert 'cannot run xrdcp' in result.stderr
