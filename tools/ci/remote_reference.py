"""Opt-in official-client validation of BriX running on another platform.

This report is deliberately separate from native_suite.py: a passing external
oracle cannot erase a failing native reference dependency or certify a full
suite. The URL must name a disposable writable lab export.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from tools.ci.remote_reference_checks import ReferenceContext, cases, execute_case
from tools.logging_support import diagnostic


def endpoint(value):
    """Only a bare lab endpoint: never echo userinfo, tokens or other queries."""
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError('invalid endpoint authority') from error
    if parsed.scheme not in ('root', 'roots') or not parsed.hostname:
        raise argparse.ArgumentTypeError('expected root://host:port/ or roots://host:port/')
    _endpoint_authority(parsed)
    if parsed.path not in ('', '/', '//'):
        raise argparse.ArgumentTypeError('endpoint must name only the disposable export root')
    if any(ord(c) < 33 for c in value):
        raise argparse.ArgumentTypeError('endpoint must not contain control characters or spaces')
    return value.rstrip('/')


def _endpoint_authority(parsed):
    """Refuse credentials and invalid ports before an endpoint can be dialed."""
    if any((parsed.username, parsed.password, parsed.query, parsed.fragment)):
        raise argparse.ArgumentTypeError('endpoint credentials/queries are forbidden; use private credential files')
    try:
        valid_port = parsed.port is not None and 1 <= parsed.port <= 65535
    except ValueError as error:
        raise argparse.ArgumentTypeError('invalid endpoint port') from error
    if not valid_port:
        raise argparse.ArgumentTypeError('an explicit valid endpoint port is required')


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    if not __debug__:
        parser.error('assertions must be enabled for validation; do not run with -O')
    parser.add_argument('--url', required=True, type=endpoint)
    parser.add_argument('--read-only-url', type=endpoint)
    parser.add_argument('--server-evidence', type=Path, required=True)
    parser.add_argument('--xrdcp', type=Path, required=True)
    parser.add_argument('--xrdfs', type=Path, required=True)
    parser.add_argument('--client-python', type=Path, default=Path(sys.executable))
    parser.add_argument('--profile', choices=('anonymous', 'gsi', 'gsi-tls'), default='anonymous')
    parser.add_argument('--proxy', type=Path)
    parser.add_argument('--ca-dir', type=Path)
    parser.add_argument('--timeout', type=int, default=60)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if not 1 <= args.timeout <= 120:
        parser.error('--timeout must be between 1 and 120 seconds')
    _profile_arguments(parser, args)
    return args


def _profile_arguments(parser, args):
    """Authenticated profiles must have explicit credentials and transport."""
    if args.profile == 'anonymous':
        return
    if None in (args.proxy, args.ca_dir):
        parser.error('authenticated profiles require --proxy and --ca-dir')
    if args.profile == 'gsi-tls' and urlsplit(args.url).scheme != 'roots':
        parser.error('gsi-tls must use roots://, not a cleartext URL')


def server_evidence(path):
    """Keep native provenance explicit and bounded, not inferred from the client."""
    if path.stat().st_size > 65536:
        raise ValueError('server evidence exceeds the 64 KiB limit')
    evidence = json.loads(path.read_text())
    assert evidence['schema_version'] == 1
    assert evidence['mode'] == 'external-reference-target' and evidence['native_full_suite'] is False
    _server_identity(evidence['server'])
    assert Path(evidence['root']).is_absolute()
    assert 0 < evidence['fixture']['size'] <= 8 * 1024 * 1024
    assert re.fullmatch('[0-9a-f]{64}', evidence['fixture']['sha256'])
    return evidence


def _server_identity(server):
    """Reject incomplete native artifact evidence rather than infer identity."""
    assert server['system'] and server['uid'] != 0
    digests = list(server['artifacts'].values())
    assert len(digests) >= 2
    assert all(re.fullmatch('[0-9a-f]{64}', value) for value in digests)


def _bindings_provenance(python, directory, timeout):
    """Inspect public module metadata in isolation, never its implementation."""
    code = (
        'import json,platform,sys,XRootD,pyxrootd.client; '
        'from importlib.metadata import version; '
        'print(json.dumps(dict(system=platform.system(), machine=platform.machine(), '
        'python=sys.executable, package=XRootD.__file__, '
        'extension=pyxrootd.client.__file__, version=version("xrootd"))))'
    )
    env = dict(os.environ, PYTHONPATH='', PYTHONDONTWRITEBYTECODE='1')
    result = subprocess.run([str(python), '-c', code], cwd=directory, env=env,
                            capture_output=True, text=True, timeout=timeout, check=True)
    record = json.loads(result.stdout)
    assert record['system'] in ('Darwin', 'Linux'), 'use the working external macOS/Linux oracle'
    assert Path(record['extension']).is_file(), 'native reference extension is missing'
    assert not (Path(record['package']).parent / '_SHADOW_MARKER').exists(), 'shadow package is not an oracle'
    with Path(record['extension']).open('rb') as source:
        record['sha256'] = hashlib.file_digest(source, 'sha256').hexdigest()
    return record


def official_provenance(args, directory):
    """Fail closed on missing tools, failed inspectors or a BriX substitution."""
    from lib_py.util import linked_libraries

    tools = {}
    for name in ('xrdcp', 'xrdfs'):
        binary = getattr(args, name).resolve(strict=True)
        assert os.access(binary, os.X_OK), f'{name} is not executable'
        linkage = linked_libraries(str(binary), check=True)
        assert re.search(r'libXrdCl[.\-]', linkage), f'{name} is not linked to the independent XrdCl'
        with binary.open('rb') as source:
            tools[name] = dict(path=str(binary), sha256=hashlib.file_digest(source, 'sha256').hexdigest())
        setattr(args, name, binary)
    version = subprocess.run([str(args.xrdcp), '--version'], capture_output=True,
                             text=True, timeout=args.timeout, check=True)
    banner = (version.stdout + version.stderr).strip()
    assert 'brix' not in banner.lower(), 'BriX cannot serve as its own reference'
    match = re.search(r'\bv?(\d+\.\d+)', banner)
    assert match, 'official client did not report a version'
    bindings = _bindings_provenance(args.client_python, directory, args.timeout)
    assert bindings['version'].startswith(match.group(1) + '.'), 'CLI/Python reference versions do not match'
    return dict(system=platform.system(), machine=platform.machine(), tools=tools,
                version=banner, bindings=bindings)


def _client_environment(args, directory):
    """Do not accidentally borrow the operator's real Grid credentials."""
    _isolate_credentials()
    os.environ['TEST_XRDCL_PYTHON'] = str(args.client_python.resolve(strict=True))
    os.environ['XRD_NETWORKSTACK'] = 'IPv4'
    os.environ['XRDCL_PROXY_TIMEOUT'] = str(args.timeout)
    absent = str(directory / 'no-operator-credentials')
    for name in ('X509_USER_PROXY', 'X509_USER_CERT', 'X509_USER_KEY'):
        os.environ[name] = absent
    os.environ['XrdSecPROTOCOL'] = 'gsi' if args.profile != 'anonymous' else 'unix'
    if args.profile != 'anonymous':
        _private_credentials(args)


def _isolate_credentials():
    """Clear ambient credential overrides and forbid TLS downgrade controls."""
    for name in list(os.environ):
        if name.startswith(('X509_', 'XrdSec', 'BEARER_TOKEN', 'SCITOKENS_', 'XRD_SEC')):
            os.environ.pop(name)
    os.environ.update(XRD_NOTLSOK='0', XRD_TLSNODATA='0')


def _private_credentials(args):
    """Only an explicitly selected owner-private proxy may authenticate."""
    proxy = args.proxy.resolve(strict=True)
    assert proxy.is_file() and proxy.stat().st_uid == os.geteuid()
    assert proxy.stat().st_mode & 0o077 == 0, 'proxy must be private to its owner'
    os.environ['X509_USER_PROXY'] = str(proxy)
    os.environ['X509_USER_CERT'] = str(proxy)
    os.environ['X509_USER_KEY'] = str(proxy)
    os.environ['X509_CERT_DIR'] = str(args.ca_dir.resolve(strict=True))


def _client(args):
    from brix_suite.clients import xrdcl
    from brix_suite.clients.xrdcl import worker_link

    selected = worker_link._worker_python()
    assert selected and Path(selected).resolve() == args.client_python.resolve(), 'reference interpreter fallback is forbidden'
    return xrdcl


def write_reports(directory, record, outcomes):
    """JUnit and JSON include every outcome, never only the passing subset."""
    counts = {name: sum(item['outcome'] == name for item in outcomes)
              for name in ('passed', 'failed', 'errors')}
    counts.update(tests=len(outcomes), skipped=0)
    record.update(counts=counts, cases=outcomes, native_full_suite=False)
    (directory / 'summary.json').write_text(json.dumps(record, indent=2) + '\n')
    suite = ET.Element('testsuite', name='external-reference-' + record['profile'],
                       tests=str(counts['tests']), failures=str(counts['failed']),
                       errors=str(counts['errors']), skipped='0')
    for outcome in outcomes:
        _junit_case(suite, record['profile'], outcome)
    ET.ElementTree(suite).write(directory / 'results.xml', encoding='utf-8', xml_declaration=True)
    return not (counts['failed'] or counts['errors'])


def _junit_case(suite, profile, outcome):
    """Keep every failure/error in the machine-readable external verdict."""
    case = ET.SubElement(suite, 'testcase', classname='external-reference.' + profile,
                         name=outcome['name'], time=str(outcome['seconds']))
    if outcome['outcome'] != 'passed':
        tag = 'failure' if outcome['outcome'] == 'failed' else 'error'
        ET.SubElement(case, tag, message=outcome['detail']).text = outcome['detail']


def run(args, directory):
    """All mutations are opt-in and confined to a newly created lab namespace."""
    repo = Path(__file__).resolve().parents[2]
    sys.path[:0] = [str(repo / 'tests'), str(repo / 'brixtest/src')]
    outcomes, record = [], dict(mode='external-reference', profile=args.profile,
                               endpoint=args.url, native_full_suite=False)
    context = None
    try:
        _client_environment(args, directory)
        record['server_evidence'] = server_evidence(args.server_evidence)
        record['reference'] = official_provenance(args, directory)
        context = ReferenceContext(args, record['server_evidence'], directory, _client(args))
        outcomes.append(execute_case('create-private-namespace', context.prepare))
        if outcomes[-1]['outcome'] == 'passed':
            for name, check in cases(context):
                outcome = execute_case(name, check)
                outcomes.append(outcome)
                diagnostic('INFO', __file__, 'external_reference_case', name + ': ' + outcome['outcome'])
    except Exception as error:
        outcomes.append(dict(name='reference-preflight', outcome='errors',
                             detail=type(error).__name__ + ': ' + str(error), seconds=0))
    finally:
        if context is not None:
            outcomes.append(execute_case('cleanup-owned-namespace', context.cleanup))
        from brix_suite.clients.xrdcl.worker_link import _shutdown_worker
        _shutdown_worker()
    return write_reports(directory, record, outcomes)


def main(argv=None):
    args = arguments(argv)
    args.output.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='external-reference-', dir=args.output))
    passed = run(args, directory)
    diagnostic('INFO' if passed else 'ERROR', __file__, 'external_reference_complete',
               f'profile={args.profile} reports={directory} native_full_suite=false')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
