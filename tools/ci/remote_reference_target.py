"""Lease private native BriX endpoints for an external official-client check.

Run as an ordinary test account in the server VM. Endpoints bind loopback;
transport them with an operator-owned SSH forward, never a public listener.
This does not run, replace, or certify the native full testsuite.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import sys
import tempfile
import time


def _arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path, required=True)
    parser.add_argument('--scratch-base', type=Path, required=True)
    parser.add_argument('--port-start', type=int, default=2000)
    parser.add_argument('--lease-seconds', type=int, default=600)
    parser.add_argument('--with-gsi', action='store_true')
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        parser.error('run under a dedicated non-root, non-wheel test account')
    if not 1 <= args.lease_seconds <= 1800:
        parser.error('--lease-seconds must be between 1 and 1800')
    if not 1024 <= args.port_start <= 30000:
        parser.error('--port-start must fit a private nonprivileged test lane')
    args.build_dir = args.build_dir.resolve(strict=True)
    args.scratch_base = args.scratch_base.resolve(strict=True)
    return args


def _configure(args):
    """Pin a private root before any of the test framework's settings load."""
    root = Path(tempfile.mkdtemp(prefix='rr-', dir=args.scratch_base))
    repo = Path(__file__).resolve().parents[2]
    sys.path[:0] = [str(repo / 'tests'), str(repo / 'brixtest/src')]
    from tools.ci.freebsd_native import validation_environment

    environment = validation_environment(args.build_dir, root)
    environment.update(TEST_PORT_START=str(args.port_start), TEST_MOCK_PORT_WIDTH='1024',
                       TEST_HOST='127.0.0.1', TEST_BIND_HOST='127.0.0.1',
                       TEST_SKIP_SERVER_SETUP='1')
    os.environ.update(environment)
    return root


def _digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def _identity(args, root):
    """Describe actual native artifacts, not the external client's platform."""
    import psutil

    modules = args.build_dir / 'modules'
    names = ('nginx', 'ngx_stream_module.so', 'ngx_stream_brix_module.so',
             'ngx_http_brix_xrdhttp_filter_module.so')
    return dict(schema_version=1, mode='external-reference-target',
                native_full_suite=False, root=str(root), pid=os.getpid(),
                process_started=psutil.Process().create_time(),
                server=dict(system=platform.system(), release=platform.release(),
                            machine=platform.machine(), uid=os.geteuid(),
                            artifacts={name: _digest(modules / name) for name in names}))


def _specs(root, include_gsi):
    """Reuse real registry templates; never relax server credential policy."""
    from ephemeral_port import free_port
    from server_registry import NginxInstanceSpec
    from settings import BIND_HOST, CA_CERT, SERVER_CERT, SERVER_KEY

    data = root / 'data'
    data.mkdir()
    payload = hashlib.shake_256(b'BriX external reference fixture').digest(4 * 1024 * 1024 + 37)
    (data / 'reference.bin').write_bytes(payload)
    (root / 'outside-sentinel').write_bytes(b'not exported\n')
    profiles = [('anonymous', 'none', ''), ('readonly', 'none', '')]
    if include_gsi:
        certs = (f'        brix_certificate {SERVER_CERT};\n'
                 f'        brix_certificate_key {SERVER_KEY};\n'
                 f'        brix_trusted_ca {CA_CERT};\n')
        profiles += [('gsi', 'gsi', certs), ('gsi-tls', 'gsi', certs + '        brix_tls on;\n')]
    for name, auth, security in profiles:
        write = 'off' if name == 'readonly' else 'on'
        yield name, NginxInstanceSpec(
            name='remote-reference-' + name, template='nginx_min_sec.conf',
            port=free_port(BIND_HOST), protocol='root', data_root=str(data),
            readiness='tcp', template_values={'BIND_HOST': BIND_HOST,
                'TLS_LINES': security + f'        brix_allow_write {write};\n',
                'AUTH': auth, 'MIN_SEC': 'none'})


def _stop_signal(_number, _frame):
    raise SystemExit(0)


def _credentials(root, evidence):
    """Publish only ephemeral proxy/public-CA paths, never CA or server keys."""
    from brix_suite.security.pki import blitz_test_pki
    from brix_suite.launcher.control_operations import public_cadir
    from settings import PKI_DIR, PROXY_STD

    blitz_test_pki()
    public_cadir(PKI_DIR, root / 'public-ca')
    evidence['credentials'] = dict(ca_dir=str(root / 'public-ca'), proxy=PROXY_STD)


def _lease(seconds):
    """A disconnected controller must not leave a permanent validation server."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))


def _final_evidence(root, evidence):
    """Retain native integrity checks after this harness has stopped."""
    fixture = evidence.get('fixture')
    if fixture is None:
        return
    record = dict(native_full_suite=False, servers_closed=True,
        reference_fixture_unchanged=_digest(root / 'data/reference.bin') == fixture['sha256'],
        outside_sentinel_unchanged=(root / 'outside-sentinel').read_bytes() == b'not exported\n',
        remaining_test_namespaces=sorted(path.name for path in (root / 'data').iterdir()
                                         if path.name.startswith('.brix-external-')))
    (root / 'final.json').write_text(json.dumps(record, indent=2) + '\n')


def serve(args):
    """Lease only this harness; preserve its evidence after bounded teardown."""
    root = _configure(args)
    from server_launcher import LifecycleHarness

    for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(number, _stop_signal)
    harness = LifecycleHarness()
    evidence = _identity(args, root)
    try:
        with redirect_stdout(sys.stderr):
            if args.with_gsi:
                _credentials(root, evidence)
            endpoints = {name: harness.start(spec).port for name, spec in _specs(root, args.with_gsi)}
        evidence['endpoints'] = endpoints
        evidence['fixture'] = dict(path='/reference.bin', size=(root / 'data/reference.bin').stat().st_size,
                                   sha256=_digest(root / 'data/reference.bin'))
        (root / 'ready.json').write_text(json.dumps(evidence, indent=2) + '\n')
        print(json.dumps(evidence), flush=True)
        _lease(args.lease_seconds)
    finally:
        with redirect_stdout(sys.stderr):
            harness.close()
        _final_evidence(root, evidence)


def main(argv=None):
    from tools.logging_support import diagnostic

    args = _arguments(argv)
    try:
        serve(args)
    except (OSError, RuntimeError) as error:
        diagnostic('ERROR', __file__, 'external_target_failed', str(error))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
