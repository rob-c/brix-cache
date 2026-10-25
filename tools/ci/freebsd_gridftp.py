#!/usr/bin/env python3
"""Build a pinned, private native FreeBSD GridCF GridFTP test dependency.

No XRootD implementation sources are fetched or inspected. The GCT patch
handles POSIX's indeterminate passwd-buffer limit without disabling the
credential-owner lookup. System libraries and BriX outputs are not replaced.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.ci.freebsd_gfal import _run as run_dependency, verify_archive  # noqa: E402
from tools.logging_support import diagnostic  # noqa: E402


def source_release():
    """The release's published SHA512 is checked before extraction."""
    return ('https://repo.gridcf.org/gct6/sources/gct-6.2.1767880040.tar.gz',
            'b156d4dfe881978dde52d3c41b85cb30f5ff5fe8cd9bb457d2c55c92491f255f5'
            '94847543079ad5c1a019cfe4d89618ee2023125044f39b9ed09dbe899f4b9c4')


def _fetch(work, env):
    url, digest = source_release()
    archive = work / 'gct.tar.gz'
    run_dependency(['curl', '--fail', '--location', '--proto', '=https',
                    '--proto-redir', '=https', '--max-time', '120',
                    '-o', str(archive), url], env)
    verify_archive(archive, digest, algorithm='sha512')
    source = work / 'source'
    source.mkdir()
    run_dependency(['tar', '-xzf', str(archive), '--strip-components=1', '-C', str(source)], env)
    return source


def _verify_client(prefix, env, work):
    """Use actual copied bytes as the success oracle, not CLI version status."""
    # This upstream CLI prints a valid version but exits 1 for -version(s).
    # A local transfer must instead exit zero and preserve every byte.
    source, target = work / 'copy-probe-source', work / 'copy-probe-target'
    payload = bytes(range(256)) * 257
    source.write_bytes(payload)
    run_dependency([str(prefix / 'bin/globus-url-copy'), source.as_uri(), target.as_uri()], env)
    if target.read_bytes() != payload:
        raise ValueError('native GridFTP client local-copy probe changed bytes')


def build_dependency(work, jobs):
    """Refuse an existing work tree; build/install only the GridFTP subset."""
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    prefix = work / 'install'
    env = dict(os.environ, PATH='/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin',
               CC='/usr/bin/cc', CXX='/usr/bin/c++', MAKE='gmake', GLOBUS_LOCATION=str(prefix))
    for name in ('LD_LIBRARY_PATH', 'PYTHONPATH', 'PYTHONHOME'):
        env.pop(name, None)
    source = _fetch(work, env)
    patch = Path(__file__).resolve().parent / 'dependency-patches/gct-freebsd.patch'
    run_dependency(['patch', '--forward', '-p1', '-i', str(patch)], env, cwd=source)
    run_dependency(['./configure', '--prefix=' + str(prefix),
                    '--disable-gram5', '--disable-gsi-openssh'], env, cwd=source)
    run_dependency(['gmake', '-j' + str(jobs), 'gridftp'], env, cwd=source)
    # Upstream install-exec-local installs only components with built stamps.
    # Unbuilt GRAM/SSH/MyProxy packages are not pulled in by this target.
    run_dependency(['gmake', '-j' + str(jobs), 'install'], env, cwd=source)
    _verify_client(prefix, env, work)
    return prefix


def _arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir', type=Path, required=True, help='new private directory; must not exist')
    parser.add_argument('--jobs', type=int, default=1)
    args = parser.parse_args(argv)
    if platform.system() != 'FreeBSD' or os.geteuid() == 0:
        parser.error('run as the dedicated non-root test account on native FreeBSD')
    if not 1 <= args.jobs <= 4:
        parser.error('--jobs must be between 1 and 4')
    return args


def main(argv=None):
    args = _arguments(argv)
    try:
        prefix = build_dependency(args.work_dir.absolute(), args.jobs)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        diagnostic('ERROR', __file__, 'dependency_build_failed', str(error))
        return 1
    diagnostic('INFO', __file__, 'dependency_build_complete',
               f'private_prefix={prefix}; prepend {prefix / "bin"} to the suite PATH')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
