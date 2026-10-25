#!/usr/bin/env python3
"""Build pinned, isolated native FreeBSD GFAL interoperability dependencies.

This builds GFAL2, its Python/CLI layer and Davix, NOT XRootD implementation
sources. The XRootD plugin links the native package's public reference API.
Nothing is installed into /usr/local or BriX's server/client build outputs.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools.logging_support import diagnostic  # noqa: E402


def source_releases():
    """Exact upstream archives tested by the native ARM64 dependency lab."""
    return (
        ('davix', 'ebf04ce538dd97d7fca57746c500ca439438d76c',
         '54a1a4e019f979c12b863c8a814b73c6f078955169ca028c3b29753facd37e6c'),
        ('gfal2', 'e301920ec26a1134d5003d189703bd5333875962',
         'a9cf6b3e45ce7333bb305fdb0c92926007359769cd935d8fbc9ca0613d3c8f0f'),
        ('gfal2-python', '4f6b29bde0c5603049d299967cdab2c2414ec6e6',
         '289c46d52cd97b818930325bdceb2005a0e9b10f35d122443aa06791cb739d82'),
        ('gfal2-util', '1041a9aa449d327bffb8f26810159ffd67f525d0',
         '2f2127144ff37856e9052ff1b58c16a3ae61f16c1d36ee3760bcc559414e21a6'),
    )


def _run(command, env, *, cwd=None):
    diagnostic('INFO', __file__, 'dependency_command', repr(command))
    subprocess.run(command, env=env, cwd=cwd, check=True, timeout=900)


def verify_archive(archive, expected, *, algorithm='sha256'):
    """Never extract or build bytes which differ from the pinned release."""
    with archive.open('rb') as stream:
        actual = hashlib.file_digest(stream, algorithm).hexdigest()
    if actual != expected:
        raise ValueError(f'checksum mismatch for {archive.name}: {actual}')


def _fetch_release(work, name, revision, checksum, env):
    archive = work / (name + '.tar.gz')
    _run(['curl', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
          '--max-time', '120', '-o', str(archive),
          f'https://api.github.com/repos/cern-fts/{name}/tarball/{revision}'], env)
    verify_archive(archive, checksum)
    source = work / 'source' / name
    source.mkdir(parents=True)
    _run(['tar', '-xzf', str(archive), '--strip-components=1', '-C', str(source)], env)
    return source


def _configure_build(work, name, options, jobs, env):
    source, build = work / 'source' / name, work / 'build' / name
    _run(['cmake', '-S', str(source), '-B', str(build), '-DCMAKE_BUILD_TYPE=Release',
          '-DCMAKE_POLICY_VERSION_MINIMUM=3.5', *options], env)
    _run(['cmake', '--build', str(build), '--parallel', str(jobs)], env)
    return build


def _install(build, env):
    _run(['cmake', '--install', str(build)], env)


def _davix_options(prefix):
    return ['-DCMAKE_INSTALL_PREFIX=' + str(prefix),
            '-DCMAKE_INSTALL_RPATH=' + str(prefix / 'lib'),
            '-DCMAKE_SHARED_LINKER_FLAGS=-L/usr/local/lib',
            '-DCMAKE_EXE_LINKER_FLAGS=-L/usr/local/lib',
            '-DUUID_LIBRARY:FILEPATH=/usr/local/lib/libuuid.so',
            '-DENABLE_THIRD_PARTY_COPY=ON', '-DDAVIX_TESTS=OFF',
            '-DENABLE_TOOLS=ON', '-DENABLE_HTML_DOCS=OFF']


def _gfal_options(prefix, davix):
    """Select real native libraries, with complete installed loader closure."""
    links = '-L' + str(davix / 'lib') + ' -L/usr/local/lib'
    includes = '-include sys/socket.h -include netinet/in.h -include arpa/inet.h'
    options = ['-DCMAKE_INSTALL_PREFIX=' + str(prefix),
        '-DCMAKE_INSTALL_RPATH=' + ';'.join(map(str, (prefix / 'lib', prefix / 'lib64', davix / 'lib'))),
        '-DCMAKE_PREFIX_PATH=' + str(davix) + ';/usr/local',
        '-DCMAKE_C_FLAGS=' + includes, '-DCMAKE_CXX_FLAGS=' + includes,
        '-DXROOTD_LOCATION=/usr/local', '-DXROOTD_INCLUDE_DIR=/usr/local/include/xrootd',
        '-DCRYPTOPP_INCLUDE_DIRS=/usr/local/include/cryptopp', '-DDAVIX_LOCATION=' + str(davix),
        '-Dpkgcfg_lib_DAVIX_PKG_davix:FILEPATH=' + str(davix / 'lib/libdavix.so'),
        '-Dpkgcfg_lib_DAVIX_COPY_PKG_davix_copy:FILEPATH=' + str(davix / 'lib/libdavix_copy.so'),
        '-DSKIP_TESTS=ON']
    options.extend('-DCMAKE_' + kind + '_LINKER_FLAGS=' + links
                   for kind in ('SHARED', 'MODULE', 'EXE'))
    options.extend('-DPLUGIN_' + name + '=ON' for name in ('FILE', 'HTTP', 'XROOTD'))
    options.extend('-DPLUGIN_' + name + '=OFF'
                   for name in ('SFTP', 'SRM', 'DCAP', 'GRIDFTP', 'LFC', 'RFIO'))
    return options


def _apply_patch(work, name, env):
    patch = Path(__file__).resolve().parent / 'dependency-patches' / (name + '-freebsd.patch')
    _run(['patch', '-p1', '-i', str(patch)], env, cwd=work / 'source' / name)


def _build_gfal(work, prefix, davix, jobs, env):
    _apply_patch(work, 'gfal2', env)
    pkgdirs = (davix / 'lib/pkgconfig', davix / 'libdata/pkgconfig', Path('/usr/local/libdata/pkgconfig'))
    child = dict(env, PKG_CONFIG_PATH=os.pathsep.join(map(str, pkgdirs)))
    build = _configure_build(work, 'gfal2', _gfal_options(prefix, davix), jobs, child)
    _install(build, child)
    headers = list(prefix.rglob('gfal_api.h'))
    if len(headers) != 1:
        raise ValueError('installed GFAL API header location is ambiguous')
    _run(['install', '-m', '0644', str(work / 'source/gfal2/src/core/gfal_freebsd_xattr.h'),
          str(headers[0].parent / 'gfal_freebsd_xattr.h')], child)


def _python_options(prefix):
    return ['-DCMAKE_INSTALL_PREFIX=' + str(prefix),
        '-DPython_EXECUTABLE=' + str(prefix / 'bin/python3'),
        '-DCMAKE_INSTALL_RPATH=' + str(prefix / 'lib64') + ';/usr/local/lib',
        '-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON',
        '-DCMAKE_MODULE_LINKER_FLAGS=-L' + str(prefix / 'lib64') + ' -L/usr/local/lib',
        '-DSKIP_TESTS=ON', '-DBUILDDOCS=OFF']


def _python_site(prefix, env):
    result = subprocess.run([str(prefix / 'bin/python3'), '-c',
        'import sysconfig; print(sysconfig.get_path("platlib"))'],
        env=env, check=True, text=True, capture_output=True, timeout=20)
    site = Path(result.stdout.strip()).resolve()
    if not site.is_relative_to(prefix.resolve()):
        raise ValueError('Python extension destination escaped the private prefix')
    return site


def _build_frontends(work, prefix, jobs, env):
    _apply_patch(work, 'gfal2-python', env)
    child = dict(env, PKG_CONFIG_PATH=str(prefix / 'lib64/pkgconfig') + ':/usr/local/libdata/pkgconfig')
    _run([sys.executable, '-m', 'venv', '--system-site-packages', str(prefix)], child)
    build = _configure_build(work, 'gfal2-python', _python_options(prefix), jobs, child)
    _run(['install', '-m', '0755', str(build / 'src/python3/gfal2.so'),
          str(_python_site(prefix, child) / 'gfal2.so')], child)
    _run([str(prefix / 'bin/python3'), '-m', 'pip', 'install', '--no-deps',
          '--no-build-isolation', '--no-cache-dir', str(work / 'source/gfal2-util')], child)


def build_dependencies(work, jobs):
    """Work only in a newly created directory; never overwrite an old lab."""
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    env = dict(os.environ, PATH='/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin',
               CC='/usr/bin/cc', CXX='/usr/bin/c++', LD='/usr/bin/ld')
    for variable in ('LD_LIBRARY_PATH', 'PYTHONPATH', 'PYTHONHOME'):
        env.pop(variable, None)
    for name, revision, checksum in source_releases():
        _fetch_release(work, name, revision, checksum, env)
    davix, prefix = work / 'install/davix', work / 'install/gfal2'
    _install(_configure_build(work, 'davix', _davix_options(davix), jobs, env), env)
    _build_gfal(work, prefix, davix, jobs, env)
    _build_frontends(work, prefix, jobs, env)
    _run([str(prefix / 'bin/gfal2_version')], env)
    _run([str(prefix / 'bin/python3'), '-c', 'import gfal2; gfal2.creat_context()'], env)
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
        prefix = build_dependencies(args.work_dir.absolute(), args.jobs)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        diagnostic('ERROR', __file__, 'dependency_build_failed', str(error))
        return 1
    diagnostic('INFO', __file__, 'dependency_build_complete',
               f'private_prefix={prefix}; prepend {prefix / "bin"} to the suite PATH')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
