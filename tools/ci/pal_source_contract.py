"""Source parsing and build selection for the PAL ownership guard.

Only concrete common-API bodies are counted. This intentionally does not claim
to preprocess every feature branch, compare C types, or certify runtime support.
"""

from __future__ import annotations

import os
import re
from pathlib import Path


HOSTS = ('linux', 'darwin', 'windows')
COMMON_API = (
    'brix_plat_name', 'brix_plat_version', 'brix_plat_arch',
    'brix_plat_anon_fd', 'brix_plat_fadvise', 'brix_plat_fsync_data',
    'brix_plat_sendfile', 'brix_plat_random', 'brix_plat_getxattr',
    'brix_plat_setxattr', 'brix_plat_removexattr', 'brix_plat_listxattr',
    'brix_plat_execvpe',
)
INLINE_API = tuple('brix_plat_' + name for name in (
    'htobe64', 'be64toh', 'htobe32', 'be32toh', 'htobe16', 'be16toh'))
PUBLIC_HEADERS = {'platform.h', 'platform_api.h'}
OWNER_ROOTS = (Path('src/platform'), Path('client/lib/platform'),
               Path('shared/cvmfs/platform'))
NONCODE = re.compile(r'''/\*.*?\*/|//[^\n]*|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*' ''',
                     re.S | re.X)
API_NAME = re.compile(r'\bbrix_(?:plat|platform)_[A-Za-z0-9_]+\s*\(')
INCLUDE = re.compile(r'^[ \t]*#[ \t]*include\s*["<]([^">]+)[">]', re.M)
SOURCE = re.compile(r'\$ngx_addon_dir/([^\s"\\]+\.c)')
HOST_BRANCH = re.compile(
    r'^(?:if|elif) \[ "\$BRIX_PLATFORM_(LINUX|DARWIN|WINDOWS)" = "1" \]; then\s*$',
    re.M)


def _blank(token):
    return ''.join('\n' if char == '\n' else ' ' for char in token)


def mask_noncode(content, keep_literals=False):
    def replace(match):
        token = match.group()
        if keep_literals and token[0] in "\"'":
            return token
        return _blank(token)
    return NONCODE.sub(replace, content)


def _closing_parenthesis(content, opening):
    depth = 0
    for position in range(opening, len(content)):
        char = content[position]
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                return position
    return None


def definitions(content):
    """PAL function bodies, excluding calls, prototypes, comments and macros."""
    code = mask_noncode(content)
    code = re.sub(r'^\s*#(?:[^\n]*\\\n)*[^\n]*',
                  lambda match: _blank(match.group()), code, flags=re.M)
    found = []
    for match in API_NAME.finditer(code):
        close = _closing_parenthesis(code, match.end() - 1)
        if close is not None and code[close + 1:].lstrip().startswith('{'):
            name = match.group().split('(')[0].strip()
            found.append((name, code.count('\n', 0, match.start()) + 1))
    return found


def include_targets(content):
    code = mask_noncode(content, keep_literals=True)
    return [(code.count('\n', 0, match.start()) + 1, match.group(1))
            for match in INCLUDE.finditer(code)]


def is_owner(path):
    return any(path.is_relative_to(root) for root in OWNER_ROOTS)


def private_pal_header(path, target):
    """Resolve quoted relative and repository include-root PAL paths."""
    candidates = (path.parent / target, Path('src') / target, Path(target))
    for candidate in candidates:
        normalized = Path(os.path.normpath(candidate))
        if normalized.is_relative_to(Path('src/platform')):
            return normalized.parent != Path('src/platform') or normalized.name not in PUBLIC_HEADERS
    return False


def repository_root(directory):
    directory = directory.resolve()
    if directory.name == 'src' and (directory.parent / 'config').is_file():
        return directory.parent
    return directory


def _production_path(path):
    return path.suffix in ('.c', '.h') and not path.stem.endswith('_unittest')


def production_files(root):
    files = []
    for name in ('src', 'shared', 'client'):
        base = root / name
        if not base.is_dir():
            raise ValueError(f'missing production directory: {base}')
        files.extend(path for path in base.rglob('*') if _production_path(path))
    return sorted(files)


def _selection_block(config):
    marker = re.search(r'^brix_shared_platform_srcs=""\n', config, re.M)
    if marker is None:
        raise ValueError('config has no host PAL source selector')
    start = marker.start()
    end = config.find('\nfi\n', start)
    if end < 0:
        raise ValueError('config host PAL source selector is unterminated')
    return config[start:end], end + 4


def _module_sources(config, position):
    match = re.search(r'\bngx_module_srcs="([^"]*)"', config[position:])
    if match is None:
        raise ValueError('config has no module source consumer after PAL selector')
    body = match.group(1)
    for variable in ('brix_platform_srcs', 'brix_shared_platform_srcs'):
        if not re.search(r'\$' + variable + r'\b', body):
            raise ValueError(f'config module source consumer omits ${variable}')
    runtime = 'src/platform/platform_runtime.c'
    if runtime not in SOURCE.findall(body):
        raise ValueError('config module source consumer omits PAL runtime')
    return runtime


def _assigned_sources(block, variable, required=True):
    match = re.search(r'\b' + variable + r'="([^"]*)"', block)
    if match is None:
        if required:
            raise ValueError(f'config does not assign {variable}')
        return []
    body = match.group(1)
    paths = SOURCE.findall(body)
    if SOURCE.sub('', body).replace('\\', '').strip():
        raise ValueError(f'unsupported expression in {variable}')
    return paths


def _valid_host_source(host, path):
    if '..' in Path(path).parts or not _production_path(Path(path)):
        return False
    if Path(path).is_relative_to(Path('src/platform') / host):
        return True
    return host == 'linux' and path == 'shared/cvmfs/platform/platform.c'


def _host_sources(block, branch, end):
    host = branch.group(1).lower()
    body = block[branch.end():end]
    paths = _assigned_sources(body, 'brix_platform_srcs')
    paths += _assigned_sources(body, 'brix_shared_platform_srcs', required=False)
    if not paths:
        raise ValueError(f'{host}: empty PAL source selection')
    for path in paths:
        if not _valid_host_source(host, path):
            raise ValueError(f'{host}: foreign or unsupported PAL source owner: {path}')
    return host, paths


def configured_sources(root):
    config = re.sub(r'^\s*#[^\n]*', '', (root / 'config').read_text(), flags=re.M)
    block, position = _selection_block(config)
    branches = list(HOST_BRANCH.finditer(block))
    runtime = _module_sources(config, position)
    selection = {}
    for index, branch in enumerate(branches):
        end = branches[index + 1].start() if index + 1 < len(branches) else len(block)
        host, paths = _host_sources(block, branch, end)
        if host in selection:
            raise ValueError(f'{host}: duplicate PAL source selector')
        selection[host] = [runtime, *paths]
    if set(selection) != set(HOSTS):
        raise ValueError('config must select each Linux, Darwin and Windows PAL once')
    return selection
