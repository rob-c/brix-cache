"""Finite contracts can link the exact configured, static server object graph.

Only the executable entry point is renamed in a private copy. Every production
implementation and its dependency stays real, including coverage counters.
"""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

import pytest

from lib_py.nginx_build import configured_compile_layout, configured_compiler_variables


def server_link_arguments(makefile):
    """Read one complete nginx link recipe; reject unresolved make expressions."""
    lines = Path(makefile).read_text().replace('\\\n', ' ').splitlines()
    recipes = [line.strip() for line in lines
               if line.strip().startswith('$(LINK) -o objs/nginx ')]
    if len(recipes) != 1:
        raise ValueError('Expected one configured nginx executable link recipe')
    arguments = shlex.split(recipes[0])[3:]
    validate_link_arguments(arguments)
    return arguments


def validate_link_arguments(arguments):
    """Never guess an unexpanded dependency or replace an ambiguous main."""
    if any('$' in argument for argument in arguments):
        raise ValueError('Unresolved expression in nginx link recipe')
    if arguments.count('objs/src/core/nginx.o') != 1:
        raise ValueError('Expected one nginx entry point object')


def checked_native_command(command, directory):
    """Keep compiler failures visible, with the selected SDK as the cwd."""
    result = subprocess.run(command, cwd=directory, capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr


def selected_server_sdk(root):
    """Select the explicit configured SDK and require a supported host."""
    if sys.platform != 'linux' or shutil.which('objcopy') is None:
        pytest.skip('The configured static server contract uses GNU objcopy')
    layout = configured_compile_layout(root, os.environ)
    if layout is None:
        pytest.skip('A configured static nginx SDK is required')
    return layout


@pytest.fixture(scope='module')
def server_native_compile(tmp_path_factory):
    """Link finite test mains without replacing any production dependency."""
    root = Path(__file__).resolve().parents[1]
    makefile, directory = selected_server_sdk(root)
    flags = configured_compiler_variables(makefile)
    arguments = server_link_arguments(makefile)
    if not any('addon/vfs/vfs_io_core.o' in item for item in arguments):
        pytest.skip('The selected nginx build uses dynamic brix modules')
    output = tmp_path_factory.mktemp('server-native')
    entry = output / 'nginx-test-entry.o'
    checked_native_command(['objcopy', '--redefine-sym',
                            'main=brix_test_nginx_main',
                            'objs/src/core/nginx.o', str(entry)], directory)
    arguments[arguments.index('objs/src/core/nginx.o')] = str(entry)

    def compile_program(name, driver, extra=()):
        """Compile the driver with this SDK and replay its actual link closure."""
        executable = output / name
        command = flags['CC'] + ['-U_FORTIFY_SOURCE'] + flags['CFLAGS']
        command += flags['ALL_INCS'] + [str(root / driver)]
        # Link recipes carry -O0 in coverage builds. Only this new driver is
        # compiled here; optimize it for glibc fortification while retaining
        # every production object's original instrumentation unchanged.
        command += arguments + list(extra) + ['-O1', '-o', str(executable)]
        checked_native_command(command, directory)
        return executable

    return compile_program


def test_server_link_recipe_retains_objects_and_libraries(tmp_path):
    makefile = tmp_path / 'Makefile'
    makefile.write_text('\t$(LINK) -o objs/nginx objs/src/core/nginx.o \\\n        objs/addon/vfs/vfs_io_core.o -Wl,-E -lssl\n')
    assert server_link_arguments(makefile) == [
        'objs/src/core/nginx.o', 'objs/addon/vfs/vfs_io_core.o', '-Wl,-E', '-lssl']


@pytest.mark.parametrize('recipe', ['', '$(LINK) -o objs/nginx other.o',
    '$(LINK) -o objs/nginx objs/src/core/nginx.o $(UNKNOWN)',
    '$(LINK) -o objs/nginx objs/src/core/nginx.o\n' * 2])
def test_incomplete_link_metadata_is_refused(tmp_path, recipe):
    makefile = tmp_path / 'Makefile'
    makefile.write_text(recipe)
    with pytest.raises(ValueError):
        server_link_arguments(makefile)
