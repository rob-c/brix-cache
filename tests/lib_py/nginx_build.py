"""Locate compile metadata without mixing separately configured nginx builds."""

from pathlib import Path
import re
import shlex
import subprocess


def configured_compile_layout(root, environment):
    """Return (Makefile, compiler cwd) for CMake, source, or objects layouts.

    An explicit missing build is authoritative: never silently use objects
    from a different SDK. Relative include paths retain their configured cwd.
    """
    configured = environment.get("BRIX_NGINX_BUILD_DIR")
    source = environment.get("TEST_NGINX_SRC") or environment.get("NGX_SRC")
    build = _selected_build(root, configured, source)
    layouts = [(build / "modules/Makefile", build / "nginx-src"),
               (build / "objs/Makefile", build)]
    layouts.extend(_objects_layout(build, configured, source))
    for makefile, working_directory in layouts:
        if makefile.is_file() and working_directory.is_dir():
            return makefile, working_directory
    return None


def _selected_build(root, configured, source):
    """Choose one authoritative build root before inspecting its layout."""
    return Path(configured or source or root / "build/alma9-merged").resolve()


def _objects_layout(build, configured, source):
    """Object-directory overrides retain the original compiler working dir."""
    if not configured or build.name not in ("objs", "modules"):
        return []
    working_directory = Path(source).resolve() if source else build.parent
    return [(build / "Makefile", working_directory)]


def configured_compiler_variables(makefile):
    """Read the selected SDK's actual compiler graph, rejecting partial metadata."""
    contents = Path(makefile).read_text().replace('\\\n', ' ')
    variables = {}
    for key in ('CC', 'CFLAGS', 'ALL_INCS'):
        match = re.search(r'^' + key + r'\s*=\s*(.*)$', contents, re.MULTILINE)
        if match is None:
            raise ValueError(f'Missing {key} in {makefile}')
        variables[key] = shlex.split(match.group(1))
    return variables


def _dependency_include(flag, remaining):
    """Extract include operands without consuming a malformed option as a path."""
    if flag in ('-I', '-isystem', '-iquote', '-idirafter'):
        path = next(remaining, None)
        if not path or path.startswith('-'):
            raise ValueError(f'Missing include path after {flag}')
        return flag, path
    if flag.startswith('-I') and len(flag) > 2:
        return '-I', flag[2:]
    return None


def configured_dependency_includes(makefile, working_directory):
    """Retain SDK dependency headers without overriding a unit's instrumentation.

    The nginx headers include PCRE2 and optional SDK headers transitively.
    Object-linked units must retain those paths from the same configured build,
    not guess /usr/include or import another installation's compiler flags.
    """
    if not Path(makefile).is_file():
        return []
    flags = iter(configured_compiler_variables(makefile)['CFLAGS'])
    includes = []
    for flag in flags:
        selected = _dependency_include(flag, flags)
        if selected is None:
            continue
        option, path = selected
        absolute = Path(working_directory) / path
        includes.extend((option, str(absolute.resolve())))
    return includes


def native_test_link_flags(arguments, host):
    """Translate equivalent test-only linker operations, never drop checks."""
    if host != "darwin":
        return list(arguments)
    replacements = {
        "-Wl,--gc-sections": "-Wl,-dead_strip",
        # This isolated clock has no __real_time call. Rewrite its C call
        # sites where Mach-O's linker has no GNU --wrap facility.
        "-Wl,--wrap=time": "-Dtime=__wrap_time",
    }
    return [replacements.get(argument, argument) for argument in arguments]


def selected_native_dependency(name):
    """Keep headers, link libraries and runtime loader on one selected SDK.

    A failed explicit pkg-config selection is an error, never permission to
    borrow system headers or a different ABI's runtime library.
    """
    flags = []
    for option in ("--cflags", "--libs"):
        result = subprocess.run(["pkg-config", option, name], check=True,
                                capture_output=True, text=True, timeout=30)
        flags.append(shlex.split(result.stdout))
    runtime = ["-Wl,-rpath," + flag[2:] for flag in flags[1]
               if flag.startswith("-L/")]
    return flags[0], flags[1] + runtime


def native_test_sdk_flags(arguments):
    """Resolve optional ring SDK flags without changing unrelated link options."""
    if '-luring' not in arguments:
        return [], list(arguments)
    includes, libraries = selected_native_dependency('liburing')
    return includes, [flag for flag in arguments if flag != '-luring'] + libraries
