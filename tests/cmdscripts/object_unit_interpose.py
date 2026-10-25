"""Darwin equivalents for test-only GNU linker wrapping of real objects."""
import sys

from cmdscripts.compile_run import compile_binary


def fsync_interposer(name, base):
    """Return link arguments and insertion environment, or fail the build."""
    if sys.platform != "darwin" or name != "publish_dirsync":
        return [], {}
    library = (base / "fsync-interpose.dylib").resolve()
    built = compile_binary(library, [
        "-dynamiclib", "-Wl,-undefined,dynamic_lookup",
        "tests/c/fsync_interpose.c",
    ])
    if built.returncode:
        raise RuntimeError("fsync interposer compile failed:\n" + built.stderr)
    return [str(library)], {"DYLD_INSERT_LIBRARIES": str(library)}
