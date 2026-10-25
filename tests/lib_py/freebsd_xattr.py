"""Linux-shaped test inspection through FreeBSD's native xattr API.

The server uses the C PAL. This only supplies missing CPython os functions;
conditional writes remain explicitly unsupported, just as in that PAL.
Reads/lists use the native package; mutations bypass its dropped-error bug.
"""
import errno
import os
import ctypes
from types import SimpleNamespace


def _name(attribute):
    name = os.fsdecode(attribute)
    if not name.startswith("user.") or len(name) == 5:
        raise OSError(errno.ENOTSUP, "only the native user xattr namespace is supported")
    return name[5:]


def functions(backend):
    """Adapt package signatures without copying its native extattr implementation."""
    def get(path, attribute, *, follow_symlinks=True):
        return backend.getxattr(path, _name(attribute), symlink=not follow_symlinks)

    def set_value(path, attribute, value, flags=0, *, follow_symlinks=True):
        name = _name(attribute)
        if flags != 0:
            raise OSError(errno.ENOTSUP, "FreeBSD has no atomic conditional extattr update")
        return backend.setxattr(path, name, bytes(value), symlink=not follow_symlinks)

    def names(path=None, *, follow_symlinks=True):
        target = "." if path is None else path
        return [os.fsdecode(name) for name in backend.listxattr(
            target, symlink=not follow_symlinks) if os.fsdecode(name).startswith("user.")]

    def remove(path, attribute, *, follow_symlinks=True):
        return backend.removexattr(path, _name(attribute), symlink=not follow_symlinks)

    return dict(getxattr=get, setxattr=set_value, listxattr=names, removexattr=remove)


def _native_string(value):
    encoded = os.fsencode(value)
    if b'\0' in encoded:
        raise ValueError('embedded null byte')
    return encoded


def _mutation_target(path, symlink):
    """Select the precise native fd/file/link ABI without following a link."""
    if isinstance(path, int):
        return 'fd', path, ctypes.c_int
    suffix = 'link' if symlink else 'file'
    return suffix, _native_string(path), ctypes.c_char_p


def _mutation_result_type(operation):
    """A delete returns int, not ssize_t (important for ARM64 sign extension)."""
    if operation == 'set':
        return ctypes.c_ssize_t, [ctypes.c_void_p, ctypes.c_size_t]
    return ctypes.c_int, []


def _mutation_call(library, operation, path, name, symlink, extra):
    """Use the native ABI: the packaged wrapper drops FreeBSD write errors."""
    suffix, target, target_type = _mutation_target(path, symlink)
    function = getattr(library, f'extattr_{operation}_{suffix}')
    function.restype, extra_types = _mutation_result_type(operation)
    function.argtypes = [target_type, ctypes.c_int, ctypes.c_char_p, *extra_types]
    result = function(target, 1, _native_string(name), *extra)
    if result < 0:
        code = ctypes.get_errno() or errno.EIO
        raise OSError(code, os.strerror(code))
    return result


def native_mutations(backend, library):
    """Keep the package's read/list API, but never hide native mutation errors."""
    def set_value(path, name, value, symlink=False):
        result = _mutation_call(library, 'set', path, name, symlink,
                                (ctypes.c_char_p(value), len(value)))
        if result != len(value):
            raise OSError(errno.EIO, 'short native extattr write')

    def remove(path, name, symlink=False):
        _mutation_call(library, 'delete', path, name, symlink, ())

    return SimpleNamespace(getxattr=backend.getxattr, listxattr=backend.listxattr,
                           setxattr=set_value, removexattr=remove)


def install():
    """Require the native package rather than fabricating metadata or success."""
    import xattr  # FreeBSD package: py312-xattr

    backend = native_mutations(xattr, ctypes.CDLL(None, use_errno=True))
    for name, function in functions(backend).items():
        setattr(os, name, function)
    os.XATTR_CREATE, os.XATTR_REPLACE = 1, 2
    if not hasattr(errno, "ENODATA"):
        errno.ENODATA = errno.ENOATTR
    return True
