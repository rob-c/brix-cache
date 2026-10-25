"""The Python inspection shim preserves the native user-namespace boundary."""
import errno
import ctypes
from types import SimpleNamespace

import pytest

from lib_py.freebsd_xattr import functions, native_mutations


@pytest.fixture
def adapter():
    values, calls = {}, []

    def get(path, name, symlink=False):
        calls.append(("get", path, name, symlink))
        return values[name]

    def put(path, name, value, symlink=False):
        calls.append(("set", path, name, symlink))
        values[name] = value

    def names(path, symlink=False):
        return ["user." + name for name in values] + ["system.hidden"]

    def remove(path, name, symlink=False):
        del values[name]

    return functions(SimpleNamespace(getxattr=get, setxattr=put,
        listxattr=names, removexattr=remove)), values, calls


def test_inspection_roundtrip_maps_names_and_binary_values(adapter):
    api, values, calls = adapter
    api["setxattr"](17, "user.brix", b"a\0b", follow_symlinks=False)
    assert values == {"brix": b"a\0b"}
    assert calls == [("set", 17, "brix", True)]
    assert api["getxattr"](17, "user.brix") == b"a\0b"
    assert api["listxattr"](17) == ["user.brix"]
    api["removexattr"](17, "user.brix")
    assert api["listxattr"](17) == []


@pytest.mark.parametrize("flag", [1, 2, 3, 8])
def test_conditional_updates_never_use_a_racy_read_then_write(adapter, flag):
    api, values, calls = adapter
    with pytest.raises(OSError) as error:
        api["setxattr"]("path", "user.brix", b"value", flag)
    assert error.value.errno == errno.ENOTSUP
    assert values == {} and calls == []


@pytest.mark.parametrize("name", ["security.brix", "system.brix", "user.", "brix"])
def test_hostile_names_never_reach_the_native_backend(adapter, name):
    api, values, calls = adapter
    with pytest.raises(OSError) as error:
        api["setxattr"]("path", name, b"value")
    assert error.value.errno == errno.ENOTSUP
    assert values == {} and calls == []


@pytest.mark.parametrize('target,symlink,suffix', [(17, False, 'fd'),
    ('path', False, 'file'), ('path', True, 'link')])
def test_native_mutations_preserve_binary_bytes_and_exact_target(target, symlink, suffix):
    calls = []

    def set_value(path, namespace, name, value, size):
        calls.append((path, namespace, name, ctypes.string_at(value, size)))
        return size

    def remove(path, namespace, name):
        calls.append((path, namespace, name))
        return 0

    native = SimpleNamespace(**{f'extattr_set_{suffix}': set_value,
                                f'extattr_delete_{suffix}': remove})
    api = native_mutations(SimpleNamespace(getxattr=None, listxattr=None), native)
    api.setxattr(target, 'brix', b'a\0b', symlink=symlink)
    api.removexattr(target, 'brix', symlink=symlink)
    expected = target if isinstance(target, int) else b'path'
    assert calls == [(expected, 1, b'brix', b'a\0b'), (expected, 1, b'brix')]


@pytest.mark.parametrize('operation', ['set', 'delete'])
def test_native_readonly_error_cannot_be_changed_into_success(operation):
    def refused(*arguments):
        ctypes.set_errno(errno.EROFS)
        return -1

    native = SimpleNamespace(**{f'extattr_{operation}_file': refused})
    api = native_mutations(SimpleNamespace(getxattr=None, listxattr=None), native)
    with pytest.raises(OSError) as error:
        if operation == 'set':
            api.setxattr('path', 'brix', b'value')
        else:
            api.removexattr('path', 'brix')
    assert error.value.errno == errno.EROFS


def test_short_native_write_is_an_error():
    native = SimpleNamespace(extattr_set_file=lambda *arguments: 0)
    api = native_mutations(SimpleNamespace(getxattr=None, listxattr=None), native)
    with pytest.raises(OSError) as error:
        api.setxattr('path', 'brix', b'value')
    assert error.value.errno == errno.EIO


@pytest.mark.parametrize('path,name', [('path\0suffix', 'brix'), ('path', 'brix\0suffix')])
def test_native_c_strings_cannot_truncate_the_requested_target(path, name):
    def forbidden(*arguments):
        pytest.fail('hostile C string must not reach the native syscall')

    native = SimpleNamespace(extattr_set_file=forbidden)
    api = native_mutations(SimpleNamespace(getxattr=None, listxattr=None), native)
    with pytest.raises(ValueError, match='embedded null byte'):
        api.setxattr(path, name, b'value')
