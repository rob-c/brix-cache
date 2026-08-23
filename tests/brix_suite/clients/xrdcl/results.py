"""Result wrappers and the wire codec.

The proxy never imports XrdCl, so every response the worker sends has to be
rebuilt into an object with the attribute surface the tests were written
against.  These classes are that surface; ``_decode_response`` is its inverse
codec, and lived in shard 2 of the grown module while the types it builds lived
in shard 1 — one module now holds both.
"""

import base64

# ==========================================================================
# Result wrappers — faithful attribute surface, no XrdCl import required.
# ==========================================================================
class Status:
    __slots__ = ("ok", "error", "fatal", "code", "status", "errno",
                 "shellcode", "message")

    def __init__(self, d):
        d = d or {}
        self.ok = bool(d.get("ok", False))
        self.error = bool(d.get("error", not d.get("ok", False)))
        self.fatal = bool(d.get("fatal", False))
        self.code = int(d.get("code", 0))
        self.status = int(d.get("status", 0))
        self.errno = int(d.get("errno", 0))
        self.shellcode = int(d.get("shellcode", 0))
        self.message = str(d.get("message", ""))

    def __bool__(self):
        return self.ok

    def __repr__(self):
        return "<Status ok=%s code=%s errno=%s msg=%r>" % (
            self.ok, self.code, self.errno, self.message)


class StatInfo:
    __slots__ = ("size", "flags", "id", "modtime", "modtimestr")

    def __init__(self, d):
        self.size = d.get("size", 0)
        self.flags = d.get("flags", 0)
        self.id = d.get("id")
        self.modtime = d.get("modtime", 0)
        self.modtimestr = d.get("modtimestr")


class StatInfoVFS:
    def __init__(self, d):
        for k, v in d.items():
            if k != "__type__":
                setattr(self, k, v)


class _ListEntry:
    __slots__ = ("name", "hostaddr", "statinfo")

    def __init__(self, d):
        self.name = d.get("name")
        self.hostaddr = d.get("hostaddr")
        si = d.get("statinfo")
        self.statinfo = StatInfo(si) if si else None


class DirectoryList:
    def __init__(self, d):
        self.parent = d.get("parent")
        self._entries = [_ListEntry(e) for e in d.get("entries", [])]
        self.size = d.get("size", len(self._entries))

    def __iter__(self):
        return iter(self._entries)

    def __len__(self):
        return len(self._entries)

    def __getitem__(self, i):
        return self._entries[i]


class _Location:
    __slots__ = ("address", "type", "accesstype", "is_server", "is_manager")

    def __init__(self, d):
        self.address = d.get("address")
        self.type = d.get("type", 0)
        self.accesstype = d.get("accesstype", 0)
        self.is_server = d.get("is_server", False)
        self.is_manager = d.get("is_manager", False)


class LocationInfo:
    def __init__(self, d):
        self.locations = [_Location(x) for x in d.get("locations", [])]

    def __iter__(self):
        return iter(self.locations)

    def __len__(self):
        return len(self.locations)

    def __getitem__(self, i):
        return self.locations[i]


class _Chunk:
    __slots__ = ("offset", "length", "buffer")

    def __init__(self, d):
        self.offset = d.get("offset", 0)
        self.length = d.get("length", 0)
        self.buffer = base64.b64decode(d.get("buffer", ""))


class VectorReadInfo:
    def __init__(self, d):
        self.size = d.get("size", 0)
        self.chunks = [_Chunk(c) for c in d.get("chunks", [])]

    # Real pyxrootd VectorReadInfo iterates its chunks.
    def __iter__(self):
        return iter(self.chunks)

    def __len__(self):
        return len(self.chunks)

    def __getitem__(self, i):
        return self.chunks[i]


class _Generic:
    """Fallback wrapper for response types without a dedicated class."""
    def __init__(self, d):
        for k, v in d.items():
            if k == "__type__":
                continue
            setattr(self, k, _decode_response(v))


_RESP_TYPES = {
    "StatInfo": StatInfo,
    "StatInfoVFS": StatInfoVFS,
    "DirectoryList": DirectoryList,
    "LocationInfo": LocationInfo,
    "VectorReadInfo": VectorReadInfo,
}


def _decode_response(payload):
    """Inverse of the worker's _encode_response.

    Markers: __bytes__ (binary), __status__ (an XRootDStatus), __list__ (a
    list), __dict__ (a plain dict, e.g. a copy-job result), __type__ (a typed
    response object).  Bare lists/dicts are decoded element-wise too.
    """
    if payload is None:
        return None
    if isinstance(payload, list):
        return [_decode_response(x) for x in payload]
    if isinstance(payload, dict):
        return _decode_mapping(payload)
    return payload


def _decode_mapping(payload):
    marker = _response_marker(payload)
    if marker is not None:
        return _decode_marker(marker, payload[marker])
    response_type = payload.get("__type__")
    if response_type is not None:
        return _typed_response(response_type, payload)
    return {key: _decode_response(value) for key, value in payload.items()}


def _response_marker(payload):
    markers = ("__bytes__", "__status__", "__list__", "__tuple__", "__dict__")
    return next((marker for marker in markers if marker in payload), None)


def _decode_marker(marker, value):
    if marker == "__bytes__":
        return base64.b64decode(value)
    if marker == "__status__":
        return Status(value)
    if marker == "__list__":
        return [_decode_response(item) for item in value]
    if marker == "__tuple__":
        return tuple(_decode_response(item) for item in value)
    return {key: _decode_response(item) for key, item in value.items()}


def _typed_response(response_type, payload):
    response_class = _RESP_TYPES.get(response_type)
    if response_class is not None:
        return response_class(payload)
    return _Generic(payload)


def _encode_arg(a):
    if isinstance(a, (bytes, bytearray, memoryview)):
        return {"__bytes__": base64.b64encode(bytes(a)).decode("ascii")}
    if isinstance(a, (list, tuple)):
        return [_encode_arg(x) for x in a]
    return a


def _encode_args(args, kwargs):
    return ([_encode_arg(a) for a in args],
            {k: _encode_arg(v) for k, v in kwargs.items()})
