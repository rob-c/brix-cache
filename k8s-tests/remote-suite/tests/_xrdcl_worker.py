"""
tests/_xrdcl_worker.py

Out-of-process worker that hosts the *real* official XRootD (pyxrootd / XrdCl)
Python bindings.  It is launched by tests/_xrdcl_proxy.py as a SEPARATE python
executable so that the bindings — and the internal C++ XrdCl poller threads they
spawn — never live inside the pytest interpreter.

WHY THIS EXISTS
    pyxrootd's synchronous calls block the calling thread inside a C++
    condition-variable wait (XrdCl::Stream::OnReadTimeout) with the GIL
    released.  When XrdCl deadlocks (e.g. a stuck read-timeout) the whole
    interpreter wedges and pytest-timeout's SIGALRM handler can never run,
    because Python only services signals at bytecode boundaries.  A single
    hung op therefore freezes the entire test session.

    By confining every XrdCl call to this child, a hang only wedges the child;
    the parent waits with a real wall-clock timeout, kills the child, and turns
    the hang into an ordinary test failure.

PROTOCOL (newline-delimited JSON, one message per line)
    request   {"id": int, "op": str, ...}
    response  {"id": int, "ok": bool, ...}            ok=False carries "error"
    Binary payloads are wrapped as {"__bytes__": "<base64>"}.

    The worker is multi-threaded: each request is serviced on its own daemon
    thread (XrdCl is thread-safe), so genuine client-side concurrency — parallel
    File/FileSystem ops issued by threads in the test — is preserved.  stdout
    writes are serialised by a lock.  A hung XrdCl op only ties up its own
    thread; the parent's per-call wall-clock timeout kills the whole worker, so
    a deadlock can never wedge the pytest interpreter (the reason this isolation
    layer exists).
"""

import base64
import json
import os
import sys
import threading


# --------------------------------------------------------------------------
# Import the REAL bindings, never the shadow package shipped in tests/.
#
# This file lives in tests/, and python puts the script's directory on
# sys.path[0], so a naive ``import XRootD`` would resolve to tests/XRootD (the
# shadow).  Drop every path entry that contains our shadow marker before
# importing.
# --------------------------------------------------------------------------
def _strip_shadow_paths():
    kept = []
    for p in sys.path:
        try:
            marker = os.path.join(p or ".", "XRootD", "_SHADOW_MARKER")
            if os.path.exists(marker):
                continue
        except Exception:
            pass
        kept.append(p)
    sys.path[:] = kept


_strip_shadow_paths()

from XRootD import client as _xrd  # noqa: E402  (real bindings)


# --------------------------------------------------------------------------
# Object registries — handles handed back to the parent are just integers.
# --------------------------------------------------------------------------
_objs = {}
_objs_lock = threading.Lock()
_next_handle = [1]


def _register(obj):
    with _objs_lock:
        h = _next_handle[0]
        _next_handle[0] += 1
        _objs[h] = obj
    return h


def _get(h):
    with _objs_lock:
        return _objs[h]


def _release(h):
    with _objs_lock:
        _objs.pop(h, None)


# --------------------------------------------------------------------------
# Encoding of XrdCl results into JSON-safe structures.
# --------------------------------------------------------------------------
def _b64(data):
    if isinstance(data, memoryview):
        data = data.tobytes()
    return {"__bytes__": base64.b64encode(bytes(data)).decode("ascii")}


def _encode_status(st):
    if st is None:
        return None
    return {
        "ok": bool(st.ok),
        "error": bool(st.error),
        "fatal": bool(st.fatal),
        "code": int(st.code),
        "status": int(st.status),
        "errno": int(st.errno),
        "shellcode": int(getattr(st, "shellcode", 0) or 0),
        "message": str(st.message),
    }


def _encode_statinfo(si):
    return {
        "__type__": "StatInfo",
        "size": int(getattr(si, "size", 0) or 0),
        "flags": int(getattr(si, "flags", 0) or 0),
        "id": getattr(si, "id", None),
        "modtime": int(getattr(si, "modtime", 0) or 0),
        "modtimestr": getattr(si, "modtimestr", None),
    }


def _encode_response(resp):
    """Convert an arbitrary XrdCl response object into a JSON-safe payload."""
    if resp is None:
        return None
    if isinstance(resp, (bytes, bytearray, memoryview)):
        return _b64(resp)
    # Primitive scalars pass through verbatim.  This branch is essential once
    # we recurse into containers: a bare str/int reached via a list/tuple/dict
    # must NOT fall through to the object-scrape fallback (which would drop its
    # value, encoding "cms" as {"__type__": "str"}).
    if isinstance(resp, (str, bool, int, float)):
        return resp
    # Preserve tuple-vs-list identity: pyxrootd returns genuine tuples (e.g.
    # get_xattr -> [(name, value, status), ...]) and tests do isinstance(x,tuple).
    if isinstance(resp, tuple):
        return {"__tuple__": [_encode_response(x) for x in resp]}
    if isinstance(resp, list):
        return {"__list__": [_encode_response(x) for x in resp]}
    if isinstance(resp, dict):
        return {"__dict__": {str(k): _encode_response(v)
                             for k, v in resp.items()}}

    tname = type(resp).__name__

    if tname == "XRootDStatus":
        return {"__status__": _encode_status(resp)}

    if tname == "StatInfo":
        return _encode_statinfo(resp)

    if tname == "StatInfoVFS":
        return {
            "__type__": "StatInfoVFS",
            "nodes_rw": int(getattr(resp, "nodes_rw", 0) or 0),
            "nodes_staging": int(getattr(resp, "nodes_staging", 0) or 0),
            "free_rw": int(getattr(resp, "free_rw", 0) or 0),
            "util_rw": int(getattr(resp, "util_rw", 0) or 0),
            "free_staging": int(getattr(resp, "free_staging", 0) or 0),
            "util_staging": int(getattr(resp, "util_staging", 0) or 0),
        }

    if tname == "DirectoryList":
        entries = []
        for e in resp:
            entries.append({
                "name": getattr(e, "name", None),
                "hostaddr": getattr(e, "hostaddr", None),
                "statinfo": (_encode_statinfo(e.statinfo)
                             if getattr(e, "statinfo", None) is not None
                             else None),
            })
        return {
            "__type__": "DirectoryList",
            "parent": getattr(resp, "parent", None),
            "size": int(getattr(resp, "size", len(entries)) or len(entries)),
            "entries": entries,
        }

    if tname == "LocationInfo":
        locs = []
        for loc in resp:
            locs.append({
                "address": getattr(loc, "address", None),
                "type": int(getattr(loc, "type", 0) or 0),
                "accesstype": int(getattr(loc, "accesstype", 0) or 0),
                "is_server": bool(getattr(loc, "is_server", False)),
                "is_manager": bool(getattr(loc, "is_manager", False)),
            })
        return {"__type__": "LocationInfo", "locations": locs}

    if tname == "VectorReadInfo":
        chunks = []
        for c in resp.chunks:
            chunks.append({
                "offset": int(getattr(c, "offset", 0) or 0),
                "length": int(getattr(c, "length", 0) or 0),
                "buffer": base64.b64encode(bytes(c.buffer)).decode("ascii"),
            })
        return {
            "__type__": "VectorReadInfo",
            "size": int(getattr(resp, "size", 0) or 0),
            "chunks": chunks,
        }

    # Fallback: scrape public, non-callable attributes.
    out = {"__type__": tname}
    for a in dir(resp):
        if a.startswith("_"):
            continue
        try:
            v = getattr(resp, a)
        except Exception:
            continue
        if callable(v):
            continue
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[a] = v
        elif isinstance(v, (bytes, bytearray, memoryview)):
            out[a] = _b64(v)
    return out


# --------------------------------------------------------------------------
# Decoding of arguments coming from the parent (flag ints pass through; byte
# payloads arrive base64-wrapped).
# --------------------------------------------------------------------------
def _decode_arg(a):
    if isinstance(a, dict) and "__bytes__" in a:
        return base64.b64decode(a["__bytes__"])
    if isinstance(a, list):
        return [_decode_arg(x) for x in a]
    if isinstance(a, tuple):
        return tuple(_decode_arg(x) for x in a)
    return a


def _decode_args(args, kwargs):
    args = [_decode_arg(a) for a in (args or [])]
    kwargs = {k: _decode_arg(v) for k, v in (kwargs or {}).items()}
    return args, kwargs


# --------------------------------------------------------------------------
# Operation handlers.
# --------------------------------------------------------------------------
def _call_method(target, method, args, kwargs):
    args, kwargs = _decode_args(args, kwargs)
    # JSON has no tuple type, so lists of pairs arrive as lists of 2-element
    # lists.  Several pyxrootd calls insist on real tuples:
    #   vector_read(chunks=[(offset, length), ...])
    #   set_xattr(path, attrs=[(name, value), ...])
    if method == "vector_read" and args and isinstance(args[0], list):
        args[0] = [tuple(c) for c in args[0]]
    elif method == "set_xattr" and len(args) >= 2 and isinstance(args[1], list):
        args[1] = [tuple(p) if isinstance(p, list) else p for p in args[1]]
    fn = getattr(target, method)
    result = fn(*args, **kwargs)
    return _encode_call_result(result)


def _is_status(obj):
    return type(obj).__name__ == "XRootDStatus"


def _encode_call_result(result):
    """Normalise a pyxrootd call's return value for transport.

    Three shapes occur:
      * (XRootDStatus, response)  — the usual stat/read/query/... pattern
      * XRootDStatus              — close/sync/truncate and friends
      * a plain value             — e.g. File.is_open() -> bool
    The third must NOT be coerced into a status (that loses the value and
    crashes _encode_status); it is returned under a distinct "value" key.
    """
    if isinstance(result, tuple) and len(result) == 2 and _is_status(result[0]):
        status, resp = result
        return {"status": _encode_status(status),
                "response": _encode_response(resp)}
    if _is_status(result):
        return {"status": _encode_status(result), "response": None}
    return {"value": _encode_response(result)}


def _handle(req):
    op = req["op"]

    if op == "ping":
        return {"pong": True}

    if op == "fs_new":
        fs = _xrd.FileSystem(req["url"])
        return {"h": _register(fs)}

    if op == "file_new":
        return {"h": _register(_xrd.File())}

    if op == "cp_new":
        return {"h": _register(_xrd.CopyProcess())}

    if op == "url_parse":
        u = _xrd.URL(req["url"])
        return {"fields": {
            "is_valid": bool(u.is_valid()),
            "protocol": u.protocol,
            "hostname": u.hostname,
            "port": int(u.port or 0),
            "path": u.path,
            "path_with_params": u.path_with_params,
        }}

    if op in ("fs_call", "file_call", "cp_call"):
        target = _get(req["h"])
        return _call_method(target, req["method"],
                            req.get("args"), req.get("kwargs"))

    if op == "release":
        _release(req["h"])
        return {"released": True}

    raise ValueError("unknown op %r" % op)


# --------------------------------------------------------------------------
# Main loop: read requests, service each on its own daemon thread, and write
# tagged responses in completion order.  stdout is line-buffered text; a lock
# serialises concurrent writes.
# --------------------------------------------------------------------------
_out = sys.stdout
_out_lock = threading.Lock()


def _send(msg):
    line = json.dumps(msg)
    with _out_lock:
        _out.write(line)
        _out.write("\n")
        _out.flush()


def _service(req):
    rid = req.get("id")
    try:
        body = _handle(req)
        body["id"] = rid
        body["ok"] = True
        _send(body)
    except Exception as exc:  # noqa: BLE001 — report every failure to parent
        # Carry the exception's type and message so the parent can re-raise the
        # SAME builtin exception (tests catch native ValueError/TypeError that
        # pyxrootd raises, e.g. I/O on a closed file or unsupported kwargs).
        _send({"id": rid, "ok": False,
               "etype": type(exc).__name__,
               "emsg": str(exc),
               "error": "%s: %s" % (type(exc).__name__, exc)})


def _apply_env(env):
    """Mirror the parent's os.environ so the bindings see live credential vars.

    Applied on the main thread in request order (never inside a worker thread)
    so the environment is settled before the op it belongs to is dispatched.
    """
    os.environ.clear()
    os.environ.update(env)


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        if req.get("op") == "shutdown":
            break
        env = req.pop("env", None)
        if env is not None:
            _apply_env(env)
        t = threading.Thread(target=_service, args=(req,), daemon=True)
        t.start()


if __name__ == "__main__":
    main()
