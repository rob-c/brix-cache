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

    THREADING CONSTRAINT
    pyxrootd's synchronous methods only complete when invoked from the process
    MAIN thread — driving them from any other Python thread deadlocks in the
    XrdCl response-delivery path (verified empirically).  The worker therefore
    services every request inline on the main thread, sequentially.  Genuine
    client-side concurrency is provided by the parent running a POOL of these
    workers (one process per concurrency slot); see tests/_xrdcl_proxy.py.
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

    tname = type(resp).__name__

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
    fn = getattr(target, method)
    result = fn(*args, **kwargs)
    # pyxrootd returns (status, response); some calls return only a status.
    if isinstance(result, tuple) and len(result) == 2:
        status, resp = result
    else:
        status, resp = result, None
    return {"status": _encode_status(status), "response": _encode_response(resp)}


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
# Main loop: read requests and service each INLINE on the main thread (the only
# thread on which pyxrootd's synchronous calls complete).  Responses are tagged
# with the request id and written in completion order.
# --------------------------------------------------------------------------
_out = sys.stdout


def _send(msg):
    _out.write(json.dumps(msg))
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
        _send({"id": rid, "ok": False,
               "error": "%s: %s" % (type(exc).__name__, exc)})


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
        _service(req)


if __name__ == "__main__":
    main()
