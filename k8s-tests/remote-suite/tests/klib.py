# brix-remote-adapted
"""klib — read/manipulate a k8s service's server-side files from an adapted
remote test, via the official ``kubernetes`` client (pod exec).

Self-contained on purpose: this file is shipped alone into the client pod, so it
must not import the local ``labkit`` package. It resolves a pod by the
``app.kubernetes.io/component=<service>`` label in the suite namespace and runs a
command in it. The exec WebSocket is kept text-only; binary payloads are base64'd
at the boundary (``svc_read``/``svc_write``/``svc_getxattr``).

Public API (unchanged for adapted tests): svc_read/write/mkdir/rm/rmtree/isdir/
isfile/exists/listdir/chmod/mode/symlink/setxattr/getxattr.
"""
import base64
import json
import os

from kubernetes import client, config
from kubernetes.stream import stream
from kubernetes.stream.ws_client import ERROR_CHANNEL

_COMPONENT = "app.kubernetes.io/component"
_kube = {"core": None, "ns": None}
_POD_CACHE = {}


def _ns(namespace):
    return namespace or os.environ.get("BRIX_SUITE_NS", "brix-remote")


def _core():
    if _kube["core"] is None:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        _kube["core"] = client.CoreV1Api()
    return _kube["core"]


def _pod(service, namespace):
    key = (service, _ns(namespace))
    if key not in _POD_CACHE:
        pods = _core().list_namespaced_pod(
            _ns(namespace), label_selector="%s=%s" % (_COMPONENT, service)).items
        if not pods:
            raise RuntimeError("no pod for service %r" % service)
        _POD_CACHE[key] = pods[0].metadata.name
    return _POD_CACHE[key]


def _returncode(resp):
    chan = resp.read_channel(ERROR_CHANNEL)
    if not chan:
        return 0
    status = json.loads(chan)
    if status.get("status") == "Success":
        return 0
    for cause in status.get("details", {}).get("causes", []):
        if cause.get("reason") == "ExitCode":
            return int(cause.get("message", 1))
    return 1


class _Result:
    """Mimics subprocess.CompletedProcess for the svc_* helpers below."""
    def __init__(self, rc, out, err):
        self.returncode = rc
        self.stdout = out.encode()
        self.stderr = err.encode()


def _exec(service, namespace, argv, stdin=None):
    resp = stream(
        _core().connect_get_namespaced_pod_exec,
        _pod(service, namespace), _ns(namespace), command=list(argv),
        container=service,  # main container is named after the component
        stderr=True, stdin=stdin is not None, stdout=True, tty=False,
        _preload_content=False,
    )
    out, err = [], []
    if stdin is not None:
        resp.write_stdin(stdin)
    while resp.is_open():
        resp.update(timeout=5)
        if resp.peek_stdout():
            out.append(resp.read_stdout())
        if resp.peek_stderr():
            err.append(resp.read_stderr())
    return _Result(_returncode(resp), "".join(out), "".join(err))


# ---------------------------------------------------------------------------
# Public helpers. Binary-safe reads/writes go through base64 at the boundary so
# the exec WebSocket only ever carries text.
# ---------------------------------------------------------------------------
def svc_read(service, path, namespace=None):
    """Return the bytes of ``path`` inside a pod of ``service``."""
    r = _exec(service, namespace, ["sh", "-c", "base64 -w0 -- '%s'" % path])
    if r.returncode != 0:
        raise FileNotFoundError("%s:%s (%s)"
                                % (service, path, r.stderr.decode().strip()))
    return base64.b64decode(r.stdout)


def svc_exists(service, path, namespace=None):
    return _exec(service, namespace, ["test", "-e", path]).returncode == 0


def svc_isdir(service, path, namespace=None):
    return _exec(service, namespace, ["test", "-d", path]).returncode == 0


def svc_isfile(service, path, namespace=None):
    return _exec(service, namespace, ["test", "-f", path]).returncode == 0


def svc_listdir(service, path, namespace=None):
    r = _exec(service, namespace, ["ls", "-1", path])
    if r.returncode != 0:
        raise FileNotFoundError("%s:%s" % (service, path))
    return [x for x in r.stdout.decode().splitlines() if x]


def svc_mkdir(service, path, namespace=None):
    if _exec(service, namespace, ["mkdir", "-p", path]).returncode != 0:
        raise OSError("mkdir %s:%s failed" % (service, path))


def svc_write(service, path, data, namespace=None):
    """Write bytes to ``path`` inside a pod of ``service`` (binary-safe)."""
    if isinstance(data, str):
        data = data.encode()
    b64 = base64.b64encode(data).decode()
    # `head -c <len>` reads exactly the base64 payload then exits, giving base64
    # its EOF — the k8s exec WebSocket has no clean "close stdin", so without a
    # bounded read `base64 -d` would block forever and hang the stream.
    r = _exec(service, namespace,
              ["sh", "-c", "head -c %d | base64 -d > '%s'" % (len(b64), path)],
              stdin=b64)
    if r.returncode != 0:
        raise OSError("write %s:%s failed (%s)"
                      % (service, path, r.stderr.decode().strip()))


def svc_rm(service, path, namespace=None):
    """Best-effort remove ``path`` (file) inside a pod of ``service``."""
    _exec(service, namespace, ["rm", "-f", path])


def svc_rmtree(service, path, namespace=None):
    """Best-effort recursive remove of ``path`` inside a pod of ``service``."""
    _exec(service, namespace, ["rm", "-rf", path])


def svc_chmod(service, path, mode, namespace=None):
    """chmod ``path`` to ``mode`` (octal int, e.g. 0o644)."""
    if _exec(service, namespace, ["chmod", "%o" % mode, path]).returncode != 0:
        raise OSError("chmod %s:%s failed" % (service, path))


def svc_mode(service, path, namespace=None):
    """Return the permission bits of ``path`` as an int (e.g. 0o644)."""
    r = _exec(service, namespace, ["stat", "-c", "%a", path])
    if r.returncode != 0:
        raise FileNotFoundError("%s:%s" % (service, path))
    return int(r.stdout.decode().strip(), 8)


def svc_setxattr(service, path, name, value, namespace=None):
    """setfattr -n ``name`` -v ``value`` ``path``."""
    if isinstance(name, bytes):
        name = name.decode()
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    r = _exec(service, namespace, ["setfattr", "-n", name, "-v", value, path])
    if r.returncode != 0:
        raise OSError("setxattr %s:%s %s failed (%s)"
                      % (service, path, name, r.stderr.decode().strip()))


def svc_getxattr(service, path, name, namespace=None):
    """Return the bytes of xattr ``name`` on ``path`` (binary-safe)."""
    if isinstance(name, bytes):
        name = name.decode()
    r = _exec(service, namespace,
              ["sh", "-c", "getfattr -n '%s' --only-values -- '%s' | base64 -w0"
               % (name, path)])
    if r.returncode != 0:
        raise KeyError("getxattr %s:%s %s (%s)"
                       % (service, path, name, r.stderr.decode().strip()))
    return base64.b64decode(r.stdout)


def svc_symlink(service, target, linkpath, namespace=None):
    """Create symlink ``linkpath`` -> ``target`` inside a pod of ``service``."""
    _exec(service, namespace, ["rm", "-rf", linkpath])
    if _exec(service, namespace, ["ln", "-s", target, linkpath]).returncode != 0:
        raise OSError("symlink %s:%s failed" % (service, linkpath))
