"""kube — a small wrapper over the official ``kubernetes`` client.

Exposes exactly what the tests and ``klib`` need: pod ``exec_`` (with exit code),
logs, pod listing, readiness waiting, and simple get/list. The WebSocket exec
channel is kept **text-only**; binary payloads are base64'd by callers at the
boundary (``klib.svc_read``/``svc_write``), which is both simpler and correct.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from kubernetes import client, config
from kubernetes.stream import stream
from kubernetes.stream.ws_client import ERROR_CHANNEL

DEFAULT_NS = "brix-remote"
COMPONENT = "app.kubernetes.io/component"


@dataclass
class Exec:
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


def _load_config():
    """In-cluster when running in a pod, else the local kubeconfig."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()


class Kube:
    def __init__(self, namespace: str = DEFAULT_NS):
        _load_config()
        self.ns = namespace
        self.core = client.CoreV1Api()
        self.apps = client.AppsV1Api()
        self._pod_cache: dict[str, str] = {}

    # -- pods ---------------------------------------------------------------
    def pod_for(self, service: str) -> str:
        """First pod name for ``app.kubernetes.io/component=<service>`` (cached)."""
        if service not in self._pod_cache:
            pods = self.core.list_namespaced_pod(
                self.ns, label_selector=f"{COMPONENT}={service}").items
            if not pods:
                raise RuntimeError(f"no pod for service {service!r} in ns {self.ns}")
            self._pod_cache[service] = pods[0].metadata.name
        return self._pod_cache[service]

    def pods(self, selector: str):
        return self.core.list_namespaced_pod(self.ns, label_selector=selector).items

    # -- exec ---------------------------------------------------------------
    def exec_(self, service: str, argv, stdin: str | None = None) -> Exec:
        """Run ``argv`` in a pod of ``service``; return rc/out/err (text)."""
        pod = self.pod_for(service)
        resp = stream(
            self.core.connect_get_namespaced_pod_exec,
            pod, self.ns, command=list(argv),
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
        return Exec(_returncode(resp), "".join(out), "".join(err))

    # -- logs / resources ---------------------------------------------------
    def logs(self, service: str, container: str | None = None) -> str:
        return self.core.read_namespaced_pod_log(
            self.pod_for(service), self.ns, container=container)

    def wait_ready(self, selector: str, timeout: int = 120) -> bool:
        """True once every pod matching ``selector`` is Ready (or timeout)."""
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            pods = self.pods(selector)
            if pods and all(_ready(p) for p in pods):
                return True
            time.sleep(2)
        return False


def _ready(pod) -> bool:
    conds = (pod.status.conditions or [])
    return any(c.type == "Ready" and c.status == "True" for c in conds)


def _returncode(resp) -> int:
    """Parse the exec exit code from the status (ERROR) channel."""
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
