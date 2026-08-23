"""TCP, HTTP, command, log, and composite readiness probes.

Compatibility aliases resolve to ``TcpProbe``. ``CommandProbe`` and
``AllOf`` support protocol-specific readiness checks.

A probe's contract: ``wait(endpoint, timeout) -> float`` returns the
elapsed seconds once the instance answered, or raises
``ReadinessTimeout``.  Probes never touch the process — liveness is
the sentinel's job; readiness is only "does it answer".
"""

from __future__ import annotations

import ssl
import subprocess
import time
import urllib.error
import urllib.request
from typing import Optional, Sequence, Tuple

from brixtest.errors import ReadinessTimeout, SpecError
from brixtest.fleet.registry import PRIMARY, ServerEndpoint
from brixtest.util.configtext import render_cfg
from brixtest.util.net import tcp_answering

__all__ = [
    "READINESS_ALIASES",
    "AllOf",
    "CommandProbe",
    "HttpProbe",
    "LogProbe",
    "NoProbe",
    "TcpProbe",
    "probe_from_alias",
    "probe_from_declaration",
]

READINESS_ALIASES: Tuple[str, ...] = ("root", "webdav", "s3", "metrics", "cms", "tcp")
_POLL = 0.1


def _log_tail(endpoint: ServerEndpoint, lines: int = 15) -> str:
    try:
        return "\n".join(endpoint.log_path.read_text(errors="replace").splitlines()[-lines:])
    except OSError:
        return ""


def _tls_context(enabled: bool):
    if not enabled:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _http_status(url: str, timeout: float, context) -> Optional[int]:
    try:
        with urllib.request.urlopen(  # noqa: S310 - caller constructs HTTP(S) URL
            url, timeout=min(2.0, timeout), context=context,
        ) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (OSError, urllib.error.URLError, ValueError):
        return None


def _url_host(host: str) -> str:
    return "[%s]" % host if ":" in host and not host.startswith("[") else host


def _check_http_deadline(
    endpoint: ServerEndpoint, url: str, elapsed: float, deadline: float,
) -> None:
    if elapsed >= deadline:
        raise ReadinessTimeout(
            endpoint.name, "http %s" % url, elapsed, log_tail=_log_tail(endpoint),
        )


class NoProbe:
    """readiness="none": the instance is ready the moment it is spawned."""

    def wait(self, endpoint: ServerEndpoint, timeout: float) -> float:
        return 0.0


class TcpProbe:
    """Ready when the named port accepts a TCP connection."""

    def __init__(self, port_role: str = PRIMARY, timeout: float = 10.0) -> None:
        self.port_role = port_role
        self.timeout = timeout

    def wait(self, endpoint: ServerEndpoint, timeout: Optional[float] = None) -> float:
        deadline = self.timeout if timeout is None else timeout
        host, port = endpoint.address(self.port_role)
        start = time.monotonic()
        while True:
            if tcp_answering(host, port):
                return time.monotonic() - start
            elapsed = time.monotonic() - start
            if elapsed >= deadline:
                raise ReadinessTimeout(
                    endpoint.name,
                    "tcp %s:%d" % (host, port),
                    elapsed,
                    log_tail=_log_tail(endpoint),
                )
            time.sleep(_POLL)


class CommandProbe:
    """Ready when a client command exits 0 against the instance.

    ``argv`` may use ``{host}``, ``{port}``, ``{name}``, ``{workdir}``
    placeholders, rendered per attempt. This supports protocol-level checks
    such as ``xrdfs stat`` or an S3 list operation.
    """

    def __init__(
        self,
        argv: Sequence[str],
        *,
        port_role: str = PRIMARY,
        timeout: float = 10.0,
        attempt_timeout: float = 5.0,
    ) -> None:
        if not argv:
            raise SpecError("argv", argv, "CommandProbe needs a non-empty command")
        self.argv = tuple(argv)
        self.port_role = port_role
        self.timeout = timeout
        self.attempt_timeout = attempt_timeout

    def _render(self, endpoint: ServerEndpoint) -> Sequence[str]:
        host, port = endpoint.address(self.port_role)
        values = {
            "host": host,
            "port": port,
            "name": endpoint.name,
            "workdir": endpoint.workdir,
        }
        return [render_cfg(part, values) for part in self.argv]

    def wait(self, endpoint: ServerEndpoint, timeout: Optional[float] = None) -> float:
        deadline = self.timeout if timeout is None else timeout
        argv = self._render(endpoint)
        start = time.monotonic()
        while True:
            try:
                proc = subprocess.run(
                    argv,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=self.attempt_timeout,
                    check=False,
                )
                if proc.returncode == 0:
                    return time.monotonic() - start
            except (subprocess.TimeoutExpired, OSError):
                pass
            elapsed = time.monotonic() - start
            if elapsed >= deadline:
                raise ReadinessTimeout(
                    endpoint.name,
                    "command %s" % " ".join(argv),
                    elapsed,
                    log_tail=_log_tail(endpoint),
                )
            time.sleep(_POLL)


class HttpProbe:
    """Ready when an HTTP endpoint returns one of the expected statuses."""

    def __init__(
        self, *, port_role: str, path: str, statuses: Sequence[int],
        tls: bool, timeout: float, interval: float,
    ) -> None:
        self.port_role = port_role
        self.path = path
        self.statuses = tuple(statuses)
        self.tls = tls
        self.timeout = timeout
        self.interval = interval

    def wait(self, endpoint: ServerEndpoint, timeout: Optional[float] = None) -> float:
        deadline = self.timeout if timeout is None else timeout
        host, port = endpoint.address(self.port_role)
        scheme = "https" if self.tls else "http"
        url = "%s://%s:%d%s" % (scheme, _url_host(host), port, self.path)
        context = _tls_context(self.tls)
        started = time.monotonic()
        while True:
            if _http_status(url, deadline, context) in self.statuses:
                return time.monotonic() - started
            elapsed = time.monotonic() - started
            _check_http_deadline(endpoint, url, elapsed, deadline)
            time.sleep(self.interval)


class LogProbe:
    """Ready when the server log contains a declared plain-text pattern."""

    def __init__(self, pattern: str, *, timeout: float, interval: float) -> None:
        if not pattern:
            raise SpecError("probe.pattern", pattern, "is required for a log probe")
        self.pattern = pattern
        self.timeout = timeout
        self.interval = interval

    def wait(self, endpoint: ServerEndpoint, timeout: Optional[float] = None) -> float:
        deadline = self.timeout if timeout is None else timeout
        started = time.monotonic()
        while True:
            try:
                if self.pattern in endpoint.log_path.read_text(errors="replace"):
                    return time.monotonic() - started
            except OSError:
                pass
            elapsed = time.monotonic() - started
            if elapsed >= deadline:
                raise ReadinessTimeout(
                    endpoint.name, "log pattern %r" % self.pattern, elapsed,
                    log_tail=_log_tail(endpoint),
                )
            time.sleep(self.interval)


class AllOf:
    """Ready when every constituent probe passed, in order, within budget."""

    def __init__(self, *probes: object) -> None:
        if not probes:
            raise SpecError("probes", probes, "AllOf needs at least one probe")
        self.probes = probes

    def wait(self, endpoint: ServerEndpoint, timeout: Optional[float] = None) -> float:
        deadline = 10.0 if timeout is None else timeout
        start = time.monotonic()
        for probe in self.probes:
            remaining = deadline - (time.monotonic() - start)
            if remaining <= 0:
                raise ReadinessTimeout(
                    endpoint.name, "allof budget", deadline, log_tail=_log_tail(endpoint)
                )
            probe.wait(endpoint, remaining)  # type: ignore[attr-defined]
        return time.monotonic() - start


class ExtensionProbe:
    """Bind an installed probe driver to one immutable declaration."""

    def __init__(self, driver: object, declaration: object) -> None:
        self.driver = driver
        self.declaration = declaration
        self.driver.validate(declaration)  # type: ignore[attr-defined]

    def wait(self, endpoint: ServerEndpoint, timeout: Optional[float] = None) -> float:
        selected = self.declaration.timeout if timeout is None else timeout  # type: ignore[attr-defined]
        return float(self.driver.wait(self.declaration, endpoint, selected))  # type: ignore[attr-defined]


def probe_from_alias(alias: str, timeout: float = 10.0):
    """Resolve and validate a readiness alias during registration."""
    if alias == "none":
        return NoProbe()
    if alias in READINESS_ALIASES:
        return TcpProbe(timeout=timeout)
    raise SpecError(
        "readiness", alias,
        "unknown alias — one of: %s, none" % ", ".join(READINESS_ALIASES),
    )


def probe_from_declaration(declaration: object):
    """Translate the public inert Probe declaration into a runtime probe."""
    from brixtest.resources import Probe

    if not isinstance(declaration, Probe):
        raise SpecError("probe", declaration, "must be a brixtest.Probe declaration")
    if declaration.kind == "none":
        return NoProbe()
    if declaration.kind == "tcp":
        return TcpProbe(declaration.endpoint, declaration.timeout)
    if declaration.kind in ("http", "https"):
        return HttpProbe(
            port_role=declaration.endpoint, path=declaration.path,
            statuses=declaration.statuses, tls=declaration.kind == "https",
            timeout=declaration.timeout, interval=declaration.interval,
        )
    if declaration.kind == "exec":
        return CommandProbe(
            [str(part) for part in declaration.command], port_role=declaration.endpoint,
            timeout=declaration.timeout,
        )
    if declaration.kind == "log":
        return LogProbe(
            declaration.pattern, timeout=declaration.timeout, interval=declaration.interval,
        )
    from brixtest.extensions import get_extension

    return ExtensionProbe(get_extension("probe", declaration.kind), declaration)
