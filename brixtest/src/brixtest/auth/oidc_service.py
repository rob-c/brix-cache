"""Supervised loopback OIDC discovery and JWKS authority service."""

from __future__ import annotations

import argparse
import http.server
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from brixtest.errors import SpecError
from brixtest.util.immutable import freeze_mapping

if TYPE_CHECKING:
    from brixtest.auth.models import TokenAuth
    from brixtest.auth.store import MaterializedAuth


_DISCOVERY = "/.well-known/openid-configuration"
_JWKS = "/jwks.json"


class _AuthorityServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, descriptor: int, root: Path) -> None:
        http.server.HTTPServer.__init__(self, ("127.0.0.1", 0), _Handler, False)
        self.socket = socket.socket(fileno=descriptor)
        address = self.socket.getsockname()
        self.server_address = address
        self.server_name = str(address[0])
        self.server_port = int(address[1])
        self.root = root


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "BriXTestAuthority/1"

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._reply(200, b'{"status":"ok"}\n')
            return
        selected = {
            _DISCOVERY: Path(".well-known/openid-configuration"),
            _JWKS: Path("jwks.json"),
        }.get(self.path)
        path = getattr(self.server, "root") / selected if selected else None
        if path is None or not path.is_file():
            self._reply(404, b'{"error":"not found"}\n')
            return
        self._reply(200, path.read_bytes())

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        self._reply(405, b'{"error":"method not allowed"}\n')

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def log_message(self, pattern: str, *args: object) -> None:
        sys.stderr.write("authority-http " + pattern % args + "\n")


class OIDCAuthority:
    """Own one stable listener and its restartable HTTP helper process."""

    def __init__(self, item: "MaterializedAuth", rotate_on_restart: bool) -> None:
        self.item = item
        self.rotate_on_restart = rotate_on_restart
        self.listener = _listener()
        port = int(self.listener.getsockname()[1])
        self.url = "http://127.0.0.1:%d" % port
        self.process: Optional[subprocess.Popen] = None
        self.log = None
        self.started = False
        _publish_endpoint(item, self.url)

    def available(self) -> bool:
        if self.process is None or self.process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(self.url + "/healthz", timeout=0.25) as reply:
                return reply.status == 200
        except (OSError, urllib.error.URLError):
            return False

    def start(self) -> None:
        if self.available():
            return
        if self.started and self.rotate_on_restart:
            self.item.rotate()
        self.log = self.item.path("authority_log").open("ab", buffering=0)
        argv = [
            sys.executable, "-m", "brixtest.auth.oidc_service",
            "--fd", str(self.listener.fileno()), "--root", str(self.item.root),
        ]
        try:
            self.process = subprocess.Popen(
                argv, stdout=self.log, stderr=subprocess.STDOUT,
                pass_fds=(self.listener.fileno(),), start_new_session=True,
            )
            _wait_ready(self)
        except Exception:
            self.stop()
            raise
        self.started = True

    def stop(self) -> None:
        process, self.process = self.process, None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
        if self.log is not None:
            self.log.close()
            self.log = None

    def close(self) -> None:
        self.stop()
        self.listener.close()


def serve(item: "MaterializedAuth", recipe: "TokenAuth") -> OIDCAuthority:
    """Start and bind a managed discovery authority to materialized token data."""
    controller = OIDCAuthority(item, recipe.rotate_on_restart)
    object.__setattr__(item, "_authority_controller", controller)
    try:
        controller.start()
    except Exception as exc:
        controller.close()
        raise SpecError("token authority", recipe.name, str(exc)) from exc
    return controller


def _listener() -> socket.socket:
    handle = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    handle.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    handle.bind(("127.0.0.1", 0))
    handle.listen(16)
    return handle


def _publish_endpoint(item: "MaterializedAuth", url: str) -> None:
    discovery_url, jwks_url = url + _DISCOVERY, url + _JWKS
    authority_log = item.root / "authority-http.log"
    authority_log.touch(mode=0o600)
    object.__setattr__(item, "files", freeze_mapping({
        **item.files, "authority_log": authority_log,
    }))
    discovery = json.loads(item.path("discovery").read_text())
    if "jwks" in item.files:
        discovery["jwks_uri"] = jwks_url
    rendered = json.dumps(discovery, indent=2, sort_keys=True) + "\n"
    item.path("discovery").write_text(rendered)
    item.path("issuer").write_text(rendered)
    _publish_role_environments(item, discovery_url, jwks_url)
    object.__setattr__(item, "metadata", freeze_mapping({
        **item.metadata, "authority_url": url,
        "discovery_url": discovery_url, "jwks_url": jwks_url if "jwks" in item.files else "",
    }))


def _publish_role_environments(
    item: "MaterializedAuth", discovery_url: str, jwks_url: str,
) -> None:
    additions = {"BRIXTEST_TOKEN_DISCOVERY_URL": discovery_url}
    if "jwks" in item.files:
        additions["BRIXTEST_TOKEN_JWKS_URL"] = jwks_url
    for field in ("test_env", "server_env", "client_env"):
        object.__setattr__(item, field, freeze_mapping({**getattr(item, field), **additions}))


def _wait_ready(controller: OIDCAuthority) -> None:
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if controller.available():
            return
        if controller.process is not None and controller.process.poll() is not None:
            break
        time.sleep(0.02)
    raise SpecError("token authority", controller.url, "did not become healthy")


def _main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--fd", type=int, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    server = _AuthorityServer(args.fd, args.root)
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = ["OIDCAuthority", "serve"]
