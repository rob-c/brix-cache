"""Render + start/stop the paired MU fleet (spec §8.1). Each server is a standalone nginx
instance: a cache-OFF `direct` server (the authoritative oracle) and a cache-ON `cache`
server per protocol. Live start/stop needs privilege; render_configs + url are usable
unprivileged.
"""
import glob
import os
import socket
import subprocess
import time

from . import creds, ports

NGINX = os.environ.get("TEST_MU_NGINX", "/tmp/nginx-1.28.3/objs/nginx")
_CFG_SRC = os.path.join(os.path.dirname(__file__), "..", "configs", "multiuser")
_svc_s3 = creds.s3_key_for("svc")


def _base_subst() -> dict:
    return {
        "{ROOT_DIRECT_PORT}": str(ports.MU.ROOT_DIRECT),
        "{ROOT_CACHE_PORT}": str(ports.MU.ROOT_CACHE),
        "{WEBDAV_DIRECT_PORT}": str(ports.MU.WEBDAV_DIRECT),
        "{WEBDAV_CACHE_PORT}": str(ports.MU.WEBDAV_CACHE),
        "{S3_DIRECT_PORT}": str(ports.MU.S3_DIRECT),
        "{S3_CACHE_PORT}": str(ports.MU.S3_CACHE),
        "{CVMFS_CACHE_PORT}": str(ports.MU.CVMFS_CACHE),
        "{CACHE_NOIMP_PORT}": str(ports.MU.CACHE_NOIMP),
        "{ORIGIN_NOIMP_PORT}": str(ports.MU.ORIGIN_NOIMP),
        "{BIND_HOST}": ports.MU.HOST,
        "{DATA_DIR}": ports.MU.DATA_ROOT,
        "{CACHE_DIR}": ports.MU.CACHE_ROOT,
        "{LOG_DIR}": ports.MU.LOG_DIR,
        "{VOMSDIR}": ports.MU.VOMSDIR,
        "{CA_DIR}": ports.MU.CA_DIR,
        "{CA}": os.path.join(ports.MU.CA_DIR, "ca.pem"),
        "{CERT}": os.path.join(ports.MU.PKI_DIR, "server", "hostcert.pem"),
        "{KEY}": os.path.join(ports.MU.PKI_DIR, "server", "hostkey.pem"),
        "{JWKS}": os.path.join(ports.MU.TOKENS_DIR, "jwks.json"),
        "{S3_SVC_KEY}": _svc_s3[0],
        "{S3_SVC_SECRET}": _svc_s3[1],
        "{TMP_DIR}": os.path.join(ports.MU.LOG_DIR, "nginx_tmp"),
    }


def render_configs(backends: dict) -> None:
    """Substitute placeholders into every configs/multiuser/*.conf and validate with nginx -t."""
    for d in (ports.MU.CONFIG_DIR, ports.MU.LOG_DIR, ports.MU.DATA_ROOT, ports.MU.CACHE_ROOT,
              os.path.join(ports.MU.LOG_DIR, "nginx_tmp")):
        os.makedirs(d, exist_ok=True)
    subst = _base_subst()
    subst.update({"{GRIDMAP}": backends.get("gridmap", ""),
                  "{AUTHDB}": backends.get("authdb", ""),
                  "{VO}": backends.get("vo", ""),
                  "{S3KEYS}": backends.get("s3keys", "")})
    for src in sorted(glob.glob(os.path.join(_CFG_SRC, "*.conf"))):
        text = open(src).read()
        for k, v in subst.items():
            text = text.replace(k, v)
        dst = os.path.join(ports.MU.CONFIG_DIR, os.path.basename(src))
        open(dst, "w").write(text)
        pid = os.path.join(ports.MU.MU_ROOT, "nginx_t.pid")
        r = subprocess.run([NGINX, "-t", "-c", dst, "-g", f"pid {pid};"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise AssertionError(f"nginx -t failed for {dst}:\n{r.stderr}")


def _pidfile(name: str) -> str:
    return os.path.join(ports.MU.MU_ROOT, f"{name}.pid")


def start() -> None:
    for src in sorted(glob.glob(os.path.join(ports.MU.CONFIG_DIR, "*.conf"))):
        name = os.path.splitext(os.path.basename(src))[0]
        subprocess.run([NGINX, "-c", src, "-g", f"pid {_pidfile(name)};"],
                       check=True, capture_output=True)


def stop() -> None:
    for pf in glob.glob(os.path.join(ports.MU.MU_ROOT, "*.pid")):
        try:
            os.kill(int(open(pf).read().strip()), 15)
        except (ProcessLookupError, ValueError, FileNotFoundError):
            pass
        try:
            os.remove(pf)
        except FileNotFoundError:
            pass


def wait_listening(timeout: int = 15) -> None:
    deadline = time.time() + timeout
    for p in ports.MU.enforcing_ports() + [ports.MU.ROOT_DIRECT, ports.MU.WEBDAV_DIRECT,
                                           ports.MU.S3_DIRECT]:
        while time.time() < deadline:
            s = socket.socket()
            s.settimeout(0.5)
            try:
                s.connect((ports.MU.HOST, p))
                s.close()
                break
            except OSError:
                s.close()
                time.sleep(0.2)
        else:
            raise TimeoutError(f"MU port {p} never listened")


def url(proto: str, variant: str) -> str:
    port = getattr(ports.MU, f"{proto.upper()}_{variant.upper()}")
    scheme = {"root": "root", "webdav": "https", "s3": "http"}[proto]
    return f"{scheme}://{ports.MU.HOST}:{port}"
