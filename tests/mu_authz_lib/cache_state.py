"""Prove / force read-cache residency via the xrdcinfo tool (spec §8.5).

COLD is proven by cache_is_resident() returning {"absent": True}; HOT by an explicit,
verified fill as a privileged principal. Never assume residency — always check the .cinfo
present-bitmap.
"""
import json
import os
import shutil
import subprocess

from . import ports

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
XRDCINFO = os.path.join(_REPO, "client", "bin", "xrdcinfo")


def _ensure_tool() -> None:
    if not os.path.exists(XRDCINFO):
        subprocess.run(["make", "-C", os.path.join(_REPO, "client"), "xrdcinfo"],
                       check=True, capture_output=True)


def cache_is_resident(rel_path: str) -> dict:
    """Return the xrdcinfo record (present bitmap, complete flag, ...) or {"absent": True}."""
    _ensure_tool()
    cache_file = os.path.join(ports.MU.CACHE_ROOT, rel_path)
    for args in ([cache_file + ".cinfo"], ["--xattr", cache_file]):
        if args[-1] == cache_file and not os.path.exists(cache_file):
            continue
        p = subprocess.run([XRDCINFO, *args], capture_output=True, text=True)
        out = p.stdout.strip()
        if out:
            try:
                rec = json.loads(out)
            except json.JSONDecodeError:
                continue
            if not rec.get("absent"):
                return rec
    return {"absent": True}


def force_cold(rel_path: "str | None" = None) -> None:
    """Reset to COLD: wipe the whole cache store, or just one path's data + sidecar."""
    if rel_path is None:
        if os.path.exists(ports.MU.CACHE_ROOT):
            shutil.rmtree(ports.MU.CACHE_ROOT)
        os.makedirs(ports.MU.CACHE_ROOT, exist_ok=True)
        return
    for suffix in ("", ".cinfo"):
        f = os.path.join(ports.MU.CACHE_ROOT, rel_path) + suffix
        try:
            os.remove(f)
        except FileNotFoundError:
            pass


def fill_as(principal, rel_path: str, proto: str = "root") -> None:
    """Populate the cache by reading the whole file via the cache server as `principal`."""
    from . import fleet
    from .adapters import measure_root, measure_webdav, measure_s3
    fn = {"root": measure_root, "webdav": measure_webdav, "s3": measure_s3}[proto]
    fn(fleet.url(proto, "cache"), "/" + rel_path, "read", principal=principal)


def verify_hot(rel_path: str) -> bool:
    rec = cache_is_resident(rel_path)
    return (not rec.get("absent")) and bool(
        rec.get("complete") or rec.get("present_count", 0) or rec.get("present_blocks"))
