"""Phase 49 ownership guards for the shared client transfer engine."""
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / "client"


def _text(relative: str) -> str:
    return (CLIENT / relative).read_text(encoding="utf-8")


def test_recursive_web_and_relay_are_library_objects() -> None:
    makefile = _text("Makefile")
    for source in (
        "lib/xfer/copy_web_recursive.c",
        "lib/xfer/copy_web_recursive_upload.c",
        "lib/xfer/copy_web_relay.c",
    ):
        assert source in makefile
    xrdcp_objects = next(
        line for line in makefile.splitlines() if line.startswith("xrdcp_OBJS")
    )
    assert "xrdcp_recursive_upload" not in xrdcp_objects


def test_brix_copy_routes_every_web_transfer_shape() -> None:
    router = _text("lib/xfer/copy_upload.c")
    assert "copy_web_recursive_download" in router
    assert "copy_web_recursive_upload" in router
    assert "copy_web_relay" in router
    assert "recursive copy is not supported for web" not in router


def test_xrdcp_has_no_private_web_copy_engine() -> None:
    app_source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((CLIENT / "apps/copy").glob("*.c"))
    )
    for private_engine in (
        "recursive_web_download(",
        "recursive_web_upload(",
        "relay_web_to_web(",
        "web_upload_walk(",
    ):
        assert re.search(rf"(?<![A-Za-z0-9_]){re.escape(private_engine)}",
                         app_source) is None
