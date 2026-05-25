import socket
import time
from pathlib import Path

THIS_DIR = Path(__file__).resolve().parent
MANAGE_SCRIPT = str(THIS_DIR / "manage_test_servers.sh")
CONFIGS_DIR = THIS_DIR / "configs"


DEDICATED_ONLY_ERROR = (
    "Ephemeral test server creation has been removed. Add the server role to "
    "tests/manage_test_servers.sh start-all, assign it a fixed port in "
    "tests/settings.py, and use the dedicated test_env/settings value instead."
)


def _read_config_text(conf_file: str) -> str:
    path = Path(conf_file)
    if not path.is_absolute():
        path = CONFIGS_DIR / path
    return path.read_text(encoding="utf-8")


def _render_config(conf_text: str, placeholders: dict[str, str]) -> str:
    text = conf_text
    for k, v in placeholders.items():
        text = text.replace(f"{{{k}}}", str(v))
    # Convert escaped braces (Python f-string convention) to literal braces
    text = text.replace("{{", "{").replace("}}", "}")
    return text


def render_config_file(conf_file: str, template_kwargs: dict | None = None) -> str:
    if template_kwargs is None:
        template_kwargs = {}
    return _render_config(_read_config_text(conf_file), template_kwargs)


def _free_port() -> int:
    raise RuntimeError(DEDICATED_ONLY_ERROR)


def _wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except Exception:
            time.sleep(0.1)
    return False


def start_nginx_instance(
    port: int | None = None,
    nginx_bin: str | None = None,
    conf_file: str | None = None,
    conf_text: str | None = None,
    template_kwargs: dict | None = None,
) -> dict:
    """Deprecated hard failure: all nginx servers are suite-level dedicated servers."""
    raise RuntimeError(DEDICATED_ONLY_ERROR)


def start_xrootd_instance(
    port: int | None = None,
    ref_bin: str | None = None,
    ref_dir: str | None = None,
    data_dir: str | None = None,
    conf_file: str = "xrootd_ref.conf",
    template_kwargs: dict | None = None,
) -> dict:
    """Deprecated hard failure: all xrootd servers are suite-level dedicated servers."""
    raise RuntimeError(DEDICATED_ONLY_ERROR)
