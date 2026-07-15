"""Helpers for reviewable nginx config templates under tests/configs."""

from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parent / "configs"


def render_config(name, **values):
    text = (CONFIG_DIR / name).read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace("{" + key + "}", str(value))
    return text
