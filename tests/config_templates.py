"""Helpers for reviewable nginx config templates under tests/configs."""

import re
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parent / "configs"
# A template placeholder is a BARE ``{KEY}``.  nginx's own brace-variable syntax
# ``${request_time}`` (used in log_format) must NOT be mistaken for one: the
# negative lookbehind excludes any ``{...}`` immediately preceded by ``$``.
_PLACEHOLDER_RE = re.compile(r"(?<!\$)\{[A-Za-z_][A-Za-z0-9_]*\}")


def unresolved_placeholders(text):
    return sorted(set(_PLACEHOLDER_RE.findall(text)))


def render_config(name, strict=False, **values):
    text = (CONFIG_DIR / name).read_text(encoding="utf-8")
    for key, value in values.items():
        text = text.replace("{" + key + "}", str(value))
    if strict:
        unresolved = unresolved_placeholders(text)
        if unresolved:
            joined = ", ".join(unresolved)
            raise ValueError(f"{name} has unresolved placeholders: {joined}")
    return text


def render_config_to_path(name, dest, strict=False, **values):
    text = render_config(name, strict=strict, **values)
    target = Path(dest)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")
    return target
