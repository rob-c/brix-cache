"""Helpers for reviewable nginx config templates under tests/configs."""

import re
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parent / "configs"
# A template placeholder is a BARE ``{KEY}``.  nginx's own brace-variable syntax
# ``${request_time}`` (used in log_format) must NOT be mistaken for one: the
# negative lookbehind excludes any ``{...}`` immediately preceded by ``$``.
_PLACEHOLDER_RE = re.compile(r"(?<!\$)\{[A-Za-z_][A-Za-z0-9_]*\}")
# The same placeholder, opening its line: nothing but indentation before it.
_LINE_LEADING_RE = re.compile(r"^[ \t]*\{([A-Za-z_][A-Za-z0-9_]*)\}")


def unresolved_placeholders(text):
    return sorted(set(_PLACEHOLDER_RE.findall(text)))


def line_carrying_placeholders(text):
    """Placeholders the template gives a whole line of their own.

    A ``{KEY}`` that OPENS its line is filled with a complete directive (or a
    block of them): the template reserves nothing but the slot, so the caller
    supplies the leading indentation and the trailing newline.  What follows on
    the same line is the block's closing brace or the next directive, which is
    why "alone on the line" is too narrow a test — ``{SSS_LINES}    }`` is the
    same shape.
    """
    return {
        match.group(1)
        for match in (_LINE_LEADING_RE.match(line) for line in text.splitlines())
        if match
    }


def comment_swallowed_placeholders(text):
    """Line-carrying placeholders this template also names inside a ``#`` comment.

    Each hit is a latent parse defect.  The value substituted for such a
    placeholder carries its own newline, so inside a comment it ends the comment
    early and hands nginx the remainder of the sentence as a directive — or, for
    a single-line value, is swallowed by the comment entirely and the directive
    silently disappears.  Comments must name these placeholders WITHOUT braces.
    Returns ``[(lineno, name), ...]``, one-based, in file order.
    """
    carried = line_carrying_placeholders(text)
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.lstrip().startswith("#"):
            continue
        for found in _PLACEHOLDER_RE.findall(line):
            name = found[1:-1]
            if name in carried:
                hits.append((lineno, name))
    return hits


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
