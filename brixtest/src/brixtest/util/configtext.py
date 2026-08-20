"""Config templating (feature F13).

``render_cfg`` is deliberately literal ``{key}`` string replacement —
not ``str.format`` — so brace constructs that belong to the target
config language (nginx blocks, shell expansions) pass through
untouched.  The optional strict scan reports unresolved placeholders
at the *cause* instead of two steps downstream, filtered through a
whitelist of deliberate literal braces.
"""

from __future__ import annotations

import re
from typing import Iterable, Mapping, Sequence

from brixtest.errors import TemplateError

__all__ = ["render_cfg", "render_cfg_strict", "unresolved_placeholders"]

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def render_cfg(text: str, values: Mapping[str, object]) -> str:
    """Replace each ``{key}`` occurrence literally; unknown braces pass through."""
    for key, value in values.items():
        text = text.replace("{" + key + "}", str(value))
    return text


def unresolved_placeholders(
    text: str, whitelist: Iterable[str] = ()
) -> Sequence[str]:
    """Names that still look like placeholders after rendering."""
    allowed = set(whitelist)
    return sorted(
        {name for name in _PLACEHOLDER.findall(text) if name not in allowed}
    )


def render_cfg_strict(
    text: str,
    values: Mapping[str, object],
    *,
    template: str = "<inline>",
    whitelist: Iterable[str] = (),
) -> str:
    rendered = render_cfg(text, values)
    missing = unresolved_placeholders(rendered, whitelist)
    if missing:
        raise TemplateError(template, missing)
    return rendered
