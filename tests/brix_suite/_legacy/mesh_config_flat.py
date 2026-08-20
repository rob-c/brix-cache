"""On-disk config-template rendering for the mesh generators.

Templates live in tests/configs/mesh/.  render() reads one and substitutes
{KEY} placeholders — the Python counterpart to the shell harness's render_cfg()
/ substitute_config().  This keeps every mesh server config an explicit,
reviewable, committed file instead of an inline f-string in the builders.

Placeholders left unsubstituted by render() (e.g. {PID} / {ERR}, filled later by
Mesh.nginx()) are preserved verbatim, so a template may carry both build-time and
launch-time placeholders.
"""

import os

CONFIGS_DIR = os.path.join(os.path.dirname(__file__), "configs", "mesh")


def render(template, **values):
    """Return the template's text with each {KEY} replaced by str(value)."""
    with open(os.path.join(CONFIGS_DIR, template), encoding="utf-8") as fh:
        text = fh.read()
    for key, value in values.items():
        text = text.replace("{" + key + "}", str(value))
    return text
