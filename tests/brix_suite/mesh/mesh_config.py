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

from brix_suite.settings import TESTS_DIR

# The templates stayed in ``tests/configs/mesh/`` (they are read by the
# guards and edited by hand); this module did not, so the directory is
# named from the suite root rather than from this file's parent.
CONFIGS_DIR = os.path.join(TESTS_DIR, "configs", "mesh")


def render(template, **values):
    """Return the template's text with each {KEY} replaced by str(value)."""
    with open(os.path.join(CONFIGS_DIR, template), encoding="utf-8") as fh:
        text = fh.read()
    for key, value in values.items():
        text = text.replace("{" + key + "}", str(value))
    return text
