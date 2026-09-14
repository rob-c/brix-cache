"""Keep installed GFAL commands independent of the pytest Python environment."""

import os
import shutil
from pathlib import Path


def clean_env(command="gfal-stat"):
    """Use the CLI installation's Python and system client libraries.

    GFAL's shell/Python launcher searches PATH for a Python with its bindings,
    but a pytest virtualenv can hide the distribution's matching interpreter.
    Its supported GFAL_PYTHONBIN override selects an adjacent python3 without
    changing PATH for other tools. Preserve an explicit caller override and
    leave missing installations to report their original execution failure.
    """
    env = dict(os.environ)
    for name in ("LD_LIBRARY_PATH", "PYTHONPATH", "PYTHONHOME"):
        env.pop(name, None)
    if not env.get("GFAL_PYTHONBIN"):
        executable = shutil.which(os.fspath(command), path=env.get("PATH", os.defpath))
        _select_installed_python(env, executable)
    return env


def _select_installed_python(env, executable):
    if executable is None:
        return
    interpreter = Path(executable).parent / "python3"
    if interpreter.is_file() and os.access(interpreter, os.X_OK):
        env["GFAL_PYTHONBIN"] = str(interpreter)
