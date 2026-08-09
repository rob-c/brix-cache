"""Load mechanically split Python source as continuations of its parent.

These shards reduce physical file size but are not standalone modules: code in
later shards intentionally refers to private helpers, registries, and classes
defined earlier.  ``import *`` cannot preserve that namespace (and suppresses
underscore-prefixed names), while executing compiled shards in order does.
"""

from pathlib import Path
from typing import MutableMapping
import importlib
import importlib.util
import re


def load(namespace: MutableMapping[str, object], anchor: str, *parts: str) -> None:
    directory = Path(anchor).resolve().parent
    for name in parts:
        path = directory / name
        source = path.read_text(encoding="utf-8")
        exec(compile(source, str(path), "exec"), namespace)


def reexport(namespace: MutableMapping[str, object], module_name: str) -> None:
    """Re-export a split helper's pre-split API, including private helpers."""
    # A suffixed helper is a physical continuation of the base helper, not a
    # standalone module.  Execute it against the accumulated parent namespace.
    if re.search(r"_helpers(?:_[a-z])+$", module_name):
        spec = importlib.util.find_spec(module_name)
        if spec is None or spec.origin is None:
            raise ModuleNotFoundError(module_name)
        path = Path(spec.origin)
        exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), namespace)
        return
    module = importlib.import_module(module_name)
    namespace.update({
        name: value for name, value in vars(module).items()
        if not (name.startswith("__") and name.endswith("__"))
    })
