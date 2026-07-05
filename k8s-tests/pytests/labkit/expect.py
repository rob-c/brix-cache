"""expect — fluent assertions so a test body reads as one line.

``Result`` wraps a finished command (exit code + combined output); ``Text`` wraps
file/string content. Both support ``.shows()`` / ``.hides()``; ``Result`` adds
``.ok()`` / ``.fails()``. Every method returns ``self`` so calls chain.
"""
from __future__ import annotations

import re


class _Match:
    @property
    def _hay(self) -> str:
        raise NotImplementedError

    def shows(self, *needles):
        for n in needles:
            assert str(n) in self._hay, f"expected {n!r} in:\n{self._hay}"
        return self

    def hides(self, *needles):
        for n in needles:
            assert str(n) not in self._hay, f"unexpected {n!r} in:\n{self._hay}"
        return self


class Result(_Match):
    def __init__(self, cp):
        self.cp = cp

    @property
    def rc(self):
        return self.cp.returncode

    @property
    def _hay(self):
        return (self.cp.stdout or "") + (self.cp.stderr or "")

    def ok(self):
        assert self.rc == 0, f"command failed (rc={self.rc}):\n{self._hay}"
        return self

    def fails(self, code=None):
        assert self.rc != 0, f"expected failure but it succeeded:\n{self._hay}"
        if code is not None:
            assert self.rc == code, f"expected rc {code}, got {self.rc}:\n{self._hay}"
        return self


class Text(_Match):
    def __init__(self, source):
        self.text = source if isinstance(source, str) else source.read_text()

    @property
    def _hay(self):
        return self.text

    def count(self, pattern, n):
        got = len(re.findall(pattern, self.text, re.M))
        assert got == n, f"expected {n}× {pattern!r}, got {got}"
        return self

    def no_unmapped_markers(self):
        left = re.findall(r"\{[A-Z_0-9]+\}", self.text)
        assert not left, f"unmapped markers remain: {left}"
        return self
