"""
Phase-65 fail2ban deliverables — filter regexes vs the sample audit log.

Two layers:
- pure-Python: parse each filter.d file, translate fail2ban's <HOST> token,
  and assert the failregex extracts exactly the expected IP from the sample
  lines (runs everywhere, no fail2ban needed);
- fail2ban-regex subprocess: the authoritative check, skipped when the tool
  is not installed.

Run:
    PYTHONPATH=tests pytest tests/test_fail2ban_regex.py -v -p no:xdist
"""

import configparser
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
FILTER_DIR = ROOT / "deploy" / "fail2ban" / "filter.d"
SAMPLE = ROOT / "deploy" / "fail2ban" / "samples" / "brix-guard-audit.sample.log"
CVMFS_SAMPLE = (ROOT / "deploy" / "fail2ban" / "samples"
                / "nginx-xrootd-cvmfs.sample.log")

CASES = [
    ("signature", "203.0.113.9"),
    ("grammar", "198.51.100.7"),
    ("notfound", "203.0.113.9"),
    ("authfail", "192.0.2.5"),
    ("notroot", "203.0.113.44"),
    ("proxyabuse", "198.51.100.23"),
    ("cvmfs_tamper", "203.0.113.77"),
]

# fail2ban's <HOST> expands to an IPv4/IPv6/hostname group.
HOST_RE = r"(?P<host>[0-9a-fA-F.:]+)"


def _load_failregex(signal):
    parser = configparser.ConfigParser()
    parser.read(FILTER_DIR / f"xrootd-guard-{signal}.conf")
    return parser["Definition"]["failregex"]


class TestFilterRegexPure:
    @pytest.mark.parametrize("signal,host", CASES)
    def test_failregex_extracts_host(self, signal, host):
        """The filter's failregex matches its sample line and captures the IP."""
        pattern = _load_failregex(signal).replace("<HOST>", HOST_RE)
        matches = [re.search(pattern, line)
                   for line in SAMPLE.read_text().splitlines()]
        hits = [m for m in matches if m]
        assert len(hits) == 1, f"{signal}: expected exactly one sample hit"
        assert hits[0].group("host") == host

    @pytest.mark.parametrize("signal", [c[0] for c in CASES])
    def test_failregex_ignores_other_signals(self, signal):
        """Each filter fires only on its own signal (no cross-matching)."""
        pattern = _load_failregex(signal).replace("<HOST>", HOST_RE)
        for line in SAMPLE.read_text().splitlines():
            if f"signal={signal}" not in line:
                assert not re.search(pattern, line), \
                    f"{signal} filter matched foreign line: {line}"


@pytest.mark.skipif(not shutil.which("fail2ban-regex"),
                    reason="fail2ban-regex not installed")
class TestFail2banRegexTool:
    @pytest.mark.parametrize("signal,host", CASES)
    def test_filter_extracts_host(self, signal, host):
        """fail2ban-regex matches the sample line and extracts the IP.

        ``--print-all-matched`` is required: without it, fail2ban-regex only
        echoes the *missed* lines, so a matched line's IP would appear in the
        output only by coincidence (e.g. when two sample lines share an IP).
        With the flag, the matched line — and hence its extracted host — is
        printed under the "Matched line(s)" section, which is what we assert on.
        """
        flt = FILTER_DIR / f"xrootd-guard-{signal}.conf"
        out = subprocess.run(
            ["fail2ban-regex", "--print-all-matched", str(SAMPLE), str(flt)],
            capture_output=True, text=True).stdout

        # Exactly one sample line must fire this filter.
        assert "1 matched" in out, f"expected one match:\n{out}"

        # The extracted host must appear on the matched line.
        matched = out.partition("Matched line(s)")[2].partition(
            "Missed line(s)")[0]
        assert host in matched, f"IP not extracted from matched line:\n{out}"


class TestCvmfsFilterRegex:
    """Phase-68: the cvmfs-reject filter vs its error-log sample lines."""

    def _pattern(self):
        parser = configparser.ConfigParser()
        parser.read(FILTER_DIR / "nginx-xrootd-cvmfs.conf")
        return parser["Definition"]["failregex"].replace("<HOST>", HOST_RE)

    def test_matches_reject_lines_and_extracts_host(self):
        pattern = self._pattern()
        hits = [re.search(pattern, line)
                for line in CVMFS_SAMPLE.read_text().splitlines()]
        hosts = [m.group("host") for m in hits if m]
        assert hosts == ["192.0.2.7", "192.0.2.7", "198.51.100.9"]

    def test_ignores_non_reject_warnings(self):
        pattern = self._pattern()
        stale = [l for l in CVMFS_SAMPLE.read_text().splitlines()
                 if "serving stale copy" in l]
        assert stale, "sample must carry a NOMATCH control line"
        for line in stale:
            assert re.search(pattern, line) is None
