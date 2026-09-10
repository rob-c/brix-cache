"""Corpus hygiene for the nginx config templates under ``tests/configs``.

THE DEFECT CLASS (found 2026-09-09, twice in one afternoon)

A template placeholder that OPENS its line is filled with a whole line: the
template reserves nothing but the slot, so the value carries the indentation
and, where the slot is a block, the trailing newline.  Naming such a
placeholder inside a ``#`` comment — the natural thing to do in a file header
that documents its own slots — makes the comment interpolate it too, and the
substitution then lands in the middle of a comment.  Both halves of the class
are silent about their real cause:

  * a value WITH a trailing newline ends the comment early, and nginx parses
    the remainder of the English sentence as a directive.  This is what broke
    ``nginx_release20_sss_validate.conf`` and ``nginx_release20_tpc_validate.conf``:
    fifteen grammar tests failed with ``unknown directive ")"`` on the third
    line, pointing at prose that had been valid comment text a moment earlier.
  * a value WITHOUT one is swallowed by the comment whole, and the directive
    simply disappears — ``nginx -t`` accepts the config and the arm the test
    believes it is driving is not armed at all.

The second half is the dangerous one: it turns an access-control or auth line
into a no-op without any diagnostic, so a security-negative test can pass
against an endpoint that is wide open.  Hence a static pin over the corpus
rather than a promise to be careful.  Comments name these placeholders WITHOUT
braces (``EXTRA_DIRECTIVES``, not ``{EXTRA_DIRECTIVES}``), which is already the
house style of the "Launcher-provided:" header lines.
"""

import pytest

from config_parse import nginx_t_text
from config_templates import (
    CONFIG_DIR,
    comment_swallowed_placeholders,
    line_carrying_placeholders,
)
from fleet_lifecycle_ports import SHARED_PARSE_PLACEHOLDER_PORT

pytestmark = [pytest.mark.timeout(120)]

# The probe body: a stream server whose only access control arrives through a
# line-carrying slot, exactly as the corpus does it.
PROBE = """worker_processes 1;
daemon off;
error_log {log}/error.log;
events {{ worker_connections 64; }}
stream {{
    server {{
        listen 127.0.0.1:{port};
        brix_root on;
        brix_storage_backend posix:{data};
        brix_auth none;
{slot}    }}
}}
"""

# Documented in a comment the way a template header documents its own slots.
HEADER = "# The {DENY_LINES} slot carries this server's access control.\n"


def _scan_corpus():
    """(templates scanned, templates with a line-carrying slot, violations)."""
    scanned, carrying, offenders = 0, 0, []
    for template in sorted(CONFIG_DIR.glob("*.conf")):
        text = template.read_text(encoding="utf-8")
        scanned += 1
        if line_carrying_placeholders(text):
            carrying += 1
        for lineno, name in comment_swallowed_placeholders(text):
            offenders.append(f"{template.name}:{lineno}: {{{name}}}")
    return scanned, carrying, offenders


def _active(body, needle):
    """The lines of ``body`` carrying ``needle`` that nginx still sees."""
    return [
        line for line in body.splitlines()
        if needle in line and not line.lstrip().startswith("#")
    ]


def _probe(tmp_path, slot, header=""):
    data = tmp_path / "data"
    data.mkdir(parents=True, exist_ok=True)
    logs = tmp_path / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    body = header + PROBE.format(
        log=logs, data=data, port=SHARED_PARSE_PLACEHOLDER_PORT, slot=slot
    )
    return body, nginx_t_text(body, tmp_path)


def test_no_template_names_a_line_carrying_placeholder_in_a_comment():
    """Every template in the corpus obeys the rule."""
    scanned, carrying, offenders = _scan_corpus()
    assert offenders == []
    # An inert scanner would also report nothing: pin that it is looking at the
    # real corpus and that most of it does use line-carrying slots.
    assert scanned > 500, scanned
    assert carrying > 100, carrying
    probe = (CONFIG_DIR / "nginx_release20_sss_validate.conf").read_text()
    assert "SSS_LINES" in line_carrying_placeholders(probe)


def test_the_scanner_names_the_line_and_the_placeholder_it_would_swallow():
    """The guard fails on the shape it exists to forbid, and only on that shape."""
    slotted = "stream {\n{DENY_LINES}}\n"
    assert comment_swallowed_placeholders(
        "# carried by {DENY_LINES}, which is the defect\n" + slotted
    ) == [(1, "DENY_LINES")]
    # The house style — the same name without braces — is clean.
    assert comment_swallowed_placeholders(
        "# carried by DENY_LINES, which is fine\n" + slotted
    ) == []
    # A placeholder that never opens a line is substituted mid-directive, so a
    # comment may interpolate it: it cannot carry a newline into one.
    assert comment_swallowed_placeholders(
        "# the front listens on {PORT}\nlisten 127.0.0.1:{PORT};\n"
    ) == []
    # nginx's own ${var} syntax is not a placeholder in either position.
    assert comment_swallowed_placeholders(
        "# logs ${request_time}\n${request_time}\n"
    ) == []


def test_a_swallowed_access_rule_parses_clean_and_leaves_the_server_open(tmp_path):
    """Security-negative: the silent half of the class defeats `nginx -t`.

    The value carries no trailing newline, so the comment absorbs it whole.
    nginx reports the config as valid while the server it describes has lost
    its only ``deny`` rule — which is why the pin above is static and does not
    rely on a parse failure to announce the defect.
    """
    armed_body, armed = _probe(tmp_path / "armed", "        deny all;\n")
    swallowed_body, swallowed = _probe(
        tmp_path / "swallowed",
        "        deny all;\n",
        header=HEADER.replace("{DENY_LINES}", "        deny all;"),
    )
    assert armed.returncode == 0, armed.stderr
    assert swallowed.returncode == 0, swallowed.stderr
    # Both are "syntax is ok" — the difference is only in what survives as a
    # directive, and every deny in the swallowed variant is commented out.
    active = _active(swallowed_body, "deny")
    assert len(active) == 1, active
    assert _active(armed_body, "deny") == active


def test_a_swallowed_block_ends_the_comment_and_derails_the_parse(tmp_path):
    """The noisy half: the 2026-09-09 witness, reproduced.

    A block-shaped value ends the comment at its own newline, so the rest of
    the sentence becomes a directive and nginx blames prose it accepted a
    moment ago — never the slot that actually went wrong.
    """
    _, derailed = _probe(
        tmp_path,
        "        deny all;\n",
        header=HEADER.replace("{DENY_LINES}", "        deny all;\n"),
    )
    assert derailed.returncode != 0
    assert "unknown directive" in derailed.stderr, derailed.stderr
    # The diagnostic names the comment's own words, not `deny`.
    assert "slot" in derailed.stderr, derailed.stderr
    assert "deny" not in derailed.stderr.split("unknown directive")[1]
