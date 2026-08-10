"""xrdfs REPL scriptability — comments + TTY-gated prompt (parity-audit §7.12).

The interactive shell had two script-hostile behaviors: a `#` comment line
tripped "unknown command '#'", and the `[host:port] cwd >` prompt was printed
even when stdin was a pipe — corrupting the captured stdout of a piped command
script.  Both are fixed: blank lines and `#` comments are skipped, and the
prompt is gated on an stdin TTY (stock xrdfs convention).

  * success   — a piped script (comments, blanks, real commands) produces
                CLEAN stdout: only the command output, no prompts, no comment
                errors
  * error     — an unknown command in a script still reports to stderr (the
                fix suppresses the PROMPT, not diagnostics)
  * interactive — with stdin on a real TTY (pty) the prompt IS shown, so the
                human experience is unchanged

Run:
    PYTHONPATH=tests pytest tests/test_xrdfs_repl_script.py -v
"""

import os
import pty
import select
import subprocess

import pytest

from settings import NGINX_ANON_PORT, SERVER_HOST

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
XRDFS = os.path.join(REPO, "client", "bin", "xrdfs")
URL = f"root://{SERVER_HOST}:{NGINX_ANON_PORT}"

pytestmark = [
    pytest.mark.requires_local_server,
    pytest.mark.timeout(60),
    pytest.mark.skipif(not os.path.exists(XRDFS),
                       reason="brix-xrdfs not built (client/bin/xrdfs)"),
]


class TestReplScript:

    def test_piped_script_clean_stdout(self):
        """(success) comments + blank lines are skipped and no prompt pollutes
        stdout — the two pwd lines are the ENTIRE output."""
        script = b"# a comment\n\npwd\ncd /alpha\npwd\nexit\n"
        res = subprocess.run([XRDFS, URL], input=script,
                             capture_output=True, timeout=30)
        assert res.returncode == 0, res.stderr
        assert res.stdout == b"/\n/alpha\n", res.stdout

    def test_comment_not_an_error(self):
        """(error-shape) a bare comment line does NOT emit the old
        'unknown command #' diagnostic."""
        res = subprocess.run([XRDFS, URL],
                             input=b"#!/usr/bin/xrdfs script\nexit\n",
                             capture_output=True, timeout=30)
        assert res.returncode == 0
        assert b"unknown command" not in res.stderr

    def test_unknown_command_still_reported(self):
        """(error) suppressing the prompt must not suppress diagnostics — an
        unknown command still goes to stderr, and never to stdout."""
        res = subprocess.run([XRDFS, URL],
                             input=b"boguscmd\nexit\n",
                             capture_output=True, timeout=30)
        assert b"unknown command 'boguscmd'" in res.stderr
        assert b"boguscmd" not in res.stdout

    def test_interactive_pty_shows_prompt(self):
        """(interactive) with stdin on a real TTY the prompt is printed, so the
        human REPL experience is preserved."""
        master, slave = pty.openpty()
        proc = subprocess.Popen([XRDFS, URL], stdin=slave,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.close(slave)
        try:
            os.write(master, b"exit\n")
            out = b""
            # drain the child's stdout until it exits
            proc.wait(timeout=30)
            while True:
                ready, _, _ = select.select([proc.stdout], [], [], 0.5)
                if not ready:
                    break
                chunk = proc.stdout.read1(65536)
                if not chunk:
                    break
                out += chunk
            assert b" > " in out, f"no prompt on a TTY: {out!r}"
        finally:
            os.close(master)
            if proc.poll() is None:
                proc.kill()
            proc.wait()
