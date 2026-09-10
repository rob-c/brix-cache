"""Fork-safety registry internals (phase-115 W7.3, parity-audit §7.7).

W7.3 was already implemented when the register row was written, and the row's
stated success criterion — "a forked child continues a parent's open stream
correctly" — describes the OPPOSITE of what shipped and of what is safe. A
child must NOT continue the parent's stream: the fd is shared, so any child
byte interleaves into the parent's session and a child `kXR_endsess` kills it
server-side. The shipped design neuters the child's copies and lets an embedder
re-dial. What was genuinely missing was coverage of the registry that does the
neutering, and two defects it was hiding:

  1. `brix_forksafe_register` appended blindly, so re-dialling an
     already-registered conn took a SECOND slot. `brix_connect_setup` memsets
     the conn, so a child re-dial is a register with no intervening
     unregister — one duplicate per fork/re-dial cycle. The table fills, the
     overflow counter starts running, and from then on new connections are
     never neutered in a child: fork safety turns itself off, silently. The
     surplus entries also outlive `brix_close`'s single unregister, leaving
     pointers into a conn the caller may free.
  2. `brix_bind` never registered the bound substream. A substream is a second
     live socket to the same server, and the high-throughput read path is made
     of them — so the connections most likely to be open when a framework
     forks were exactly the ones nothing neutered.

  * success   — registration is idempotent by identity, distinct conns get
                distinct slots, a real fork() neuters the child's copies and
                empties the child's table
  * error     — a double unregister is harmless; the overflow counter is
                readable, so "the table filled and fork safety is off" is an
                observable state rather than a silent one
  * safety    — the PARENT's conn survives the child untouched; every code
                path in the client that establishes a live socket registers it

Run:
    PYTHONPATH=tests pytest tests/test_client_forksafe_registry.py -v
"""

import os
import re
import subprocess
from brix_suite.client_build import client_make
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_DIR = os.path.join(REPO, "client")
FORKSAFE_BIN = os.path.join(CLIENT_DIR, "bin", "forksafe_test")
CONN_C = os.path.join(CLIENT_DIR, "lib", "net", "conn.c")
STREAMS_C = os.path.join(CLIENT_DIR, "lib", "net", "streams.c")
FORKSAFE_C = os.path.join(CLIENT_DIR, "lib", "net", "forksafe.c")

pytestmark = pytest.mark.timeout(300)


def _run_env():
    """Make the optional codec/krb5 libs resolvable for both link and runtime
    when the toolchain is a conda prefix; a no-op on a system build."""
    env = dict(os.environ)
    prefix = env.get("CONDA_PREFIX") or sys.prefix
    pcdir = os.path.join(prefix, "lib", "pkgconfig")
    if os.path.isdir(pcdir):
        libdir = os.path.join(prefix, "lib")
        env["LD_LIBRARY_PATH"] = libdir + os.pathsep + env.get("LD_LIBRARY_PATH", "")
        env["PKG_CONFIG_PATH"] = pcdir + os.pathsep + env.get("PKG_CONFIG_PATH", "")
    return env


@pytest.fixture(scope="module")
def forksafe_bin():
    """Build only when missing — a failed link would delete a good pre-built
    binary, and this suite's static half is worth running either way."""
    out = b""
    if not os.path.exists(FORKSAFE_BIN):
        r = client_make(CLIENT_DIR, "forksafe", env=_run_env(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        out = r.stdout
    if not os.path.exists(FORKSAFE_BIN):
        pytest.skip("run `make -C client forksafe`:\n"
                    f"{out.decode(errors='replace')[-800:]}")
    return FORKSAFE_BIN


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)


def _code(path):
    """The file with comments blanked out.

    Every guard below asks whether a source file CALLS something. The header
    of `forksafe.c` explains at length why it must never call `SSL_free` or
    `fclose` — a scan of the raw text would read that explanation as the
    offence it warns about, and would go on passing if the call appeared.
    Newlines are preserved so any line arithmetic still lines up."""
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)),
                        _read(path))


# A C function body: the definition line through the closing brace in column 0.
_FUNC = re.compile(r"^([a-z_][a-z_0-9]*)\(.*?^\}", re.M | re.S)


def _functions(text):
    """{name: body} for every top-level function in a source file."""
    return {m.group(1): m.group(0) for m in _FUNC.finditer(text)}


class TestForksafeRegistryUnits:
    """The C unit binary: idempotency, exhaustive unregister, a real fork()."""

    def test_the_registry_units_all_pass(self, forksafe_bin):
        """(success + error + safety) every check the C harness makes, in one
        row because the binary reports them as one verdict. Its stderr is
        attached on failure so the failing check names itself."""
        p = subprocess.run([forksafe_bin], env=_run_env(),
                           capture_output=True, text=True, timeout=120)
        assert p.returncode == 0, p.stderr
        assert "PASSED" in p.stderr, p.stderr

    def test_every_named_check_actually_ran(self, forksafe_bin):
        """(error class) a harness that silently stopped early would still exit
        0 on the checks it did reach. Pin the count and the sections."""
        p = subprocess.run([forksafe_bin], env=_run_env(),
                           capture_output=True, text=True, timeout=120)
        assert p.returncode == 0, p.stderr
        assert p.stderr.count("  ok: ") == 12, p.stderr
        for section in ("[registry] register is idempotent",
                        "[registry] distinct conns are distinct entries",
                        "[registry] unregister leaves nothing behind",
                        "[fork] the child's inherited conn is neutered"):
            assert section in p.stderr, section


class TestEveryLiveSocketIsRegistered:
    """The static half: the hole `brix_bind` had, made un-reopenable."""

    # brix_reconnect re-establishes an EXISTING conn after a redirect. The
    # pointer never left the table (brix_close is the only unregister on that
    # path and it has not run), so re-registering would be redundant — and is
    # harmless anyway now that registration is idempotent.
    _EXEMPT = {"brix_reconnect", "brix_bringup", "brix_bringup_ex"}

    def test_every_bringup_caller_registers_its_connection(self):
        """(safety) THE guard. Any function that brings a socket up to a
        usable state owns a live fd a forked child would inherit; if it does
        not register, that fd is never neutered and the child's first send
        interleaves into the parent's stream."""
        funcs = _functions(_read(CONN_C))
        offenders = [
            name for name, body in funcs.items()
            if name not in self._EXEMPT
            and re.search(r"\bbrix_bringup(_ex)?\s*\(", body)
            and "brix_forksafe_register" not in body
        ]
        assert offenders == [], offenders

    def test_the_bound_substream_is_registered(self):
        """(safety) named explicitly, because this is the one that was
        missing: the high-throughput read path is made of bound substreams,
        so these were the connections most likely to be live at fork time."""
        body = _functions(_code(CONN_C))["brix_bind"]
        assert "brix_forksafe_register(sec)" in body

    def test_the_substream_teardown_unregisters(self):
        """(safety) a bound stream owns no session, so it never goes through
        brix_close — the only other unregister. Without this the streamset's
        memory is reused with the registry still pointing at it, and the next
        fork's child handler writes through that pointer."""
        body = _functions(_code(STREAMS_C))["brix_streams_close"]
        assert "brix_forksafe_unregister" in body
        shutdown = re.search(r"[^_a-z]close\(ss->", body)
        assert shutdown and body.index("brix_forksafe_unregister") < shutdown.start()

    def test_close_unregisters_before_any_teardown_byte(self):
        """(safety) ordering matters: brix_close may emit kXR_endsess, and a
        conn still in the table while it does is a conn a concurrent fork
        would neuter mid-write."""
        body = _functions(_code(CONN_C))["brix_close"]
        assert "brix_forksafe_unregister" in body
        tail = body[body.index("brix_forksafe_unregister"):]
        assert "brix_forksafe_unregister" in tail.split("\n")[0]
        head = body[:body.index("brix_forksafe_unregister")]
        assert "endsess" not in head and "brix_send" not in head


class TestRegistryInvariants:
    """Properties of forksafe.c that the C harness cannot see from outside."""

    def test_registration_looks_for_the_conn_before_taking_a_slot(self):
        """(success) the fix, pinned at the source: a scan that returns the
        existing slot, not the first free one."""
        body = _functions(_code(FORKSAFE_C))["forksafe_slot_for"]
        assert "g_fs_reg[i] == c" in body
        assert "return i;" in body

    def test_unregister_clears_every_slot_not_the_first(self):
        """(error class) the `break` that used to be here left duplicates
        behind whenever one existed."""
        body = _functions(_code(FORKSAFE_C))["brix_forksafe_unregister"]
        assert "break;" not in body, "unregister stops at the first match"

    def test_the_child_handler_never_emits_a_byte(self):
        """(safety) the whole premise. close() drops only the child's
        descriptor reference and transmits nothing; SSL_free would send
        close_notify and fclose would flush the parent's buffered bytes, so
        both handles are abandoned instead."""
        body = _functions(_code(FORKSAFE_C))["forksafe_child"]
        assert re.search(r"c->io\.ssl\s*= NULL", body), body
        assert re.search(r"c->diag\.cap\s*= NULL", body), body
        for emitter in ("SSL_free", "SSL_shutdown", "fclose", "fflush",
                        "brix_send", "write(", "brix_close"):
            assert emitter not in body, emitter

    def test_the_overflow_state_is_observable(self):
        """(error) past the table's capacity fork safety is off for the
        excess. A counter nobody can read is a counter nobody acts on."""
        text = _code(FORKSAFE_C)
        assert "brix_forksafe_stats" in text
        assert "g_fs_overflow" in _functions(text)["brix_forksafe_stats"]
