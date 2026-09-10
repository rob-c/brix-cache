"""Compile + run the CTA request-queue unit suite
(src/protocols/ssi/svc_cta/cta_queue_unittest.c), and pin the journal's record
grammar against forgery.

Two discoveries drove this file, 2026-09-07:

1. **Nothing executed that unit suite.** It has existed since the CTA service
   landed, but no pytest compiled it and its header comment only documented a
   manual `gcc` line whose paths went stale when `src/` grew its buckets
   (`src/ssi/svc_cta/` where the tree has `src/protocols/ssi/svc_cta/`). A test
   nobody runs is not coverage, so the first job here is simply to run it — and
   to run it with `-Werror`, because "still compiles" is half of what a
   standalone C suite is for.

2. **The journal could be forged from the wire.** `journal_append()` wrote
   `"%llu\\t%d\\t%d\\t%s\\t%s\\n"` with `e->owner` and `e->req.path` raw.
   `req.path` is `Notification.file.lpath`, up to 1023 bytes chosen by whoever
   submitted the request, so a path containing a newline appended a SECOND
   record — with an `owner` of the submitter's choosing, and `owner` is the
   principal `cta_queue_cancel()` checks. A tab was the same attack one field
   narrower. The forgery was inert until the next replay, so the request that
   planted it looked unremarkable at the time.

The fix escapes `\\`, tab, CR and LF in both text fields with a symmetric
unescape on replay, and discards an over-long line whole rather than letting
fgets hand its tail back as a record of its own. The C suite carries the
assertions; this file makes them run, and adds the one check the C side cannot
make about itself — that the suite's negatives can actually fail.
"""
import os
import re
import shutil
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVC = os.path.join(REPO, "src", "protocols", "ssi", "svc_cta")
QUEUE = os.path.join(SVC, "cta_queue.c")
TEST = os.path.join(SVC, "cta_queue_unittest.c")

CFLAGS = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-Isrc"]

pytestmark = pytest.mark.xdist_group("p115-cta-journal")


def _cc():
    cc = shutil.which("gcc") or shutil.which("cc")
    if cc is None:
        pytest.skip("no C compiler")
    if not (os.path.exists(QUEUE) and os.path.exists(TEST)):
        pytest.skip("cta_queue sources missing")
    return cc


def _build(sources, out, strict=True):
    """Compile the unit suite against `sources`; returns the CompletedProcess."""
    flags = CFLAGS if strict else [f for f in CFLAGS if f != "-Werror"]
    return subprocess.run([_cc(), *flags, *sources, "-o", out],
                          cwd=REPO, capture_output=True, text=True)


def _run(binary, tmp_path):
    """Run the suite with its scratch journals confined to `tmp_path`."""
    env = dict(os.environ, TMPDIR=str(tmp_path))
    return subprocess.run([binary], capture_output=True, text=True, env=env,
                          timeout=60)


@pytest.fixture(scope="module")
def cta_bin(tmp_path_factory):
    out = str(tmp_path_factory.mktemp("ctaut") / "ut")
    r = _build([os.path.relpath(TEST, REPO), os.path.relpath(QUEUE, REPO)], out)
    if r.returncode != 0:
        pytest.fail("cta_queue unit suite failed to COMPILE "
                    f"(warnings are errors):\n{r.stderr}")
    return out


# --------------------------------------------------------------------------
# success
# --------------------------------------------------------------------------
class TestUnitSuiteRuns:
    def test_the_suite_passes(self, cta_bin, tmp_path):
        """The whole standalone suite is green — the first time anything ran it."""
        r = _run(cta_bin, tmp_path)
        assert r.returncode == 0, f"{r.stdout}\n{r.stderr}"
        assert r.stdout.strip().endswith("OK"), r.stdout
        assert "FAIL" not in r.stdout, r.stdout

    def test_the_suite_builds_with_warnings_as_errors(self, cta_bin):
        """cta_bin only exists if -Wall -Wextra -Werror was clean; assert it ran."""
        assert os.path.exists(cta_bin)

    def test_the_queue_stays_free_of_nginx(self):
        """`cta_queue.c` compiles with nothing but `-Isrc` and libc.

        That is what lets this suite exist at all: the state machine is pure C,
        so its rules can be tested without a server, a config or an event loop.
        A stray `ngx_` include here would take the whole suite offline, and the
        loss would show up as a skip rather than a failure.
        """
        src = open(QUEUE).read()
        assert "ngx_" not in src, "cta_queue.c grew an nginx dependency"
        assert "#include <ngx" not in src

    def test_the_documented_build_command_names_real_paths(self):
        """The header's manual `gcc` line must name files that exist.

        It had rotted to `src/ssi/svc_cta/` — a path the tree has not had since
        `src/` was split into buckets — so anyone following the comment got
        "No such file or directory" and, reasonably, concluded the suite was
        dead. Stale instructions are how a suite stops being run.
        """
        header = open(TEST).read().split("*/", 1)[0]
        paths = re.findall(r"src/[\w/]+\.c", header)
        assert paths, "the header no longer documents how to build the suite"
        for rel in paths:
            assert os.path.exists(os.path.join(REPO, rel)), rel


# --------------------------------------------------------------------------
# error / security negatives
# --------------------------------------------------------------------------
class TestJournalGrammarIsEnforced:
    """The suite's journal negatives must be able to FAIL.

    Each of these compiles the same suite against a copy of `cta_queue.c` with
    one defence removed, and asserts the suite reddens with the expected check.
    Without this, `test_the_suite_passes` would keep passing if someone quietly
    deleted the escaping — the assertions would still be there, just unreachable.
    """

    @staticmethod
    def _neutered(tmp_path, name, signature, body):
        """A copy of cta_queue.c with one function's body replaced."""
        src = open(QUEUE).read()
        pat = re.compile(re.escape(signature) + r"\n\{.*?\n\}", re.S)
        assert pat.search(src), f"{name}: signature not found — the fix moved"
        out = tmp_path / "cta_queue_neutered.c"
        out.write_text(pat.sub(signature + "\n{\n" + body + "\n}", src, count=1))
        return str(out)

    def _fails_with(self, tmp_path, signature, body, needles):
        src = self._neutered(tmp_path, "neuter", signature, body)
        binary = str(tmp_path / "ut")
        # -Werror off: a stubbed body has unused parameters by construction.
        r = _build([os.path.relpath(TEST, REPO), src, "-Isrc/protocols/ssi/svc_cta"],
                   binary, strict=False)
        assert r.returncode == 0, f"neutered build failed:\n{r.stderr}"
        run = _run(binary, tmp_path)
        assert run.returncode != 0, (
            f"the suite passed WITHOUT the defence — its journal negatives are "
            f"vacuous:\n{run.stdout}")
        for needle in needles:
            assert needle in run.stdout, (
                f"expected check {needle!r} did not fire:\n{run.stdout}")

    def test_without_escaping_a_path_forges_a_record(self, tmp_path):
        """Drop `journal_escape` and the wire-supplied path plants an entry.

        The security core: id 4242, owner `root`, submitted by `mallory`.
        """
        self._fails_with(
            tmp_path,
            "static int\njournal_escape(const char *in, char *out, size_t cap)",
            '    snprintf(out, cap, "%s", in); return 0;',
            ["cta_queue_find(q, 4242) == NULL"])

    def test_without_unescaping_a_legal_path_comes_back_mangled(self, tmp_path):
        """Drop `journal_unescape` and replay returns the ESCAPED bytes.

        Not a security hole on its own, but a silent data-corruption one: the
        path a caller gets back is no longer the path they submitted.
        """
        self._fails_with(
            tmp_path,
            "static void\njournal_unescape(const char *in, char *out, size_t cap)",
            '    snprintf(out, cap, "%s", in);',
            # The check lives in journal_expect_entry(), so the needle names
            # that helper's PARAMETER — not the caller's local. Both journal
            # round-trip tests share the helper; what this pins is that the
            # round-trip check fires at all, which it cannot do vacuously
            # because the sibling test above proves the same suite still
            # passes when only `journal_escape` is neutered.
            ["strcmp(e->req.path, req_path) == 0"])

    def test_without_the_whole_line_check_a_long_field_resynchronises(self, tmp_path):
        """Drop `journal_line_whole` and an over-long line's TAIL parses.

        The same forgery through a different door: pad a field past the read
        buffer and fgets hands the remainder back as if it were a record.
        """
        self._fails_with(
            tmp_path,
            "static int\njournal_line_whole(FILE *f, const char *line)",
            "    (void) f; (void) line; return 1;",
            ["cta_queue_find(q, 7777) == NULL"])


class TestJournalSource:
    """Structural pins on the fix itself."""

    def test_both_text_fields_are_escaped_on_append(self):
        """`owner` AND `path` — a grammar that holds for one field is not one."""
        body = re.search(r"journal_append\(brix_cta_queue_t \*q, const cta_req_t \*e\)"
                         r"\n\{.*?\n\}", open(QUEUE).read(), re.S)
        assert body, "journal_append moved"
        text = body.group(0)
        assert text.count("journal_escape(") == 2, text
        assert "e->owner, e->req.path" not in text, (
            "journal_append is formatting the RAW fields again")

    def test_a_field_that_will_not_fit_writes_no_record(self):
        """Truncation is not a safe failure here.

        A half-written record re-parses as a different, shorter record rather
        than as an error — which is the forgery again, granted by the escaping
        itself. So `journal_escape` returns -1 and the append is abandoned.
        """
        body = re.search(r"journal_append\(.*?\n\}", open(QUEUE).read(),
                         re.S).group(0)
        guard = re.search(r"if \(journal_escape.*?\n    \}", body, re.S)
        assert guard, "journal_append no longer guards the escape results"
        assert "return;" in guard.group(0), (
            "journal_append no longer bails when a field does not fit")

    def test_the_escaped_buffers_cannot_overflow_from_a_legal_field(self):
        """The -1 branch above is unreachable from any legal field, by sizing.

        Worth stating, because the branch reads like live error handling and is
        not: every byte can escape to two, so a buffer of 2*width+1 always fits
        and the guard only ever fires if someone shrinks a constant or widens a
        struct field without the other. This test is that pairing. (The branch
        stays anyway — an unreachable bail is cheaper than a reachable one.)
        """
        queue_h = open(os.path.join(SVC, "cta_queue.h")).read()
        pb_h = open(os.path.join(SVC, "cta_pb.h")).read()
        src = open(QUEUE).read()

        def const(name):
            m = re.search(rf"#define {name}\s+(\d+)", src)
            assert m, f"{name} is gone"
            return int(m.group(1))

        def width(header, decl):
            m = re.search(rf"{decl}\[(\d+)\]", header)
            assert m, f"{decl} is gone"
            return int(m.group(1))

        owner = width(queue_h, "owner")
        path = width(pb_h, "path")
        assert const("CTA_JOURNAL_OWNER_ESC") >= 2 * (owner - 1) + 1
        assert const("CTA_JOURNAL_PATH_ESC") >= 2 * (path - 1) + 1
        # and the line must hold a whole worst-case record
        assert const("CTA_JOURNAL_LINE_MAX") >= (
            const("CTA_JOURNAL_OWNER_ESC") + const("CTA_JOURNAL_PATH_ESC") + 64)
