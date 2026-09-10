"""LD_PRELOAD shim readdir + stdio interposition (phase-115 W7.1, §7.8).

The POSIX shim could open and read a remote FILE but could not LIST a remote
directory, and it interposed nothing in the stdio family — so every tool that
DISCOVERS its inputs (`ls`, `find`, anything globbing) fell through to a local
path that does not exist, and every program that reaches for `FILE*` instead of
a raw fd saw the same nothing.  `client/preload/brixposix_dir.c` adds the
readdir family over one `brix_dirlist` snapshot, and
`client/preload/brixposix_stdio.c` adds `fopen` over `fopencookie` so glibc
keeps doing the buffering.

Register correction banked here as well: W7.1 is written as "the preload
library is read-only today", which was already stale — the write half landed
with `remote_open_write`/`write`/`pwrite` and is covered by
`tests/test_preload_write.py`.  Only readdir and stdio were missing.

  * success   — a remote directory enumerates through `ls`/`os.scandir` with
                the server's entries, `.` and `..`, and non-zero inodes;
                `fopen`+`fgets` reads remote bytes; `fopen("w")` uploads
  * error     — opendir of a missing directory FAILS (it does not report an
                empty directory); `fopen("r")` of a missing file returns NULL
  * safety    — a foreign `DIR*` and a foreign `FILE*` are passed to real libc
                untouched (pointer identity, never a dereference); an fopen
                mode the shim cannot honour is REFUSED rather than falling
                back to a local file wearing the remote path's name

Run:
    PYTHONPATH=tests pytest tests/test_preload_dir_stdio.py -v
"""

import errno
import os
import subprocess
import textwrap

import pytest

from settings import DATA_ROOT, NGINX_ANON_PORT, SERVER_HOST
from sanitizer_preload import sanitizer_runtimes

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PRELOAD = os.path.join(REPO, "client", "libbrixposix_preload.so")
DIR_SRC = os.path.join(REPO, "client", "preload", "brixposix_dir.c")
STDIO_SRC = os.path.join(REPO, "client", "preload", "brixposix_stdio.c")
MAKEFILE = os.path.join(REPO, "client", "Makefile")

pytestmark = [
    pytest.mark.timeout(120),
    pytest.mark.skipif(not os.path.exists(PRELOAD),
                       reason="preload shim not built"),
]

_ASAN_RT = sanitizer_runtimes(PRELOAD)


def _env(extra=None):
    """Host environment plus the shim, its sanitizer runtimes and the prefix."""
    env = dict(os.environ)
    env["LD_PRELOAD"] = " ".join(x for x in (_ASAN_RT, PRELOAD) if x)
    if _ASAN_RT:
        env.setdefault("ASAN_OPTIONS",
                       "detect_leaks=0:verify_asan_link_order=0")
    env["BRIX_VMP"] = f"/xrd=root://{SERVER_HOST}:{NGINX_ANON_PORT}/"
    if extra:
        env.update(extra)
    return env


def _run(argv, env=None, **kw):
    return subprocess.run(argv, env=env if env is not None else _env(),
                          capture_output=True, text=True, timeout=90, **kw)


# ---------------------------------------------------------------------------
# A C driver, because the interposed entry points are LIBC's.  CPython's
# `open()` is its own io stack over os.open and never calls fopen, so a Python
# driver can exercise readdir (posixmodule does call opendir/readdir) but not
# one line of the stdio TU.
# ---------------------------------------------------------------------------
_DRIVER_C = r"""
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* argv: <verb> <path> [mode]; prints one line per observation. */
static int do_ls(const char *path)
{
    DIR *d = opendir(path);
    struct dirent *e;
    if (d == NULL) { printf("OPENDIR_FAIL errno=%d\n", errno); return 0; }
    errno = 0;
    int fd = dirfd(d);          /* sequenced: argument order would read errno first */
    printf("DIRFD %d errno=%d\n", fd, errno);
    while ((e = readdir(d)) != NULL) {
        printf("ENT %s ino=%llu type=%d\n", e->d_name,
               (unsigned long long) e->d_ino, (int) e->d_type);
    }
    printf("REWIND\n");
    rewinddir(d);
    e = readdir(d);
    printf("FIRST %s\n", e ? e->d_name : "(null)");
    printf("CLOSE %d\n", closedir(d));
    return 0;
}

static int do_fopen(const char *path, const char *mode)
{
    char buf[256];
    FILE *f = fopen(path, mode);
    if (f == NULL) { printf("FOPEN_FAIL errno=%d\n", errno); return 0; }
    if (mode[0] == 'w') {
        fputs("written-through-stdio\n", f);
        printf("WROTE %d\n", fclose(f));
        return 0;
    }
    while (fgets(buf, sizeof(buf), f) != NULL) {
        printf("LINE %s", buf);
        if (strchr(buf, '\n') == NULL) { printf("\n"); }
    }
    printf("EOF %d\n", feof(f) ? 1 : 0);
    printf("CLOSE %d\n", fclose(f));
    return 0;
}

static int do_freopen(const char *path)
{
    FILE *f = freopen(path, "r", stdin);
    printf("FREOPEN %s errno=%d\n", f ? "ok" : "null", f ? 0 : errno);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) { return 2; }
    if (strcmp(argv[1], "ls") == 0)      { return do_ls(argv[2]); }
    if (strcmp(argv[1], "freopen") == 0) { return do_freopen(argv[2]); }
    if (strcmp(argv[1], "fopen") == 0 && argc > 3) {
        return do_fopen(argv[2], argv[3]);
    }
    return 2;
}
"""


@pytest.fixture(scope="module")
def driver(tmp_path_factory):
    """Compile the C driver once. Skips (not fails) without a compiler: the
    shim's own build already proved one exists, so a missing `cc` here means
    a stripped test image, not a defect in what is under test."""
    out = tmp_path_factory.mktemp("preload-drv") / "drv"
    src = out.with_suffix(".c")
    src.write_text(_DRIVER_C)
    cc = subprocess.run(["cc", "-O0", "-o", str(out), str(src)],
                        capture_output=True, text=True)
    if cc.returncode != 0:
        pytest.skip(f"no working C compiler: {cc.stderr[:200]}")
    return str(out)


def _entries(stdout):
    """`ENT <name> ino=<n> type=<n>` lines, as {name: (ino, type)}."""
    out = {}
    for line in stdout.splitlines():
        if line.startswith("ENT "):
            name, ino, dtype = line.split()[1:4]
            out[name] = (int(ino.split("=")[1]), int(dtype.split("=")[1]))
    return out


@pytest.fixture
def remote_dir():
    """A directory of three files on the server, removed afterwards."""
    root = os.path.join(DATA_ROOT, "preload-dir-lab")
    os.makedirs(root, exist_ok=True)
    names = ["alpha.txt", "beta.txt", "gamma.txt"]
    for i, name in enumerate(names):
        with open(os.path.join(root, name), "w") as f:
            f.write(f"line-{i}\n")
    try:
        yield "preload-dir-lab", names
    finally:
        for name in names:
            try:
                os.remove(os.path.join(root, name))
            except FileNotFoundError:
                pass
        try:
            os.rmdir(root)
        except OSError:
            pass


@pytest.mark.requires_local_server
class TestPreloadReaddir:

    def test_a_remote_directory_enumerates(self, driver, remote_dir):
        """(success) every server-side name comes back, and `.`/`..` with it —
        a directory without them is not a POSIX directory, and `find` prunes
        on their absence."""
        lab, names = remote_dir
        r = _run([driver, "ls", f"/xrd/{lab}"])
        assert r.returncode == 0, r.stderr
        ents = _entries(r.stdout)
        assert set(names) <= set(ents), r.stdout
        assert {".", ".."} <= set(ents), r.stdout

    def test_no_entry_carries_a_zero_inode(self, driver, remote_dir):
        """(success) d_ino == 0 reads as "deleted" to readdir consumers, so an
        entry carrying one is skipped by code that has nothing to do with us.
        The server may send no file id at all; the shim hashes the name."""
        lab, _ = remote_dir
        r = _run([driver, "ls", f"/xrd/{lab}"])
        assert r.returncode == 0, r.stderr
        zeroes = [n for n, (ino, _t) in _entries(r.stdout).items() if ino == 0]
        assert zeroes == [], r.stdout

    def test_python_scandir_sees_the_same_names(self, tmp_path, remote_dir):
        """(success) through a second consumer of the same wrappers: CPython's
        listdir is opendir/readdir, so this proves the entries survive a
        caller that is not the C driver."""
        lab, names = remote_dir
        drv = tmp_path / "s.py"
        drv.write_text(textwrap.dedent(f"""
            import os
            print(" ".join(sorted(os.listdir("/xrd/{lab}"))))
        """))
        r = _run(["python3", str(drv)])
        assert r.returncode == 0, r.stderr
        assert sorted(names) == sorted(r.stdout.split()), r.stdout

    def test_rewinddir_restarts_the_snapshot(self, driver, remote_dir):
        """(success) rewinddir returns to `.`, and does NOT refetch: the
        listing is a snapshot the handle owns, which is the semantics a
        single kXR_dirlist can honour."""
        lab, _ = remote_dir
        r = _run([driver, "ls", f"/xrd/{lab}"])
        assert r.returncode == 0, r.stderr
        assert "FIRST ." in r.stdout, r.stdout

    def test_a_missing_directory_fails_rather_than_reading_empty(self, driver):
        """(error) opendir of a path that is not there must FAIL. Reporting an
        empty directory instead would turn "you cannot see this" into
        "there is nothing here", and every caller would believe it."""
        r = _run([driver, "ls", "/xrd/no-such-directory-here"])
        assert r.returncode == 0, r.stderr
        assert "OPENDIR_FAIL" in r.stdout, r.stdout
        assert "errno=0" not in r.stdout, "failed with no errno set"

    def test_dirfd_refuses_rather_than_inventing_a_descriptor(self, driver,
                                                             remote_dir):
        """(safety) there is no kernel fd behind a remote listing. Handing back
        a number would send a caller's openat() into the wrong directory —
        or, with a shadow fd, into a file. -1/ENOTSUP is the honest answer."""
        lab, _ = remote_dir
        r = _run([driver, "ls", f"/xrd/{lab}"])
        assert r.returncode == 0, r.stderr
        assert f"DIRFD -1 errno={errno.ENOTSUP}" in r.stdout, r.stdout

    def test_a_foreign_dir_pointer_is_never_dereferenced(self, driver,
                                                         tmp_path):
        """(safety) a local directory opened under the shim must be served by
        real libc. The wrappers recognise their own handles by POINTER
        IDENTITY against a registry — a magic field would mean reading
        libc's opaque DIR, whose memory we do not own."""
        (tmp_path / "local-one").write_text("x")
        (tmp_path / "local-two").write_text("y")
        r = _run([driver, "ls", str(tmp_path)])
        assert r.returncode == 0, r.stderr
        ents = _entries(r.stdout)
        assert {"local-one", "local-two"} <= set(ents), r.stdout
        assert "DIRFD -1" not in r.stdout, "libc's own dirfd was hijacked"


@pytest.mark.requires_local_server
class TestPreloadStdio:

    def test_fopen_reads_remote_bytes(self, driver, remote_dir):
        """(success) fopen + fgets + feof + fclose over a remote file, with all
        the buffering still done by glibc — the shim interposes only the call
        that CREATES the stream."""
        lab, _ = remote_dir
        r = _run([driver, "fopen", f"/xrd/{lab}/alpha.txt", "r"])
        assert r.returncode == 0, r.stderr
        assert "LINE line-0" in r.stdout, r.stdout
        assert "EOF 1" in r.stdout, r.stdout
        assert "CLOSE 0" in r.stdout, r.stdout

    def test_fopen_w_uploads(self, driver, remote_dir):
        """(success) the write mode the fd layer already supports, reached
        through stdio."""
        lab, _ = remote_dir
        name = "stdio-written.txt"
        path = os.path.join(DATA_ROOT, lab, name)
        try:
            r = _run([driver, "fopen", f"/xrd/{lab}/{name}", "w"])
            assert r.returncode == 0, r.stderr
            assert "WROTE 0" in r.stdout, r.stdout
            with open(path) as f:
                assert f.read() == "written-through-stdio\n"
        finally:
            try:
                os.remove(path)
            except FileNotFoundError:
                pass

    def test_a_missing_remote_file_returns_null(self, driver):
        """(error) fopen of an absent remote path fails with the server's own
        errno, not a fallback to some local file of the same name."""
        r = _run([driver, "fopen", "/xrd/no-such-file.txt", "r"])
        assert r.returncode == 0, r.stderr
        assert "FOPEN_FAIL" in r.stdout, r.stdout
        assert "errno=0" not in r.stdout, "failed with no errno set"

    @pytest.mark.parametrize("mode", ["a", "r+", "w+", "a+"])
    def test_an_unsupported_mode_is_refused_not_shadowed(self, driver, mode):
        """(safety) THE point of this file. A mode the shim cannot honour must
        be refused: falling through to the real fopen would open — or create —
        a LOCAL file wearing the remote path's name, and the caller would then
        read bytes that are not the ones it asked for. ENOTSUP is legible; a
        silent local shadow is not."""
        r = _run([driver, "fopen", "/xrd/mode-probe.txt", mode])
        assert r.returncode == 0, r.stderr
        assert f"FOPEN_FAIL errno={errno.ENOTSUP}" in r.stdout, r.stdout
        assert not os.path.exists("/xrd/mode-probe.txt"), "a local shadow"

    def test_freopen_refuses_a_remote_target(self, driver):
        """(safety) freopen's contract is "close this stream, reopen IT" — the
        caller keeps its FILE*, which is the whole point of
        `freopen(p, "r", stdin)`. fopencookie cannot rebind an existing
        stream, so a remote target is refused rather than half-served."""
        r = _run([driver, "freopen", "/xrd/anything.txt"])
        assert r.returncode == 0, r.stderr
        assert f"FREOPEN null errno={errno.ENOTSUP}" in r.stdout, r.stdout

    def test_a_foreign_stream_is_untouched(self, driver, tmp_path):
        """(safety) a local path opened "r+" — a mode the shim refuses — is
        served normally by libc, because the refusal applies only to paths
        under the prefix."""
        local = tmp_path / "local.txt"
        local.write_text("local-line\n")
        r = _run([driver, "fopen", str(local), "r+"])
        assert r.returncode == 0, r.stderr
        assert "LINE local-line" in r.stdout, r.stdout


class TestPreloadBuildWiring:
    """No server needed: what the .so exports, and how it got built."""

    def test_the_shim_exports_every_new_entry_point(self):
        """(success) the wrappers are interposable — a symbol that stayed
        internal would leave libc's own version in front of it, and the
        file would compile, link and do nothing."""
        out = subprocess.run(["nm", "-D", "--defined-only", PRELOAD],
                             capture_output=True, text=True).stdout
        exported = {line.split()[-1] for line in out.splitlines()
                    if " T " in line}
        wanted = {"opendir", "readdir", "readdir64", "readdir_r", "closedir",
                  "rewinddir", "telldir", "seekdir", "dirfd",
                  "fopen", "fopen64", "freopen", "freopen64"}
        assert wanted <= exported, sorted(wanted - exported)

    def test_the_internal_helpers_stay_internal(self):
        """(safety) the shim must interpose libc WITHOUT its own helpers
        interposing, or being interposed by, the host program's symbols."""
        out = subprocess.run(["nm", "-D", "--defined-only", PRELOAD],
                             capture_output=True, text=True).stdout
        leaked = [n for n in ("dir_of", "dir_fill", "dir_next", "dir_register",
                              "cookie_read", "cookie_seek", "mode_to_flags",
                              "stream_over", "remote_fopen")
                  if f" {n}\n" in out or out.endswith(f" {n}")]
        assert leaked == [], leaked

    def test_both_new_units_are_built_and_linked(self):
        """(error class) a TU named in only one of the Makefile's two lists
        either links without dep tracking or is dep-tracked and never
        linked; one shared variable is why that can no longer happen."""
        text = open(MAKEFILE, encoding="utf-8").read()
        assert "brixposix_dir.pic.o" in text
        assert "brixposix_stdio.pic.o" in text
        for site in ("ALL_OBJS := ", "$(PRELOAD_SO): "):
            line = [ln for ln in text.splitlines() if ln.startswith(site)]
            assert line and "$(PRELOAD_OBJS)" in line[0], site
