# tests/test_client_make_graph.py
"""Guards the client build GRAPH against the clean-tree link failure.

`client/Makefile` builds the shared protocol core by recursing into
`shared/xrdproto`.  Every target that links the archive names `$(PROTO_LIB)` as
a normal prerequisite, so a codec/configuration change in that archive forces
the consumer to relink.  That is only legal if the archive is a real make target:
when the recursion lived on the phony alone, any tree without a pre-built
`shared/xrdproto/libxrdproto.a` (i.e. every clean CI checkout) died with

    make: *** No rule to make target '../shared/xrdproto/libxrdproto.a',
          needed by 'libbrixposix_preload.so'.  Stop.

which is exactly how the `asan` lane failed.  A local incremental tree hides
the bug because the archive is already on disk, so this has to be checked
against a deliberately absent archive.

The dry runs below point `PROTO_LIB` at a path that cannot exist and neuter the
recursion with `MAKE=true`, so the graph is exercised without building or
touching anything.

    PYTHONPATH=tests pytest tests/test_client_make_graph.py -v
"""

from __future__ import annotations

import pathlib
import importlib
import platform
import re
import shutil
import subprocess
from brix_suite.client_build import client_make

import pytest

from lib_py.preload_shim import SHIM_NAME

REPO = pathlib.Path(__file__).resolve().parent.parent
CLIENT = REPO / "client"
MAKEFILE = CLIENT / "Makefile"
PROTO_MAKEFILE = REPO / "shared" / "xrdproto" / "Makefile"
ABSENT = "/nonexistent/brix-make-graph/libxrdproto.a"

pytestmark = pytest.mark.timeout(120)


@pytest.mark.parametrize("module_name", ["test_ipv6_fallback", "test_net_resilience"])
def test_network_fixtures_build_the_real_archive_before_linking(monkeypatch, module_name):
    """Pretending libbrix.a is new can link helpers against old socket code."""
    module = importlib.import_module(module_name)
    calls = []
    monkeypatch.setattr(module, "client_make", lambda *args, **kwargs:
        calls.append(args) or subprocess.CompletedProcess(args, 0, stdout=b""))
    monkeypatch.setattr(module.os.path, "exists", lambda path: True)
    module._build.__wrapped__()
    assert len(calls) == 1
    assert "libbrix.a" in calls[0][1:], calls
    assert "-W" not in calls[0][1:], calls


@pytest.mark.parametrize("flags,expected", [
    ("-L/opt/brix-sdk/lib -luring", "-Wl,-rpath,/opt/brix-sdk/lib"),
    ("-luring", "-luring"),
    ("-Lrelative -luring", "-Lrelative"),
])
def test_static_dependency_runtime_paths_are_absolute(flags, expected):
    result = client_make(CLIENT,
        "-nB", "libbrix.pc", "URING_LIBS=" + flags,
        "OPENSSL_LIBS=", "KRB5_LIBS=", "CODEC_LIBS=",
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    private = next(line for line in result.stdout.splitlines() if "Libs.private:" in line)
    assert expected in private
    _assert_absolute_runtime_paths(private)
    assert "-pthread" in private, "static consumers need pthread on pre-2.34 glibc"


def _assert_absolute_runtime_paths(private):
    """Allow native absolute SDK paths, never empty or relative loader paths."""
    runtime_paths = re.findall(r"-Wl,-rpath,([^\s'\"]*)", private)
    assert all(path.startswith('/') for path in runtime_paths), runtime_paths


@pytest.mark.parametrize("system_dir", ["/usr/lib", "/usr/lib64", "/usr/lib/aarch64-linux-gnu"])
def test_parallel_sdk_cannot_be_shadowed_by_a_codec_system_directory(system_dir):
    """A codec's -L must not silently downgrade the selected external SDK."""
    result = client_make(CLIENT,
        "-nB", "libbrix.pc", "URING_LIBS=-L/opt/brix-sdk/lib -luring",
        "OPENSSL_LIBS=", "KRB5_LIBS=", f"CODEC_LIBS=-L{system_dir} -lzstd",
        capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    private = next(line for line in result.stdout.splitlines() if "Libs.private:" in line)
    assert private.index("-L/opt/brix-sdk/lib") < private.index(f"-L{system_dir}")
    assert "-Wl,-rpath,/opt/brix-sdk/lib" in private


def _make_variables(makefile: pathlib.Path, **overrides: str) -> dict[str, str]:
    """Return make's expanded simple variables without building any target."""
    command = ["-f", str(makefile), "-pn", *(
        f"{name}={value}" for name, value in overrides.items()
    )]
    proc = client_make(makefile.parent, *command,
                          capture_output=True, text=True)
    variables = {}
    for line in proc.stdout.splitlines():
        match = re.match(
            r"^(HARDEN|OPT|OPENSSL_CFLAGS|KRB5_CFLAGS)\s*:?=\s*(.*)$",
            line,
        )
        if match:
            variables[match.group(1)] = match.group(2)
    return variables


@pytest.mark.parametrize("makefile", [MAKEFILE, PROTO_MAKEFILE])
def test_arm64_defaults_never_select_an_x86_profile(makefile: pathlib.Path) -> None:
    """An ARM64 build must use an ARM ISA even when no profile is supplied."""
    variables = _make_variables(makefile, HOST_ARCH="arm64", HOST_OS="Darwin")
    assert "-march=armv8" in variables["OPT"]
    assert "x86-64" not in variables["OPT"]


@pytest.mark.parametrize("makefile", [MAKEFILE, PROTO_MAKEFILE])
def test_unknown_arm64_profile_fails_closed_to_auto(makefile: pathlib.Path) -> None:
    """A misspelled ARM64 profile must not fall back to the x86 default."""
    variables = _make_variables(
        makefile, HOST_ARCH="aarch64", HOST_OS="Linux",
        BRIX_OPTIMIZE="not-a-profile",
    )
    assert "-march=armv8" in variables["OPT"]
    assert "x86-64" not in variables["OPT"]


@pytest.mark.parametrize("makefile", [MAKEFILE, PROTO_MAKEFILE])
def test_hardening_tracks_host_and_architecture_capabilities(
        makefile: pathlib.Path) -> None:
    """Keep Linux stack-clash and x86 CET without passing them to Darwin."""
    darwin = _make_variables(makefile, HOST_ARCH="arm64", HOST_OS="Darwin")
    linux_arm = _make_variables(makefile, HOST_ARCH="aarch64", HOST_OS="Linux")
    linux_x86 = _make_variables(makefile, HOST_ARCH="x86_64", HOST_OS="Linux")
    assert "-fcf-protection=full" not in darwin["HARDEN"]
    assert "-fstack-clash-protection" not in darwin["HARDEN"]
    assert "-fcf-protection=full" not in linux_arm["HARDEN"]
    assert "-fstack-clash-protection" in linux_arm["HARDEN"]
    assert "-fcf-protection=full" in linux_x86["HARDEN"]
    assert "-fstack-clash-protection" in linux_x86["HARDEN"]


@pytest.mark.parametrize("makefile", [MAKEFILE, PROTO_MAKEFILE])
def test_openssl_pkg_config_flags_reach_every_client_compile(
        makefile: pathlib.Path) -> None:
    """Keg-only OpenSSL headers must be present on every compile command."""
    body = makefile.read_text()
    assert re.search(r"^OPENSSL_CFLAGS\s*:=.*pkg-config --cflags openssl", body,
                     re.MULTILINE)
    all_cflags = re.search(r"^ALL_CFLAGS\s*:=.*?(?=\n[^ \t])", body,
                           re.MULTILINE | re.DOTALL)
    assert all_cflags and "$(OPENSSL_CFLAGS)" in all_cflags.group(0)


def test_shared_codec_probes_propagate_non_system_include_paths() -> None:
    """Enabling an optional codec must carry its pkg-config include flags."""
    body = PROTO_MAKEFILE.read_text()
    for package in ("libzstd", "liblzma", "libbrotlienc", "bzip2"):
        assert re.search(
            rf"CODEC_CFLAGS\s*\+=.*?pkg-config --cflags[^\n]*{package}", body,
            re.MULTILINE | re.DOTALL,
        )


def test_module_hardening_flags_are_compiler_probed() -> None:
    """Architecture-specific mitigations must not be unconditional CFLAGS."""
    body = (REPO / "config").read_text()
    base_flags = re.search(r'^CFLAGS="\$CFLAGS ([^\n]+)"$', body, re.MULTILINE)
    assert base_flags and "-fcf-protection=full" not in base_flags.group(1)
    assert "for _brix_hflag in -fstack-clash-protection -fcf-protection=full" in body


@pytest.mark.parametrize("makefile", [MAKEFILE, PROTO_MAKEFILE])
def test_darwin_discovers_keg_only_openssl_metadata(
        makefile: pathlib.Path) -> None:
    """A stock Homebrew shell must find the OpenSSL headers and libraries."""
    if platform.system() != "Darwin":
        pytest.skip("Homebrew discovery requires a Darwin host")
    variables = _make_variables(makefile, HOST_ARCH="arm64", HOST_OS="Darwin")
    assert "/openssl@3/" in variables["OPENSSL_CFLAGS"]


def test_darwin_client_discovers_keg_only_kerberos_metadata() -> None:
    """Homebrew Kerberos support remains enabled without caller environment."""
    if platform.system() != "Darwin":
        pytest.skip("Homebrew discovery requires a Darwin host")
    variables = _make_variables(MAKEFILE, HOST_ARCH="arm64", HOST_OS="Darwin")
    assert "-DBRIX_HAVE_KRB5" in variables["KRB5_CFLAGS"]
    assert "/krb5/" in variables["KRB5_CFLAGS"]


def test_cvmfs_compile_uses_discovered_openssl_headers() -> None:
    """The special CVMFS recipe must retain keg-only OpenSSL discovery."""
    body = MAKEFILE.read_text()
    rule = re.search(
        r"\$\(BRIX_CVMFS_OBJS\):.*?(?=\n[^\t#].*?:)", body,
        re.MULTILINE | re.DOTALL,
    )
    assert rule and "$(OPENSSL_CFLAGS)" in rule.group(0)
    assert "$(ZSTD_CFLAGS)" in rule.group(0)


def test_darwin_lz4_link_retains_homebrew_library_path() -> None:
    """ld64 must receive pkg-config's directory for keg-only liblz4."""
    body = MAKEFILE.read_text()
    darwin_branch = re.search(
        r"ifeq \(\$\(HOST_OS\),Darwin\)\n"
        r"\s*LZ4_SONAME_LINK\s*:=([^\n]+)", body,
    )
    assert darwin_branch and "pkg-config --libs liblz4" in darwin_branch.group(1)


def _dry_run(goal: str) -> subprocess.CompletedProcess:
    """Resolve `goal`'s graph with the protocol archive absent.

    `MAKE=true` replaces the recursive sub-make (GNU make executes recipe lines
    containing `$(MAKE)` even under `-n`) with a no-op that ignores its
    arguments, so nothing is built and `shared/xrdproto` is never entered.

    `-B` is load-bearing: the Makefile's blanket `.SECONDARY:` makes every file
    secondary, and make forgives a missing secondary prerequisite when the goal
    is already up to date — which on a developer box it always is.  Forcing the
    goal out of date is what makes make actually ask how to build the archive,
    i.e. what reproduces the clean-checkout question locally.
    """
    if shutil.which("make") is None:
        pytest.skip("no make")
    return client_make(str(CLIENT), "-n", "-B", "MAKE=true", f"PROTO_LIB={ABSENT}", goal, capture_output=True, text=True)


@pytest.mark.parametrize("goal", [SHIM_NAME, "lib"])
def test_shared_object_goals_resolve_with_the_archive_missing(goal: str) -> None:
    """The clean-tree regression: both shared-object goals (the preload shim
    under its host's name, libbrix) must have a rule for the archive."""
    proc = _dry_run(goal)
    combined = proc.stdout + proc.stderr
    assert "No rule to make target" not in combined, (
        f"`make {goal}` cannot build the protocol archive on a clean tree:\n{combined}"
    )
    assert proc.returncode == 0, combined


@pytest.mark.parametrize("goal", ["aio-smoke", "aio-resil", "aio-waitresp",
                                  "aio-mfile", "ssi-client-smoke", "netfb",
                                  "dirfanout", "forksafe", "nettmo"])
def test_optional_drivers_build_the_protocol_archive_on_a_clean_tree(goal):
    """An optional driver's link closure is also a normal build dependency."""
    rule = re.search(rf"^{re.escape(goal)}:.*$", MAKEFILE.read_text(), re.MULTILINE)
    assert rule and "$(PROTO_LIB)" in rule.group(0)
    result = _dry_run(goal)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "true -C ../shared/xrdproto" in result.stdout


@pytest.mark.parametrize("flags,expected", [
    ("-L/opt/brix-sdk/lib -lz", ["-Wl,-rpath,/opt/brix-sdk/lib"]),
    ("-Lrelative -lz", []),
    ("-lz", []),
])
def test_optional_driver_runtime_paths_follow_absolute_sdk_dirs(flags, expected):
    """External SDKs are loadable; a relative library path never becomes RPATH."""
    result = client_make(CLIENT, "-nB", "MAKE=true", "dirfanout",
                         "URING_LIBS=" + flags, "OPENSSL_LIBS=",
                         "KRB5_LIBS=", "CODEC_LIBS=", "PLATFORM_LIBS=",
                         capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr
    links = _link_lines(result.stdout, "bin/dirfanout_test")
    assert len(links) == 1, result.stdout
    assert [flag for flag in links[0].split() if flag.startswith("-Wl,-rpath,")] == expected


def test_protocol_archive_is_a_real_target() -> None:
    """The invariant behind both goals: $(PROTO_LIB) carries its own rule.

    An order-only `| proto` dependency does NOT make the archive buildable — it
    only orders the work — so a target that links the archive needs this rule to
    exist.  Losing it reintroduces the clean-tree failure silently, because an
    incremental tree still has the archive lying around.
    """
    body = MAKEFILE.read_text()
    assert re.search(r"^\$\(PROTO_LIB\)\s*:", body, re.M), (
        "$(PROTO_LIB) has no rule of its own — targets that link it will fail "
        "on any tree where shared/xrdproto/libxrdproto.a does not exist yet"
    )


def test_every_generic_executable_relinks_when_protocol_archive_changes() -> None:
    """Optional codec changes in libxrdproto must invalidate native tools."""
    body = MAKEFILE.read_text()
    rule = re.search(
        r"^\$\(BIN_EXES\):\s+\$\(BINDIR\)/%:.*$", body, re.MULTILINE)
    assert rule and "$(PROTO_LIB)" in rule.group(0)


@pytest.mark.parametrize("goal", ["xrootdfs", "brixMount"])
def test_special_executables_relink_when_protocol_archive_changes(goal: str) -> None:
    """The two bespoke link recipes obey the same archive dependency rule."""
    body = MAKEFILE.read_text()
    rule = re.search(rf"^\$\(BINDIR\)/{goal}:.*$", body, re.MULTILINE)
    assert rule and "$(PROTO_LIB)" in rule.group(0)


def test_client_clean_removes_shared_protocol_build_products() -> None:
    """A feature-probe rebuild cannot reuse codec-disabled shared objects."""
    body = MAKEFILE.read_text()
    clean = re.search(r"^clean:.*?(?=\n[^\t\n#])", body, re.MULTILINE | re.DOTALL)
    assert clean
    assert "$(PROTO_LIB)" in clean.group(0)
    assert "$(PROTO_DIR)/build" in clean.group(0)


def test_the_protocol_core_has_exactly_one_recursion_point() -> None:
    """Two rules recursing into shared/xrdproto would race under `make -j`.

    A parallel build could then run two sub-makes in the same directory and link
    a half-written archive into a hardened binary, so the recursion must live in
    exactly one recipe with every other path reaching it through `proto`.
    """
    recipes = [
        line
        for line in MAKEFILE.read_text().splitlines()
        if line.startswith("\t") and "$(MAKE) -C $(PROTO_DIR)" in line
    ]
    assert len(recipes) == 1, f"expected one sub-make into $(PROTO_DIR), got {recipes}"


# --- archive ORDER: the protocol core's PAL callers must still resolve --------
#
# shared/xrdproto ships no PAL.  Its storage backends call brix_plat_* entry
# points that each consumer supplies for its own host, so libxrdproto.a reaches
# the linker with brix_plat_pwrite_at, brix_plat_blockdev_size and friends
# undefined and libbrix.a is what defines them.  GNU ld resolves an archive
# once, against the undefined symbols it holds at that moment: a link line
# naming libbrix.a only BEFORE libxrdproto.a is already past it when those
# symbols appear, and xrdcksum/xrddiag died with "undefined reference to
# `brix_plat_pwrite_at'".  Every executable therefore offers libbrix.a on both
# sides, which is also the only cure that survives Mach-O linking.


def _link_lines(output: str, goal: str) -> list[str]:
    """Every line in a dry run that links `goal` against the proto archive."""
    return [
        line
        for line in output.splitlines()
        if f"-o {goal}" in line and "libxrdproto.a" in line
    ]


def _link_line(goal: str) -> str:
    """The compiler command `make` would run to link `goal`.

    `-B` forces the goal out of date (an incremental tree has the binary) and
    `MAKE=true` neuters the sub-make, so this reads the graph without building.
    """
    if shutil.which("make") is None:
        pytest.skip("no make")
    proc = client_make(str(CLIENT), "-n", "-B", "MAKE=true", goal, capture_output=True, text=True)
    links = _link_lines(proc.stdout + proc.stderr, goal)
    assert len(links) == 1, f"expected one link line for {goal}, got {links}"
    return links[0]


@pytest.mark.parametrize("goal", ["bin/xrdcksum", "bin/xrddiag"])
def test_executables_close_the_archive_cycle(goal: str) -> None:
    """Every native binary must close the libbrix/libxrdproto cycle.

    GNU ld needs an archive group so it can rescan both sides to a fixed point.
    Darwin's ld64 already rescans archives, so the plain pair is sufficient
    there and avoids GNU-only options.
    """
    line = _link_line(goal)
    _assert_archive_pair(goal, line)
    _assert_platform_archive_closure(goal, line)


def _assert_archive_pair(goal: str, line: str) -> None:
    """Require the shared pair once; the linker controls any rescans."""
    order = [tok for tok in re.findall(r"\S*lib(?:brix|xrdproto)\.a", line)]
    assert len(order) == 2, f"{goal} must link exactly one archive pair: {line}"
    assert order[0].endswith("libbrix.a")
    assert order[1].endswith("libxrdproto.a")


def _assert_platform_archive_closure(goal: str, line: str) -> None:
    """Require GNU grouping while keeping the Darwin command ld64-safe."""
    if platform.system() == "Darwin":
        assert "--start-group" not in line and "--end-group" not in line
        return
    assert re.search(
        r"--start-group\s+\S*libbrix\.a\s+"
        r"\S*libxrdproto\.a\s+-Wl,--end-group",
        line,
    ), f"{goal} does not group the cyclic archives:\n{line}"


def test_every_executable_link_uses_the_shared_archive_pair() -> None:
    """One variable owns the order so a new front-end cannot reintroduce it.

    The bug was per-recipe, and twelve recipes spelt the pair by hand; a
    thirteenth would have copied the broken order. Only the definition of
    $(BRIX_LIBS) and the `install` rule may name the two archives directly.
    """
    offenders = [
        line
        for line in MAKEFILE.read_text().splitlines()
        if line.lstrip().startswith("$(CC)") and "$(CLIENT_LIB) $(PROTO_LIB)" in line
    ]
    assert not offenders, (
        "these link recipes spell the archive pair by hand instead of using "
        f"$(BRIX_LIBS), and so carry the single-pass ordering bug: {offenders}"
    )


def test_the_unit_recipe_closes_the_same_cycle() -> None:
    """`make <name>-unit` links the same two archives and needs the same cure.

    Ordinary units use $(BRIX_LIBS), the same platform-specific closure as the
    executables. Tests that require every client object retain the explicit
    whole-archive branch.
    """
    body = MAKEFILE.read_text()
    recipe = re.search(r"^%-unit:.*?(?=\n[^\t\n#])", body, re.M | re.S)
    assert recipe, "the %-unit pattern rule is gone"
    link = recipe.group(0)
    assert "lib='$(BRIX_LIBS)'" in link, (
        "the %-unit ordinary link no longer uses the shared cyclic archive "
        f"closure:\n{link}"
    )


def test_the_sweep_recipe_closes_the_same_cycle() -> None:
    """`make test` links each unit itself and needs the cure independently.

    The sweep at the `test:` target has its OWN $(CC) line — fixing only the
    %-unit pattern rule left `make test` dying on brix_plat_wait_pid_timeout /
    brix_plat_pipe2 at cred_refresh_unit, because libxrdproto's subprocess.o
    calls back into the PAL that libbrix defines and GNU ld had already walked
    past libbrix.a. The two recipes must stay in step.
    """
    body = MAKEFILE.read_text()
    recipe = re.search(r"^test:.*?(?=\n[^\t\n#])", body, re.M | re.S)
    assert recipe, "the `test` sweep target is gone"
    link = recipe.group(0)
    assert "lib='$(BRIX_LIBS)'" in link, (
        "the `make test` ordinary link no longer uses the shared cyclic "
        f"archive closure:\n{link}"
    )


def test_the_ordering_cure_stays_portable_to_macos() -> None:
    """GNU grouping must remain confined to the non-Darwin make branch."""
    body = MAKEFILE.read_text()
    branch = re.search(
        r"ifeq \(\$\(HOST_OS\),Darwin\)\n"
        r"BRIX_LIBS := (?P<darwin>[^\n]+)\n"
        r"else\n"
        r"BRIX_LIBS := (?P<other>[^\n]+)\n"
        r"endif",
        body,
    )
    assert branch, "BRIX_LIBS no longer has explicit Darwin/non-Darwin arms"
    assert "--start-group" not in branch["darwin"]
    assert "--end-group" not in branch["darwin"]
    assert branch["darwin"].split() == ["$(CLIENT_LIB)", "$(PROTO_LIB)"]
    assert "--start-group" in branch["other"]
    assert "--end-group" in branch["other"]


def _undefined_pal_symbols(binary) -> list[str]:
    """The `brix_plat_*` imports `binary` still leaves unresolved, sorted."""
    if not binary.exists():
        pytest.skip(f"{binary} not built")
    if shutil.which("nm") is None:
        pytest.skip("no nm")
    proc = subprocess.run(["nm", "-u", str(binary)], capture_output=True, text=True)
    return sorted({s for s in proc.stdout.split() if s.startswith("brix_plat_")})


@pytest.mark.parametrize("goal", ["xrdcksum", "xrddiag"])
def test_built_executables_carry_no_undefined_pal_symbols(goal: str) -> None:
    """The proof the order actually worked, read off the real artifact.

    The dry runs above check the recipe; this checks the binary the recipe
    produced, so a link that silently left a brix_plat_* import unresolved
    (a lazily bound .so would only fail at the first call) is caught here.
    """
    binary = CLIENT / "bin" / goal
    dangling = _undefined_pal_symbols(binary)
    assert not dangling, f"{goal} has unresolved PAL symbols: {dangling}"
