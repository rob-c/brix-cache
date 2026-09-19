"""Low-complexity operations shared by both launcher compatibility surfaces."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import stat
import subprocess

import pytest


def _kind_row(namespace, spec):
    return namespace["LAUNCHER_KINDS"].get(spec.kind)


def _quiescence_mode(row):
    if row is None:
        return "pidfile"
    return row.quiescence


def _has_runtime_handle(launcher, name):
    return name in launcher._external_stops or name in launcher._xrootd_procs


def _ports_are_idle(spec, listeners, declared_ports):
    return not any(port in listeners for port in declared_ports(spec))


def _may_be_quiescent(launcher, spec, listeners, row, declared_ports):
    mode = _quiescence_mode(row)
    return all(
        (
            listeners is not None,
            not _has_runtime_handle(launcher, spec.name),
            mode != "never",
            _ports_are_idle(spec, listeners or {}, declared_ports),
        )
    )


def _endpoint_or_none(spec, endpoint_for):
    try:
        return endpoint_for(spec)
    except ValueError:
        return None


def _quiescence_pidfile(endpoint, row):
    relpath = None if row is None else row.pidfile
    if relpath:
        return os.path.join(endpoint.prefix, relpath)
    return endpoint.pidfile


def quiescent(launcher, spec, listeners, namespace):
    """Return whether a registry instance has no observable live resources."""
    row = _kind_row(namespace, spec)
    declared_ports = namespace["declared_ports"]
    if not _may_be_quiescent(launcher, spec, listeners, row, declared_ports):
        return False
    endpoint = _endpoint_or_none(spec, namespace["endpoint_for"])
    if endpoint is None:
        return False
    if _quiescence_mode(row) == "ports-only":
        return True
    return not os.path.exists(_quiescence_pidfile(endpoint, row))


def _dispatch_special(launcher, spec, namespace):
    row = _kind_row(namespace, spec)
    if row is None or row.start_method is None:
        return False
    getattr(launcher, row.start_method)(spec)
    return True


def _open_ancestors_within_test_root(path):
    """a+rx from TEST_ROOT down to `path`, so the worker can traverse to it.

    Opening the export itself is not enough when it sits in a pytest temp dir:
    pytest creates its basetemp — and every ``tmp_path`` under it — mode 0700,
    so the de-escalated worker (``nobody``) is stopped at an ancestor it cannot
    enter.  The symptom is not a permission error in the test but "brix: unable
    to open export root for confined syscall (13: Permission denied)" in the
    error log and a 403/502 where the case expected content.  TEST_ROOT bounds
    the walk to the dedicated test tree; an export outside it is left alone
    rather than have its parents (a home directory, a real export) widened.
    """
    from brix_suite.settings import TEST_ROOT  # noqa: PLC0415

    path = os.path.abspath(path)
    while path.startswith(TEST_ROOT + os.sep):
        path = os.path.dirname(path)
        # a+rwX on pytest's own temp roots, a+rx on everything else: a worker
        # (or a program the worker execs — a stage hook, an fsxeq operator
        # program) writes its output beside the inputs the test left there, and
        # traversal alone gets EACCES on the create.  See _is_pytest_temp_root
        # for why widening these in particular overwrites nobody's intent.
        extra = 0o777 if _is_pytest_temp_root(path) else 0o555
        try:
            os.chmod(path, os.stat(path).st_mode | extra)
        except OSError:
            pass


def _is_pytest_temp_root(path):
    """Whether `path` is a directory pytest itself made, not one a test made.

    pytest creates its basetemp and every per-test directory under it mode
    0700 (`_pytest/tmpdir.py`), which says nothing about intent — it is the
    plugin's blanket default for `$TEST_ROOT/tmp/pytest-of-<user>/pytest-<n>/`
    and the `<name><n>` directory inside it.  A 0700 directory a test made FOR
    ITSELF is the opposite: chosen, and load-bearing (a credential store is
    held to exactly 0700 by `test_delegation_t4_credential`, and the module
    warns when it is not).  Only the three pytest-owned levels match here, so
    widening them cannot overwrite a decision any test made.
    """
    parts = os.path.abspath(path).split(os.sep)
    return (len(parts) >= 3
            and parts[-3].startswith("pytest-of-")
            and parts[-2].startswith("pytest-"))


#: The one directory mode that says nothing about who may write: what `mkdir`
#: leaves under the suite's umask.  Every other mode has said something — 0o555
#: frozen, 0o500 locked, 0o000 sealed, and 0o700 CHOSEN: a credential store is
#: held to exactly that (`test_delegation_t4_credential`), and the module warns
#: "credential store ... is group/other-accessible" when it is not.  pytest's
#: own 0o700 on every temp directory is indistinguishable from that one, so a
#: test that wants its `tmp_path` served has to widen it itself.
_UNTOUCHED_DIR_MODES = (0o755,)


def _session_artifact_roots():
    """The prep-built trees the launcher must never re-permission.

    `prep_steps` hardens these on purpose and the clients enforce it: XrdCl
    refuses a CA file an untrusted user could alter (`_harden_ca_entries`), the
    native `brix_open_credfile()` refuses a bearer file writable by group or
    other (`_harden_bearer_tokens`), and a proxy or a keytab must stay
    owner-only (`_harden_proxy_file`).  Every GSI template passes `{CA_DIR}`,
    so without this the widening below would undo that hardening on each start
    and every roots:// handshake in the suite would fail with a bare
    "[FATAL] TLS error: Failed to initialize TLS".
    """
    from brix_suite import settings  # noqa: PLC0415

    roots = []
    for name in ("PKI_DIR", "TOKENS_DIR", "KRB5_DIR"):
        value = getattr(settings, name, None)
        if value:
            roots.append(os.path.abspath(str(value)))
    return tuple(roots)


def _is_session_artifact(path, roots):
    return any(path == root or path.startswith(root + os.sep) for root in roots)


def _spec_directories_within_test_root(spec):
    """Every directory this spec named for itself, as absolute paths.

    `endpoint.data_root` is always ``$TEST_ROOT/data-<name>``, so the walk above
    it only ever reaches TEST_ROOT — it never sees an export a test pointed
    somewhere else.  And a test that hands the template its own ``tmp_path``
    does exactly that: pytest creates EVERY temp directory it makes, basetemp
    and per-test alike, mode 0700, so the de-escalated worker is stopped at an
    ancestor and dies with "cannot open export root ... (13: Permission
    denied)" before it can serve.  The master survives (it holds the listener),
    so the case does not look like a start failure at all — the client connects
    and then waits for an accept that never comes.

    The export root is spelled ~70 different ways across the templates
    (`{DATA_ROOT}`, `{EXPORT_ROOT}`, `{ACC_DIR}`, ...), so what the spec passed
    is scanned rather than a key list that would need an entry per template.

    `spec.env` is scanned with it, because a template value is not the only way
    a spec hands the server a directory: an `env TMPDIR;` instance gets its
    scratch that way, and MIT krb5 puts the replay cache there — a root-owned
    one answers "krb5 credential verification failed: Permission denied
    (filename: .../krb5_65534.rcache2)", naming the worker's own uid and
    nothing else.
    """
    from brix_suite.settings import TEST_ROOT  # noqa: PLC0415

    artifacts = _session_artifact_roots()
    marker = TEST_ROOT + os.sep
    for value in _spec_passed_values(spec):
        path = _existing_dir_in(str(value), marker)
        if path is not None and not _is_session_artifact(path, artifacts):
            yield path


def _spec_passed_values(spec):
    """Every value this spec handed the instance: template substitutions first,
    then the environment.  Both are optional on a spec, so both are read
    defensively."""
    values = list((getattr(spec, "template_values", None) or {}).values())
    values += list((getattr(spec, "env", None) or {}).values())
    return values


def _open_if_still_default(path):
    """Widen a directory still at a creation default so anyone may write it.

    lstat, so a symlink (mode 0o777) matches no default and its target is never
    reached through it; `stat.S_ISDIR` because only directories are widened at
    all.  A FILE's mode is never touched: across this suite a file mode is a
    security statement — a proxy or keytab is owner-only, a CA file must not be
    group-writable, a bearer token must not be either — and the launcher cannot
    tell a test's own PKI under `tmp_path` from its export.

    A pytest-owned temp level counts as a default whatever pytest stamped on it
    (`_is_pytest_temp_root`): the ancestor walk already grants those three
    levels a+rwX on exactly that reasoning, so leaving the LAST one shut — only
    because the spec named the `mktemp()` directory itself rather than something
    inside it — hands the worker a tree it cannot enter.  That is what an s3://
    store built with `tmp_path_factory.mktemp()` looks like: the seeded object
    is 0644 and the bucket below it 0777, and every read still answers "file not
    found" because 0700 stops the worker one level higher up.
    """
    try:
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode):
            return
        if stat.S_IMODE(info.st_mode) in _UNTOUCHED_DIR_MODES \
                or _is_pytest_temp_root(path):
            os.chmod(path, 0o777)
    except OSError:
        pass


def _open_spec_tree(path):
    """Make `path` reachable, and writable by whoever the worker turns out to be.

    Reachable is the fatal half (see `_spec_directories_within_test_root`).
    Writable is the quiet half: the server creates its upload staging, its
    store and its cache under paths like this, and a root-owned 0755 tree
    denies `nobody` every create — `oci: cannot create store directory ... (13:
    Permission denied)` answered as a 500, with nothing in the test naming a
    permission.  The registry's own data root has been opened 0o777 since the
    launcher was written; this is the same courtesy for the export a test
    brought itself, minus the part that would overwrite the test's intent.
    """
    _open_ancestors_within_test_root(path)
    _open_if_still_default(path)
    for parent, dirs, _files in os.walk(path):
        for name in dirs:
            _open_if_still_default(os.path.join(parent, name))


#: Directives naming a PRIVATE FILE the WORKER opens at runtime — an outbound
#: bearer, an upstream token or proxy, a key it presents to a third party.  Not
#: keytabs and not `brix_certificate_key`: those are read by the root master at
#: config load, which is why `cmdscripts._credential_snapshot` leaves them alone
#: too.  Anything here has to survive the read as a CREDENTIAL — owner-only —
#: so the handoff chowns and never widens: `brix_open_credfile()` refuses a
#: bearer a group or other could write, and the GSI loaders refuse a lax key.
_WORKER_CREDENTIAL_FILES = (
    "brix_tpc_outbound_bearer_file",
    "brix_upstream_token_file",
    "brix_upstream_x509_proxy",
    "brix_upstream_x509_key",
    "brix_webdav_tpc_key",
    "brix_pwd_file",
    "x509_proxy",
    "x509_key",
)

#: One directive: name, then its arguments up to the `;`.  Matching the whole
#: argument list rather than one value is what reaches the program in
#: `brix_cms_fsxeq mkdir rm <program> --tag` — the path is not the first
#: argument, and a per-directive parser would need a rule for every such shape.
#:
#: A directive starts at a line start OR straight after `{`, `}` or `;`, because
#: nginx lets a whole block live on one line and the fixtures use that:
#:
#:     brix_credential p115 { x509_proxy /…/proxy.pem; ca_dir /…/ca.pem; }
#:
#: Anchored to `^` alone this line yields NOTHING — `brix_credential` fails on
#: the `{` its argument class excludes, and the two directives that name real
#: files are not at a line start — so the worker never got the proxy it is the
#: only reader of, and the cache-origin GSI fill failed "cannot load proxy
#: credential" with the path sitting in the config in plain sight.  The trailing
#: `;` is a LOOKAHEAD, not consumed: it is the delimiter the next directive on
#: the same line has to start from.
_DIRECTIVE = re.compile(r"(?:^|[{};])[ \t]*([a-z_][a-z0-9_]*)[ \t]+([^;{}]+)(?=;)",
                        re.MULTILINE)


def _config_paths(config_path):
    """Every existing path under TEST_ROOT this config hands the server.

    Yields ``(directive, path)``.  Scanned from the RENDERED config rather than
    from `spec.template_values`, because that is where a path actually lands:
    most templates take their knobs as one pre-rendered blob, so the value the
    spec passed is a block of directive text, not a path.

    Session artifacts are skipped — the shared PKI, token and krb5 trees are
    `prep_steps`' to permission, they are read by the root-run test CLIENTS as
    well as by the worker, and re-opening them on every start is what makes
    every roots:// handshake in the suite fail (`_session_artifact_roots`).
    """
    from brix_suite.settings import TEST_ROOT  # noqa: PLC0415

    try:
        text = open(config_path, encoding="utf-8", errors="replace").read()
    except OSError:
        return
    artifacts = _session_artifact_roots()
    marker = TEST_ROOT + os.sep
    for directive, arguments in _DIRECTIVE.findall(text):
        for raw in arguments.split():
            path = _existing_path_in(raw.strip('"'), marker)
            if path is not None and not _is_session_artifact(path, artifacts):
                yield directive, path


def _test_root_candidates(token, marker):
    """The local paths `token` might be carrying, longest first.

    Cut at TEST_ROOT rather than requiring the token to START there: a storage
    path is as often carried inside a URL as it is written bare —
    `brix_storage_backend posix:<dir>`, `frm://exec<dir>`,
    `pblock://<dir>?quota=150m` — and a startswith() test sees a scheme, skips
    all three, and leaves the export shut inside a 0700 `tmp_path` ("cannot
    open export root ... (13: Permission denied)", from a worker whose master
    parsed the same path as root without complaint).

    The second candidate drops a URL query, because only the part before `?` is
    a path; it is offered SECOND so a directory whose name genuinely contains a
    `?` still wins.  Existence is what decides between them, so a token that
    merely looks like a local path costs one stat.
    """
    cut = token.find(marker)
    if cut < 0:
        return ()
    tail = token[cut:]
    trimmed = tail.split("?", 1)[0]
    return (tail,) if trimmed == tail else (tail, trimmed)


def _existing_path_in(token, marker):
    """The existing TEST_ROOT-rooted path `token` carries, or None."""
    for candidate in _test_root_candidates(token, marker):
        path = os.path.abspath(candidate)
        if os.path.exists(path):
            return path
    return None


def _existing_dir_in(token, marker):
    """The same, narrowed to an existing DIRECTORY."""
    path = _existing_path_in(token, marker)
    return path if path is not None and os.path.isdir(path) else None


def _prepare_worker_paths(config_path):
    """Make every path this config names usable by the worker that will read it.

    The de-escalation is unconditional (`src/auth/impersonate/lifecycle_worker.c`
    refuses a uid-0 worker even with an explicit `user root;`), so all of this
    is opened as `nobody`, while a test that builds its inputs under `tmp_path`
    leaves them root-owned inside a 0700 directory.  Each failure names the
    directive and never the reason:

      * "TPC cannot read brix_tpc_outbound_bearer_file: Permission denied" (3007)
      * "cms blacklist file ... stat failed; keeping previous 0 entries (13)"
      * "fsxeq program exited 127" — exec of an unreachable program

    Three treatments, because the readers disagree about what a safe file is:

      * a CREDENTIAL is chowned and never chmodded — 0600 is exactly what
        `brix_open_credfile()` and the GSI loaders demand, so widening one
        trades a traversal refusal for a mode refusal;
      * any other FILE gets a+r, plus a+x when it is already executable, so an
        operator program stays a program;
      * a DIRECTORY goes through `_open_spec_tree`, which widens only what is
        still at a creation default.
    """
    from cmdscripts import (  # noqa: PLC0415
        hand_credential_file_to_worker, handoff_credential_store)

    for directive, path in _config_paths(config_path):
        _open_ancestors_within_test_root(path)
        if directive == "brix_storage_credential_dir":
            # The one directory that must NOT be opened: `cred_dir_check`
            # refuses a store that is group/other-accessible or not owned by
            # the writing worker, and answers 507.  Owner + 0700 is the whole
            # contract, which `handoff_credential_store` is written to.
            handoff_credential_store(path)
        elif os.path.isdir(path):
            _open_spec_tree(path)
        elif directive in _WORKER_CREDENTIAL_FILES:
            hand_credential_file_to_worker(path)
        else:
            _open_worker_readable_file(path)


def _open_worker_readable_file(path):
    """Let the worker read one file the config named — without leaking a key.

    An owner-only mode is a SECURITY STATEMENT, the same way `_open_if_still_default`
    treats a directory that is no longer at its creation default: the fixtures
    here chmod 0600 exactly where a private key or a bearer lives, and the
    readers agree (`brix_open_credfile()` refuses a bearer group/other can
    write, the GSI loaders refuse a lax key).  Widening one would publish it to
    every account on the host to buy a read the owner can have for free, so
    those are handed over instead — which is also what the explicit
    `_WORKER_CREDENTIAL_FILES` directives get, and this is the net under them
    for the key a template spells some other way.

    Everything else — a CA bundle, a blacklist, an operator program — is public
    by construction and takes a+r, plus a+x when it is already executable so a
    program stays a program.
    """
    from cmdscripts import hand_credential_file_to_worker  # noqa: PLC0415

    try:
        mode = stat.S_IMODE(os.lstat(path).st_mode)
    except OSError:
        return
    if not mode & 0o077:
        hand_credential_file_to_worker(path)
        return
    opened = mode | 0o444 | (0o111 if mode & stat.S_IXUSR else 0)
    if opened != mode:
        try:
            os.chmod(path, opened)
        except OSError:
            pass


def _prepare_nginx_permissions(launcher, spec, endpoint):
    if os.geteuid() != 0:
        return
    if os.path.isdir(endpoint.data_root):
        launcher._chmod_r(endpoint.data_root, 0o777, add_only=True)
        _open_ancestors_within_test_root(endpoint.data_root)
    for directory in _spec_directories_within_test_root(spec):
        _open_spec_tree(directory)
    _prepare_worker_paths(endpoint.config)
    logs_dir = os.path.join(endpoint.prefix, "logs")
    if os.path.isdir(logs_dir):
        launcher._chmod_add(logs_dir, 0o777)


def _master_owns_prefix(launcher, endpoint):
    master = launcher._read_pid(endpoint.pidfile)
    if master is None:
        return False
    from lib_py.util import process_cmdline  # noqa: PLC0415

    try:
        os.kill(master, 0)
        command = process_cmdline(master)
    except (OSError, ValueError):
        return False
    return endpoint.prefix.encode() in command


def _launch_nginx(launcher, spec, endpoint, namespace):
    failure_type = namespace["RegistryCommandFailure"]
    try:
        launcher._nginx(
            ["-p", endpoint.prefix, "-c", "conf/nginx.conf"],
            spec=spec,
            env=spec.env,
        )
    except failure_type:
        if not _master_owns_prefix(launcher, endpoint):
            raise
        launcher._wait_ready(endpoint.host, endpoint.port, spec.readiness)


def start_nginx(launcher, spec, namespace):
    """Dispatch special kinds or start one rendered nginx instance."""
    if _dispatch_special(launcher, spec, namespace):
        return
    endpoint = launcher.render_nginx(spec)
    _prepare_nginx_permissions(launcher, spec, endpoint)
    launcher.nginx_test(spec)
    _launch_nginx(launcher, spec, endpoint, namespace)
    launcher._wait_ready(endpoint.host, endpoint.port, spec.readiness)
    launcher._owned.append(spec)


def _xrootd_binary(namespace):
    selected = namespace["BRIX_BIN"]
    binary = shutil.which(selected)
    if not binary:
        pytest.skip(f"selected xrootd binary is unavailable: {selected}")
    return binary


def _prepare_xrootd_paths(endpoint):
    prefix = Path(endpoint.prefix)
    paths = {
        "prefix": prefix,
        "admin": prefix / "admin",
        "run": prefix / "run",
        "logs": prefix / "logs",
        "tmp": prefix / "tmp",
    }
    for path in (
        prefix / "conf",
        paths["logs"],
        paths["admin"],
        paths["run"],
        Path(endpoint.data_root),
    ):
        path.mkdir(parents=True, exist_ok=True)
    return paths


def _base_xrootd_values(launcher, spec, endpoint, paths):
    return {
        **launcher._session_values(spec),
        "PORT": endpoint.port,
        "DATA_ROOT": endpoint.data_root,
        "DATA_DIR": endpoint.data_root,
        "LOG_DIR": str(paths["logs"]),
        "TMP_DIR": str(paths["tmp"]),
        "ADMIN_DIR": str(paths["admin"]),
        "RUN_DIR": str(paths["run"]),
        **endpoint.extra_ports,
        **launcher._endpoint_template_values(),
        **spec.template_values,
    }


def _add_security_library(launcher, values):
    security = launcher._find_xrd_library("libXrdSec-5.so", "libXrdSec.so")
    if security and "SECLIB" not in values:
        values["SECLIB"] = str(security)


def _render_xrootd_config(spec, path, values, namespace):
    namespace["render_config_to_path"](
        spec.template,
        str(path),
        strict=namespace["REGISTRY_STRICT_TEMPLATES"],
        **values,
    )


def _process_environment(extra):
    environment = os.environ.copy()
    if extra:
        environment.update(extra)
    return environment


def _xrootd_argv(launcher, binary, config, log_path):
    argv = [binary, "-c", str(config), "-l", str(log_path)]
    run_as = launcher._xrootd_runas_user(
        config.read_text(encoding="utf-8"), str(log_path)
    )
    if run_as:
        argv.extend(("-R", run_as))
    return argv


def _spawn_xrootd(argv, environment):
    return subprocess.Popen(
        argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env=environment,
    )


def _track_xrootd(launcher, spec, endpoint, process):
    launcher._xrootd_procs[spec.name] = process
    try:
        launcher._wait_ready(endpoint.host, endpoint.port, spec.readiness)
    except Exception:
        launcher._kill_xrootd(spec.name)
        raise
    launcher._owned.append(spec)


def start_xrootd(launcher, spec, namespace):
    binary = _xrootd_binary(namespace)
    endpoint = namespace["endpoint_for"](spec)
    paths = _prepare_xrootd_paths(endpoint)
    values = _base_xrootd_values(launcher, spec, endpoint, paths)
    _add_security_library(launcher, values)
    config = paths["prefix"] / "conf" / "xrootd.cfg"
    _render_xrootd_config(spec, config, values, namespace)
    log_path = paths["logs"] / "xrootd.log"
    argv = _xrootd_argv(launcher, binary, config, log_path)
    process = _spawn_xrootd(argv, _process_environment(spec.env))
    _track_xrootd(launcher, spec, endpoint, process)


def _http_libraries(launcher):
    libraries = {
        "HTTP_LIB": launcher._find_xrd_library("libXrdHttp-5.so", "libXrdHttp.so"),
        "TPC_LIB": launcher._find_xrd_library("libXrdHttpTPC-5.so", "libXrdHttpTPC.so"),
        "SECLIB": launcher._find_xrd_library("libXrdSec-5.so", "libXrdSec.so"),
    }
    if not libraries["HTTP_LIB"] or not libraries["TPC_LIB"]:
        pytest.skip("XrdHttp/XrdHttpTPC libraries not installed")
    return libraries


def _http_values(launcher, spec, endpoint, paths, libraries, ca_public):
    values = _base_xrootd_values(launcher, spec, endpoint, paths)
    values.update(
        {
            "HTTP_LIB": str(libraries["HTTP_LIB"]),
            "TPC_LIB": str(libraries["TPC_LIB"]),
            "SECLIB": str(libraries["SECLIB"] or "/usr/lib64/libXrdSec-5.so"),
            "CA_DIR": str(ca_public),
        }
    )
    return values


def start_xrdhttp(launcher, spec, namespace):
    binary = _xrootd_binary(namespace)
    libraries = _http_libraries(launcher)
    endpoint = namespace["endpoint_for"](spec)
    paths = _prepare_xrootd_paths(endpoint)
    ca_public = paths["prefix"] / "ca-public"
    pki_dir = os.environ.get("PKI_DIR") or str(namespace["PKI_DIR"])
    launcher._public_cadir(pki_dir, str(ca_public))
    values = _http_values(launcher, spec, endpoint, paths, libraries, ca_public)
    config = paths["prefix"] / "conf" / "xrdhttp.cfg"
    _render_xrootd_config(spec, config, values, namespace)
    log_path = paths["logs"] / "xrdhttp.log"
    argv = _xrootd_argv(launcher, binary, config, log_path)
    process = _spawn_xrootd(argv, _process_environment(spec.env))
    _track_xrootd(launcher, spec, endpoint, process)
