"""Default gateway write-staging under /tmp/staging — config-time provisioning.

Regression for the runtime_server_backend change: a WRITABLE export forwarding
to a whole-object remote backend (http(s):// WebDAV or s3://) with NO stage
tier configured at all auto-provisions the stock sd_stage decorator over a
brix-managed posix store at /tmp/staging/<sanitised-backend-url> (0700, 0711
base), shouted at the admin via a multi-line startup [warn] banner.  The
default composes the EXISTING tier grammar (brix_stage on + brix_stage_store
posix:...), so tier_parse_local and sd_stage do all the real work.

Covers the mandated triplet:
  success           — no stage directive at all: nginx -t succeeds, the banner
                      names the managed directory, and the directory exists
                      mode 0700 under a 0711 /tmp/staging base;
  error             — "brix_stage on" without brix_stage_store stays a hard
                      [emerg] (the default never masks the operator error);
  security-negative — a read-only gateway (brix_allow_write off) must NOT
                      silently gain a writable spool: no banner, no directory;
plus the opt-out: an explicit "brix_stage off" keeps staging off with no
banner and no directory.

Run:
  TEST_SKIP_SERVER_SETUP=1 PYTHONPATH=tests \
      pytest tests/test_stage_default_gateway.py -v -p no:xdist
"""

import os
import shutil
import stat
import subprocess
import textwrap

import pytest

from settings import NGINX_BIN
from server_launcher import RegistryCommandFailure
from server_registry import NginxInstanceSpec

BASE = "/tmp/staging"
BANNER = "DEFAULT WRITE-STAGING"

pytestmark = pytest.mark.uses_lifecycle_harness


def _san(url):
    """Mirror brix_tier_default_stage_dir: [A-Za-z0-9._-] kept, else '_',
    then the runtime worker uid suffix (leaves are per-identity so instances
    of different users never fight over one 0700 spool)."""
    sanitised = "".join(
        c if (c.isalnum() or c in "._-") else "_" for c in url[:160]
    )
    return f"{sanitised}.{_worker_uid()}"


def _worker_uid():
    if os.geteuid() != 0:
        return os.geteuid()
    import pwd
    return pwd.getpwnam(os.environ.get("BRIX_WORKER_USER", "nobody")).pw_uid


def _spec(name, backend, stage_directives="", allow_write="on"):
    return NginxInstanceSpec(
        name=name,
        template="nginx_stage_default_gateway.conf",
        protocol="webdav",
        readiness="none",
        template_values={
            "BACKEND": backend,
            "ALLOW_WRITE": allow_write,
            "STAGE_DIRECTIVES": stage_directives,
        },
    )


def _nginx_t(lifecycle, spec):
    """Render + nginx -t via the harness; return (exit code, combined output).

    nginx_test raises RegistryCommandFailure on rc != 0 — fold that back into
    the (code, output) shape so the error-path test can assert on the emerg.
    """
    reg = lifecycle.register(spec)
    lifecycle.launcher.render_nginx(reg)
    try:
        res = lifecycle.launcher.nginx_test(reg)
    except RegistryCommandFailure as exc:
        return 1, str(exc)
    return res.returncode, res.stdout + res.stderr


def _spool(backend):
    return os.path.join(BASE, _san(backend))


@pytest.fixture()
def clean_spool():
    """Remove the per-test spool leaf afterwards (keep a pre-existing base)."""
    created = []
    yield created
    for d in created:
        shutil.rmtree(d, ignore_errors=True)


def test_default_spool_created_and_banner(lifecycle, clean_spool):
    """Success: no stage directive -> banner + managed 0700 spool directory."""
    backend = "https://127.0.0.1:39101/vo/stagedef"
    spool = _spool(backend)
    clean_spool.append(spool)

    code, out = _nginx_t(lifecycle, _spec("stage-default-on", backend))
    assert code == 0, f"gateway config with defaulted staging must pass:\n{out}"
    assert BANNER in out, f"missing the default-staging banner:\n{out}"
    assert spool in out, f"banner must name the managed directory:\n{out}"
    assert "tmpfs" in out, f"banner must mention the tmpfs option:\n{out}"
    assert "PrivateTmp DETECTED" not in out, \
        f"PrivateTmp warning must not fire on a normal (shared) /tmp:\n{out}"

    assert os.path.isdir(spool), "managed spool directory was not created"
    assert stat.S_IMODE(os.stat(spool).st_mode) == 0o700
    base_mode = stat.S_IMODE(os.stat(BASE).st_mode)
    assert base_mode & 0o022 == 0, \
        f"{BASE} must not be group/other-writable (mode {oct(base_mode)})"


def test_explicit_off_opts_out(lifecycle, clean_spool):
    """Opt-out: `brix_stage off;` -> no banner, no spool directory."""
    backend = "https://127.0.0.1:39102/vo/stageoff"
    spool = _spool(backend)
    clean_spool.append(spool)

    code, out = _nginx_t(
        lifecycle, _spec("stage-default-off", backend, "brix_stage off;"))
    assert code == 0, out
    assert BANNER not in out, \
        f"explicit brix_stage off must suppress the default:\n{out}"
    assert not os.path.isdir(spool), \
        "brix_stage off must not create a managed spool directory"


def test_stage_on_without_store_still_fatal(lifecycle, clean_spool):
    """Error: explicit `brix_stage on` without a store keeps the hard emerg."""
    backend = "https://127.0.0.1:39103/vo/stagebroken"
    clean_spool.append(_spool(backend))

    code, out = _nginx_t(
        lifecycle, _spec("stage-on-no-store", backend, "brix_stage on;"))
    assert code != 0, \
        f"brix_stage on without brix_stage_store must fail nginx -t:\n{out}"
    assert "requires brix_stage_store" in out, out


def test_read_only_gateway_gets_no_spool(lifecycle, clean_spool):
    """Security-negative: a non-writable gateway must not gain a spool dir."""
    backend = "https://127.0.0.1:39104/vo/stagero"
    spool = _spool(backend)
    clean_spool.append(spool)

    code, out = _nginx_t(
        lifecycle, _spec("stage-default-ro", backend, allow_write="off"))
    assert code == 0, out
    assert BANNER not in out, \
        f"a read-only gateway must not get default staging:\n{out}"
    assert not os.path.isdir(spool), \
        "a read-only gateway must not create a managed spool directory"


def test_privatetmp_service_warned_loudly(tmp_path):
    """A service whose /tmp is a systemd PrivateTmp mount must be shouted at:
    the /tmp-hosted spool is deleted on every service restart.  Simulated with
    a private mount namespace whose /tmp is bind-mounted from a
    /tmp/systemd-private-*/tmp subtree — the exact mountinfo shape systemd
    produces.  The config lives under /var/tmp so it survives the bind."""
    if os.geteuid() != 0:
        pytest.skip("needs root (mount namespace + bind mount)")
    if shutil.which("unshare") is None:
        pytest.skip("unshare not available")

    base = "/var/tmp/brix-privatetmp-test"
    shutil.rmtree(base, ignore_errors=True)
    for d in ("logs", "tmp", "data"):
        os.makedirs(os.path.join(base, d), exist_ok=True)
    conf = os.path.join(base, "nginx.conf")
    with open(conf, "w") as f:
        f.write(textwrap.dedent(f"""\
            user root;
            worker_processes 1;
            pid {base}/logs/nginx.pid;
            error_log {base}/logs/error.log info;
            events {{ worker_connections 64; }}
            http {{
                access_log off;
                client_body_temp_path {base}/tmp;
                server {{
                    listen 127.0.0.1:39199;
                    location /dav/ {{
                        brix_webdav on;
                        brix_export {base}/data;
                        brix_allow_write on;
                        brix_webdav_auth none;
                        brix_storage_backend https://127.0.0.1:39105/vo/ptmp;
                    }}
                }}
            }}
            """))
    # The build-tree nginx binary may itself live under /tmp — copy it out so
    # it survives the bind mount that replaces /tmp inside the namespace.
    nginx = os.path.join(base, "nginx")
    shutil.copy2(NGINX_BIN, nginx)
    try:
        r = subprocess.run(
            ["unshare", "-m", "sh", "-ec",
             "mount --make-rprivate / && "
             "mkdir -p /tmp/systemd-private-brixtest/tmp && "
             "mount --bind /tmp/systemd-private-brixtest/tmp /tmp && "
             f"exec {nginx} -t -c {conf}"],
            capture_output=True, text=True, timeout=60)
        out = r.stdout + r.stderr
        assert r.returncode == 0, f"nginx -t failed under private /tmp:\n{out}"
        assert BANNER in out, \
            f"default staging must still provision under a private /tmp:\n{out}"
        assert "PrivateTmp DETECTED" in out, \
            f"missing the loud PrivateTmp warning:\n{out}"
        assert "does NOT survive a restart" in out, out
    finally:
        shutil.rmtree(base, ignore_errors=True)
        shutil.rmtree("/tmp/systemd-private-brixtest", ignore_errors=True)
