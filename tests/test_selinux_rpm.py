# tests/test_selinux_rpm.py
"""Verifies the SELinux policy shipped by the nginx-mod-brix-cache-selinux RPM
on the host it is installed on: the brix module is loaded in the targeted
module store, the file-context database and on-disk labels match brix.fc, the
brix_port_t port labels from the %post scriptlet are present, and the compiled
policy actually contains the httpd_t allow rules from brix.te (ports,
data-plane manage+map, impersonation-broker capabilities, outbound connects).

Run as root on an SELinux-enabled host with the -selinux subpackage installed:

    cd /usr/share/brix && sudo python3 -m pytest tests/test_selinux_rpm.py -v

The whole module self-skips on hosts without SELinux (dev boxes, containers),
without root, or without the brix policy module, so it is safe in the general
suite.  Individual checks skip when their driving tool is absent — install
libselinux-utils, policycoreutils-python-utils and setools-console (weak deps
of brix-cache-tests) for full coverage.

Source of truth being verified: packaging/selinux/brix.{te,fc} and the
%post/%postun port scriptlets in packaging/rpm/nginx-mod-brix-cache.spec.
"""
import os
import re
import shutil
import subprocess
import pytest

pytestmark = [pytest.mark.selinux, pytest.mark.timeout(120)]

# Keep in sync with %%global brix_ports in the spec / the brix.te header.
BRIX_PORTS = {1094, 1095, 9001, 9100}

# path -> expected type, per brix.fc (canonical + legacy spellings).
FILE_CONTEXTS = {
    "/var/lib/brix-cache":          "brix_var_lib_t",
    "/var/lib/brix-cache/data/f":   "brix_var_lib_t",
    "/var/lib/nginx-xrootd":        "brix_var_lib_t",
    "/var/cache/brix-cache":        "brix_cache_t",
    "/var/cache/brix-cache/sub/f":  "brix_cache_t",
    "/var/cache/nginx-xrootd":      "brix_cache_t",
    "/etc/brix-cache":              "httpd_config_t",
    "/etc/brix-cache/jwks.json":    "httpd_config_t",
    "/etc/nginx-xrootd":            "httpd_config_t",
    "/etc/grid-security":           "cert_t",
    "/etc/grid-security/hostkey.pem": "cert_t",
}


def _run(argv, check=True):
    return subprocess.run(argv, capture_output=True, text=True, check=check)


def _selinux_enabled():
    tool = shutil.which("selinuxenabled")
    return tool is not None and subprocess.run([tool]).returncode == 0


def _brix_selinux_rpm_installed():
    """True only when the -selinux subpackage that ships the policy under test is
    actually installed.  Without it there is nothing to verify — a source/static
    dev tree has no policy in the store — so the whole module must skip rather than
    fail 16 packaging assertions against a policy that was never installed."""
    rpm = shutil.which("rpm")
    if rpm is None:
        return False
    return subprocess.run(
        [rpm, "-q", "nginx-mod-brix-cache-selinux"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


if not _selinux_enabled():
    pytestmark.append(pytest.mark.skip(reason="SELinux not enabled on this host"))
elif os.geteuid() != 0:
    pytestmark.append(pytest.mark.skip(reason="SELinux policy verification needs root"))
elif not _brix_selinux_rpm_installed():
    pytestmark.append(pytest.mark.skip(
        reason="nginx-mod-brix-cache-selinux RPM not installed — no policy to verify "
               "(source/static dev tree); install the -selinux subpackage to run these"))


def _need(tool, package):
    path = shutil.which(tool)
    if path is None:
        pytest.skip(f"{tool} not installed (dnf install {package})")
    return path


def _sesearch_allow(source, target, tclass):
    """All permissions the loaded policy allows source->target:tclass, as a set."""
    sesearch = _need("sesearch", "setools-console")
    out = _run([sesearch, "-A", "-s", source, "-t", target, "-c", tclass]).stdout
    perms = set()
    for m in re.finditer(r"allow\s+\S+\s+\S+:\S+\s+(?:\{([^}]*)\}|(\S+));", out):
        perms.update((m.group(1) or m.group(2)).split())
    return perms


# ---------------------------------------------------------------------------
# Module store
# ---------------------------------------------------------------------------

def test_brix_module_loaded_at_priority_200():
    semodule = _need("semodule", "policycoreutils")
    out = _run([semodule, "--list-modules=full"]).stdout
    rows = [l.split() for l in out.splitlines() if l.split()[1:2] == ["brix"]]
    assert rows, "brix policy module not present in the module store"
    # The spec installs via %selinux_modules_install => vendor priority 200,
    # and the module must not be flagged disabled (a 4th column when disabled).
    assert any(r[0] == "200" and len(r) == 3 for r in rows), \
        f"brix module rows {rows!r}: expected an enabled priority-200 entry"


# ---------------------------------------------------------------------------
# File contexts: label database, on-disk state, and inheritance
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path,expected", sorted(FILE_CONTEXTS.items()))
def test_fcontext_database(path, expected):
    matchpathcon = _need("matchpathcon", "libselinux-utils")
    out = _run([matchpathcon, "-n", path]).stdout.strip()
    assert re.search(rf":{expected}(:|$)", out), \
        f"{path}: expected type {expected}, label database says {out!r}"


def test_on_disk_labels_match_database():
    """restorecon -n reports every path whose actual label differs from the
    database — the RPM relabel scriptlets must have left nothing to fix."""
    restorecon = _need("restorecon", "policycoreutils")
    trees = [p for p in ("/var/lib/brix-cache", "/var/cache/brix-cache",
                         "/etc/brix-cache", "/etc/grid-security")
             if os.path.isdir(p)]
    if not trees:
        pytest.skip("no brix data/config trees present on this host")
    out = _run([restorecon, "-nvR", *trees]).stdout.strip()
    assert out == "", f"on-disk labels drifted from the policy:\n{out}"


def test_new_file_inherits_export_root_label():
    """A file created under the export root must come out brix_var_lib_t —
    this is what makes operator/staging writes correct without restorecon."""
    root = "/var/lib/brix-cache"
    if not os.path.isdir(root):
        pytest.skip(f"{root} not present (main RPM not installed?)")
    probe = os.path.join(root, ".selinux-inherit-probe")
    with open(probe, "w") as f:
        f.write("probe")
    try:
        ctx = _run(["stat", "-c", "%C", probe]).stdout.strip()
        assert ":brix_var_lib_t:" in ctx + ":", \
            f"file created in {root} got context {ctx!r}, not brix_var_lib_t"
    finally:
        os.unlink(probe)


# ---------------------------------------------------------------------------
# Port labels (%post semanage scriptlet)
# ---------------------------------------------------------------------------

def test_brix_ports_labelled():
    semanage = _need("semanage", "policycoreutils-python-utils")
    out = _run([semanage, "port", "-l"]).stdout
    labelled = set()
    for line in out.splitlines():
        cols = line.split()
        if cols[:2] == ["brix_port_t", "tcp"] or (cols and cols[0] == "brix_port_t" and "tcp" in cols):
            for tok in re.findall(r"\d+(?:-\d+)?", line):
                if "-" in tok:
                    lo, hi = map(int, tok.split("-"))
                    labelled.update(range(lo, hi + 1))
                else:
                    labelled.add(int(tok))
    missing = BRIX_PORTS - labelled
    assert not missing, \
        f"ports {sorted(missing)} not labelled brix_port_t (got {sorted(labelled)})"


# ---------------------------------------------------------------------------
# Allow rules in the loaded policy (brix.te)
# ---------------------------------------------------------------------------

def test_httpd_can_bind_and_connect_brix_ports():
    perms = _sesearch_allow("httpd_t", "brix_port_t", "tcp_socket")
    assert {"name_bind", "name_connect"} <= perms, \
        f"httpd_t->brix_port_t:tcp_socket missing bind/connect (got {sorted(perms)})"


@pytest.mark.parametrize("dtype", ["brix_var_lib_t", "brix_cache_t"])
def test_httpd_manages_and_maps_data_plane(dtype):
    fperms = _sesearch_allow("httpd_t", dtype, "file")
    need = {"create", "read", "write", "append", "unlink", "rename", "map"}
    assert need <= fperms, \
        f"httpd_t->{dtype}:file missing {sorted(need - fperms)} (got {sorted(fperms)})"
    dperms = _sesearch_allow("httpd_t", dtype, "dir")
    dneed = {"create", "add_name", "remove_name", "rmdir", "search"}
    assert dneed <= dperms, \
        f"httpd_t->{dtype}:dir missing {sorted(dneed - dperms)} (got {sorted(dperms)})"


def test_httpd_impersonation_broker_rules():
    caps = _sesearch_allow("httpd_t", "httpd_t", "capability")
    need = {"setuid", "setgid", "chown", "fowner", "fsetid",
            "dac_override", "dac_read_search"}
    assert need <= caps, \
        f"httpd_t self:capability missing {sorted(need - caps)} (got {sorted(caps)})"
    assert "setcap" in _sesearch_allow("httpd_t", "httpd_t", "process"), \
        "httpd_t self:process setcap missing (broker capset would be denied)"


def test_httpd_reads_grid_credentials():
    assert "read" in _sesearch_allow("httpd_t", "cert_t", "file"), \
        "httpd_t cannot read cert_t (/etc/grid-security hostcert/CAs/CRLs)"


@pytest.mark.parametrize("port_type,why", [
    ("http_port_t", "WebDAV/HTTP-TPC pulls + https origins"),
    ("kerberos_port_t", "krb5 auth against the site KDC"),
])
def test_httpd_outbound_connects(port_type, why):
    assert "name_connect" in _sesearch_allow("httpd_t", port_type, "tcp_socket"), \
        f"httpd_t->{port_type} name_connect missing ({why})"


def test_httpd_can_exec_curl():
    """The WebDAV HTTP-TPC handler fork/execs curl(1) from bin_t, no domain
    transition (corecmd_exec_bin)."""
    perms = _sesearch_allow("httpd_t", "bin_t", "file")
    assert {"execute", "execute_no_trans"} <= perms, \
        f"httpd_t->bin_t:file exec rules missing (got {sorted(perms)})"
