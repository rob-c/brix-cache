"""``lib_py.host_env``: the macOS process-environment defaults for stock XRootD.

The stock XRootD library reverse-resolves the host's LAN address in a static
initialiser; on a Mac whose address has no PTR record that is a 30 s stall in
every process that loads it.  ``install()`` applies XRootD's own short-circuit
(``XRDNET_IDENTITY``) on Darwin only, and never overrides an operator's value.
"""
import os
from unittest import mock

from lib_py import host_env


def test_darwin_gets_the_loopback_identity():
    """success: on Darwin the default lands and every child inherits it."""
    with mock.patch.object(host_env.sys, "platform", "darwin"), \
            mock.patch.dict(os.environ, {}, clear=True):
        host_env.install()
        assert os.environ["XRDNET_IDENTITY"] == "localhost"


def test_an_operator_value_is_kept():
    """error path: an explicit identity wins over the default."""
    with mock.patch.object(host_env.sys, "platform", "darwin"), \
            mock.patch.dict(os.environ, {"XRDNET_IDENTITY": "ds1.example.org"}, clear=True):
        host_env.install()
        assert os.environ["XRDNET_IDENTITY"] == "ds1.example.org"


def test_other_hosts_are_untouched():
    """security-negative: Linux keeps its real DNS identity (cmsd members must
    advertise their resolvable name there, never a forced loopback alias)."""
    with mock.patch.object(host_env.sys, "platform", "linux"), \
            mock.patch.dict(os.environ, {}, clear=True):
        host_env.install()
        assert "XRDNET_IDENTITY" not in os.environ
        assert "PKG_CONFIG_PATH" not in os.environ


def test_the_krb5_keg_is_put_on_pkg_config_path_once(tmp_path):
    """success + idempotence: the keg dir is prepended when it exists on disk
    and never duplicated on a second install()."""
    keg = tmp_path / "pkgconfig"
    keg.mkdir()
    with mock.patch.object(host_env.sys, "platform", "darwin"), \
            mock.patch.object(host_env, "_KRB5_PKGCONFIG_DIRS", (str(keg),)), \
            mock.patch.dict(os.environ, {"PKG_CONFIG_PATH": "/x/pkgconfig"}, clear=True):
        host_env.install()
        host_env.install()
        assert os.environ["PKG_CONFIG_PATH"] == f"{keg}{os.pathsep}/x/pkgconfig"


def test_a_missing_keg_leaves_pkg_config_path_alone(tmp_path):
    """error path: a keg that is not installed is not invented."""
    with mock.patch.object(host_env.sys, "platform", "darwin"), \
            mock.patch.object(host_env, "_KRB5_PKGCONFIG_DIRS", (str(tmp_path / "absent"),)), \
            mock.patch.dict(os.environ, {"PKG_CONFIG_PATH": "/x/pkgconfig"}, clear=True):
        host_env.install()
        assert os.environ["PKG_CONFIG_PATH"] == "/x/pkgconfig"
