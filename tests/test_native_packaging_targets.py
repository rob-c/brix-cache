"""Static contracts for the native packaging target matrix."""

from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
RPM = ROOT / "packaging/rpm"


def test_rpm_driver_exposes_every_supported_target() -> None:
    driver = (RPM / "build-rpm-container.sh").read_text()
    for target in (
        "alma8",
        "alma9",
        "alma10",
        "fedora43",
        "fedora44",
        "fedora-rawhide",
        "centos-stream9",
        "centos-stream10",
    ):
        assert target in driver, f"RPM build driver omits {target}"
    for dockerfile in ("Dockerfile.fedora", "Dockerfile.centos-stream"):
        assert (RPM / dockerfile).is_file()


def test_el8_target_is_explicitly_client_only_and_uses_openssl3() -> None:
    dockerfile = (RPM / "Dockerfile.alma8").read_text()
    spec = (RPM / "brix-cache-client-el8.spec").read_text()
    assert "openssl3-devel" in dockerfile
    assert "RPM_SPEC=/build/src/packaging/rpm/brix-cache-client-el8.spec" in dockerfile
    assert "Requires:       openssl3-libs" in spec
    assert "nginx-mod-devel" not in dockerfile
    assert "%{nginx_moddir}" not in spec


def test_alma_rpms_carry_one_shared_rocky_platform_notice() -> None:
    builder = (RPM / "build-rpm.sh").read_text()
    spec = (RPM / "nginx-mod-brix-cache.spec").read_text()
    el8_spec = (RPM / "brix-cache-client-el8.spec").read_text()
    warning = RPM / "alma-platform-warning.sh"

    assert 'platform_id" == "almalinux"' in builder
    assert 'brix_vendor_alma 1' in builder
    assert "%package -n brix-cache-alma-platform-warning" in spec
    assert "%post -n brix-cache-alma-platform-warning" in spec
    assert "Rocky Linux is NOT supported" in warning.read_text()
    assert "%post" in el8_spec
    assert "alma-platform-warning" in el8_spec
    for release in ("9", "10", "11"):
        dockerfile = (RPM / f"Dockerfile.alma{release}").read_text()
        assert '--define "brix_vendor_alma 1"' in dockerfile


def _release_workflow() -> str:
    workflow_path = ROOT / ".github/workflows/packages.yml"
    if not workflow_path.exists():
        pytest.skip("release workflow metadata is not shipped in native source archives")
    return workflow_path.read_text()


@pytest.mark.parametrize("target", (
    "alma8",
    "alma9",
    "alma10",
    "fedora43",
    "fedora44",
    "fedora-rawhide",
    "centos-stream9",
    "centos-stream10",
))
def test_release_workflow_builds_every_rpm_target(target: str) -> None:
    assert f"- {target}" in _release_workflow()


def test_release_workflow_uses_unique_assets_and_checks_nix() -> None:
    workflow = _release_workflow()
    assert "brix-cache-${{ matrix.distro }}-arm64.tar.gz" in workflow
    assert 'nix --extra-experimental-features "nix-command flakes"' in workflow
    assert "flake check path:/src" in workflow


def test_nix_flake_has_pinned_supported_system_outputs() -> None:
    flake = (ROOT / "flake.nix").read_text()
    lock = (ROOT / "flake.lock").read_text()
    assert 'nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05"' in flake
    assert '"aarch64-linux"' in flake
    assert '"x86_64-linux"' in flake
    assert '"locked"' in lock
    assert "nginx-brix-cache" in flake


def test_nix_test_sdk_keeps_the_built_nginx_objects() -> None:
    """The SDK must exercise native seams, not turn them into missing-object skips."""
    package = (ROOT / "packaging/nix/package.nix").read_text()
    sdk = package[package.index("nginx-brix-test-sdk ="):
                  package.index("in {", package.index("nginx-brix-test-sdk ="))]
    assert "buildPhase =" not in sdk
    assert "dontBuild" not in sdk
    assert 'cp -R . "$out/"' in sdk


def test_nix_dev_shell_carries_external_interop_tools() -> None:
    flake = (ROOT / "flake.nix").read_text()
    for package in (
        "createrepo_c", "fail2ban", "fuse3", "gfal2-util", "kubernetes-helm",
        "minio-client", "nghttp2", "podman", "squid", "valgrind", "varnish",
    ):
        assert package in flake, f"Nix dev shell omits {package}"


def test_nix_dev_shell_does_not_opt_into_the_insecure_minio_server() -> None:
    flake = (ROOT / "flake.nix").read_text()
    assert "NIXPKGS_ALLOW_INSECURE" not in flake
    assert "permittedInsecurePackages" not in flake
    assert "\n              minio\n" not in flake


def test_nix_python_includes_optional_feature_bindings() -> None:
    flake = (ROOT / "flake.nix").read_text()
    python = flake[flake.index("python = pkgs.python3.withPackages"):
                   flake.index("in {", flake.index("python = pkgs.python3.withPackages"))]
    for package in ("boto3", "botocore", "brotli", "crc32c", "numpy", "psutil",
                    "requests-aws4auth", "xattr", "pyopenssl", "zstandard"):
        assert package in python, f"Nix Python environment omits {package}"


def test_nix_python_reference_bindings_meet_the_declared_major_version() -> None:
    flake = (ROOT / "flake.nix").read_text()
    assert 'version = "6.2.1";' in flake
    assert 'format = "wheel";' in flake
    assert "complexipy xrootdBindings" in flake
    assert "autoPatchelfHook" in flake
    assert "xrootd-6.2.1-cp313-cp313-manylinux_2_28_aarch64.whl" in flake
    assert "xrootd-6.2.1-cp313-cp313-manylinux_2_28_x86_64.whl" in flake


def test_nix_source_package_excludes_appledouble_archive_metadata() -> None:
    package = (ROOT / "packaging/nix/package.nix").read_text()
    assert '!(lib.hasPrefix "._" name)' in package


def test_nix_compiles_the_installed_io_uring_backend() -> None:
    package = (ROOT / "packaging/nix/package.nix").read_text()
    assert "liburing" in package
    assert 'BRIX_ENABLE_IO_URING = "1";' in package


def test_rpm_test_package_bundles_its_brixtest_runtime() -> None:
    spec = (RPM / "nginx-mod-brix-cache.spec").read_text()
    assert "cp -a brixtest/src" in spec
    assert "%{_datadir}/brix/brixtest" in spec


def test_rpm_test_package_documented_command_exposes_brixtest() -> None:
    spec = (RPM / "nginx-mod-brix-cache.spec").read_text()
    assert "PYTHONPATH=tests:brixtest/src python3 -m pytest" in spec
    assert "TEST_SKIP_SERVER_SETUP=1" in spec


def test_rpm_test_package_keeps_brixtest_noarch_payload_data_only() -> None:
    spec = (RPM / "nginx-mod-brix-cache.spec").read_text()
    cleanup = spec[spec.index("# Never ship the prebuilt test nginx binary"):]
    assert "%{_datadir}/brix/brixtest -name '__pycache__'" in cleanup
    assert "%{_datadir}/brix/brixtest -name '*.pyc'" in cleanup
    assert "%{_datadir}/brix/brixtest -type f" in cleanup


def test_stock_named_client_packages_conflict_with_xrootd_client() -> None:
    """The replacement clients must never reach an ambiguous file collision."""
    deb = (ROOT / "packaging/deb/debian/control").read_text()
    deb_client = deb[deb.index("Package: brix-cache-client\n"):
                     deb.index("Package: brix-cache-client-compat\n")]
    spec = (RPM / "nginx-mod-brix-cache.spec").read_text()
    rpm_client = spec[spec.index("%package -n brix-cache-client\n"):
                      spec.index("%package -n brix-cache-client-compat\n")]
    assert "Conflicts: xrootd-client" in deb_client
    assert "Conflicts:      xrootd-client" in rpm_client


def test_native_test_package_uses_coinstallable_prefixed_clients() -> None:
    """Tests retain the official interoperability client beside BriX tools."""
    control = (ROOT / "packaging/deb/debian/control").read_text()
    tests = control[control.index("Package: brix-cache-tests\n"):
                    control.index("Package: brix-tools\n")]
    assert "brix-cache-client-compat (= ${source:Version})" in tests
    assert "brix-cache-client (= ${source:Version})" not in tests


def test_prefixed_debian_client_remains_coinstallable() -> None:
    control = (ROOT / "packaging/deb/debian/control").read_text()
    compat = control[control.index("Package: brix-cache-client-compat\n"):
                     control.index("Package: brix-xrootdfs-fuse\n")]
    assert "Conflicts: xrootd-client" not in compat


def test_native_source_archives_keep_required_migration_tools() -> None:
    """Package staging keeps runtime scripts while still excluding VCS data."""
    for builder in (RPM / "build-rpm.sh",
                    ROOT / "packaging/deb/build-deb.sh"):
        text = builder.read_text()
        assert "--exclude='./tools'" not in text
        assert ("--exclude-vcs" in text or "--exclude=.git" in text
                or "--exclude='./.git'" in text)
        assert "--exclude='./.github'" not in text
        assert "--exclude='./dist'" in text


def test_native_source_archives_exclude_host_client_artifacts() -> None:
    """A source archive made on macOS must never seed Linux with Mach-O tools."""
    for builder in (RPM / "build-rpm.sh",
                    ROOT / "packaging/deb/build-deb.sh"):
        text = builder.read_text()
        assert "--exclude='./client/bin'" in text
        assert "--exclude='./client/*.dylib'" in text
        assert "--exclude='*.o'" in text
        assert "--exclude='*.a'" in text


def test_webdav_curl_default_is_resolved_by_the_build() -> None:
    config = (ROOT / "config").read_text()
    source = (ROOT / "src/protocols/webdav/tpc_config.c").read_text()
    assert 'command -v curl' in config
    assert '-DBRIX_DEFAULT_CURL_PATH=' in config
    assert "BRIX_DEFAULT_CURL_PATH);" in source


def test_webdav_curl_default_requires_an_absolute_path() -> None:
    config = (ROOT / "config").read_text()
    assert 'BRIX_CURL_BIN="${BRIX_CURL_BIN:-' in config
    assert 'curl executable not found at build time' in config
    assert '/*)' in config


def test_webdav_curl_default_rejects_compiler_metacharacters() -> None:
    config = (ROOT / "config").read_text()
    assert "contains characters unsafe for a compiled path" in config
    assert "*[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./+-]*" in config


def test_ubuntu_distro_modules_use_the_exact_patched_nginx_sdk() -> None:
    builder = (ROOT / "packaging/deb/build-deb.sh").read_text()
    rules = (ROOT / "packaging/deb/debian/rules").read_text()
    assert 'sdk_source="/usr/share/nginx/src"' in builder
    assert 'dpkg-query -W -f \'${Version}\' nginx-dev' in builder
    assert 'sdk_version" != "$distro_package_version' in builder
    assert 'cp -a "$sdk_source/." "$nginx_src/"' in builder
    assert "-f objs/Makefile" in rules
    assert "objs/ngx_stream_brix_module.so" in rules
    assert "objs/ngx_http_brix_xrdhttp_filter_module.so" in rules

    for release in ("22", "24", "26"):
        dockerfile = (ROOT / f"packaging/deb/Dockerfile.ubuntu{release}").read_text()
        assert 'apt-get install -y --no-install-recommends nginx-dev' in dockerfile
