"""Static contracts preventing the Darwin build verifier from false-passing."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = (ROOT / "tools/ci/verify_platform_builds.sh").read_text()
SERVING_CONFIG = (
    ROOT / "tests/configs/nginx_darwin_serving_smoke.conf"
).read_text()


def test_homebrew_source_cache_is_content_addressed():
    assert 'shasum -a 256 "$source_archive"' in VERIFIER
    assert 'source_dir="$build_subdir/nginx-src-$source_id"' in VERIFIER


def test_serving_smoke_drives_and_verifies_brix_webdav_bytes():
    assert "brix_webdav on" in SERVING_CONFIG
    assert "brix_storage_backend posix:{EXPORT}" in SERVING_CONFIG
    assert "listen unix:{SOCKET}" in SERVING_CONFIG
    assert 's|{SOCKET}|$runtime_socket|g' in VERIFIER
    assert 's|{EXPORT}|$REPO_ROOT|g' in VERIFIER
    assert 'curl --silent --show-error --fail --unix-socket "$runtime_socket"' in VERIFIER
    assert 'cmp -s "$REPO_ROOT/README.md" "$runtime_response"' in VERIFIER


def test_crc_probe_selects_native_architecture_flags():
    crc_probe = VERIFIER.index("crc_cflags=()")
    arm_branch = VERIFIER.index('if [[ "$arch" == "arm64" ]]', crc_probe)
    intel_branch = VERIFIER.index("else", arm_branch)
    branch_end = VERIFIER.index("fi", intel_branch)
    assert "-march=armv8-a+crc" in VERIFIER[arm_branch:intel_branch]
    assert "-march=armv8-a+crc" not in VERIFIER[intel_branch:branch_end]
    assert "-DBRIX_ARCH_X86_64=1" in VERIFIER[intel_branch:branch_end]


def test_client_build_discards_foreign_shared_checkout_artifacts():
    client_clean = 'make -C "$REPO_ROOT/client" clean'
    protocol_clean = 'make -C "$REPO_ROOT/shared/xrdproto" clean'
    client_build = 'make -C "$REPO_ROOT/client" -j"$make_jobs" all'
    assert client_clean in VERIFIER
    assert protocol_clean in VERIFIER
    assert VERIFIER.index(client_clean) < VERIFIER.index(client_build)
    assert VERIFIER.index(protocol_clean) < VERIFIER.index(client_build)
