"""``brix_host_identity`` (src/core/compat/host_identity.c): the one name the
node advertises in kXR_locate prefname tokens and cms.d registrations.

XRDNET_IDENTITY — the stock XRootD short-circuit for the same value — wins when
it is a syntactically valid host name; anything else falls back to
gethostname(2).  The C helper is exercised through a tiny probe binary so the
validator's edges are pinned on every host, not only where the env is set.
"""
import os
import shutil
import socket
import subprocess

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROGRAM = r'''
#include <stdio.h>
#include <string.h>
#include "core/compat/host_identity.h"

int main(int argc, char **argv)
{
    if (argc == 3 && strcmp(argv[1], "valid") == 0) {
        printf("%d\n", brix_host_identity_valid(argv[2], strlen(argv[2])));
        return 0;
    }
    printf("%s\n", brix_host_identity());
    return 0;
}
'''


@pytest.fixture(scope="module")
def probe(tmp_path_factory):
    cc = shutil.which("cc") or shutil.which("gcc")
    if cc is None:
        pytest.skip("no C compiler on PATH")
    work = tmp_path_factory.mktemp("hostident")
    src = work / "probe.c"
    src.write_text(PROGRAM)
    out = str(work / "probe")
    build = subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-I", os.path.join(REPO, "src"), str(src),
                            os.path.join(REPO, "src", "core", "compat", "host_identity.c"),
                            "-o", out], capture_output=True, text=True, timeout=180)
    if build.returncode != 0:
        pytest.fail(f"probe failed to compile:\n{build.stderr}")

    def run(*args, identity=None):
        env = {k: v for k, v in os.environ.items() if k != "XRDNET_IDENTITY"}
        if identity is not None:
            env["XRDNET_IDENTITY"] = identity
        return subprocess.run([out, *args], capture_output=True, text=True,
                              env=env, timeout=30).stdout.strip()

    return run


def test_a_valid_identity_is_advertised(probe):
    """success: the override is what the node publishes, verbatim."""
    assert probe(identity="ds1.example.org") == "ds1.example.org"
    assert probe("valid", "ds1.example.org") == "1"
    assert probe("valid", "[::1]"[1:-1]) == "1"      # v6 literal digits and ':'


def test_no_override_means_gethostname(probe):
    """error path: unset or empty ⇒ gethostname(2), never an empty token."""
    assert probe() == socket.gethostname()
    assert probe(identity="") == socket.gethostname()
    assert probe("valid", "") == "0"


@pytest.mark.parametrize("bad", ["evil.test/redirect", "a b", "host:port?x=1",
                                 "x" * 256, "name\n"])
def test_malformed_identities_are_refused(probe, bad):
    """security-negative: anything a client would parse as more than a host
    name is ignored, so the env cannot inject paths or options into a token."""
    assert probe("valid", bad) == "0"
    assert probe(identity=bad) == socket.gethostname()
