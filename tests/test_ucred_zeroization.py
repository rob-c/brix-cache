"""A-4/T4 — per-user backend secrets are zeroized after use.

A resolved credential (WLCG bearer, S3 secret key, CephX keyring path) lives in
process memory only as long as it is needed; leaving it in a stack scratch buffer
or a reusable ``brix_sd_ucred_t`` after the consumer is done turns any later
info-leak (a core dump, an adjacent over-read, a freed-then-reused allocation)
into a secret disclosure (CWE-226).  The fix has two halves:

  1. Every ``ucred.c`` reader that stages a secret in a stack buffer
     ``OPENSSL_cleanse``\\s that buffer on EVERY return that could follow the
     secret landing in it — the success path and the post-read reject paths.
  2. ``brix_sd_ucred_wipe()`` cleanses the three secret-bearing fields of a
     resolved credential, and is wired into every backend/VFS/root/webdav/stage
     consumer that finishes with one.

These are file-static readers driven only under the impersonation/broker
machinery, so — matching the OCSP-transport and tree-depth guardrails already in
this suite — the properties are asserted against the source.  The
security-negative case pins the property the whole item depends on: a reader must
never reach ``return NGX_OK`` with a live secret still resident in its scratch
buffer (the cleanse must immediately precede the success return).
"""

import re
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[1] / "src"

UCRED_C = _SRC / "fs" / "backend" / "ucred.c"
# The per-reader parsers (ucred_read_token/_s3/_keyring) live in the split sibling.
UCRED_PARSE_C = _SRC / "fs" / "backend" / "ucred_parse.c"
UCRED_H = _SRC / "fs" / "backend" / "ucred.h"

# Consumers that resolve a credential and must wipe it when done.  Sampled across
# the three module trees so the guard fails if the discipline is dropped in any.
WIPE_CONSUMERS = [
    _SRC / "fs" / "vfs" / "vfs_open.c",
    _SRC / "fs" / "vfs" / "vfs_staged.c",
    _SRC / "fs" / "xfer" / "stage_engine.c",
    _SRC / "protocols" / "root" / "read" / "open_request_resolve.c",
    _SRC / "protocols" / "webdav" / "tpc_user_proxy.c",
]


class TestUcredZeroization:
    @pytest.fixture(scope="class")
    def ucred(self):
        return (UCRED_C.read_text(encoding="utf-8") + "\n"
                + UCRED_PARSE_C.read_text(encoding="utf-8"))

    @pytest.fixture(scope="class")
    def header(self):
        return UCRED_H.read_text(encoding="utf-8")

    # -- success: the wipe helper cleanses all three secret fields ----------- #
    def test_wipe_helper_cleanses_every_secret_field(self, ucred):
        # Isolate the brix_sd_ucred_wipe body.
        start = ucred.index("brix_sd_ucred_wipe(brix_sd_ucred_t")
        body = ucred[start:start + 800]
        for field in ("cred->bearer", "cred->s3_sk", "cred->ceph_keyring"):
            assert f"OPENSSL_cleanse({field}" in body, field

    # -- coverage: every secret-staging reader cleanses its scratch buffer --- #
    def test_readers_cleanse_scratch_on_all_post_secret_returns(self, ucred):
        # ucred_read_token: cleanse on the trimmed-empty reject and on success.
        tok = _fn_body(ucred, "ucred_read_token")
        assert tok.count("OPENSSL_cleanse(buf") >= 2, "token reader under-wipes"
        # ucred_read_s3: three post-read rejects + the success path.
        s3 = _fn_body(ucred, "ucred_read_s3")
        assert s3.count("OPENSSL_cleanse(buf") >= 4, "s3 reader under-wipes"

    # -- error: the reusable credential struct is wiped by consumers, not just
    #    defined -- the helper is actually called across the consumer trees --- #
    def test_wipe_is_wired_into_consumers(self):
        hits = 0
        for path in WIPE_CONSUMERS:
            src = path.read_text(encoding="utf-8")
            assert "brix_sd_ucred_wipe(" in src, f"{path.name} never wipes"
            hits += src.count("brix_sd_ucred_wipe(")
        assert hits >= len(WIPE_CONSUMERS)

    # -- security-negative: no reader returns success with a live secret still
    #    in its scratch buffer -- the cleanse must immediately precede the
    #    `return NGX_OK` on every secret-staging reader ---------------------- #
    def test_no_success_return_leaves_secret_in_scratch(self, ucred):
        for fn in ("ucred_read_token", "ucred_read_s3"):
            body = _fn_body(ucred, fn)
            # The last statement before each `return NGX_OK;` in a secret reader
            # must be a cleanse of the scratch buffer.
            for m in re.finditer(r"return NGX_OK;", body):
                preceding = body[:m.start()]
                tail = preceding.rstrip().splitlines()[-1].strip()
                assert tail.startswith("OPENSSL_cleanse(buf"), (
                    f"{fn}: success return not immediately preceded by a scratch "
                    f"cleanse (found: {tail!r})"
                )


def _fn_body(src: str, name: str) -> str:
    """Return the text of a top-level static function `name` (its brace block)."""
    # Find the definition line (name at column 0-ish after the return type line).
    m = re.search(rf"\n{re.escape(name)}\(", src)
    assert m, f"function {name} not found"
    i = src.index("{", m.end())
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    raise AssertionError(f"unbalanced braces in {name}")
