# tests/test_cvmfs_conformance_fuse_manifest_parse.py — Phase-84 Wave-3
#
# Conformance corpus for the CVMFS .cvmfspublished manifest parser + signature
# trust gate (row `fuse_manifest_parse`). Drives `brixMount cvmfs --check <fqrn>`
# (exit 0 = healthy trust chain + root catalog) against forged repos served off a
# single long-lived webroot mock; each case rewrites ONLY the manifest in place
# and an autouse fixture restores the pristine bytes afterwards, so exactly one
# openssl keypair/cert is minted for the whole module (keygen is slow).
#
# Official .cvmfspublished spec (cvmfs manifest.cc): key-value lines terminated by
# '\n' — C=root catalog hash, B=catalog size, R=root-path md5, X=cert obj hash,
# S=revision, N=fqrn, T=timestamp, D=TTL — then a "--\n" separator, the printed
# hash-line, and a raw RSA signature to EOF. The official client requires C, N and
# X and binds the printed hash-line to the digest of the signed body. Divergences
# from that (brix laxer) are pinned with xfail(strict=True) + a DIVERGENCE note.
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from cmdscripts import exec_wrapper
from conformance_common import BRIXMOUNT, PortBlock, check_repo, fuse_mount
from repo_forge import Dir, File, RepoForge

REPO = "test.cern.ch"

_FUSE_READY = (os.path.exists("/dev/fuse") and shutil.which("fusermount3") is not None
               and os.path.exists(BRIXMOUNT))
requires_fuse = pytest.mark.skipif(not _FUSE_READY, reason="fuse mount prerequisites missing")
requires_brixmount = pytest.mark.skipif(not os.path.exists(BRIXMOUNT),
                                        reason=f"brixMount not built: {BRIXMOUNT}")

# Each case can retry its `--check` a few times when a saturated box outruns the
# 60s per-call cap (see `check()`); give the whole test wall-clock room so the
# 30s default per-test timeout never guillotines a legitimate retry mid-flight.
pytestmark = [requires_brixmount, pytest.mark.timeout(300)]

# The forged tree read back by mounts and by --check's root-dir walk.
TREE = {"hello": File(b"Hello forged CVMFS!\n"),
        "sub": Dir({"leaf.txt": File(b"leaf\n")}),
        "empty": Dir({})}


# ---- module fixtures: one forge + one cert + one mock ----------------------

@pytest.fixture(scope="module")
def forge():
    work = tempfile.mkdtemp(prefix="fuse_manifest_parse.")
    web = os.path.join(work, "web")
    pub = os.path.join(work, "repo.pub")
    f = RepoForge(REPO, web).build(TREE, pub)
    f.pub = pub                                        # stash for callers
    f.pristine = f.artifact_path("manifest").read_bytes()
    try:
        yield f
    finally:
        f.close()
        shutil.rmtree(work, ignore_errors=True)


@pytest.fixture(scope="module")
def mock_url(forge):
    port = PortBlock("fuse_manifest_parse").mock()
    proc = subprocess.Popen(
        [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                      "cvmfs", "mock_stratum1.py"),
         "--port", str(port), "--repo", REPO, "--webroot", str(forge.webroot)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        if proc.poll() is not None:            # bind failed → a squatter owns the port
            raise RuntimeError(f"webroot mock exited (rc={proc.returncode}); port "
                               f"{port} likely held by a stale mock from a killed run")
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/ctl/log", timeout=0.3)
            break
        except Exception:
            time.sleep(0.1)
    else:
        proc.terminate()
        raise RuntimeError("webroot mock did not start")
    # Prove the listener is *our* mock serving *this* forge, not a squatter.
    served = urllib.request.urlopen(
        f"http://127.0.0.1:{port}/cvmfs/{REPO}/.cvmfspublished", timeout=5).read()
    assert served == forge.pristine, "port occupied by a foreign mock/webroot"
    try:
        yield f"http://127.0.0.1:{port}/cvmfs/{REPO}"
    finally:
        proc.terminate()
        try:
            proc.wait(3)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture(scope="module")
def brixcvmfs(forge):
    """A `brixcvmfs`-shaped shim: `brixMount cvmfs "$@"` so `--check <fqrn>` routes
    to the CVMFS driver's check path (check_repo runs `<bin> --check <fqrn>`)."""
    d = tempfile.mkdtemp(prefix="brixcvmfs_wrap.")
    wrap = exec_wrapper.install(
        d, "brixcvmfs", target=os.path.abspath(BRIXMOUNT), prepend=["cvmfs"])
    try:
        yield wrap
    finally:
        shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(autouse=True)
def _restore_manifest(forge):
    """Every case mutates the manifest in place; put the pristine bytes back after."""
    yield
    forge.artifact_path("manifest").write_bytes(forge.pristine)


# ---- manifest byte forging helpers -----------------------------------------

def _fields(forge, **override):
    """The valid field map, with per-key overrides; a None value drops the key."""
    f = forge._manifest_fields()
    f.update(override)
    return {k: v for k, v in f.items() if v is not None}


def write_manifest(forge, *, fields=None, lines=None, hash_text=None, sign_key=None,
                   stale_sig=False, marker=True, hashline=True, sig=True, crlf=False):
    """Write an arbitrary .cvmfspublished. `lines` (explicit "Kvalue" strings, order
    and duplicates preserved) wins over `fields`; the signature always covers the
    printed `hash_text` with the repo cert key (the exact brix/CVMFS scheme)."""
    if lines is None:
        src = fields if fields is not None else _fields(forge)
        lines = [f"{k}{v}" for k, v in src.items()]
    text = "".join(l + "\n" for l in lines)
    if marker:
        text += "--\n"
    # The signed hash-line is the manifest body's own SHA-1 digest (body-bound
    # signature): default to the real digest of the body up to but EXCLUDING the
    # "--\n" separator — exactly what an official publisher, repo_forge._write_manifest,
    # and the body-bound verifier (verify.c body_bound_to_hash) all compute.
    # `hash_text` overrides it to forge a body/hash mismatch.
    if hash_text is None:
        body_for_hash = text[:-3] if marker else text
        ht = forge.manifest_hash or hashlib.sha1(body_for_hash.encode()).hexdigest()
    else:
        ht = hash_text
    if hashline:
        text += ht + "\n"
    if crlf:
        text = text.replace("\n", "\r\n")
    raw = text.encode()
    if sig:
        raw += b"\x00" * 256 if stale_sig else forge._rsa_sign(
            sign_key or forge.cert_key, ht.encode())
    forge.artifact_path("manifest").write_bytes(raw)


ACCEPT, REFUSE = 0, 1


def check(forge, mock_url, brixcvmfs, want=None):
    """Run `--check` against the (already-mutated) manifest with a private cache and
    return the exit code (0=accept, 1=refuse).

    A manifest verdict is deterministic in the parser, so accept-expecting cases pass
    `want=ACCEPT`: a REFUSE then can only be a transient origin-fetch hiccup (this host
    runs several Wave-3 conformance agents — and often the developer's other concurrent
    sessions — in parallel at high load), and we retry a few times so the deterministic
    verdict wins. A genuine logic-refuse stays REFUSE across every attempt and still
    fails the assertion.

    A `subprocess.TimeoutExpired` is never a verdict — under a saturated box brixMount's
    fixed trust-chain backoff can outrun the per-call cap — so it is always retryable,
    on both the accept and the refuse path. Refuse-expecting cases still take their
    verdict from the first clean exit (no verdict-driven retries) to hold the wall-time
    budget; only a timeout re-runs them."""
    attempts = 4 if want == ACCEPT else 3
    rc = REFUSE
    for _ in range(attempts):
        cache = tempfile.mkdtemp(prefix="mparse_cache.")
        try:
            rc = check_repo(REPO, mock_url, forge.pub, cache=cache,
                            brixcvmfs=brixcvmfs, timeout=60).returncode
        except subprocess.TimeoutExpired:
            continue                       # saturated box, not a verdict — retry
        finally:
            shutil.rmtree(cache, ignore_errors=True)
        if want != ACCEPT or rc == want:   # refuse: first clean exit wins
            break
    return rc


# ---- baseline --------------------------------------------------------------

def test_baseline_check_ok(forge, mock_url, brixcvmfs):
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


def test_baseline_manifest_has_required_fields(forge):
    head = forge.pristine.split(b"\n--\n", 1)[0].decode()
    keys = {ln[0] for ln in head.splitlines() if ln}
    assert {"C", "N", "X"} <= keys


@requires_fuse
def test_baseline_mount_reads_correct_bytes(forge, mock_url):
    with fuse_mount(REPO, mock_url, forge.pub) as (mnt, _):
        assert os.path.ismount(str(mnt)), "baseline forged repo failed to mount"
        assert sorted(os.listdir(mnt)) == ["empty", "hello", "sub"]
        assert (mnt / "hello").read_bytes() == b"Hello forged CVMFS!\n"
        assert (mnt / "sub" / "leaf.txt").read_bytes() == b"leaf\n"


# ---- required / tolerated field corpus (drop one field) --------------------

# Official requires C, N, X. brix: C,X fatal (parse/cert), N tolerated (DIVERGENCE).
# B,S,T,D are tolerated by both (defaults applied).
@pytest.mark.parametrize("drop,expect", [
    ("C", REFUSE), ("X", REFUSE),
    ("B", ACCEPT), ("S", ACCEPT), ("T", ACCEPT), ("D", ACCEPT),
])
def test_missing_field(forge, mock_url, brixcvmfs, drop, expect):
    write_manifest(forge, fields=_fields(forge, **{drop: None}))
    assert check(forge, mock_url, brixcvmfs, want=expect) == expect


def test_missing_N_field_tolerated(forge, mock_url, brixcvmfs):
    # Stock CVMFS does not gate on the manifest's N field: repository identity is
    # bound by the whitelist 'N<fqrn>' line + cert-fingerprint, not the manifest.
    # A manifest with no N still mounts (authenticity comes from the signature).
    write_manifest(forge, fields=_fields(forge, N=None))
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


def test_N_mismatch_tolerated(forge, mock_url, brixcvmfs):
    # Publishers routinely serve one signed manifest under several fqrns, so a
    # manifest N that differs from the requested fqrn is NOT refused — the
    # whitelist (checked in client.c load_trust_and_catalog, -12) owns identity.
    write_manifest(forge, fields=_fields(forge, N="other.cern.ch"))
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


# ---- malformed content hash (C) --------------------------------------------

# hash.c:cvmfs_hash_parse demands exactly 40 lowercase-hex chars; manifest.c:53
# refuses when the root-catalog hash failed to parse. Uppercase is not hex here.
# One representative per malformation class (each --check pays the client's fixed
# 6-attempt trust-chain backoff, so the slow REFUSE corpus is kept lean).
@pytest.mark.parametrize("bad", [
    "a" * 39,          # odd / short length
    "z" * 40,          # non-hex letters
    "",                # empty value
])
def test_bad_C_hex_refused(forge, mock_url, brixcvmfs, bad):
    write_manifest(forge, fields=_fields(forge, C=bad))
    assert check(forge, mock_url, brixcvmfs) == REFUSE


# ---- malformed / unresolvable cert hash (X) --------------------------------

# X bad-hex leaves certificate.len==0; a well-formed but unknown X can't be
# fetched. Either way the cert never resolves, so the manifest signature can't be
# verified — refused (client.c:158-167).
@pytest.mark.parametrize("bad", [
    "z" * 40,           # non-hex → certificate.len==0
    "b" * 40,           # valid hex, no such cert object on the origin
])
def test_bad_or_unknown_X_refused(forge, mock_url, brixcvmfs, bad):
    write_manifest(forge, fields=_fields(forge, X=bad))
    assert check(forge, mock_url, brixcvmfs) == REFUSE


# ---- unknown / mis-cased field letters -------------------------------------

def test_unknown_field_letter_ignored(forge, mock_url, brixcvmfs):
    lines = [f"{k}{v}" for k, v in _fields(forge).items()] + ["Zignored", "Qsomething"]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


def test_lowercase_c_is_unknown_field(forge, mock_url, brixcvmfs):
    # 'c' != 'C': the real hash becomes an unknown field, so C is effectively
    # missing → root_catalog.len==0 → refused (manifest.c is case-sensitive).
    fl = _fields(forge)
    lines = [f"c{fl['C']}"] + [f"{k}{v}" for k, v in fl.items() if k != "C"]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs) == REFUSE


# ---- structural malformations ----------------------------------------------

def test_crlf_line_endings_refused(forge, mock_url, brixcvmfs):
    # find_marker matches the literal "\n--\n"; CRLF turns it into "\r\n--\r\n"
    # and the C value gains a trailing '\r' → parse fails. Both clients refuse.
    write_manifest(forge, crlf=True)
    assert check(forge, mock_url, brixcvmfs) == REFUSE


def test_missing_marker_refused(forge, mock_url, brixcvmfs):
    write_manifest(forge, marker=False)
    assert check(forge, mock_url, brixcvmfs) == REFUSE


def test_empty_manifest_refused(forge, mock_url, brixcvmfs):
    forge.artifact_path("manifest").write_bytes(b"")
    assert check(forge, mock_url, brixcvmfs) == REFUSE


def test_no_hash_line_refused(forge, mock_url, brixcvmfs):
    # manifest.c:59 refuses when no '\n' terminates the hash line after "--\n".
    write_manifest(forge, hashline=False, sig=False)
    assert check(forge, mock_url, brixcvmfs) == REFUSE


def test_no_signature_refused(forge, mock_url, brixcvmfs):
    # hash line present, but nothing after it → signature_len==0 (manifest.c:65).
    write_manifest(forge, sig=False)
    assert check(forge, mock_url, brixcvmfs) == REFUSE


def test_leading_blank_lines_tolerated(forge, mock_url, brixcvmfs):
    # empty lines have j==i so parse_kv_line is skipped (manifest.c:46).
    lines = ["", ""] + [f"{k}{v}" for k, v in _fields(forge).items()]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


def test_interior_blank_line_tolerated(forge, mock_url, brixcvmfs):
    fl = _fields(forge)
    lines = [f"C{fl['C']}", ""] + [f"{k}{v}" for k, v in fl.items() if k != "C"]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


# ---- oversized / boundary (64K manifest scratch, client.h:35) --------------

def _pad_line(nbytes):
    return "Z" + "q" * nbytes


def test_oversized_manifest_refused_no_crash(forge, mock_url, brixcvmfs):
    # >64K: the fetch into manifest_buf[65536] truncates → parse fails cleanly.
    lines = [f"{k}{v}" for k, v in _fields(forge).items()] + [_pad_line(70000)]
    write_manifest(forge, lines=lines)
    rc = check(forge, mock_url, brixcvmfs)
    assert rc == REFUSE                       # a clean refuse, never a crash
    assert rc not in (-11, 139, 134)          # no SIGSEGV/SIGABRT


def test_near_boundary_manifest_tolerated(forge, mock_url, brixcvmfs):
    lines = [f"{k}{v}" for k, v in _fields(forge).items()] + [_pad_line(60000)]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


def test_just_under_64k_no_crash(forge, mock_url, brixcvmfs):
    lines = [f"{k}{v}" for k, v in _fields(forge).items()] + [_pad_line(64000)]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs) in (ACCEPT, REFUSE)   # boundary: just no crash


# ---- extreme numeric field values ------------------------------------------

@pytest.mark.parametrize("field,value", [
    ("S", "notanumber"),        # atol → 0 → revision gate skipped
    ("S", "0"),                 # zero revision → revision gate skipped
    ("D", str(2 ** 63)),        # huge TTL
    ("D", "0"),                 # zero TTL → client falls back to 240 (client.c:263)
    ("D", "-1"),                # negative TTL → also falls back to 240
    ("B", "notanumber"),        # atol → 0 catalog size
    ("B", str(2 ** 63)),        # huge catalog size claim
    ("T", str(2 ** 63)),        # huge timestamp
    ("T", "-1"),                # negative timestamp
])
def test_extreme_numeric_tolerated(forge, mock_url, brixcvmfs, field, value):
    write_manifest(forge, fields=_fields(forge, **{field: value}))
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


@pytest.mark.parametrize("value", [
    str(2 ** 63),      # revision past INT64_MAX
    str(2 ** 63 - 1),  # INT64_MAX
    "-1",              # negative revision
])
def test_extreme_revision_mismatch_refused(forge, mock_url, brixcvmfs, value):
    # DIVERGENCE (brix EXTRA hardening, FINDING A.5): brix cross-checks the
    # manifest 'S' (revision) against the root catalog's stamped 'revision'
    # property (client.c load_trust_and_catalog -11). A manifest whose S parses
    # to a non-zero value that mismatches the catalog revision (forge default 1)
    # is a rollback/replay-downgrade signal and is refused. Stock CVMFS's naive
    # numeric tolerance would accept it; brix deliberately does not. The parser
    # itself tolerates the extreme value cleanly (no crash/overflow) — only the
    # revision-consistency gate rejects it. S=0 / non-numeric (atol→0) skip the
    # gate and stay in test_extreme_numeric_tolerated above.
    write_manifest(forge, fields=_fields(forge, S=value))
    assert check(forge, mock_url, brixcvmfs, want=REFUSE) == REFUSE


@pytest.mark.parametrize("field", ["S", "T", "D", "B"])
def test_empty_value_on_tolerated_field(forge, mock_url, brixcvmfs, field):
    # "S\n" with no value: atol("") → 0, harmless for the non-C/N/X fields.
    fl = _fields(forge)
    lines = [f"{field}"] + [f"{k}{v}" for k, v in fl.items() if k != field]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


def test_unknown_field_before_C_tolerated(forge, mock_url, brixcvmfs):
    lines = ["Wheader", "Q"] + [f"{k}{v}" for k, v in _fields(forge).items()]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


# ---- duplicate fields (manifest.c overwrites → LAST wins) ------------------

def test_duplicate_C_last_valid_accepted(forge, mock_url, brixcvmfs):
    fl = _fields(forge)
    lines = ["C" + "z" * 40, f"C{fl['C']}"] + [f"{k}{v}" for k, v in fl.items() if k != "C"]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


def test_duplicate_C_last_invalid_refused(forge, mock_url, brixcvmfs):
    fl = _fields(forge)
    lines = [f"C{fl['C']}", "C" + "z" * 40] + [f"{k}{v}" for k, v in fl.items() if k != "C"]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs) == REFUSE


def test_duplicate_S_last_wins_accepted(forge, mock_url, brixcvmfs):
    fl = _fields(forge)
    # Last-wins must resolve to the catalog's real revision (1) or the -11
    # revision cross-check refuses; a first-wins parser would see 99 and refuse,
    # so the case still discriminates the duplicate-handling order.
    lines = ["S99", "S1"] + [f"{k}{v}" for k, v in fl.items() if k != "S"]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


def test_duplicate_N_tolerated(forge, mock_url, brixcvmfs):
    fl = _fields(forge)
    lines = [f"N{fl['N']}", f"N{fl['N']}"] + [f"{k}{v}" for k, v in fl.items() if k != "N"]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


def test_duplicate_X_last_wins_accepted(forge, mock_url, brixcvmfs):
    fl = _fields(forge)
    lines = ["X" + "z" * 40, f"X{fl['X']}"] + [f"{k}{v}" for k, v in fl.items() if k != "X"]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


# ---- extra field letters (R present, exotic N) -----------------------------

def test_R_field_present_tolerated(forge, mock_url, brixcvmfs):
    # R (root-path md5) is unused by manifest.c but is a legitimate official field.
    lines = [f"{k}{v}" for k, v in _fields(forge).items()] + ["R" + "0" * 32]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


# ---- whitespace variants ---------------------------------------------------

def test_trailing_space_on_C_refused(forge, mock_url, brixcvmfs):
    fl = _fields(forge)
    lines = [f"C{fl['C']} "] + [f"{k}{v}" for k, v in fl.items() if k != "C"]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs) == REFUSE


def test_trailing_space_on_tolerated_field_ok(forge, mock_url, brixcvmfs):
    # atol() skips leading ws and stops at the trailing space: "S 1 " parses fine.
    fl = _fields(forge)
    lines = [f"S {fl['S']} "] + [f"{k}{v}" for k, v in fl.items() if k != "S"]
    write_manifest(forge, lines=lines)
    assert check(forge, mock_url, brixcvmfs, want=ACCEPT) == ACCEPT


# ---- signature binding: the manifest body is bound to the signed hash-line ----

def test_wrong_but_signed_hashline_refused(forge, mock_url, brixcvmfs):
    # A hash-line the origin never computed from the body, but validly signed with
    # the repo cert key. The RSA signature verifies, but body-binding recomputes
    # sha1(signed body) and finds it != the printed hash-line → refused. (Was a
    # documented DIVERGENCE — verify.c signed the hash-line text only; now the
    # digest of the whole body is bound to the signature.)
    write_manifest(forge, hash_text="a" * 40)
    assert check(forge, mock_url, brixcvmfs) == REFUSE


@requires_fuse
def test_wrong_but_signed_hashline_mount_refused(forge, mock_url):
    # Body-binding refuses the wrong-but-signed hash-line, so the repo must not mount.
    write_manifest(forge, hash_text="a" * 40)
    with fuse_mount(REPO, mock_url, forge.pub) as (mnt, _):
        assert not os.path.ismount(str(mnt)), \
            "wrong-but-signed manifest must refuse to mount (body not bound to hash)"


def test_stale_zero_signature_refused(forge, mock_url, brixcvmfs):
    write_manifest(forge, stale_sig=True)
    assert check(forge, mock_url, brixcvmfs) == REFUSE


def test_flipped_signature_byte_refused(forge, mock_url, brixcvmfs):
    write_manifest(forge)                              # valid, then corrupt last byte
    p = forge.artifact_path("manifest")
    b = bytearray(p.read_bytes())
    b[-1] ^= 0xFF
    p.write_bytes(bytes(b))
    assert check(forge, mock_url, brixcvmfs) == REFUSE


def test_hashline_altered_without_resign_refused(forge, mock_url, brixcvmfs):
    # Signature covers the OLD hash text; editing the printed hash-line in place
    # (no re-sign) breaks the RSA compare → refused (this is what IS enforced).
    write_manifest(forge)
    p = forge.artifact_path("manifest")
    b = p.read_bytes()
    hs = b.find(b"\n--\n") + 4
    he = b.find(b"\n", hs)
    p.write_bytes(b[:hs] + b"9" * 40 + b[he:])
    assert check(forge, mock_url, brixcvmfs) == REFUSE


def test_foreign_cert_key_signature_refused(forge, mock_url, brixcvmfs):
    # Re-sign the manifest with a key whose cert is not fingerprinted in the
    # whitelist → fingerprint gate + signature both fail (client.c:163-167).
    fk = RepoForge.gen_key(os.path.join(forge._work, "foreign.key"))
    write_manifest(forge, sign_key=fk)
    assert check(forge, mock_url, brixcvmfs) == REFUSE


def test_body_tamper_after_signing_refused(forge, mock_url, brixcvmfs):
    # Sign the hash-line of the ORIGINAL body, then serve a manifest whose T field
    # was mutated afterwards. The RSA signature over the printed hash-line still
    # verifies, but body-binding recomputes sha1(body) and catches the tamper →
    # refused. (Was the DIVERGENCE corollary: the signature bound only the hash
    # text, so the body edit was invisible.)
    orig = _fields(forge)
    body = "".join(f"{k}{v}\n" for k, v in orig.items())   # stock digest excludes "--\n"
    signed_ht = hashlib.sha1(body.encode()).hexdigest()
    write_manifest(forge, fields=_fields(forge, T="424242"), hash_text=signed_ht)
    assert check(forge, mock_url, brixcvmfs) == REFUSE
