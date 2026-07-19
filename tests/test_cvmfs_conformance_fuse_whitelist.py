# tests/test_cvmfs_conformance_fuse_whitelist.py — Phase-84 Wave-3 fuse corpus.
#
# Conformance corpus for the CVMFS `.cvmfswhitelist` trust gate as parsed by
# shared/cvmfs/signature/{whitelist,verify}.c and enforced by the client trust
# chain in shared/cvmfs/client/client.c (load_trust_and_catalog). We forge a
# valid signed repo once (module-scoped keys — openssl keygen is slow), then
# stamp one cheaply-rewritten whitelist per case into its own fqrn subtree under
# a single --webroot mock origin, and drive `brixcvmfs --check` (no FUSE mount)
# against each. A handful of real brixMount mounts confirm the gate end-to-end.
#
# Official whitelist format (the reference we assert against):
#   line 0   : expiry timestamp, 14 digits YYYYMMDDhhmmss (UTC)
#   line 1   : "N<fqrn>"  — repository the whitelist is bound to
#   lines 2+ : one or more signing-cert SHA1 fingerprints, colon-separated hex
#   "--"     : end-of-body marker
#   next line: the signed hash-line text
#   tail     : raw RSA-PKCS#1-v1.5 signature by the repo MASTER key over that text
#
# Because every `--check` that ends in refusal pays the client's 6-attempt
# trust-chain retry (~12.6s of exponential backoff — client.c cvmfs_client_mount),
# all cases are dispatched CONCURRENTLY in a module fixture and each test merely
# asserts the pre-computed outcome. Accept cases return in ~0.1s.
#
# DIVERGENCES pinned below (xfail strict, official behavior asserted):
#   * the whitelist "N<fqrn>" line is parsed-and-ignored: client.c never compares
#     it to the repository, so a foreign / missing / wrong-case N is accepted.
#   * the fingerprint set is capped at 16 (whitelist.c fingerprints[16]); a 17th
#     matching fingerprint is silently dropped → refused (must NOT overflow/crash).
# RETIRED divergences (fixed in source, now asserted positively):
#   * expiry enforced against wall-clock UTC (client.c passes time(NULL), was
#     CLOCK_MONOTONIC — expired whitelists were accepted forever).
#   * hash-line bound to the body digest (verify.c body_bound_to_hash) — the
#     signature now covers the WHOLE artifact, so the forge must emit a REAL
#     sha1(body) hash-line by default (_compose), matching official publishers.

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import BRIXMOUNT, PortBlock, fuse_mount  # noqa: E402
from repo_forge import File, RepoForge  # noqa: E402

# The module fixture forges the corpus and runs ~20 refusing --checks in
# parallel (each ~12.6s of client-side trust-chain backoff); its setup and the
# never-mounts negative cases exceed the 30s default per-test timeout.
pytestmark = pytest.mark.timeout(180)

BLOCK = PortBlock("fuse_whitelist")
MOCK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs", "mock_stratum1.py")
BASE_REPO = "base.cern.ch"

_FUSE3 = shutil.which("pkg-config") and subprocess.run(
    ["pkg-config", "--exists", "fuse3"], stdout=subprocess.DEVNULL).returncode == 0
requires_fuse = pytest.mark.skipif(
    not (_FUSE3 and os.path.exists("/dev/fuse") and shutil.which("fusermount3")
         and os.path.exists(BRIXMOUNT)),
    reason="fuse mount prerequisites missing")


# ---- whitelist composition (local helpers; repo_forge is a shared file) -----

def _sign_pkcs1(key: str, msg: bytes) -> bytes:
    """Raw RSA-PKCS#1-v1.5 over `msg`, no DigestInfo — the CVMFS whitelist scheme."""
    return subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey", key,
                           "-pkeyopt", "rsa_padding_mode:pkcs1"],
                          input=msg, check=True, stdout=subprocess.PIPE).stdout


def _compose(dest_dir: Path, body_lines: list, *, hash_text: str | None = None,
             sign_key: str, marker: bool = True, hash_line: bool = True,
             signature: bool = True, flip_sig: bool = False) -> None:
    """Write a `.cvmfswhitelist` with full control over every structural element.

    By default the signed hash-line is the REAL sha1 of the body (what official
    publishers emit, and what the body-bound verifier demands); pass `hash_text`
    to forge a mismatched/freeform hash-line instead."""
    body = "".join(l + "\n" for l in body_lines)
    if hash_text is None:
        # Stock CVMFS hashes the body up to but EXCLUDING the "--\n" separator.
        hash_text = hashlib.sha1(body.encode()).hexdigest()
    if marker:
        body += "--\n"
    raw = bytearray(body.encode())
    signed = hash_text.encode()
    if hash_line:
        raw += signed + b"\n"
    if signature:
        sig = bytearray(_sign_pkcs1(sign_key, signed))
        if flip_sig:
            sig[10] ^= 0xFF
        raw += sig
    (dest_dir / ".cvmfswhitelist").write_bytes(bytes(raw))


def _decoy(i: int) -> str:
    """A syntactically valid but non-matching 20-byte colon-hex fingerprint."""
    return ":".join(f"{(i * 7 + j * 13 + 3) % 256:02X}" for j in range(20))


def _ts(delta_s: int) -> str:
    """Epoch+delta as a 14-digit UTC whitelist timestamp."""
    return time.strftime("%Y%m%d%H%M%S", time.gmtime(time.time() + delta_s))


# ---- case model -------------------------------------------------------------

class Ctx:
    """Signing material + the correct fingerprint, handed to each case builder."""

    def __init__(self, fp: str, master: str, foreign: str):
        self.fp = fp
        self.master = master
        self.foreign = foreign


# Each case: name, official_expected outcome, divergence reason (=> xfail strict),
# a `make` callable (ctx, fqrn) -> compose kwargs / {"delete": True}, and which
# client pubkey to pin ("base" | "foreign" | "multi").
def _c(name, expected, make, *, divergence=None, client="base"):
    return {"name": name, "expected": expected, "make": make,
            "divergence": divergence, "client": client}


def _wl(body, **kw):
    return lambda ctx, fqrn, _b=body, _k=kw: {
        "body_lines": _b(ctx, fqrn), **{k: (v(ctx) if callable(v) else v)
                                        for k, v in _k.items()}}


FUTURE = "20991231235959"

CASES = [
    # -- baseline ------------------------------------------------------------
    _c("valid_baseline", "accept",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp])),

    # -- expiry: future (accept) — margins sized so pool queueing (~12.6s per
    # refusing check, 24 workers) can never race a future expiry into the past
    _c("expiry_far_future", "accept", _wl(lambda c, f: [FUTURE, "N" + f, c.fp])),
    _c("expiry_now_plus_10min", "accept", _wl(lambda c, f: [_ts(600), "N" + f, c.fp])),
    _c("expiry_now_plus_1hour", "accept", _wl(lambda c, f: [_ts(3600), "N" + f, c.fp])),
    _c("expiry_year_2100", "accept", _wl(lambda c, f: ["21000101000000", "N" + f, c.fp])),

    # -- expiry: past — refused (wall-clock enforcement, retired divergence) --
    _c("expiry_year_2000", "refuse", _wl(lambda c, f: ["20000101000000", "N" + f, c.fp])),
    _c("expiry_yesterday", "refuse", _wl(lambda c, f: [_ts(-86400), "N" + f, c.fp])),
    _c("expiry_now_minus_1min", "refuse", _wl(lambda c, f: [_ts(-60), "N" + f, c.fp])),
    _c("expiry_now_minus_1hour", "refuse", _wl(lambda c, f: [_ts(-3600), "N" + f, c.fp])),

    # -- expiry: 14-digit but out-of-range fields — timegm normalizes, accepted
    _c("expiry_month_13", "accept", _wl(lambda c, f: ["20991301000000", "N" + f, c.fp])),
    _c("expiry_day_32", "accept", _wl(lambda c, f: ["20990132000000", "N" + f, c.fp])),
    _c("expiry_hour_25", "accept", _wl(lambda c, f: ["20991231250000", "N" + f, c.fp])),
    _c("expiry_minute_61", "accept", _wl(lambda c, f: ["20991231236100", "N" + f, c.fp])),
    _c("expiry_second_61", "accept", _wl(lambda c, f: ["20991231235961", "N" + f, c.fp])),
    # 15 digits: parse reads the leading 14, the trailing digit is ignored -> accept
    _c("expiry_fifteen_digits", "accept",
       _wl(lambda c, f: [FUTURE + "9", "N" + f, c.fp])),

    # -- expiry: malformed — parse fails, refused (both) ---------------------
    _c("expiry_short_4_digits", "refuse", _wl(lambda c, f: ["2099", "N" + f, c.fp])),
    _c("expiry_thirteen_digits", "refuse",
       _wl(lambda c, f: ["2099123123595", "N" + f, c.fp])),
    _c("expiry_non_numeric", "refuse", _wl(lambda c, f: ["20AB1231235959", "N" + f, c.fp])),
    _c("expiry_embedded_space", "refuse", _wl(lambda c, f: ["2099 231235959", "N" + f, c.fp])),
    _c("expiry_empty_line", "refuse", _wl(lambda c, f: ["", "N" + f, c.fp])),
    # Unix epoch 0 -> timegm()==0, which parse treats as "bad" -> refused.
    _c("expiry_epoch_zero", "refuse", _wl(lambda c, f: ["19700101000000", "N" + f, c.fp])),
    # No timestamp line at all: line 0 is the N-line -> no expiry -> refused.
    _c("expiry_missing_line", "refuse", _wl(lambda c, f: ["N" + f, c.fp])),

    # -- N-line — binds the whitelist to the repository (client.c -12) -------
    _c("nline_mismatch_fqrn", "refuse", _wl(lambda c, f: [FUTURE, "Nother.cern.ch", c.fp])),
    _c("nline_missing", "refuse", _wl(lambda c, f: [FUTURE, c.fp])),
    _c("nline_uppercase", "refuse",
       _wl(lambda c, f: [FUTURE, "N" + f.upper(), c.fp])),
    _c("nline_subdomain_confusion", "refuse",
       _wl(lambda c, f: [FUTURE, "Nevil." + f, c.fp])),

    # -- fingerprints: accept variants --------------------------------------
    _c("fp_lowercase", "accept", _wl(lambda c, f: [FUTURE, "N" + f, c.fp.lower()])),
    _c("fp_mixed_case", "accept",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp[:6] + c.fp[6:].lower()])),
    _c("fp_count_2", "accept", _wl(lambda c, f: [FUTURE, "N" + f, _decoy(1), c.fp])),
    _c("fp_count_3", "accept",
       _wl(lambda c, f: [FUTURE, "N" + f, _decoy(1), c.fp, _decoy(2)])),
    _c("fp_count_8", "accept",
       _wl(lambda c, f: [FUTURE, "N" + f, *[_decoy(i) for i in range(7)], c.fp])),
    _c("fp_count_15", "accept",
       _wl(lambda c, f: [FUTURE, "N" + f, *[_decoy(i) for i in range(14)], c.fp])),
    _c("fp_16_correct_first", "accept",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp, *[_decoy(i) for i in range(15)]])),
    _c("fp_16_correct_last", "accept",
       _wl(lambda c, f: [FUTURE, "N" + f, *[_decoy(i) for i in range(15)], c.fp])),
    _c("fp_17_correct_first", "accept",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp, *[_decoy(i) for i in range(16)]])),
    _c("fp_garbage_lines_interspersed", "accept",
       _wl(lambda c, f: [FUTURE, "N" + f, "not-a-fingerprint zzz", "# a comment",
                         "", c.fp, "trailing garbage!"])),

    # -- fingerprints: refuse variants --------------------------------------
    _c("fp_zero", "refuse", _wl(lambda c, f: [FUTURE, "N" + f])),
    _c("fp_wrong_cert", "refuse", _wl(lambda c, f: [FUTURE, "N" + f, _decoy(42)])),
    _c("fp_no_colons", "refuse",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp.replace(":", "")])),
    _c("fp_truncated", "refuse", _wl(lambda c, f: [FUTURE, "N" + f, c.fp[:-3]])),
    _c("fp_below_min_length", "refuse", _wl(lambda c, f: [FUTURE, "N" + f, "AB:CD"])),

    # 17th matching fingerprint is dropped by the 16-cap: official accepts,
    # brix refuses. MUST NOT overflow (see test_fp_17_dropped_does_not_crash).
    _c("fp_17_correct_17th", "accept",
       _wl(lambda c, f: [FUTURE, "N" + f, *[_decoy(i) for i in range(16)], c.fp]),
       divergence="16-fingerprint cap (whitelist.c fingerprints[16]) drops 17th match"),

    # -- signature: refuse variants -----------------------------------------
    _c("sig_foreign_master", "refuse",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp], sign_key=lambda c: c.foreign)),
    _c("sig_tampered_byte", "refuse",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp], flip_sig=True)),
    _c("sig_missing_marker", "refuse",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp], marker=False)),
    _c("sig_missing_signature", "refuse",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp], signature=False)),
    _c("sig_nothing_after_marker", "refuse",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp], hash_line=False, signature=False)),
    _c("sig_empty_hash_text", "refuse",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp], hash_text="")),

    # -- signature binding: hash-line must be the body digest (retired div) --
    # `hash_text` here signs a literal that is NOT sha1(body): the signature
    # verifies but body_bound_to_hash refuses — the keyless-forgery gate.
    # signed hash = digest of the ORIGINAL body; a line is then injected. The
    # master signature stays valid over the hash-line — only body-binding
    # catches the alteration.
    _c("sig_body_altered_after_signing", "refuse",
       lambda c, f: {"body_lines": [FUTURE, "N" + f, c.fp,
                                    "INJECTED_UNSIGNED_BODY_LINE"],
                     "hash_text": hashlib.sha1(
                         "".join(l + "\n" for l in [FUTURE, "N" + f, c.fp])
                         .encode()).hexdigest()}),
    _c("sig_freeform_hash_text", "refuse",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp], hash_text="a" * 40)),

    # -- client-supplied master pubkey --------------------------------------
    _c("client_wrong_pubkey", "refuse",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp]), client="foreign"),
    _c("client_multi_pubkey_has_correct", "accept",
       _wl(lambda c, f: [FUTURE, "N" + f, c.fp]), client="multi"),

    # -- whitelist absent at origin -----------------------------------------
    _c("whitelist_404_missing", "refuse", lambda c, f: {"delete": True}),
]


# ---- module fixture: forge once, stamp per case, check all in parallel ------

def _compile_brixcvmfs(dst: Path) -> None:
    cflags = subprocess.run(["pkg-config", "--cflags", "fuse3"], check=True,
                            stdout=subprocess.PIPE, text=True).stdout.split()
    libs = subprocess.run(["pkg-config", "--libs", "fuse3"], check=True,
                          stdout=subprocess.PIPE, text=True).stdout.split()
    root = Path(__file__).resolve().parents[1]
    deps = ["client/apps/fs/brixcvmfs.c", "shared/cvmfs/client/client.c",
            "shared/cvmfs/fetch/fetch.c", "shared/cvmfs/object/object.c",
            "shared/cvmfs/failover/failover.c", "shared/cvmfs/catalog/catalog.c",
            "shared/cvmfs/grammar/hash.c", "shared/cvmfs/grammar/classify.c",
            "shared/cvmfs/signature/manifest.c", "shared/cvmfs/signature/whitelist.c",
            "shared/cvmfs/signature/verify.c", "shared/cvmfs/config/repo.c",
            "shared/cvmfs/config/cvmfs_conf.c", "shared/cache/cas_store.c",
            "shared/cvmfs/walk/walk.c",   # brixcvmfs prewarm -> cvmfs_walk_*
            "shared/net/proxy_env.c"]
    # brixcvmfs.c now pulls in the client net stack (net/cpool.h -> brix.h -> src
    # wire structs, brix_cpool_* in libbrix.a), so the standalone compile needs
    # the client/lib + src includes, the XRDPROTO_NO_NGX shim, and the prebuilt
    # client archives — else it dies "net/cpool.h: No such file or directory".
    archives = ["client/libbrix.a", "shared/xrdproto/libxrdproto.a"]
    for a in archives:
        if not (root / a).is_file():
            pytest.skip(f"prebuilt {a} not present (build the client first)")
    subprocess.run(["gcc", "-Wall", "-I", "shared", "-I", "client/lib", "-I", "src",
                    "-DXRDPROTO_NO_NGX", *cflags, *deps, *archives, *libs,
                    "-lcurl", "-lsqlite3", "-lcrypto", "-lz", "-lssl", "-pthread",
                    "-o", str(dst)],
                   cwd=str(root), check=True)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    """Build one signed repo, stamp every case's whitelist, run all --checks."""
    if not (_FUSE3 and shutil.which("openssl")):
        pytest.skip("fuse3 / openssl toolchain unavailable")

    work = tmp_path_factory.mktemp("fuse_whitelist")
    binary = work / "brixcvmfs"
    _compile_brixcvmfs(binary)

    webroot = work / "web"
    base_pub = work / "master.pub"
    forge = RepoForge(BASE_REPO, webroot).build(
        {"hello": File(b"whitelist corpus\n")}, base_pub)
    base_repo_dir = webroot / "cvmfs" / BASE_REPO

    foreign_key = RepoForge.gen_key(work / "foreign.key")
    foreign_pub = work / "foreign.pub"
    foreign_pub.write_bytes(subprocess.run(
        ["openssl", "pkey", "-in", str(foreign_key), "-pubout"],
        check=True, stdout=subprocess.PIPE).stdout)
    multi_pub = work / "multi.pub"
    multi_pub.write_bytes(foreign_pub.read_bytes() + base_pub.read_bytes())
    pubkeys = {"base": base_pub, "foreign": foreign_pub, "multi": multi_pub}

    ctx = Ctx(forge.fingerprint, str(forge.master_key), str(foreign_key))

    # Materialize one fqrn subtree per case (copy base repo, rewrite whitelist).
    fqrns = {}
    for case in CASES:
        fqrn = case["name"].replace("_", "-") + ".cern.ch"
        fqrns[case["name"]] = fqrn
        repo_dir = webroot / "cvmfs" / fqrn
        shutil.copytree(base_repo_dir, repo_dir)
        spec = case["make"](ctx, fqrn)
        if spec.get("delete"):
            (repo_dir / ".cvmfswhitelist").unlink()
        else:
            spec.setdefault("sign_key", ctx.master)
            _compose(repo_dir, **spec)

    # One threaded webroot mock serves every case subtree.
    port = BLOCK.mock()
    mock = subprocess.Popen([sys.executable, MOCK, "--port", str(port), "--repo",
                             BASE_REPO, "--webroot", str(webroot)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _wait_listen(port)

        def _check(case):
            fqrn = fqrns[case["name"]]
            cdir = work / "cache" / case["name"]
            tdir = work / "tmp" / case["name"]
            cdir.mkdir(parents=True, exist_ok=True)
            tdir.mkdir(parents=True, exist_ok=True)
            cenv = {**os.environ,
                    "BRIXCVMFS_SERVER": f"http://127.0.0.1:{port}/cvmfs/{fqrn}",
                    "BRIXCVMFS_PUBKEY": str(pubkeys[case["client"]]),
                    "BRIXCVMFS_CACHE": str(cdir), "BRIXCVMFS_TMP": str(tdir)}
            return case["name"], subprocess.run(
                [str(binary), "--check", fqrn], env=cenv, capture_output=True,
                text=True, timeout=90)

        with ThreadPoolExecutor(max_workers=24) as ex:
            results = dict(ex.map(_check, CASES))

        yield {"results": results, "port": port, "webroot": webroot,
               "base_pub": base_pub, "foreign_pub": foreign_pub, "fqrns": fqrns}
    finally:
        mock.terminate()
        try:
            mock.wait(5)
        except subprocess.TimeoutExpired:
            mock.kill()
        forge.close()


def _wait_listen(port: int, timeout: float = 10) -> None:
    import socket
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"mock did not listen on {port}")


def _assert(res: subprocess.CompletedProcess, expected: str) -> None:
    if expected == "accept":
        assert res.returncode == 0 and "HEALTHY" in res.stdout, \
            f"expected accept, got rc={res.returncode}: {res.stderr[-200:]}"
    else:
        assert res.returncode != 0, \
            f"expected refuse, got rc=0 (whitelist accepted): {res.stdout[-200:]}"


# ---- the corpus -------------------------------------------------------------

@pytest.mark.parametrize("case", [
    pytest.param(c, id=c["name"], marks=(
        [pytest.mark.xfail(strict=True, reason=f"DIVERGENCE: {c['divergence']}")]
        if c["divergence"] else []))
    for c in CASES])
def test_whitelist_case(env, case):
    """Assert OFFICIAL accept/refuse for each forged whitelist; divergences xfail."""
    _assert(env["results"][case["name"]], case["expected"])


# ---- targeted non-crash / structural assertions -----------------------------

def test_fp_17_dropped_does_not_crash(env):
    # The 16-cap must drop the 17th fingerprint safely — never write past
    # fingerprints[16] or crash. A signal-kill shows as a negative returncode.
    res = env["results"]["fp_17_correct_17th"]
    assert res.returncode is not None and res.returncode >= 0, \
        f"brixcvmfs crashed on a 17-fingerprint whitelist: rc={res.returncode}"
    assert res.returncode == 1, "17th-match whitelist should refuse (fp dropped by cap)"


def test_fp_17_first_match_within_cap(env):
    # A 17-entry list whose match is #1 stays inside the cap → accepted, no crash.
    res = env["results"]["fp_17_correct_first"]
    assert res.returncode == 0 and "HEALTHY" in res.stdout


def test_forge_whitelist_baseline_structure(env):
    # The forged baseline whitelist has the canonical layout the parser expects.
    wl = (env["webroot"] / "cvmfs" / env["fqrns"]["valid_baseline"]
          / ".cvmfswhitelist").read_bytes()
    body, _, tail = wl.partition(b"\n--\n")
    lines = body.split(b"\n")
    assert lines[0] == FUTURE.encode()
    assert lines[1].startswith(b"N")
    assert lines[2].count(b":") == 19          # 20-byte SHA1 fingerprint
    # hash-line is the digest of the body up to but EXCLUDING the "--\n"
    # separator (stock CVMFS convention)
    want = hashlib.sha1(body + b"\n").hexdigest().encode()
    assert tail.split(b"\n", 1)[0] == want
    assert len(tail.split(b"\n", 1)[1]) > 0    # signature present


def test_fingerprint_is_uppercase_colon_hex(env):
    res = env["results"]["valid_baseline"]
    assert res.returncode == 0 and "HEALTHY" in res.stdout


# ---- real end-to-end brixMount confirmations --------------------------------

@requires_fuse
def test_mount_valid_repo_reads_content(env):
    fqrn = env["fqrns"]["valid_baseline"]
    url = f"http://127.0.0.1:{env['port']}/cvmfs/{fqrn}"
    with fuse_mount(fqrn, url, env["base_pub"]) as (mnt, _):
        assert os.path.ismount(str(mnt)), "valid whitelist failed to mount"
        assert (mnt / "hello").read_bytes() == b"whitelist corpus\n"


@requires_fuse
def test_mount_expired_whitelist_refused(env):
    # Wall-clock expiry is enforced (retired divergence): a whitelist dated in
    # the year 2000 must NOT mount, matching official CVMFS.
    fqrn = env["fqrns"]["expiry_year_2000"]
    url = f"http://127.0.0.1:{env['port']}/cvmfs/{fqrn}"
    with fuse_mount(fqrn, url, env["base_pub"], timeout=8) as (mnt, _):
        assert not os.path.ismount(str(mnt)), \
            "an expired whitelist must NOT mount (wall-clock expiry enforcement)"


@requires_fuse
def test_mount_wrong_pubkey_refused(env):
    fqrn = env["fqrns"]["valid_baseline"]
    url = f"http://127.0.0.1:{env['port']}/cvmfs/{fqrn}"
    with fuse_mount(fqrn, url, env["foreign_pub"], timeout=8) as (mnt, _):
        assert not os.path.ismount(str(mnt)), \
            "a whitelist signed by an unknown master key must NOT mount"
