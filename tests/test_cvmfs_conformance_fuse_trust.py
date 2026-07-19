"""Phase-84 CVMFS conformance corpus — row ``fuse_trust``.

Theme
-----
The end-to-end **trust matrix**: forge a signed repo, tamper exactly one artifact
region, and assert the client's SAFETY property — a broken repo is either
*refused* (no mount / nonzero ``--check``) or *read-errors*, but the client NEVER
serves wrong bytes. Every refusal must be a clean, stable diagnostic, and a
refused mount must leave NO orphan behind (empty mountpoint, absent from
``/proc/mounts``); a subsequent valid mount of the same fqrn with a clean cache
must then succeed (no poisoned state).

Driver
------
Two probes, matching how a real operator would triage a repo:
  * ``brixcvmfs --check <fqrn>`` — verifies the whole trust chain + root catalog
    WITHOUT mounting (fast, no /dev/fuse). Exit 0 = healthy, nonzero + a
    ``trust/catalog error -N`` diagnostic on tamper. The full tamper matrix is
    driven here, concurrently (each ``--check`` on a persistent tamper pays the
    client's ~10 s trust-chain retry-with-backoff, so the matrix runs in a thread
    pool — otherwise ~40 serial cases would blow the wall-time budget).
  * a real FUSE mount (standalone ``brixcvmfs <fqrn> <mnt>``) — confirms the
    serve path: clean bytes read back, a content tamper read-errors (EIO) rather
    than serving corruption, and every refused mount leaves no orphan.

Trust-model facts pinned from the sources (``shared/cvmfs/signature/*``,
``shared/cvmfs/client/client.c``, ``shared/cvmfs/fetch/fetch.c``):
  * The manifest / whitelist signature covers ONLY the printed hash-line text
    (raw RSA-PKCS#1 over the literal line after ``\n--\n``); the KV/fingerprint
    *body* is not bound to the signature. So a body tamper that leaves the signed
    hash-line intact and does not break a downstream hash/fetch is ACCEPTED — a
    divergence from official CVMFS (which binds the body via the signed digest).
    Those rows are pinned ``xfail(strict)`` + ``# DIVERGENCE:``.
  * CAS object identity == SHA1 of the STORED bytes; a flipped catalog/cert/chunk
    object fails the fetch-layer hash-verify and is refused (metadata) or
    read-errors (content) — never served.
  * Cert trust = fingerprint(cert DER) ∈ whitelist fingerprint list AND manifest
    signature verifies under that cert.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import pytest

# conftest chdir()s into a scratch dir — anchor imports on this file's dir.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "cvmfs"))

from conformance_common import (BRIXMOUNT, MOCK, _unmount, _wait_mounted,  # noqa: E402
                                check_repo)
from repo_forge import Dir, File, RepoForge  # noqa: E402
from settings import free_port  # noqa: E402

REPO = "trust.cern.ch"
pytestmark = pytest.mark.timeout(180)

# The 20-port block 13420-13439 is reserved for this file (conformance_common
# PORT_BLOCKS['fuse_trust']); the concurrent tamper matrix needs ~40 mock origins
# at once, so it draws ephemeral ports via free_port() — the same pattern the
# Wave-1 smoke suite uses for its webroot mocks.

# ---------------------------------------------------------------------------
# process bookkeeping: every mock/mount is torn down at module exit, always.
# ---------------------------------------------------------------------------
_PROCS: list[subprocess.Popen] = []
_WORKDIRS: list[str] = []
_LOCK = threading.Lock()


def _track(proc: subprocess.Popen) -> subprocess.Popen:
    with _LOCK:
        _PROCS.append(proc)
    return proc


def _workdir(prefix: str) -> str:
    d = tempfile.mkdtemp(prefix=prefix)
    with _LOCK:
        _WORKDIRS.append(d)
    return d


def _serve(web: str) -> str:
    """Spawn a webroot-backed mock Stratum-1 on an ephemeral port; return its
    repo base URL. Thread-safe (used from the matrix worker pool)."""
    port = free_port()
    proc = _track(subprocess.Popen(
        [sys.executable, MOCK, "--port", str(port), "--repo", REPO, "--webroot", web],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/ctl/log", timeout=0.3)
            break
        except Exception:
            if proc.poll() is not None:
                raise RuntimeError("mock exited before it listened")
            time.sleep(0.05)
    return f"http://127.0.0.1:{port}/cvmfs/{REPO}"


def _forge(**kw) -> tuple[RepoForge, str, str]:
    """Build a fresh signed repo (two-entry tree) under a tracked webroot."""
    web = _workdir("ft_web.")
    pub = os.path.join(web, "repo.pub")
    tree = {"hello": File(b"hello trust\n"), "sub": Dir({"leaf": File(b"leaf bytes\n")})}
    forge = RepoForge(REPO, web, **kw).build(tree, pub)
    return forge, web, pub


# ---------------------------------------------------------------------------
# offset resolvers — locate a byte inside a named region of a built artifact.
# ---------------------------------------------------------------------------

def _artifact_bytes(web: str, which: str) -> bytes:
    name = ".cvmfspublished" if which == "manifest" else ".cvmfswhitelist"
    with open(os.path.join(web, "cvmfs", REPO, name), "rb") as f:
        return f.read()


def _sig_off(blob: bytes, frac: str) -> int:
    """A byte inside the trailing 256-byte raw-RSA signature."""
    base = len(blob) - 256
    return {"start": base, "mid": base + 128, "end": len(blob) - 1}[frac]


def _hashline_off(blob: bytes, frac: str) -> int:
    """A byte inside the signed hash-line text (40 chars after ``\\n--\\n``)."""
    hl = blob.index(b"\n--\n") + 4
    return {"start": hl, "mid": hl + 20, "end": hl + 39}[frac]


def _field_off(blob: bytes, key: bytes) -> int:
    """The first value byte of a manifest KV field (``C68..`` → the '6')."""
    if blob[:1] == key:                       # C is the first line
        return 1
    return blob.index(b"\n" + key) + 2


# ---------------------------------------------------------------------------
# tamper case builders — each returns (rc, stderr, stdout) from a --check run.
# Each runs entirely inside a worker thread (build + serve + check), so the whole
# matrix parallelises across the client's serial per-case retry latency.
# ---------------------------------------------------------------------------

def _check(pub: str, url: str) -> tuple[int, str, str]:
    r = check_repo(REPO, url, pub, cache=_workdir("ft_cache."),
                   tmp=_workdir("ft_tmp."), timeout=90)
    return r.returncode, r.stderr.strip(), r.stdout.strip()


def _case_clean() -> tuple[int, str, str]:
    forge, web, pub = _forge()
    return _check(pub, _serve(web))


def _case_flip(which: str, region: str, frac_or_key):
    def run() -> tuple[int, str, str]:
        forge, web, pub = _forge()
        blob = _artifact_bytes(web, which)
        if region == "sig":
            off = _sig_off(blob, frac_or_key)
        elif region == "hashline":
            off = _hashline_off(blob, frac_or_key)
        elif region == "field":
            off = _field_off(blob, frac_or_key)
        elif region == "expiry":
            off = 2
        elif region == "wl_nline":
            off = blob.index(b"\nN") + 2
        elif region == "wl_fp":
            off = blob.index(b"\n", blob.index(b"\nN") + 1) + 3
        else:
            raise AssertionError(region)
        forge.flip_byte(which, off)
        return _check(pub, _serve(web))
    return run


def _case_flip_cas(suffix: str):
    def run() -> tuple[int, str, str]:
        forge, web, pub = _forge()
        if suffix == "":
            key = next(k for k in forge.cas if len(k) == 40)
        elif suffix == "C":
            key = next(k for k in forge.cas if k.endswith("C"))
        else:  # "X" cert
            key = forge.cert_hash + "X"
        forge.flip_byte(key, 8)
        return _check(pub, _serve(web))
    return run


def _foreign_cert() -> tuple[str, str, str]:
    """(key_path, pem_path, fingerprint) for a fresh attacker cert."""
    key = RepoForge.gen_key(_workdir("ft_akey.") + "/k.key")
    pem = _workdir("ft_apem.") + "/c.pem"
    subprocess.run(["openssl", "req", "-x509", "-new", "-key", str(key), "-days", "1",
                    "-subj", "/CN=attacker", "-out", pem],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    der = subprocess.run(["openssl", "x509", "-in", pem, "-outform", "DER"],
                         check=True, stdout=subprocess.PIPE).stdout
    d = hashlib.sha1(der).hexdigest().upper()
    fp = ":".join(d[i:i + 2] for i in range(0, len(d), 2))
    return str(key), pem, fp


def _case_replace_cert_not_in_wl() -> tuple[int, str, str]:
    """Sign the manifest with a valid foreign cert whose fingerprint is NOT in
    the (untouched) whitelist → fingerprint check refuses."""
    forge, web, pub = _forge()
    key, pem, _fp = _foreign_cert()
    forge.cert_hash = forge.store_uncompressed(open(pem, "rb").read(), "X")
    forge.rewrite_manifest(forge._manifest_fields(), sign_key=key)
    return _check(pub, _serve(web))


def _case_substitute_cert() -> tuple[int, str, str]:
    """Full substitute-cert forgery WITHOUT the master key: swap in an attacker
    cert, re-sign the manifest with the attacker key (self-consistent, so it
    passes manifest body-binding on the attacker cert), and append the attacker
    fingerprint to the whitelist body WITHOUT re-signing — the attacker has no
    master key. This is refused iff the whitelist body is bound to the master
    signature (SHA1(body) no longer matches the signed hash-line)."""
    forge, web, pub = _forge()
    key, pem, fp = _foreign_cert()
    forge.cert_hash = forge.store_uncompressed(open(pem, "rb").read(), "X")
    forge.rewrite_manifest(forge._manifest_fields(), sign_key=key)
    forge.append_whitelist_fp_unsigned(fp)
    return _check(pub, _serve(web))


def _case_resign_foreign_master() -> tuple[int, str, str]:
    forge, web, pub = _forge()
    forge.resign_with(master_key=RepoForge.gen_key(_workdir("ft_fm.") + "/m.key"))
    return _check(pub, _serve(web))


def _case_expired_wl() -> tuple[int, str, str]:
    forge, web, pub = _forge()
    forge.rewrite_whitelist(expiry="20000101000000")
    return _check(pub, _serve(web))


def _case_downgrade() -> tuple[int, str, str]:
    """Rewrite the manifest to an OLDER revision (the S field is unsigned) — a
    replay/rollback the client cannot detect (no persistent max-revision)."""
    forge, web, pub = _forge(revision=7)
    fields = forge._manifest_fields()
    fields["S"] = "3"                         # roll the revision backwards
    forge.rewrite_manifest(fields)
    return _check(pub, _serve(web))


def _case_wrong_pubkey() -> tuple[int, str, str]:
    forge, web, pub = _forge()
    k = RepoForge.gen_key(_workdir("ft_wp.") + "/k.key")
    with open(pub, "wb") as f:
        f.write(subprocess.run(["openssl", "pkey", "-in", str(k), "-pubout"],
                               check=True, stdout=subprocess.PIPE).stdout)
    return _check(pub, _serve(web))


def _case_pubkey(kind: str):
    def run() -> tuple[int, str, str]:
        forge, web, pub = _forge()
        if kind == "missing":
            os.remove(pub)
        elif kind == "empty":
            open(pub, "wb").close()
        elif kind == "garbage":
            open(pub, "wb").write(b"-----BEGIN PUBLIC KEY-----\nnot base64\n----\n")
        elif kind == "ec":
            ec = _workdir("ft_ec.") + "/ec.key"
            subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt",
                            "ec_paramgen_curve:P-256", "-out", ec],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            open(pub, "wb").write(subprocess.run(
                ["openssl", "pkey", "-in", ec, "-pubout"],
                check=True, stdout=subprocess.PIPE).stdout)
        return _check(pub, _serve(web))
    return run


def _case_splice(mode: str):
    """Cross-repo splice: serve repo A's tree but with repo B's signed artifacts
    spliced in. 'both' → B's whitelist+manifest (B's master ≠ A's pubkey);
    'manifest' → only B's manifest under A's whitelist (B's cert ∉ A's fps)."""
    def run() -> tuple[int, str, str]:
        fa, weba, puba = _forge()
        fb, webb, _pubb = _forge()
        src = os.path.join(webb, "cvmfs", REPO)
        dst = os.path.join(weba, "cvmfs", REPO)
        shutil.copy(os.path.join(src, ".cvmfspublished"),
                    os.path.join(dst, ".cvmfspublished"))
        if mode == "both":
            shutil.copy(os.path.join(src, ".cvmfswhitelist"),
                        os.path.join(dst, ".cvmfswhitelist"))
        return _check(puba, _serve(weba))
    return run


# case registry: (cid, kind, callable). kind ∈ REFUSED | HEALTHY | DIVERGENCE.
REFUSED, HEALTHY, DIVERGENCE = "refused", "healthy", "divergence"

_CASES: list[tuple[str, str, object]] = [
    ("clean", HEALTHY, _case_clean),
    # manifest signature blob — flipping any byte breaks the RSA verify.
    ("man_sig_start", REFUSED, _case_flip("manifest", "sig", "start")),
    ("man_sig_mid", REFUSED, _case_flip("manifest", "sig", "mid")),
    ("man_sig_end", REFUSED, _case_flip("manifest", "sig", "end")),
    # manifest signed hash-line text — the signature is over exactly this text.
    ("man_hashline_start", REFUSED, _case_flip("manifest", "hashline", "start")),
    ("man_hashline_mid", REFUSED, _case_flip("manifest", "hashline", "mid")),
    ("man_hashline_end", REFUSED, _case_flip("manifest", "hashline", "end")),
    # manifest KV fields (pre-'--', body — NOT signature-covered).
    ("man_field_C", REFUSED, _case_flip("manifest", "field", b"C")),   # root-catalog hash
    ("man_field_X", REFUSED, _case_flip("manifest", "field", b"X")),   # cert hash
    ("man_field_B", REFUSED, _case_flip("manifest", "field", b"B")),  # catalog size
    ("man_field_S", REFUSED, _case_flip("manifest", "field", b"S")),  # revision
    ("man_field_N", REFUSED, _case_flip("manifest", "field", b"N")),  # repo name
    ("man_field_T", REFUSED, _case_flip("manifest", "field", b"T")),  # timestamp
    ("man_field_D", REFUSED, _case_flip("manifest", "field", b"D")),  # ttl
    # whitelist signature blob + signed hash-line (master-signed).
    ("wl_sig_start", REFUSED, _case_flip("whitelist", "sig", "start")),
    ("wl_sig_mid", REFUSED, _case_flip("whitelist", "sig", "mid")),
    ("wl_sig_end", REFUSED, _case_flip("whitelist", "sig", "end")),
    ("wl_hashline_start", REFUSED, _case_flip("whitelist", "hashline", "start")),
    ("wl_hashline_mid", REFUSED, _case_flip("whitelist", "hashline", "mid")),
    ("wl_hashline_end", REFUSED, _case_flip("whitelist", "hashline", "end")),
    # whitelist body regions (pre-'--', NOT signature-covered).
    ("wl_expiry", REFUSED, _case_flip("whitelist", "expiry", None)),   # → parse fail
    ("wl_fp", REFUSED, _case_flip("whitelist", "wl_fp", None)),        # legit fp no longer matches
    ("wl_nline", REFUSED, _case_flip("whitelist", "wl_nline", None)),  # repo name in wl
    # CAS objects — identity is SHA1 of stored bytes.
    ("cert_obj_flip", REFUSED, _case_flip_cas("X")),
    ("catalog_obj_flip", REFUSED, _case_flip_cas("C")),
    # cert substitution.
    ("replace_cert_not_in_wl", REFUSED, _case_replace_cert_not_in_wl),
    ("substitute_cert", REFUSED, _case_substitute_cert),
    # master-key trust.
    ("wrong_pubkey", REFUSED, _case_wrong_pubkey),
    ("resign_foreign_master", REFUSED, _case_resign_foreign_master),
    ("pubkey_empty", REFUSED, _case_pubkey("empty")),
    ("pubkey_garbage", REFUSED, _case_pubkey("garbage")),
    ("pubkey_ec_not_rsa", REFUSED, _case_pubkey("ec")),
    ("pubkey_missing", REFUSED, _case_pubkey("missing")),
    # cross-repo splice.
    ("splice_both", REFUSED, _case_splice("both")),
    ("splice_manifest", REFUSED, _case_splice("manifest")),
    # expiry + replay/rollback.
    ("expired_whitelist", REFUSED, _case_expired_wl),
    ("replay_downgrade", REFUSED, _case_downgrade),
]


# ---------------------------------------------------------------------------
# build the standalone brixcvmfs binary (for --check) once per module.
# ---------------------------------------------------------------------------
_CVMFS_CORE = [
    "shared/cvmfs/client/client.c", "shared/cvmfs/fetch/fetch.c",
    "shared/cvmfs/object/object.c", "shared/cvmfs/failover/failover.c",
    "shared/cvmfs/catalog/catalog.c", "shared/cvmfs/grammar/hash.c",
    "shared/cvmfs/grammar/classify.c", "shared/cvmfs/signature/manifest.c",
    "shared/cvmfs/signature/whitelist.c", "shared/cvmfs/signature/verify.c",
    "shared/cvmfs/config/repo.c", "shared/cvmfs/config/cvmfs_conf.c",
    "shared/cvmfs/walk/walk.c", "shared/cache/cas_store.c", "shared/net/proxy_env.c",
]

# Since phase-86 brixcvmfs.c fetches through the pooled brix_cpool
# (client/lib/net/cpool.c), so it transitively includes client/lib/brix.h and
# the whole client lib. Mirror the client Makefile: include client/lib + src,
# add the rw seam + prefetch walk, and LINK the prebuilt libbrix.a /
# libxrdproto.a rather than re-listing every lib .c. Requires `make -C client`
# to have produced those archives (the fuse suites need brixMount built anyway).
_CLIENT_ARCHIVES = ["client/libbrix.a", "shared/xrdproto/libxrdproto.a"]
_EXTRA_LIBS = [
    "-lcurl", "-lsqlite3", "-lssl", "-lcrypto", "-lz", "-lkrb5", "-lk5crypto",
    "-lcom_err", "-lzstd", "-llzma", "-lbrotlienc", "-lbrotlidec", "-lbz2",
    "-l:liblz4.so.1", "-luring", "-lpthread",
]

_BUILD_ERR = ""   # last compile failure, surfaced in the skip reason


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _build_brixcvmfs() -> str | None:
    """Compile the standalone brixcvmfs --check binary; None if deps missing."""
    global _BUILD_ERR
    root = _repo_root()
    if shutil.which("pkg-config") is None:
        _BUILD_ERR = "pkg-config not found"
        return None
    if subprocess.run(["pkg-config", "--exists", "fuse3"]).returncode != 0:
        _BUILD_ERR = "pkg-config: fuse3 not present"
        return None
    missing = [a for a in _CLIENT_ARCHIVES if not os.path.isfile(os.path.join(root, a))]
    if missing:
        _BUILD_ERR = f"prebuilt archive(s) missing: {missing} — run `make -C client`"
        return None
    out = os.path.join(_workdir("ft_bin."), "brixcvmfs")
    cflags = subprocess.run(["pkg-config", "--cflags", "fuse3"],
                            capture_output=True, text=True).stdout.split()
    libs = subprocess.run(["pkg-config", "--libs", "fuse3"],
                          capture_output=True, text=True).stdout.split()
    argv = ["gcc", "-O1", "-I", "client/lib", "-I", "src", "-I", "shared",
            "-DXRDPROTO_NO_NGX", *cflags,
            "client/apps/fs/brixcvmfs.c", "client/apps/fs/brixcvmfs_rw.c",
            *_CVMFS_CORE, *_CLIENT_ARCHIVES, *libs, *_EXTRA_LIBS, "-o", out]
    r = subprocess.run(argv, cwd=root, capture_output=True, text=True)
    if r.returncode != 0:
        _BUILD_ERR = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "gcc failed"
        return None
    return out


@pytest.fixture(scope="module")
def matrix() -> dict[str, tuple[int, str, str]]:
    """Run every registered --check tamper case concurrently; yield {cid: result}."""
    binary = _build_brixcvmfs()
    if binary is None:
        pytest.skip(f"cannot build brixcvmfs --check binary: {_BUILD_ERR}")
    os.environ["BRIXCVMFS_BIN"] = binary

    results: dict[str, tuple[int, str, str]] = {}
    try:
        with ThreadPoolExecutor(max_workers=12) as ex:
            futs = {ex.submit(fn): cid for cid, _kind, fn in _CASES}
            for fut, cid in [(f, futs[f]) for f in futs]:
                results[cid] = fut.result()
        yield results
    finally:
        with _LOCK:
            for p in _PROCS:
                if p.poll() is None:
                    p.terminate()
            for p in _PROCS:
                try:
                    p.wait(3)
                except subprocess.TimeoutExpired:
                    p.kill()
            for d in _WORKDIRS:
                shutil.rmtree(d, ignore_errors=True)
            _PROCS.clear()
            _WORKDIRS.clear()


# ---------------------------------------------------------------------------
# matrix assertions — one collected test per registered case.
# ---------------------------------------------------------------------------

def _ids(kind):
    return [c[0] for c in _CASES if c[1] == kind]


@pytest.mark.parametrize("cid", _ids(HEALTHY))
def test_clean_repo_check_healthy(matrix, cid):
    rc, stderr, stdout = matrix[cid]
    assert rc == 0, f"{cid}: clean repo must --check clean (stderr={stderr!r})"
    assert "HEALTHY" in stdout
    assert "trust chain .... OK" in stdout


@pytest.mark.parametrize("cid", _ids(REFUSED))
def test_tamper_refused(matrix, cid):
    """SAFETY: a tampered trust artifact must be refused — nonzero exit, and a
    clean diagnostic (never a crash, never HEALTHY)."""
    rc, stderr, stdout = matrix[cid]
    assert rc != 0, f"{cid}: tamper was ACCEPTED (rc=0) — {stdout[:120]!r}"
    assert "HEALTHY" not in stdout
    diag = stderr + stdout
    assert ("trust/catalog error" in diag) or ("cannot read master key" in diag), \
        f"{cid}: no stable diagnostic (stderr={stderr!r})"


# distinct/stable exit-diagnostic pins (the trust chain's error taxonomy).
_STABLE_CODES = {
    "man_sig_mid": -9,          # manifest signature verify
    "man_hashline_mid": -9,     # signed text no longer matches signature
    "man_field_C": -7,          # root-catalog hash unparseable → manifest reject
    "wl_sig_mid": -5,           # whitelist master-signature verify
    "wl_hashline_mid": -5,
    "wl_expiry": -4,            # whitelist parse (bad expiry field)
    "wl_fp": -5,               # whitelist BODY edit caught by body-binding (master sig)
    "wl_nline": -5,            # whitelist N-line edit → body no longer matches signed hash
    "wrong_pubkey": -5,
    "resign_foreign_master": -5,
    "pubkey_empty": -5,
    "pubkey_garbage": -5,
    "pubkey_ec_not_rsa": -5,
    "replace_cert_not_in_wl": -9,
    "substitute_cert": -5,      # attacker fp appended to whitelist body, unsigned
    "man_field_S": -9,          # manifest BODY edit caught by body-binding (cert sig)
    "expired_whitelist": -6,    # wall-clock expiry now enforced
    "replay_downgrade": -11,    # manifest 'S' ≠ root-catalog revision
}


@pytest.mark.parametrize("cid,code", list(_STABLE_CODES.items()))
def test_refusal_diagnostic_is_stable(matrix, cid, code):
    rc, stderr, stdout = matrix[cid]
    assert rc != 0
    assert f"trust/catalog error {code}" in (stderr + stdout), \
        f"{cid}: expected code {code}; got {stderr!r}"


def test_missing_pubkey_distinct_message(matrix):
    rc, stderr, _ = matrix["pubkey_missing"]
    assert rc != 0
    assert "cannot read master key" in stderr


# ---------------------------------------------------------------------------
# CLOSED trust-chain gaps (were DIVERGENCE strict-xfail; brix now matches official
# CVMFS). Each is covered by the generic REFUSED matrix + a stable-code pin above:
#   man_field_B/S/N/T/D  — manifest body bound to signature (verify.c) → -9
#   wl_nline             — whitelist body bound to master signature      → -5
#   substitute_cert      — keyless fp-append to whitelist body refused   → -5
#   expired_whitelist    — wall-clock expiry enforced (client.c)         → -6
#   replay_downgrade     — manifest 'S' cross-checked vs catalog revision → -11
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# real FUSE mount confirmation — the serve path, and the no-orphan guarantee.
# ---------------------------------------------------------------------------
_FUSE_READY = (os.path.exists("/dev/fuse")
               and shutil.which("fusermount3") is not None)
requires_fuse = pytest.mark.skipif(not _FUSE_READY, reason="fuse prerequisites missing")


class _Mount:
    """Mount a forged repo via the standalone ``brixcvmfs <fqrn> <mnt>`` and
    ALWAYS unmount on exit — an orphaned FUSE mount wedges the whole fleet."""

    def __init__(self, binary: str, web: str, pub: str, cache: str | None = None):
        self.binary, self.url, self.pub = binary, _serve(web), pub
        self.cache = cache
        self.wd = _workdir("ft_mnt.")
        self.mnt = os.path.join(self.wd, "mnt")
        os.mkdir(self.mnt)
        self.proc: subprocess.Popen | None = None

    def __enter__(self):
        cache = self.cache or os.path.join(self.wd, "cache")
        os.makedirs(cache, exist_ok=True)
        env = {**os.environ, "BRIXCVMFS_SERVER": self.url, "BRIXCVMFS_PUBKEY": self.pub,
               "BRIXCVMFS_CACHE": cache, "BRIXCVMFS_TMP": os.path.join(self.wd, "tmp")}
        os.makedirs(env["BRIXCVMFS_TMP"], exist_ok=True)
        self.proc = _track(subprocess.Popen(
            [self.binary, REPO, self.mnt, "-o", "auto_unmount", "-f"],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        _wait_mounted(self.mnt, 20)
        return self

    @property
    def mounted(self) -> bool:
        return os.path.ismount(self.mnt)

    def __exit__(self, *_):
        from pathlib import Path
        _unmount(Path(self.mnt))
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        _unmount(Path(self.mnt))


@pytest.fixture(scope="module")
def bin_mount(matrix) -> str:
    """The built binary (matrix fixture guarantees it and BRIXCVMFS_BIN)."""
    return os.environ["BRIXCVMFS_BIN"]


@requires_fuse
def test_mount_clean_serves_exact_bytes(bin_mount):
    forge, web, pub = _forge()
    with _Mount(bin_mount, web, pub) as m:
        assert m.mounted, "clean forged repo must mount"
        assert sorted(os.listdir(m.mnt)) == ["hello", "sub"]
        assert open(os.path.join(m.mnt, "hello"), "rb").read() == b"hello trust\n"
        assert open(os.path.join(m.mnt, "sub", "leaf"), "rb").read() == b"leaf bytes\n"


@requires_fuse
def test_mount_content_tamper_read_errors_not_wrong_bytes(bin_mount):
    """A flipped content object: the trust chain is intact so the mount comes up,
    but the fetch-layer hash-verify fails on read → EIO, NEVER corrupt bytes."""
    forge, web, pub = _forge()
    key = next(k for k in forge.cas if len(k) == 40)
    forge.flip_byte(key, 6)
    with _Mount(bin_mount, web, pub) as m:
        assert m.mounted
        with pytest.raises(OSError) as ei:
            data = open(os.path.join(m.mnt, "hello"), "rb").read()
            assert data != b"hello trust\n", "corrupt object served as clean bytes!"
        assert ei.value.errno == 5  # EIO


@requires_fuse
def test_mount_missing_content_object_read_errors(bin_mount):
    forge, web, pub = _forge()
    key = next(k for k in forge.cas if len(k) == 40)
    forge.delete_cas(key)
    with _Mount(bin_mount, web, pub) as m:
        assert m.mounted
        with pytest.raises(OSError):
            open(os.path.join(m.mnt, "hello"), "rb").read()


# each broken-trust class: the mount must be refused and leave NO orphan.
def _broken_wrong_pubkey():
    forge, web, pub = _forge()
    k = RepoForge.gen_key(_workdir("ft_bp.") + "/k.key")
    open(pub, "wb").write(subprocess.run(["openssl", "pkey", "-in", str(k), "-pubout"],
                                         check=True, stdout=subprocess.PIPE).stdout)
    return web, pub


def _broken_manifest_sig():
    forge, web, pub = _forge()
    forge.flip_byte("manifest", -5)
    return web, pub


def _broken_whitelist_sig():
    forge, web, pub = _forge()
    forge.flip_byte("whitelist", -5)
    return web, pub


def _broken_catalog_obj():
    forge, web, pub = _forge()
    forge.flip_byte(next(k for k in forge.cas if k.endswith("C")), 8)
    return web, pub


@requires_fuse
@pytest.mark.parametrize("broken", [_broken_wrong_pubkey, _broken_manifest_sig,
                                    _broken_whitelist_sig, _broken_catalog_obj],
                         ids=["wrong_pubkey", "manifest_sig", "whitelist_sig", "catalog_obj"])
def test_broken_repo_mount_refused_no_orphan(bin_mount, broken):
    web, pub = broken()
    with _Mount(bin_mount, web, pub) as m:
        if m.proc is not None:
            m.proc.wait(30)
        assert not m.mounted, "broken repo must NOT mount"
        assert m.mnt not in open("/proc/mounts").read(), "orphaned mount left behind!"
        assert os.listdir(m.mnt) == [], "mountpoint not empty after refusal"
        assert m.proc.returncode not in (None, 0), "refused mount must exit nonzero"


@requires_fuse
def test_valid_mount_after_refusal_not_poisoned(bin_mount):
    """After a refused mount, a fresh valid mount of the SAME fqrn with a clean
    cache must succeed — no poisoned client/cache state persists."""
    bad_web, bad_pub = _broken_manifest_sig()
    with _Mount(bin_mount, bad_web, bad_pub) as bad:
        if bad.proc is not None:
            bad.proc.wait(30)
        assert not bad.mounted

    forge, web, pub = _forge()
    with _Mount(bin_mount, web, pub, cache=os.path.join(_workdir("ft_clean."), "c")) as good:
        assert good.mounted, "clean re-mount after a refusal must succeed"
        assert open(os.path.join(good.mnt, "hello"), "rb").read() == b"hello trust\n"
