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
                                check_repo, matrix_port)
from cmdscripts.cvmfs_driver_units import (  # noqa: E402
    BRIXCVMFS_CORE_DEPS,
    BRIXCVMFS_DRIVER_SRCS,
)
from repo_forge import Dir, File, RepoForge  # noqa: E402
from settings import HOST

REPO = "trust.cern.ch"
pytestmark = pytest.mark.timeout(180)

_FUSE_READY = (os.path.exists("/dev/fuse")
               and shutil.which("fusermount3") is not None)
requires_fuse = pytest.mark.skipif(not _FUSE_READY,
                                   reason="fuse prerequisites missing")

# The 20-port block is reserved for this file (conformance_common
# PORT_BLOCKS['fuse_trust']); the concurrent tamper matrix needs ~40 mock origins
# at once, so it draws FIXED ports from the dedicated cvmfs matrix sub-range via
# matrix_port() — all within TEST_PORT_START+2000 (the main fleet band), never an
# OS-ephemeral port that would escape it.

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
    port = matrix_port()
    proc = _track(subprocess.Popen(
        [sys.executable, MOCK, "--port", str(port), "--repo", REPO, "--webroot", web],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"http://{HOST}:{port}/ctl/log", timeout=0.3)
            break
        except Exception:
            if proc.poll() is not None:
                raise RuntimeError("mock exited before it listened")
            time.sleep(0.05)
    return f"http://{HOST}:{port}/cvmfs/{REPO}"


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
        elif region == "wl_nline":
            off = blob.index(b"\nN") + 2
        elif region == "wl_fp":
            off = blob.index(b"\n", blob.index(b"\nN") + 1) + 3
        else:
            raise AssertionError(region)
        forge.flip_byte(which, off)
        return _check(pub, _serve(web))
    return run


def _case_wl_badstamps():
    """No parsable timestamp anywhere: official E line AND the line-0 creation
    stamp both malformed (honestly signed, so parsing — not body-binding — is
    what must refuse)."""
    def run() -> tuple[int, str, str]:
        forge, web, pub = _forge()
        forge.rewrite_whitelist(expiry="XXXXXXXXXXXXXX", created="YYYYYYYYYYYYYY")
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
    ("wl_expiry", REFUSED, _case_wl_badstamps()),                      # → parse fail
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
# Shared-core source list is single-truth in cmdscripts (tracks every
# phase-87 seam brixcvmfs pulls in); the client-lib half comes from the
# prebuilt archives below, so keep only the shared/ .c entries.
_CVMFS_CORE = [d for d in BRIXCVMFS_CORE_DEPS
               if d.startswith("shared/") and d.endswith(".c")]

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
            *BRIXCVMFS_DRIVER_SRCS, "client/apps/fs/brixcvmfs_rw.c",
            *_CVMFS_CORE, *_CLIENT_ARCHIVES, *libs, *_EXTRA_LIBS, "-o", out]
    r = subprocess.run(argv, cwd=root, capture_output=True, text=True)
    if r.returncode != 0:
        _BUILD_ERR = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "gcc failed"
        return None
    return out


# Re-export from split helpers
from split_continuation import reexport as _reexport
_reexport(globals(), "_test_cvmfs_conformance_fuse_trust_helpers_b")
