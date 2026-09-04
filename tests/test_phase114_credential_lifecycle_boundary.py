"""Phase-114 closure: the credential-artifact lifecycle boundary the phase
*keeps*, pinned as assertions.

Phase 114 is CLOSED / DEFERRED BY DESIGN. It does **not** build the cross-store
TTL reaper, the lease table or the secret-index metadata database — those would
change active-lease semantics for four caller-owned stores that do not share a
lifetime contract, with no consumer that needs cross-store policy. So there is
no reaper to test, and the doc's Verification list (success / active-use /
restart / generation-substitution) describes the *conditional* model, not
shipped code.

What the phase actually decided is a boundary, stated in one sentence of the
Goal:

    "Creation remains unified through `brix_cred_write`; expiry remains
     explicitly owned and tested by each store. That is the supported
     lifecycle boundary."

The deferral is only safe while that boundary holds — and every load-bearing
half of it was true by construction and guarded by nothing. This file pins the
supported half so a later change cannot quietly turn the deferral into a
regression:

  * security / regression — creation is unified: the credential-staging surface
                    is exactly the six caller sites plus the one gate, every one
                    routing through the shared engine, and no site open-codes an
                    `mkstemp("/tmp/...")` (the CWE-377 co-tenant race the surface
                    exists to close);
  * security     — a persistent write is domain-gated *before* the engine runs,
                    so an EXPORT-domain claim can never be laundered into a
                    credential write ("reap through the credential service
                    domain, never the export mutation path" — the creation half
                    of that same rule);
  * isolation    — the one audit line names arm/kind/dir/outcome and structurally
                    cannot name the bytes, the subject or the secret-bearing
                    basename (Verification: "logs and metrics contain no
                    credential bytes, subjects or paths");
  * feature      — credential *kind* is audit vocabulary and a future TTL key,
                    never a storage mechanic: no code path in the engine or the
                    gate branches on kind, which is exactly why deferring the
                    per-kind reaper leaves nothing half-built behind.

Run:
    PYTHONPATH=tests pytest tests/test_phase114_credential_lifecycle_boundary.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

pytestmark = [pytest.mark.timeout(120),
              pytest.mark.xdist_group("phase114-closure")]

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"

# The credential-staging surface, named by intent (not discovered) so that a new
# member is a test failure, not a silent expansion of the trusted set.
HEADER = "core/compat/cred_stage.h"
ENGINE = "core/compat/cred_stage.c"           # the pure-libc mechanics
GATE = "core/compat/cred_write.c"             # the domain-gated, audited form
STAGERS = (                                   # the six materialization sites
    "fs/backend/cred_mint.c",
    "protocols/webdav/delegation.c",
    "auth/krb5/deleg_capture.c",
    "net/proxy/gsi_upstream.c",
    "protocols/webdav/tpc_cred_exchange.c",
    "tpc/outbound/tpc_token_exchange.c",
)
# The two verbs every stager must reach the engine through.
WRITE_VERBS = ("brix_cred_write", "brix_cred_stage_write")

# The four credential kinds — one per caller-owned store, in enum order.
KINDS = ("BRIX_CRED_KIND_BEARER", "BRIX_CRED_KIND_PROXY",
         "BRIX_CRED_KIND_CCACHE", "BRIX_CRED_KIND_KEYTAB")

# An open-coded temporary-secret file: the anti-pattern the shared surface
# replaced. `/tmp` staging, the mkstemp family, an anonymous O_TMPFILE, or a
# raw $TMPDIR lookup — any of them, in a stager, reopens the co-tenant race.
_TEMP_ANTIPATTERN = re.compile(
    r'\bmkstemp\b|\bmkostemp\b|\bO_TMPFILE\b|"/tmp|getenv\s*\(\s*"TMPDIR"')


def _text(rel):
    return (SRC / rel).read_text()


def _strip(text):
    """C source with comments removed — a comment naming `/tmp` or a kind is
    documentation, not a live code path."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    return re.sub(r"//[^\n]*", " ", text)


def _includes_header():
    """Every src/ .c that includes the credential-staging header."""
    out = set()
    for path in SRC.rglob("*.c"):
        if f'"{HEADER}"' in path.read_text() or f"/{HEADER}" in path.read_text():
            out.add(path.relative_to(SRC).as_posix())
    return out


def _open_codes_temp(text):
    return bool(_TEMP_ANTIPATTERN.search(_strip(text)))


# --- creation is unified -----------------------------------------------------

def test_the_staging_surface_is_exactly_the_six_stagers_plus_the_one_gate():
    """The boundary sentence, made a census.

    "Creation remains unified through `brix_cred_write`" only holds while the
    set of files that stage a credential is a closed, known set. The header is
    included by exactly the six caller sites and the gate that fronts them —
    nothing else in the tree touches credential staging. A seventh includer is
    a new, unaudited materialization path and must be classified here before it
    is trusted.
    """
    expected = set(STAGERS) | {GATE}
    assert _includes_header() == expected, (
        "the set of files staging credentials changed: unexpected "
        f"{sorted(_includes_header() - expected)}, missing "
        f"{sorted(expected - _includes_header())}. Creation is only 'unified' "
        "while this set is closed")


@pytest.mark.parametrize("rel", STAGERS)
def test_every_stager_reaches_the_engine_through_a_shared_write_verb(rel):
    """Including the header is not routing through it — this pins that each
    stager actually calls one of the two shared write verbs, so no site holds
    the header for its types while open-coding the write itself."""
    body = _strip(_text(rel))
    assert any(f"{verb}(" in body for verb in WRITE_VERBS), (
        f"{rel} includes the staging header but calls neither "
        f"{' nor '.join(WRITE_VERBS)}; it does not route through the shared "
        "engine")


# --- the co-tenant race the surface closes -----------------------------------

def test_no_credential_stager_open_codes_a_temporary_secret_file():
    """Security. The whole point of the shared surface is that the temp file is
    created once, correctly (per-uid 0700 tmpfs, 0600, NOFOLLOW, owner-checked).
    A stager that open-codes `mkstemp("/tmp/...")` reintroduces exactly the
    CWE-377 co-tenant race the surface was built to remove — and would do so
    while the deferred reaper is documented as safe because 'creation is
    hardened'.
    """
    offenders = [rel for rel in STAGERS if _open_codes_temp(_text(rel))]
    assert not offenders, (
        f"credential stagers {offenders} open-code a temporary secret file "
        "instead of delegating to the shared engine; the co-tenant race is back")


def test_the_temp_antipattern_probe_actually_fires():
    """Non-vacuity for the scan above: it flags an open-coded `/tmp` mkstemp and
    passes a clean delegation, so a green run over the real stagers means they
    delegate, not that the probe is blind."""
    assert _open_codes_temp('char t[] = "/tmp/cred.XXXXXX"; int f = mkstemp(t);')
    assert _open_codes_temp('fd = open(dir, O_TMPFILE | O_RDWR, 0600);')
    assert not _open_codes_temp(
        'brix_cred_stage_write("tpc_token_body_", buf, len, out, cap);')


# --- the persistent write is domain-gated ------------------------------------

def test_a_credential_write_claims_the_credential_domain_before_the_engine():
    """Security. brix_cred_write claims the CREDENTIAL storage domain through
    the typed policy seam *before* it runs the engine. Because the claim fails
    closed to EROFS on an EXPORT-domain path (phase-105 kernel), an operator
    cannot point a persistent credential dir at an export and launder a mutation
    through the credential write — the creation-time half of "reap through the
    credential service domain, never the export mutation path".
    """
    body = _strip(_text(GATE))
    claim = body.find("brix_vfs_domain_claim")
    engine = body.find("brix_cred_write_engine(")
    assert claim != -1, f"{GATE} never claims a storage domain"
    assert "BRIX_VFS_DOMAIN_CREDENTIAL" in body, (
        f"{GATE} claims a domain but not the CREDENTIAL domain")
    assert engine != -1 and claim < engine, (
        f"{GATE} runs the engine before (or without) the domain claim; an "
        "EXPORT-domain path could be laundered into a credential write")


# --- the audit line is isolated ----------------------------------------------

def test_the_audit_line_names_arm_kind_dir_outcome_and_nothing_secret():
    """Isolation (Verification: no credential bytes, subjects or paths in logs).

    The single audit emitter names the arm, the kind, the destination directory
    and the outcome. It must never name the bytes, the length, the full path or
    the final basename — a credential's basename can encode a subject identity;
    only the directory is safe. This pins both the format-string vocabulary and
    the fact that the audit helper is not even *handed* the secret-bearing
    arguments, so it cannot leak them by a later edit.
    """
    body = _strip(_text(GATE))
    audit = re.search(r"cred_write_audit\s*\(([^)]*)\)\s*\n?\s*\{", body)
    assert audit, f"{GATE} no longer defines cred_write_audit as expected"
    params = audit.group(1)
    for secret in ("bytes", "len", "path_out", "name"):
        assert secret not in params, (
            f"cred_write_audit is handed `{secret}`; the audit helper must not "
            f"receive secret-bearing arguments it could log:\n{params}")

    fmt = re.search(r'ngx_log_error\([^,]+,[^,]+,[^,]+,\s*"((?:[^"\\]|\\.)*)"',
                    body)
    assert fmt, f"{GATE} audit line is not a plain literal format string"
    tokens = set(re.findall(r"(\w+)=", fmt.group(1)))
    assert tokens == {"arm", "kind", "dir", "outcome"}, (
        f"the audit line's fields changed to {sorted(tokens)}; it must carry "
        "exactly arm/kind/dir/outcome")
    for leak in ("%V", "subject", "token", "path", "bytes", "basename"):
        assert leak not in fmt.group(1), (
            f"the audit format string names `{leak}`; a secret or a "
            f"secret-bearing path escaped into the log line:\n{fmt.group(1)}")


# --- kind is vocabulary, not a mechanic --------------------------------------

def test_the_kind_enum_is_exactly_the_four_caller_owned_stores():
    """Feature. The kind enum is the future TTL-reaper key and the audit
    vocabulary — one value per caller-owned store. It is exactly four (bearer,
    proxy, ccache, keytab); a fifth kind is a fifth store and a new lifetime
    contract, which is precisely the cross-store scope this phase deferred.
    """
    header = _strip((SRC / HEADER).read_text())
    block = re.search(r"typedef enum\s*\{([^}]*)\}\s*brix_cred_kind_t", header)
    assert block, "brix_cred_kind_t enum not found in the staging header"
    found = tuple(re.findall(r"BRIX_CRED_KIND_\w+", block.group(1)))
    assert found == KINDS + ("BRIX_CRED_KIND_COUNT",), (
        f"the credential-kind enum changed to {found}; each kind is a "
        "caller-owned store and a fifth is out-of-scope for the deferred phase")


@pytest.mark.parametrize("rel", (ENGINE, GATE))
def test_no_storage_path_branches_on_credential_kind(rel):
    """Feature / deferral safety. "both arms treat every kind identically on the
    wire to disk" — kind selects no syscall. Neither the engine nor the gate may
    `switch (…kind…)` or open a `case BRIX_CRED_KIND_*`; the only permitted use
    of kind is the bounds check and the audit name-table lookup. This is why
    deferring the per-kind reaper leaves nothing half-built: no storage mechanic
    is already keyed on kind waiting to be finished.
    """
    body = _strip(_text(rel))
    assert "case BRIX_CRED_KIND_" not in body, (
        f"{rel} opens a case on a credential kind; storage now branches on "
        "kind, which the surface promises it never does")
    for m in re.finditer(r"switch\s*\(([^)]*)\)", body):
        assert "kind" not in m.group(1), (
            f"{rel} switches on `{m.group(1).strip()}`; kind must not select a "
            "storage path")
