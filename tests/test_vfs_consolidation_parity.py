"""test_vfs_consolidation_parity.py — phase-108 W0: the parity pins.

W0's real product (phase-108 §7/W0): four tests that PASS against today's
tree, pinning the exact behaviour the later waves will change — including the
defects.  Pinning a defect is deliberate: each wave's diff must show its pins
inverting in the SAME commit, or the wave changed something else.

  - test_oci_publish_parity           — the §2.1/C10 table AFTER W2: the two
                                        hand-rolled publish primitives are gone
                                        and every store write routes through
                                        brix_service_publish_* behind the typed
                                        REGISTRY claim, with all four publish
                                        defects fixed at the verb.  The pre-W2
                                        version of this pin held the four
                                        defects; W2's commit inverted it here,
                                        as §7 requires.
  - test_cred_write_parity            — the §2.1/C11 table AFTER W1: the
                                        four implementations collapsed into
                                        one engine + one gated verb, every
                                        cell equal or stronger (the VOLATILE
                                        arm's no-fsync is §3.3's one recorded
                                        'weaker on purpose').  The pre-W1
                                        version of this pin held the
                                        disagreement table; W1's commit
                                        inverted it here, as §7 requires.
  - test_site_n2n_wired               — W3 landed: the site_n2n translators now
                                        HAVE production callers, and every call
                                        site is confined to the sanctioned
                                        locations (the RADOS driver's key
                                        derivation and the path-layer stage).
                                        The pre-W3 version asserted ZERO callers;
                                        Step B retargeted it from the coarse
                                        `brix_n2n_` substring to the translator
                                        FUNCTION CALLS, so the A.4 ctx/registry/
                                        config plumbing (which references the cfg
                                        type and directive names by design) is
                                        not miscounted as scatter.
  - test_n2n_stage_delegates_and_adds_no_logic,
    test_ctx_binds_n2n_at_the_single_construction_seam,
    test_rados_listing_reverse_goes_through_the_shared_translator
                                      — W3 Step B (Full A.4): the generic stage
                                        delegates to the pure translators without
                                        re-implementing composition, the cfg is
                                        bound to the ctx at its single
                                        construction seam, and the RADOS listing
                                        reverse routes key→LFN through the shared
                                        brix_n2n_pfn2lfn rather than a re-inlined
                                        prefix strip.
  - test_edge_gate_removed_still_refused
                                      — W4 landed: every VFS entry point now
                                        inherits the fused policy/authz gate,
                                        so removing a protocol-edge check no
                                        longer permits storage access.

Source-contract pins in the shape of test_vfs_exchange.py: the behaviour
being pinned is syscall-sequence shape (which fsync, which open flags, which
close is checked), which the C compiles from exactly these tokens, so the
source IS the contract here.

Reference: docs/refactor/phase-108-vfs-consolidation.md §2.1, §7/W0, §8.3.

Run:
  PYTHONPATH=tests pytest tests/test_vfs_consolidation_parity.py -v
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]


def _src(rel: str) -> str:
    return (REPO / rel).read_text(encoding="utf-8")


def _fn(text: str, name: str) -> str:
    """The body of a top-level C function: from its definition line to the
    first closing brace at column 0."""
    m = re.search(rf"^{re.escape(name)}\(.*?^\}}", text, re.S | re.M)
    assert m, f"function {name} not found — re-anchor this pin"
    return m.group(0)


# --------------------------------------------------------------------------
# Pin 1 — the OCI publish primitive's four defects (§2.1/C10; inverted by W2)
# --------------------------------------------------------------------------

def _check_oci_publish_adapters(store: str) -> None:
    assert not re.search(r"^brix_oci_store_put_text\(", store, re.M), (
        "brix_oci_store_put_text survived W2 — the verb replaces it")
    assert not re.search(r"^brix_oci_store_publish\(", store, re.M), (
        "brix_oci_store_publish survived W2 — the verb replaces it")
    assert "brix_service_publish_bytes(&req" in \
        _fn(store, "brix_oci_store_publish_bytes")
    assert "brix_service_publish_fd(&req" in \
        _fn(store, "brix_oci_store_publish_staged")


def _check_oci_store_has_no_publish_mechanics(store: str) -> None:
    for token in ("ngx_pid", '"%s.tmp.%ld"', "open(tmp,", "O_TRUNC"):
        assert token not in store, (
            f"oci_store regrew publish mechanics ({token}) — the verb owns them")


def _check_oci_publish_durability(verb: str, commit: str) -> None:
    assert re.search(r"service_domain_durable\(req->domain\) && fsync\(fd\)",
                     verb), "the pre-publish data fsync (defect 1) is gone"
    assert "brix_staged_commit(" in verb
    assert "brix_staged_commit_excl(" in verb
    commit_internal = _fn(commit, "staged_commit_internal")
    assert "brix_publish_dirsync(" in commit_internal, (
        "the C3 directory barrier (defect 2) is gone from the commit path")
    assert "brix_vfs_backend_durable(" in commit_internal
    assert re.search(r"if \(close\(fd\) != 0 && errno != EINTR\)", verb), (
        "the checked close (defect 3) is gone from the verb")


def _check_oci_publish_temp_safety(verb: str) -> None:
    assert "brix_staged_open(" in verb
    assert "O_TRUNC" not in verb
    assert "open_flags = O_WRONLY" in verb
    assert "O_NOFOLLOW" in verb


def test_oci_publish_parity():
    """INVERTED IN W2.  The registry's two hand-rolled publish primitives
    (brix_oci_store_put_text, brix_oci_store_publish) are gone; every store
    write now routes through brix_service_publish_* behind the typed REGISTRY
    domain claim, and the four §2.1/C10 defects are fixed AT THE VERB.  This is
    the exact mirror of the pre-W2 pin — every assertion that documented a
    defect now asserts its fix, in the same commit that landed the verb (§7/W0).
    The syscall-shape contract moved from oci_store.c to the verb it now calls,
    so the pins read from compat/service_publish.c and compat/staged_file.c."""
    store = _src("src/protocols/oci/oci_store.c")
    verb = _src("src/core/compat/service_publish.c")
    commit = _src("src/core/compat/staged_file.c")

    _check_oci_publish_adapters(store)
    _check_oci_store_has_no_publish_mechanics(store)
    _check_oci_publish_durability(verb, commit)
    _check_oci_publish_temp_safety(verb)


# --------------------------------------------------------------------------
# Pin 2 — the credential-write disagreement table (§2.1/C11; W1 re-runs it)
# --------------------------------------------------------------------------

def _check_cred_call_site(body: str, who: str, arm: str, kind: str) -> None:
    assert "brix_cred_write(&req" in body, f"{who} lost the shared verb"
    assert f"BRIX_CRED_ARM_{arm}" in body, f"{who}'s arm changed"
    assert f"BRIX_CRED_KIND_{kind}" in body, f"{who}'s kind changed"
    for token in ("mkstemp(", "open(", "rename(", "unlink(", "fsync",
                  'getenv("TMPDIR")', "getpid()"):
        assert token not in body, (
            f"{who} regrew hand-rolled mechanics ({token}) — the engine "
            f"owns the write, the site owns only the request")


def _check_cred_call_sites(capture: str, delegation: str,
                           mint_pem: str, mint: str) -> None:
    _check_cred_call_site(capture, "deleg_capture", "VOLATILE", "CCACHE")
    _check_cred_call_site(delegation, "delegation", "PERSISTENT", "PROXY")
    _check_cred_call_site(mint_pem, "cred_mint", "PERSISTENT", "PROXY")
    assert "mint_write_tmp" not in mint
    assert "mint_build_paths" not in mint
    assert "vfs-seam-allow" not in _src("src/protocols/webdav/delegation.c")


def _check_cred_directory(stage: str, stage_dir: str, dir_check: str,
                          persistent: str) -> None:
    assert '#define BRIX_CRED_STAGE_BASE "/dev/shm/brix-creds"' in stage
    assert "BRIX_CRED_STAGE_BASE, (unsigned) geteuid()" in stage_dir
    assert "lstat(" in dir_check
    assert "S_ISDIR" in dir_check
    assert "st.st_uid != geteuid()" in dir_check
    assert "(st.st_mode & 0077) != 0" in dir_check
    assert "errno = EPERM" in dir_check
    assert "cred_dir_check(" in stage_dir
    assert "cred_dir_check(req->dir)" in persistent, (
        "the persistent destination lost the staging-dir standard — the W1 "
        "strengthening (loose cred dirs → EPERM) regressed")


def _check_cred_create(stage: str, create: str, volatile: str,
                       persistent: str) -> None:
    assert re.search(
        r"O_CREAT \| O_EXCL \| O_WRONLY \| O_NOFOLLOW \| O_CLOEXEC", create)
    assert "S_IRUSR | S_IWUSR" in create
    assert "getentropy(" in create
    assert "cred_create_excl(" in volatile
    assert "cred_create_excl(" in persistent
    assert "mkstemp(" not in stage, (
        "mkstemp is back — cred_create_excl's flag set (O_NOFOLLOW|O_CLOEXEC "
        "included) is the C11.2 contract, not mkstemp's")


def _check_cred_mode_and_write(write_full: str, volatile: str,
                               persistent: str) -> None:
    assert "fchmod(fd, S_IRUSR | S_IWUSR)" in volatile
    assert "fchmod(fd, S_IRUSR | S_IWUSR)" in persistent
    assert "EINTR" in write_full
    assert "cred_write_full(fd, bytes, len)" in volatile
    assert "cred_write_full(fd, bytes, len)" in persistent


def _check_cred_durability(dir_flush: str, volatile: str,
                           persistent: str) -> None:
    assert "fsync" not in volatile
    assert re.search(r"\|\| fsync\(fd\) != 0", persistent), (
        "the persistent arm's pre-publish data fsync is gone")
    assert "O_RDONLY | O_DIRECTORY | O_CLOEXEC" in dir_flush
    assert "cred_dir_flush(req->dir)" in persistent
    assert "NOT unlinked" in persistent


def _check_cred_publish(stage: str, volatile: str, persistent: str) -> None:
    assert "getpid" not in stage
    assert "ngx_pid" not in stage
    assert '"%s/.%s.", req->dir, req->name' in persistent
    assert "rename(" not in volatile
    assert "rename(tmp, path_out)" in persistent


def _check_cred_cleanup(stage: str, dir_flush: str, volatile: str,
                        persistent: str) -> None:
    assert "(void) unlink(path);" in _fn(stage, "cred_fail_fd")
    assert "cred_fail_fd(fd," in volatile
    assert "cred_fail_fd(fd," in persistent
    assert persistent.count("(void) unlink(tmp);") >= 2
    assert "if (close(fd) != 0)" in volatile
    assert "if (close(fd) != 0)" in persistent
    assert "close(fd) == 0 ? 0 : -1" in dir_flush


def _check_cred_shape(stage: str, engine: str) -> None:
    assert "bytes == NULL && len > 0" in engine
    assert "cred_name_ok(req->prefix)" in engine
    assert "cred_name_ok(req->name)" in engine
    assert "strchr(s, '/')" in _fn(stage, "cred_name_ok")


def _check_cred_gate(gate: str, verb: str) -> None:
    assert "BRIX_VFS_DOMAIN_CREDENTIAL" in verb
    assert "BRIX_VFS_MUTATE_CREDENTIAL" in verb
    assert verb.index("brix_vfs_domain_claim") \
        < verb.index("brix_cred_write_engine"), (
        "the engine runs before the domain claim — the gate is decorative")
    for outcome in ('"denied"', '"err"', '"ok"'):
        assert outcome in verb
    audit = _fn(gate, "cred_write_audit")
    assert "arm=%s kind=%s dir=" in audit
    assert "req->name" not in audit
    assert "path_out" not in audit


def _check_cred_legacy_wrapper(stage_write: str) -> None:
    assert "brix_cred_write_engine(&req" in stage_write
    for token in (r"\bopen\(", r"\bmkstemp\(",
                  r"(?<![_a-zA-Z])write\(", r"\brename\("):
        assert not re.search(token, stage_write), (
            f"the legacy wrapper grew mechanics ({token})")


def test_cred_write_parity():
    """The §2.1 table AFTER W1: one engine (cred_stage.c), one gated verb
    (cred_write.c), three migrated call sites that carry a request struct and
    nothing else.  Every cell of the old disagreement table is now asserted
    equal or STRONGER at the engine, with §3.3's tmpfs carve-out (the
    VOLATILE arm's deliberate no-fsync) as the one recorded 'weaker on
    purpose'.  Runtime behaviour (0600, reaping, EPERM fail-closed, atomic
    publish) is exercised by tests/c/test_cred_stage.c; this pin holds the
    source contract so a cell cannot silently regress in any one caller."""
    stage = _src("src/core/compat/cred_stage.c")
    stage_dir = _fn(stage, "brix_cred_stage_dir")
    dir_check = _fn(stage, "cred_dir_check")
    create = _fn(stage, "cred_create_excl")
    write_full = _fn(stage, "cred_write_full")
    dir_flush = _fn(stage, "cred_dir_flush")
    volatile = _fn(stage, "cred_write_volatile")
    persistent = _fn(stage, "cred_write_persistent")
    engine = _fn(stage, "brix_cred_write_engine")
    stage_write = _fn(stage, "brix_cred_stage_write")
    gate = _src("src/core/compat/cred_write.c")
    verb = _fn(gate, "brix_cred_write")
    deleg = _fn(_src("src/protocols/webdav/delegation.c"),
                "delegation_store_pem")
    capture = _fn(_src("src/auth/krb5/deleg_capture.c"),
                  "brix_krb5_deleg_mkccache")
    mint = _src("src/fs/backend/cred_mint.c")
    mint_pem = _fn(mint, "mint_write_pem")

    _check_cred_call_sites(capture, deleg, mint_pem, mint)

    # -- row: directory (STRONGER: both arms, one fail-closed check) -------
    _check_cred_directory(stage, stage_dir, dir_check, persistent)

    # -- row: create (STRONGER: full C11.2 flag set, entropy suffix) -------
    _check_cred_create(stage, create, volatile, persistent)

    # -- row: mode (defensive fchmod pin in BOTH arms) ---------------------
    _check_cred_mode_and_write(write_full, volatile, persistent)

    # -- row: fsync (the §3.3 carve-out, and the persistent barrier) -------
    _check_cred_durability(dir_flush, volatile, persistent)

    # -- row: temp name (entropy suffix; nothing pid-keyed anywhere) -------
    _check_cred_publish(stage, volatile, persistent)

    # -- row: dir fsync after rename (STRONGER: both PEM sites get it) -----
    _check_cred_cleanup(stage, dir_flush, volatile, persistent)

    # -- row: shape refusal (EINVAL before any file exists) ----------------
    _check_cred_shape(stage, engine)

    # -- the gate: domain claim FIRST, then engine, then ONE audit line ----
    _check_cred_gate(gate, verb)

    # -- the legacy volatile wrapper stays a thin engine alias -------------
    # Its six pre-C11 callers keep auditless behaviour by design (C11.4 row
    # 4: "do not change at all"); the wrapper must not grow mechanics.
    _check_cred_legacy_wrapper(stage_write)


# --------------------------------------------------------------------------
# Pin 3 — site_n2n is WIRED: it now has production callers, confined to the
#         sanctioned locations (§2.1/C13; W3 inverted the pre-W3 zero-caller pin)
# --------------------------------------------------------------------------

# The only src/ locations permitted to CALL the site_n2n translation logic
# (the composition functions, not the cfg type).  W3 Step A wired the RADOS
# driver's key derivation; W3 Step B (Full A.4) added the generic path-layer
# stage (src/fs/path/n2n_stage.c) that binds the export's cfg to those same
# pure functions.  Anything else INVOKING brix_n2n_lfn2pfn/_pfn2lfn/_canonicalize/
# _extract_pool is the scatter the consolidation exists to prevent, and fails
# this pin.  The cfg TYPE (brix_n2n_cfg_t) and the directive NAMES
# ("brix_n2n_scheme" etc.) are plumbing, referenced more widely by design — the
# ctx carrier, the registry entry, the config validator, the directive tables —
# and are pinned separately (test_n2n_stage_delegates / test_ctx_binds_n2n).
_N2N_SANCTIONED_PREFIXES = (
    "src/fs/path/",
    "src/fs/backend/rados/",
)

# A CALL to one of the four translation primitives: the identifier immediately
# followed by "(".  A declaration/prototype ends in ";" on the same line or has
# a return type before it; we match the call form and exclude the header-comment
# lines (a "() /" or "()." doc reference) by requiring an argument character.
_N2N_CALL = re.compile(
    r"\bbrix_n2n_(?:lfn2pfn|pfn2lfn|canonicalize|extract_pool)\s*\([^)\s]")


def _n2n_translator_callers():
    """Every src/ file (excluding site_n2n itself) that CALLS one of the four
    translation primitives, as repo-relative path strings."""
    own = {"site_n2n.c", "site_n2n.h"}
    callers = []
    for path in sorted(REPO.glob("src/**/*.[ch]")):
        if path.name in own:
            continue
        text = path.read_text(encoding="utf-8")
        if any(_N2N_CALL.search(line) for line in text.splitlines()):
            callers.append(str(path.relative_to(REPO)))
    return callers


def test_site_n2n_wired():
    """The same census mechanism the phase-107 audit used, inverted: W3 made
    site_n2n load-bearing, so this asserts (a) the translation primitives now
    HAVE at least one production caller — the module is no longer dead — and (b)
    every call site is under a sanctioned prefix, so the logic stays one
    path-layer stage plus the driver key derivation and does not scatter a
    private copy across the tree.  The census is on the FUNCTION CALLS (the
    composition logic), not the bare `brix_n2n_` substring: after A.4 the cfg
    type and directive names are referenced by the ctx/registry/config plumbing
    by design, and conflating those with a scattered reimplementation is what the
    coarser Step-A pin did.  The unit stays in `config` and SPECS throughout."""
    callers = _n2n_translator_callers()
    assert callers, (
        "the site_n2n translators have no production callers — W3 is meant to "
        "wire them; if the module was instead deleted, delete this pin and the "
        "config/SPECS lines")
    stray = [c for c in callers
             if not any(c.startswith(p) for p in _N2N_SANCTIONED_PREFIXES)]
    assert stray == [], (
        f"the site_n2n translation is CALLED from outside the sanctioned "
        f"locations {stray} — the logic must stay in the path-layer stage and "
        f"the RADOS driver, not a scattered private copy "
        f"(allowed: {_N2N_SANCTIONED_PREFIXES})")


# --------------------------------------------------------------------------
# Pin 3b/3c/3d — A.4's three shape contracts (§A.4; W3 Step B).  The generic
#         stage delegates (adds no logic), the ctx binds the cfg at its single
#         construction seam, and the RADOS listing reverse goes THROUGH the
#         shared translator (no re-inlined prefix strip).
# --------------------------------------------------------------------------

def test_n2n_stage_delegates_and_adds_no_logic():
    """A.4: the two ctx wrappers "bind the export's cfg to the existing pure
    brix_n2n_lfn2pfn()/brix_n2n_pfn2lfn().  They must not add logic."  So
    brix_path_lfn_to_pfn MUST call brix_n2n_lfn2pfn and brix_path_pfn_to_lfn MUST
    call brix_n2n_pfn2lfn, and neither wrapper may re-implement composition — no
    manual scheme branch, no strcat/memcpy/snprintf of a pool or prefix.  The
    only decision a wrapper makes is the NULL-cfg→IDENTITY fallback."""
    fwd = _fn(_src("src/fs/path/n2n_stage.c"), "brix_path_lfn_to_pfn")
    rev = _fn(_src("src/fs/path/n2n_stage.c"), "brix_path_pfn_to_lfn")
    assert "brix_n2n_lfn2pfn(" in fwd, fwd
    assert "brix_n2n_pfn2lfn(" in rev, rev
    # No re-implemented composition: a wrapper that concatenated a prefix itself
    # (rather than delegating) is exactly the "adds logic" A.4 forbids.
    for name, body in (("lfn_to_pfn", fwd), ("pfn_to_lfn", rev)):
        for banned in ("strcat", "strncat", "memcpy", "snprintf", "sprintf",
                       "BRIX_N2N_RAL", "BRIX_N2N_CEPHFS_PATH"):
            assert banned not in body, (
                f"brix_path_{name} contains {banned!r} — the wrapper must "
                f"delegate composition to the pure translator, not add logic")


def test_ctx_binds_n2n_at_the_single_construction_seam():
    """A.4/§4: the cfg is bound to the ctx exactly once, at brix_vfs_ctx_init —
    the same seam that resolves the backend — so no open site has to plumb it.
    The ctx carrier field exists and ctx_init fills it from the registry."""
    assert "brix_n2n_cfg_t" in _src("src/fs/vfs/vfs.h"), \
        "the ctx lost its n2n carrier field"
    init = _fn(_src("src/fs/vfs/vfs_open_adopt.c"), "brix_vfs_ctx_init")
    assert "brix_vfs_backend_n2n(" in init, (
        "brix_vfs_ctx_init no longer binds ctx->n2n from the registry — every "
        "translation would silently fall back to IDENTITY")
    assert "->n2n" in init, init


def test_posix_rootfd_open_uses_export_relative_name():
    """A resolved VFS path is absolute for ACL/logging, but openat2 receives a
    name relative to the export rootfd.  Passing the absolute form would make
    ``/export/file`` resolve as ``<rootfd>/export/file`` and report ENOENT."""
    body = _fn(_src("src/fs/vfs/vfs_open.c"),
               "brix_vfs_open_confined_fd")
    assert "brix_vfs_export_relative(ctx, path)" in body
    assert "driver->open(ctx->sd, logical" in body
    assert "brix_open_beneath(ctx->rootfd, logical" in body


def test_rados_listing_reverse_goes_through_the_shared_translator():
    """§A.4/C13: the enumerate reverse (object key → LFN) must run through the
    shared brix_n2n_pfn2lfn, not a re-inlined `strncmp(prefix)`+pointer-bump.
    That inline strip was the private copy C13 consolidates; its return here
    would mean the driver and the stage can disagree on what a name maps to."""
    body = _fn(_src("src/fs/backend/rados/sd_ceph_io.c"), "sd_ceph_enumerate_io")
    assert "brix_n2n_pfn2lfn(" in body, (
        "sd_ceph_enumerate_io stopped routing the key→LFN reverse through the "
        "shared translator")
    assert "brix_n2n_pfn2lfn" in body and "strncmp" not in body, (
        "sd_ceph_enumerate_io re-inlined a prefix strip (strncmp) instead of "
        "delegating to brix_n2n_pfn2lfn")


def test_n2n_unreachable_without_resolve_path():
    """§8.2/C13 security-neg + §11.2 DoD — INVARIANT #4: the translation stage
    is unreachable by a path that did not come through ``resolve_path()``.  Two
    structural witnesses hold it, and this pin names both so the invariant is
    discoverable from the test list alone:

    (1) *Input is confined by construction.*  The one driver-facing entry that
        turns a request into a physical key, ``brix_path_resolved_to_pfn``,
        derives its LFN with ``brix_vfs_export_relative(ctx, resolved_path)`` —
        its formal parameter is a *resolved* path and it strips the export root
        rather than accepting a caller-supplied physical name.  A raw,
        pre-confinement request path cannot enter the stage through it.

    (2) *Defense in depth.*  Even reached directly, the sole composition point
        (``brix_n2n_lfn2pfn`` → ``brix_n2n_canonicalize``) REJECTS ``..`` with
        EINVAL, so the stage can never emit a key that escapes the export.  That
        runtime property is proven in the C unit by
        ``test_a_dotdot_b_is_rejected_not_resolved`` /
        ``test_traversal_rejected_before_prefix`` / ``test_fuzz_no_escape``; here
        we pin that the canonicalizer stays wired into the forward translator so
        those tests keep guarding the live path.

    If either witness is refactored away, an unconfined path could reach a
    driver key derivation and this pin fails."""
    stage = _src("src/fs/path/n2n_stage.c")

    # Witness (1): the driver-facing derivation takes a *resolved* path and
    # strips the export root — it never accepts a physical name from the caller.
    resolved = _fn(stage, "brix_path_resolved_to_pfn")
    assert "resolved_path" in resolved, (
        "brix_path_resolved_to_pfn no longer names a resolved_path input — the "
        "one confinement-preserving entry to the stage")
    assert "brix_vfs_export_relative(ctx, resolved_path)" in resolved, (
        "brix_path_resolved_to_pfn stopped deriving its LFN by stripping the "
        "export root from the resolved path — a caller could now hand the stage "
        "a raw, pre-resolve_path() name (INVARIANT #4)")
    assert "brix_path_lfn_to_pfn(ctx, lfn" in resolved, (
        "brix_path_resolved_to_pfn no longer delegates the confined LFN to the "
        "shared translator")

    # Witness (2): the forward translator is still routed through the ``..``-
    # rejecting canonicalizer, so the runtime traversal-rejection C-unit tests
    # keep covering the live composition point.
    fwd = _fn(_src("src/fs/path/site_n2n.c"), "brix_n2n_lfn2pfn")
    assert "brix_n2n_canonicalize(" in fwd, (
        "brix_n2n_lfn2pfn no longer canonicalizes — the `..`-rejection that "
        "makes the stage safe even when reached directly is bypassed "
        "(INVARIANT #4 defense-in-depth)")


# --------------------------------------------------------------------------
# Pin 4 — the VFS independently asks the rule engine (§2.1/C12; W4 inversion)
# --------------------------------------------------------------------------

def test_edge_gate_removed_still_refused():
    """INVERTED IN W4.  Authorization is re-derived behind the protocol edge,
    and every mutation reaches that backstop through the fused VFS gate."""
    authz = _src("src/fs/vfs/vfs_authz.c")
    internal = _src("src/fs/vfs/vfs_internal.h")
    guard = _src("tools/ci/check_authz_backstop.py")

    assert "brix_authz_check_identity(&query)" in authz
    assert "brix_vfs_gate_confined(ctx, op)" in internal
    assert "MUTATION_SITES" in guard
    assert "READ_SITES" in guard
