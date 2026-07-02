"""
test_shm_slab_safety_lint.py — static guard against reintroducing the SHM/fork bug.

WHAT
    A source-level lint that fails if any nginx-xrootd shared-memory zone lays its
    own struct directly over ``shm_zone->shm.addr``. nginx initialises every
    ``shared_memory`` zone as an ``ngx_slab_pool_t`` and force-unlocks
    ``((ngx_slab_pool_t*)zone.shm.addr)->mutex`` on EVERY child death
    (ngx_process.c ngx_unlock_mutexes, walked unconditionally). A zone that
    overwrites that slab header SIGSEGVs the master the instant any worker exits
    — the codebase-wide bug fixed 2026-06-14. The runtime counterpart that proves
    a live master survives the reap is tests/test_shm_fork_safety.py.

WHY A LINT
    The runtime test only fires if a build happens to register the offending
    zone and a worker happens to die during the test. This lint is the durable,
    build-time guarantee: it reads the source and rejects the dangerous pattern
    before it can ever ship — so the framework cannot quietly regrow the bug when
    someone adds the next SHM zone by copy-paste.

THE CONTRACT (encoded below)
    R1 (anti-clobber, the real guard): the ONLY legitimate use of a zone's
       ``shm.addr`` is to view it as ``ngx_slab_pool_t`` (the slab pool itself).
       Any other cast/assignment/ngx_memzero through ``shm.addr`` clobbers the
       header and is rejected.
    R2 (completeness): every file that registers a zone (ngx_shared_memory_add)
       must allocate its table with a slab-safe allocator — ``xrootd_shm_table_alloc``
       (src/core/compat/shm_slots.c) or raw ``ngx_slab_alloc`` — either in the file
       itself or in the ``->init`` callback it registers. A pure no-op init
       (never touches shm.addr) is accepted (it cannot clobber).

RUN
    PYTHONPATH=tests pytest tests/test_shm_slab_safety_lint.py -v
"""

import os
import re

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_REPO, "src")

# Files exempt from R1: the slab-safe helper legitimately views shm.addr as the
# slab pool (it contains ngx_slab_pool_t so it would pass R1 anyway, but we name
# it explicitly so the intent is documented).
_R1_EXEMPT = frozenset({"compat/shm_slots.c"})

# Files exempt from R2: documented registrars that intentionally do not allocate
# a table (none today). Add a rel-path here ONLY with a comment explaining why a
# zone is safe without a slab-safe allocator.
_R2_EXEMPT = frozenset()


# ---------------------------------------------------------------------------
# C source preprocessing
# ---------------------------------------------------------------------------

def _strip_c_comments(text):
    """Blank out // and /* */ comments while preserving every newline (so line
    numbers stay accurate) and string/char literal contents."""
    out = []
    i, n = 0, len(text)
    state = "code"
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line"; out.append("  "); i += 2; continue
            if c == "/" and nxt == "*":
                state = "block"; out.append("  "); i += 2; continue
            if c == '"':
                state = "str"; out.append(c); i += 1; continue
            if c == "'":
                state = "char"; out.append(c); i += 1; continue
            out.append(c); i += 1; continue
        if state == "line":
            if c == "\n":
                state = "code"; out.append("\n"); i += 1; continue
            out.append("\t" if c == "\t" else " "); i += 1; continue
        if state == "block":
            if c == "*" and nxt == "/":
                state = "code"; out.append("  "); i += 2; continue
            out.append("\n" if c == "\n" else " "); i += 1; continue
        if state == "str":
            out.append(c)
            if c == "\\" and nxt:
                out.append(nxt); i += 2; continue
            if c == '"':
                state = "code"
            i += 1; continue
        if state == "char":
            out.append(c)
            if c == "\\" and nxt:
                out.append(nxt); i += 2; continue
            if c == "'":
                state = "code"
            i += 1; continue
    return "".join(out)


def _iter_repo_sources():
    """(relpath, raw_text) for every .c/.h under src/."""
    out = []
    for dirpath, _dirs, files in os.walk(_SRC):
        for fn in files:
            if not (fn.endswith(".c") or fn.endswith(".h")):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, _SRC)
            try:
                out.append((rel, open(full, errors="replace").read()))
            except OSError:
                continue
    return out


# ---------------------------------------------------------------------------
# the two rules — operate on a list of (path, raw_text) so the self-test can
# feed synthetic sources
# ---------------------------------------------------------------------------

def _rule1_clobber_violations(sources, exempt=frozenset()):
    """Flag any use of a zone's shm.addr that is not an ngx_slab_pool_t view."""
    viol = []
    for path, raw in sources:
        if path in exempt:
            continue
        t = _strip_c_comments(raw)
        for m in re.finditer(r"shm\.addr", t):
            idx = m.start()
            start = max(t.rfind(";", 0, idx), t.rfind("{", 0, idx),
                        t.rfind("}", 0, idx))
            end = t.find(";", idx)
            stmt = t[start + 1: end if end != -1 else idx + 8]
            if "ngx_slab_pool_t" in stmt:
                continue  # legitimate: viewing the slab pool itself
            line = t.count("\n", 0, idx) + 1
            viol.append((path, line, " ".join(stmt.split())[:140]))
    return viol


def _find_init_body(stripped_by_path, name):
    """Body ({...}) of a zone-init function `name(ngx_shm_zone_t ...)`, searched
    across all sources. Returns the brace-balanced body text, or None."""
    pat = re.compile(r"\b" + re.escape(name) + r"\s*\(\s*ngx_shm_zone_t")
    for t in stripped_by_path.values():
        m = pat.search(t)
        if not m:
            continue
        brace = t.find("{", m.end())
        if brace == -1:
            continue
        depth = 0
        for j in range(brace, len(t)):
            if t[j] == "{":
                depth += 1
            elif t[j] == "}":
                depth -= 1
                if depth == 0:
                    return t[brace:j + 1]
        return t[brace:]
    return None


_SAFE_ALLOC = ("xrootd_shm_table_alloc", "ngx_slab_alloc")


def _rule2_unsafe_registrars(sources, exempt=frozenset()):
    """Flag any ngx_shared_memory_add registrar that never reaches a slab-safe
    allocator (in the file or in a registered ->init callback)."""
    stripped = {p: _strip_c_comments(raw) for p, raw in sources}
    viol = []
    for path, t in stripped.items():
        if path in exempt:
            continue
        if "ngx_shared_memory_add" not in t:
            continue

        if any(a in t for a in _SAFE_ALLOC):
            continue  # allocates safely in this very file

        inits = set(re.findall(r"(?:->|\.)init\s*=\s*([A-Za-z_]\w*)", t))
        detail = []
        safe = False
        for name in inits:
            body = _find_init_body(stripped, name)
            if body is None:
                detail.append("init %s(): definition not found" % name)
                continue
            if any(a in body for a in _SAFE_ALLOC):
                safe = True
                break
            if "shm.addr" not in body:
                safe = True  # pure stub / no-op init cannot clobber
                break
            detail.append("init %s(): touches shm.addr without a slab-safe "
                          "allocator" % name)
        if safe:
            continue
        if not inits:
            detail.append("registers a zone but has no resolvable ->init "
                          "assignment and no slab-safe allocator")
        viol.append((path, "; ".join(detail) or "no slab-safe allocator found"))
    return viol


# ---------------------------------------------------------------------------
# self-test: prove the scanner actually detects the bug pattern (teeth)
# ---------------------------------------------------------------------------

_SYNTHETIC_BAD = """
typedef struct { ngx_uint_t capacity; } my_table_t;

static ngx_int_t
bad_init(ngx_shm_zone_t *shm_zone, void *data)
{
    my_table_t *t = (my_table_t *) shm_zone->shm.addr;   /* CLOBBERS header */
    ngx_memzero(t, sizeof(*t));
    t->capacity = 16;
    return NGX_OK;
}

ngx_int_t
configure(ngx_conf_t *cf)
{
    ngx_shm_zone_t *z = ngx_shared_memory_add(cf, &name, 4096, &mod);
    z->init = bad_init;
    return NGX_OK;
}
"""

_SYNTHETIC_GOOD = """
#include "core/compat/shm_slots.h"
typedef struct { ngx_shmtx_sh_t lock; ngx_uint_t capacity; } my_table_t;

static ngx_int_t
good_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_flag_t fresh;
    my_table_t *t = xrootd_shm_table_alloc(shm_zone, data, sizeof(*t),
                                           &my_mtx, &fresh);
    if (t == NULL) { return NGX_ERROR; }
    if (fresh) { t->capacity = 16; }
    return NGX_OK;
}

ngx_int_t
configure(ngx_conf_t *cf)
{
    ngx_shm_zone_t *z = ngx_shared_memory_add(cf, &name,
                            xrootd_shm_zone_size(sizeof(my_table_t)), &mod);
    z->init = good_init;
    return NGX_OK;
}
"""

_SYNTHETIC_SLABPOOL_OK = """
/* the limit_req-style pattern: view the slab pool, alloc from it — SAFE */
static ngx_int_t
rl_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t *sp = (ngx_slab_pool_t *) shm_zone->shm.addr;
    my_ctx_t *ctx = ngx_slab_alloc(sp, sizeof(my_ctx_t));
    sp->data = ctx;
    return NGX_OK;
}
ngx_int_t cfg(ngx_conf_t *cf)
{
    ngx_shm_zone_t *z = ngx_shared_memory_add(cf, &name, 4096, &mod);
    z->init = rl_init;
    return NGX_OK;
}
"""


def test_self_clobber_is_detected():
    """The R1 scanner MUST flag a struct laid over shm.addr (proves teeth)."""
    v = _rule1_clobber_violations([("synthetic/bad.c", _SYNTHETIC_BAD)])
    assert v, "R1 failed to detect a struct cast over shm.addr — the lint is toothless"
    assert any("my_table_t" in stmt for _p, _l, stmt in v)


def test_self_unsafe_registrar_is_detected():
    """The R2 scanner MUST flag a registrar whose init clobbers shm.addr."""
    v = _rule2_unsafe_registrars([("synthetic/bad.c", _SYNTHETIC_BAD)])
    assert v, "R2 failed to detect an unsafe registrar — the lint is toothless"


def test_self_safe_helper_pattern_passes():
    """The slab-safe helper pattern must NOT be flagged (no false positives)."""
    src = [("synthetic/good.c", _SYNTHETIC_GOOD)]
    assert not _rule1_clobber_violations(src)
    assert not _rule2_unsafe_registrars(src)


def test_self_slabpool_view_pattern_passes():
    """The limit_req-style 'view slab pool + ngx_slab_alloc' pattern is safe."""
    src = [("synthetic/rl.c", _SYNTHETIC_SLABPOOL_OK)]
    assert not _rule1_clobber_violations(src)
    assert not _rule2_unsafe_registrars(src)


# ---------------------------------------------------------------------------
# the actual guard over the real tree
# ---------------------------------------------------------------------------

def test_no_zone_clobbers_slab_header():
    """R1 over src/: no zone may write a struct over its slab-pool header."""
    if not os.path.isdir(_SRC):
        pytest.skip("src/ not found at %s" % _SRC)
    sources = _iter_repo_sources()
    viol = _rule1_clobber_violations(sources, exempt=_R1_EXEMPT)
    if viol:
        lines = "\n".join("  %s:%d  %s" % v for v in viol)
        pytest.fail(
            "Shared-memory zones must not lay a struct over shm.addr (it clobbers "
            "the ngx_slab_pool_t header that ngx_unlock_mutexes() dereferences on "
            "every child death -> master SIGSEGV). Use xrootd_shm_table_alloc() "
            "from src/core/compat/shm_slots.h instead. Offending uses:\n" + lines)


def test_every_zone_uses_a_slab_safe_allocator():
    """R2 over src/: every ngx_shared_memory_add registrar reaches a slab-safe
    allocator (xrootd_shm_table_alloc or ngx_slab_alloc)."""
    if not os.path.isdir(_SRC):
        pytest.skip("src/ not found at %s" % _SRC)
    sources = _iter_repo_sources()
    viol = _rule2_unsafe_registrars(sources, exempt=_R2_EXEMPT)
    if viol:
        lines = "\n".join("  %s  ->  %s" % v for v in viol)
        pytest.fail(
            "Every SHM zone must allocate its table from the slab pool "
            "(xrootd_shm_table_alloc, or raw ngx_slab_alloc) so nginx's slab "
            "header survives. These registrars do not:\n" + lines)


def test_lint_actually_covered_the_known_zones():
    """Sanity: the scanner sees a realistic number of registrars, so a future
    refactor that hides ngx_shared_memory_add behind a wrapper does not silently
    disable the guard."""
    if not os.path.isdir(_SRC):
        pytest.skip("src/ not found at %s" % _SRC)
    sources = _iter_repo_sources()
    registrars = [p for p, raw in sources
                  if "ngx_shared_memory_add" in _strip_c_comments(raw)]
    assert len(registrars) >= 8, (
        "expected the lint to find the known SHM-zone registrars (>=8); found %d "
        "(%r) — has ngx_shared_memory_add been wrapped/renamed? Update the guard."
        % (len(registrars), registrars))
