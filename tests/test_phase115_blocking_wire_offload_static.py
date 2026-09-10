"""Static guard: which storage drivers may not read on the event loop.

A driver that owns a blocking socket cannot be read from nginx's event loop:
the loop is what would have to pump the socket, and it is sitting inside the
read.  `brix_http_serve_offload_remote` exists to move those reads to the
thread pool, and it decides who needs it in one predicate,
`serve_is_remote_socket`.

That predicate used to decide by NAME — `ngx_strcmp(driver->name, "xroot")`.
It was correct exactly once, on the day xroot was the only such driver.  The
gsiftp driver arrived later speaking a whole FTP conversation per read (connect,
USER/PASS, PASV, RETR, drain), was never added to the list, and so served every
byte on the loop.  Nothing failed loudly: a worker just stopped answering for
the length of each transfer, and where the origin was reachable only through
that same worker the request could not complete at all.

The repair was to stop asking the name.  A driver now declares
`BRIX_SD_CAP_BLOCKING_WIRE` for itself, and this file guards the two halves of
that claim — that the predicate reads the bit, and that the set of drivers
carrying the bit is exactly the set that opens a socket of its own.  The second
half is a CENSUS rather than a spelling check: it derives both sides from the
tree, so a new socket driver that forgets the bit reddens here on the day it is
added rather than on the day someone notices a stalled worker.
"""

import re
from pathlib import Path

from csource_scan import driver_tables, function_body

REPO_ROOT = Path(__file__).resolve().parents[1]
SD_H = REPO_ROOT / "src/fs/backend/sd.h"
OFFLOAD_C = REPO_ROOT / "src/protocols/shared/http_serve_offload.c"
BACKEND_DIR = REPO_ROOT / "src/fs/backend"

CAP = "BRIX_SD_CAP_BLOCKING_WIRE"

# The helpers a driver calls to open and dial a socket it then blocks on.  Both
# take a deadline and return only when the peer answers or the clock runs out,
# which is the whole property: an event loop cannot be inside one of these.
BLOCKING_DIAL = ("brix_connect_fd_deadline", "brix_cache_origin_connect")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _driver_tables() -> dict[str, str]:
    """Every backend's driver table body, keyed by the `.name` it declares.

    Read out of the tree rather than listed here on purpose: a backend added
    tomorrow is in this dict without anyone editing this file.
    """
    tables: dict[str, str] = {}
    for source in sorted(BACKEND_DIR.rglob("*.c")):
        tables.update(driver_tables(_text(source)))
    return tables


def _dialling_backends() -> set[str]:
    """Backend directories whose sources call a blocking dial helper."""
    dialling = set()
    for source in sorted(BACKEND_DIR.rglob("*.c")):
        text = _text(source)
        if any(helper in text for helper in BLOCKING_DIAL):
            dialling.add(source.relative_to(BACKEND_DIR).parts[0])
    return dialling


def _declaring_backends() -> set[str]:
    """Backend directories whose driver table advertises the capability."""
    declaring = set()
    for source in sorted(BACKEND_DIR.rglob("*.c")):
        if CAP in _text(source):
            declaring.add(source.relative_to(BACKEND_DIR).parts[0])
    return declaring


# ---- the predicate reads the bit ---------------------------------------------

def test_the_offload_predicate_consults_the_capability():
    """`serve_is_remote_socket` decides by capability, not by driver name."""
    body = function_body(_text(OFFLOAD_C), "serve_is_remote_socket")
    assert CAP in body, (
        "the serve-offload predicate no longer reads " + CAP + "; whatever it "
        "reads instead has to be something a NEW driver sets for itself")
    assert not re.search(r'->name\s*,\s*"', body), (
        "the predicate is comparing a driver NAME again — that is the exact "
        "shape that left gsiftp reading on the event loop for a whole release")


def test_the_capability_bit_is_its_own():
    """No two capabilities share a bit; a collision would arm the wrong path."""
    bits = re.findall(r"(BRIX_SD_CAP_\w+)\s*=\s*1u\s*<<\s*(\d+)", _text(SD_H))
    assert bits, "the capability bitmap is not where this guard looks for it"
    shifts = [int(shift) for _, shift in bits]
    assert len(set(shifts)) == len(shifts), f"duplicate capability bits: {bits}"
    assert CAP in dict(bits), f"{CAP} is not in the bitmap"


# ---- the census: who carries the bit -----------------------------------------

def test_every_backend_that_dials_a_socket_declares_the_capability():
    """Both sides derived from the tree, so a new socket driver cannot slip in.

    The failure this reproduces is not hypothetical: gsiftp dialled through
    `brix_connect_fd_deadline` from the day it landed and was absent from the
    offload list for as long as that list was a name.
    """
    dialling = _dialling_backends()
    assert dialling, (
        "no backend appears to dial a socket, so this census is measuring "
        f"nothing — the helper names {BLOCKING_DIAL} have probably moved")
    missing = dialling - _declaring_backends()
    assert not missing, (
        f"{sorted(missing)} open a blocking socket but do not advertise {CAP}, "
        "so their reads run on the event loop and stall the worker")


def test_no_backend_declares_it_without_dialling():
    """The other direction: the bit costs a whole extra copy of every object.

    An offloaded serve materialises the object into a temp file before a byte
    reaches the client.  For a local or in-process driver that is pure loss —
    a second full read and a second full write of everything served — so a
    driver that does not actually own a socket must not claim the bit.
    """
    spurious = _declaring_backends() - _dialling_backends()
    assert not spurious, (
        f"{sorted(spurious)} advertise {CAP} but never dial a socket; every "
        "object they serve would be copied through a temp file for nothing")


def test_the_local_drivers_are_still_served_inline():
    """The named negative, so the census above cannot pass by being empty.

    `posix` is the driver every ordinary export uses.  If it ever advertised
    the bit, every local GET would go through the thread pool and a temp file,
    and the tests above would still be green — they only compare two derived
    sets, and this is the one place a concrete expectation is written down.
    """
    tables = _driver_tables()
    for name in ("posix", "ram"):
        assert name in tables, f"the {name} driver table is not where it was"
        assert CAP not in tables[name], (
            f"the {name} driver claims {CAP}; it has no socket to block on")
    assert CAP in tables["gsiftp"], "gsiftp must declare its blocking socket"
    assert CAP in tables["xroot"], "xroot must declare its blocking socket"
