"""Build deterministic NSS records for isolated workload identities."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Mapping, Optional

from brixtest._design_managed import Identity


def nss_records(identity: Identity) -> Optional[Mapping[str, str]]:
    """Return passwd/group text when both primary numeric IDs are declared."""
    if identity.uid is None or identity.gid is None:
        return None
    name = "brixtest_%s" % re.sub(r"[^A-Za-z0-9_-]", "_", identity.name)
    passwd = (
        "root:x:0:0:root:/root:/sbin/nologin\n"
        "%s:x:%d:%d:BriXTest identity:/nonexistent:/sbin/nologin\n"
        "nobody:x:65534:65534:Nobody:/nonexistent:/sbin/nologin\n"
    ) % (name, identity.uid, identity.gid)
    groups = {0: "root", 65534: "nobody", identity.gid: name}
    groups.update({value: "%s_g%d" % (name, value) for value in identity.groups})
    group = "".join(
        "%s:x:%d:%s\n" % (group_name, group_id, name if group_id in identity.groups else "")
        for group_id, group_name in sorted(groups.items())
    )
    return {"passwd": passwd, "group": group}


def write_nss_files(root: Path, identity: Identity) -> Optional[Mapping[str, Path]]:
    """Write mode-0644 run-owned NSS files for an OCI bind projection."""
    records = nss_records(identity)
    if records is None:
        return None
    destination = Path(root) / "nss"
    destination.mkdir(parents=True, exist_ok=False)
    files = {}
    for name, content in records.items():
        path = destination / name
        path.write_text(content)
        path.chmod(0o644)
        files[name] = path
    return files


__all__ = ["nss_records", "write_nss_files"]
