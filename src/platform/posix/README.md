# Shared POSIX adapters

| File | Responsibility |
|---|---|
| `path_walk.inc` | Descriptor-relative, bounded symlink walk implementing the PAL BENEATH/IN_ROOT/stat contracts for Darwin and FreeBSD. Included by the selected host's namespace adapter so standalone/native object-link tests retain the same source closure. |
