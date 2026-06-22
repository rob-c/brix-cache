"""
Shadow of ``XRootD.client.flags``.

The values mirror the real XrdCl enums exactly (captured from the installed
bindings) so that flag arguments forwarded to the worker reproduce the wire
behaviour bit-for-bit.  They are plain IntEnum/IntFlag and carry no native code.
"""

from enum import IntFlag


class OpenFlags(IntFlag):
    NONE = 0
    DELETE = 2
    FORCE = 4
    NEW = 8
    READ = 16
    UPDATE = 32
    REFRESH = 128
    MAKEPATH = 256
    POSC = 4096
    NOWAIT = 8192
    SEQIO = 16384
    WRITE = 32768
    DUP = 65536
    REPLICA = 2048
    SAMEFS = 131072


class QueryCode(IntFlag):
    STATS = 1
    PREPARE = 2
    CHECKSUM = 3
    XATTR = 4
    SPACE = 5
    CHECKSUMCANCEL = 6
    CONFIG = 7
    VISA = 8
    OPAQUE = 16
    OPAQUEFILE = 32


class DirListFlags(IntFlag):
    NONE = 0
    STAT = 1
    LOCATE = 2
    RECURSIVE = 4
    MERGE = 8
    CHUNKED = 16
    ZIP = 32


class StatInfoFlags(IntFlag):
    X_BIT_SET = 1
    IS_DIR = 2
    OTHER = 4
    OFFLINE = 8
    IS_READABLE = 16
    IS_WRITABLE = 32
    POSC_PENDING = 64
    BACKUP_EXISTS = 128


class MkDirFlags(IntFlag):
    NONE = 0
    MAKEPATH = 1


class AccessMode(IntFlag):
    NONE = 0
    OR = 4
    OW = 2
    OX = 1
    GR = 32
    GW = 16
    GX = 8
    UR = 256
    UW = 128
    UX = 64


class PrepareFlags(IntFlag):
    STAGE = 8
    WRITEMODE = 16
    COLOCATE = 32
    FRESH = 64
    EVICT = 256
