"""The kernel's mount table (getfsstat/statfs), for verifying the client's
mosbind mounts (PLAN D-4) and finding leftovers at teardown."""

from __future__ import annotations

import ctypes
import os
import urllib.parse
from dataclasses import dataclass

MNT_RDONLY = 0x00000001
MNT_NOWAIT = 2  # never MNT_WAIT: a wedged FSKit volume would hang us (spike S-9)
MOS_TYPES = ("mosbind", "mosoverlay", "mosdev")


class _Statfs(ctypes.Structure):
    # struct statfs, 64-bit inode layout (the only one on arm64)
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


assert ctypes.sizeof(_Statfs) == 2168


@dataclass(frozen=True)
class Mount:
    on: str  # mount point
    source: str  # f_mntfromname, as the kernel has it
    fstype: str
    owner: int
    readonly: bool

    @property
    def source_path(self) -> str | None:
        """The source as a normalised path. FSKit path resources show as a
        file:// URL of whatever spelling was mounted ("file:///usr/./")."""
        s = self.source
        if s.startswith("file://"):
            s = urllib.parse.unquote(urllib.parse.urlparse(s).path)
        if not s.startswith("/"):
            return None
        n = os.path.normpath(s)
        return "/" + n.lstrip("/")


_libc = None


def _lib():
    global _libc
    if _libc is None:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        lib.getfsstat.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
        lib.statfs.argtypes = [ctypes.c_char_p, ctypes.POINTER(_Statfs)]
        _libc = lib
    return _libc


def _mount(s: _Statfs) -> Mount:
    return Mount(on=s.f_mntonname.decode(errors="surrogateescape"),
                 source=s.f_mntfromname.decode(errors="surrogateescape"),
                 fstype=s.f_fstypename.decode(), owner=s.f_owner,
                 readonly=bool(s.f_flags & MNT_RDONLY))


def all_mounts() -> list[Mount]:
    lib = _lib()
    while True:
        n = lib.getfsstat(None, 0, MNT_NOWAIT)
        if n < 0:
            raise OSError(ctypes.get_errno(), "getfsstat")
        buf = (_Statfs * (n + 8))()
        got = lib.getfsstat(buf, ctypes.sizeof(buf), MNT_NOWAIT)
        if got < 0:
            raise OSError(ctypes.get_errno(), "getfsstat")
        if got < n + 8:
            return [_mount(buf[i]) for i in range(got)]


def statfs(path: str) -> Mount:
    s = _Statfs()
    if _lib().statfs(os.fsencode(path), ctypes.byref(s)) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), path)
    return _mount(s)


def under(root: str) -> list[Mount]:
    """Mounts at or below root, deepest first (the order to unmount in)."""
    root = root.rstrip("/")
    ms = [m for m in all_mounts() if m.on == root or m.on.startswith(root + "/")]
    return sorted(ms, key=lambda m: m.on.count("/"), reverse=True)
