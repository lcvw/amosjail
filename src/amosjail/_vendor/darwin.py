"""Thin macOS bindings: peer credentials on unix sockets and libproc queries."""

from __future__ import annotations

import ctypes
import ctypes.util
import socket
import struct
from dataclasses import dataclass

# <sys/un.h>
SOL_LOCAL = 0
LOCAL_PEERCRED = 0x001
LOCAL_PEERPID = 0x002
LOCAL_PEERTOKEN = 0x006

# audit_token_t: val[0..7] = auid, euid, egid, ruid, rgid, pid, asid, pidversion
_AUDIT_TOKEN = struct.Struct("=8I")

PROC_PIDTBSDINFO = 3
# struct proc_bsdinfo is 136 bytes; pbi_ppid is the fifth uint32.
_PROC_BSDINFO_SIZE = 136
_PBI_PPID_OFFSET = 16

# struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[16]; }
_XUCRED = struct.Struct("=IIh2x16I")

PROC_PIDPATHINFO_MAXSIZE = 4 * 1024


@dataclass(frozen=True)
class PeerCred:
    pid: int
    uid: int


def peer_cred(sock: socket.socket) -> PeerCred:
    """Kernel-reported pid/uid of the process that connected to a unix socket."""
    pid = struct.unpack("=i", sock.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4))[0]
    _version, uid, *_ = _XUCRED.unpack(
        sock.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, _XUCRED.size)
    )
    return PeerCred(pid=pid, uid=uid)


@dataclass(frozen=True)
class AuditToken:
    auid: int
    euid: int
    egid: int
    ruid: int
    rgid: int
    pid: int
    asid: int
    pidversion: int


def peer_token(sock: socket.socket) -> AuditToken:
    return AuditToken(*_AUDIT_TOKEN.unpack(sock.getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN, _AUDIT_TOKEN.size)))


_libproc = None


def _lib():
    global _libproc
    if _libproc is None:
        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "libproc.dylib", use_errno=True)
        lib.proc_listchildpids.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        lib.proc_listchildpids.restype = ctypes.c_int
        lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        lib.proc_pidpath.restype = ctypes.c_int
        lib.proc_pidinfo.argtypes = [
            ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int,
        ]
        lib.proc_pidinfo.restype = ctypes.c_int
        _libproc = lib
    return _libproc


def child_pids(ppid: int) -> list[int]:
    """Direct children of ppid. Empty if ppid is gone."""
    lib = _lib()
    cap = 64
    while True:
        buf = (ctypes.c_int * cap)()
        n = lib.proc_listchildpids(ppid, buf, ctypes.sizeof(buf))
        if n <= 0:
            return []
        if n < cap:
            return [p for p in buf[:n] if p > 0]
        cap *= 4


def parent_pid(pid: int) -> int | None:
    buf = ctypes.create_string_buffer(_PROC_BSDINFO_SIZE)
    n = _lib().proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, buf, _PROC_BSDINFO_SIZE)
    if n != _PROC_BSDINFO_SIZE:
        return None
    return struct.unpack_from("=I", buf.raw, _PBI_PPID_OFFSET)[0]


TASK_AUDIT_TOKEN = 15
_libsystem = None


def _sys():
    global _libsystem
    if _libsystem is None:
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        u32 = ctypes.c_uint32
        lib.task_name_for_pid.argtypes = [u32, ctypes.c_int, ctypes.POINTER(u32)]
        lib.task_info.argtypes = [u32, ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(u32)]
        lib.mach_port_deallocate.argtypes = [u32, u32]
        lib.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
        _libsystem = lib
    return _libsystem


def all_pids() -> list[int]:
    lib = _sys()
    cap = 4096
    while True:
        buf = (ctypes.c_int * cap)()
        n = lib.proc_listallpids(buf, ctypes.sizeof(buf))
        if n < cap:
            return [p for p in buf[: max(n, 0)] if p > 0]
        cap *= 2


def task_audit_token(pid: int) -> AuditToken | None:
    """Any process's audit token, via its task *name* port (root only;
    works for hardened and platform processes alike)."""
    lib = _sys()
    me = ctypes.c_uint32.in_dll(lib, "mach_task_self_").value
    name = ctypes.c_uint32()
    if lib.task_name_for_pid(me, pid, ctypes.byref(name)) != 0:
        return None
    try:
        vals = (ctypes.c_uint32 * 8)()
        count = ctypes.c_uint32(8)
        if lib.task_info(name, TASK_AUDIT_TOKEN, vals, ctypes.byref(count)) != 0:
            return None
        return AuditToken(*vals)
    finally:
        lib.mach_port_deallocate(me, name.value)


@dataclass(frozen=True)
class SessionScan:
    members: dict[int, int]  # asid -> live process count, for asids asked about
    opaque: list[int]  # live pids whose session could not be read


def scan_sessions(asids: set[int]) -> SessionScan:
    """Count live members of each audit session. A pid that vanished
    mid-scan is skipped; a live pid we cannot inspect is reported as opaque,
    because it might be a member."""
    members = dict.fromkeys(asids, 0)
    opaque = []
    for pid in all_pids():
        token = task_audit_token(pid)
        if token is None:
            if parent_pid(pid) is not None:  # still alive
                opaque.append(pid)
            continue
        if token.asid in members:
            members[token.asid] += 1
    return SessionScan(members=members, opaque=opaque)


def pid_path(pid: int) -> str | None:
    buf = ctypes.create_string_buffer(PROC_PIDPATHINFO_MAXSIZE)
    n = _lib().proc_pidpath(pid, buf, PROC_PIDPATHINFO_MAXSIZE)
    return buf.value.decode(errors="replace") if n > 0 else None
