"""Jail roots: creation, mount verification, teardown (PLAN D-4, D-12).

Layout, all under the root-owned jail_dir:

    <jail_dir>/<uid>/<id>/root/          root:wheel 0755, the chroot
        <bind targets>                   owned by the caller: they mount there
        <scratch dirs>                   owned by the caller, 0700
        dev/                             devfs, mounted by the daemon
        <unix socket links>              hard links made by the daemon

The daemon only creates, mounts and deletes below jail_dir, and never
follows a symlink or crosses a mount while deleting.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import signal
import stat
import subprocess
import time
from dataclasses import asdict, dataclass, field

from amosjail import mounts
from amosjail.compile import host_path
from amosjail.config import Spec, norm

logger = logging.getLogger(__name__)


class JailError(RuntimeError):
    pass


@dataclass
class MountPlan:
    source: str  # host path (realpath)
    target: str  # host path of the mount point
    fstype: str
    readonly: bool
    lower: list[str] = field(default_factory=list)
    workdir: str | None = None
    notify: dict | None = None  # {"match": ..., "command": [...]}


@dataclass
class State:
    """What the reaper needs after a daemon crash; saved to state_dir."""

    id: str
    uid: int
    gid: int
    base: str  # <jail_dir>/<uid>/<id>
    root: str  # host path, /private form
    mounts: list[MountPlan]
    sockets: list[str] = field(default_factory=list)  # links we made
    asid: int | None = None
    pid: int | None = None
    created: float = field(default_factory=time.time)
    role: str = ""
    stopped: bool = False  # killed and untagged; only unmounting is left

    def save(self, state_dir: str) -> None:
        path = os.path.join(state_dir, self.id + ".json")
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(asdict(self), f)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> State:
        with open(path) as f:
            d = json.load(f)
        d["mounts"] = [MountPlan(**m) for m in d["mounts"]]
        return cls(**d)


def check_root_dir(path: str, create: bool = True) -> None:
    """A directory only root may change, with no symlink anywhere on its
    path, or the daemon refuses to work in it."""
    if create:
        os.makedirs(path, mode=0o755, exist_ok=True)
    # /var -> /private/var is the one symlink allowed (firmlinks).
    p = os.path.realpath(path)
    if p != host_path(path):
        raise JailError(f"{path}: must not go through a symlink")
    while True:
        st = os.lstat(p)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise JailError(f"{p}: must be a root-owned directory not writable by others")
        if p == "/":
            break
        p = os.path.dirname(p)


def _mkdir(path: str, uid: int = 0, gid: int = 0, mode: int = 0o755) -> None:
    os.mkdir(path, mode)
    os.chmod(path, mode)
    if uid or gid:
        os.chown(path, uid, gid)


def _mkdirs_root(root: str, jail_path: str) -> None:
    """Root-owned directories leading to jail_path (not jail_path itself)."""
    cur = root
    for part in norm(jail_path).strip("/").split("/")[:-1]:
        cur = os.path.join(cur, part)
        if not os.path.lexists(cur):
            _mkdir(cur)
        elif not stat.S_ISDIR(os.lstat(cur).st_mode):
            raise JailError(f"{cur}: expected a directory")


def check_source(path: str) -> str:
    """A bind source as its real path. Never a mosbind volume: mounting one
    with mosbind hangs the extension and every getfsstat on the machine
    (spike S-9)."""
    real = os.path.realpath(path)
    if not os.path.isdir(real):
        raise JailError(f"bind source {path}: not a directory")
    m = mounts.statfs(real)
    if m.fstype in mounts.MOS_TYPES:
        raise JailError(f"bind source {path} is on a {m.fstype} volume ({m.on}); bind its source instead")
    return real


def create(spec: Spec, uid: int, gid: int, jail_dir: str) -> State:
    check_root_dir(jail_dir)
    user_dir = os.path.join(jail_dir, str(uid))
    if not os.path.lexists(user_dir):
        _mkdir(user_dir)
    check_root_dir(user_dir, create=False)
    jid = "j" + secrets.token_hex(4)
    base = os.path.join(user_dir, jid)
    _mkdir(base)
    root_path = os.path.join(base, "root")
    _mkdir(root_path)
    root = host_path(os.path.realpath(root_path))
    st = State(id=jid, uid=uid, gid=gid, base=host_path(os.path.realpath(base)), root=root,
               mounts=[], role=spec.role)
    try:
        for b in spec.binds:
            source = check_source(b.source)
            lower = [check_source(x) for x in b.lower]
            workdir = os.path.realpath(b.workdir) if b.workdir else None
            _mkdirs_root(root, b.target)
            target = root + b.target
            _mkdir(target, uid, gid)
            st.mounts.append(MountPlan(
                source=source, target=target, fstype=b.fstype, readonly=b.mode == "ro",
                lower=lower, workdir=workdir,
                notify={"match": b.notify.match, "command": list(b.notify.command)} if b.notify else None))
        for s in spec.scratch:
            _mkdirs_root(root, s)
            _mkdir(root + s, uid, gid, 0o700)
        for link, text in spec.links.items():
            _mkdirs_root(root, link)
            os.symlink(text, root + link)
        for s in spec.unix_sockets:
            _mkdirs_root(root, s.target)
        _mkdir(root + "/dev")
    except BaseException:
        remove_tree(st.base)
        raise
    return st


def verify(st: State) -> None:
    """Every planned mount is there, as planned, made by the caller, and
    nothing else is mounted in the jail (D-4)."""
    expected = {m.target: m for m in st.mounts}
    for m in mounts.under(st.root):
        if m.on not in expected:
            raise JailError(f"unexpected mount at {m.on} ({m.fstype})")
    for target, plan in expected.items():
        m = mounts.statfs(target)
        if m.on != target:
            raise JailError(f"{target}: not mounted")
        if m.fstype != plan.fstype:
            raise JailError(f"{target}: is {m.fstype}, expected {plan.fstype}")
        if m.owner != st.uid:
            raise JailError(f"{target}: mounted by uid {m.owner}, expected {st.uid}")
        if m.readonly != plan.readonly:
            raise JailError(f"{target}: read-only is {m.readonly}, expected {plan.readonly}")
        if m.source_path != plan.source:
            raise JailError(f"{target}: source is {m.source}, expected {plan.source}")


def finish(st: State, spec: Spec) -> None:
    """Root's part of the jail, after verification: /dev and socket links."""
    dev = st.root + "/dev"
    r = subprocess.run(["/sbin/mount", "-t", "devfs", "devfs", dev], capture_output=True, text=True)
    if r.returncode:
        raise JailError(f"mount devfs: {r.stderr.strip()}")
    for s in spec.unix_sockets:
        try:
            lst = os.lstat(s.host)
        except FileNotFoundError:
            raise JailError(f"unix socket {s.host}: not found") from None
        if not stat.S_ISSOCK(lst.st_mode):
            raise JailError(f"{s.host}: not a socket")
        dst = st.root + s.target
        os.link(s.host, dst, follow_symlinks=False)
        st.sockets.append(dst)


def asid_members(asid: int) -> list[int]:
    from amosjail._vendor.darwin import all_pids, task_audit_token

    out = []
    for pid in all_pids():
        t = task_audit_token(pid)
        if t is not None and t.asid == asid:
            out.append(pid)
    return out


def kill_session(asid: int, rounds: int = 50) -> bool:
    """Stop, then kill, every process in the jail's audit session until
    none is left. Members can't leave the session or start a new one, and
    stopped ones can't fork, so this converges."""
    for _ in range(rounds):
        pids = [p for p in asid_members(asid) if p != os.getpid()]
        if not pids:
            return True
        for sig in (signal.SIGSTOP, signal.SIGKILL):
            for p in pids:
                try:
                    os.kill(p, sig)
                except ProcessLookupError:
                    pass
        time.sleep(0.02)
    return not asid_members(asid)


def unmount_all(root: str) -> list[str]:
    """Unmount everything below root, deepest first, never forcibly.
    Returns what is still mounted.

    Never `umount -f`: each chroot gets its own dyld shared region, backed
    by the jail's /System mount, and the kernel keeps it for a while after
    the jail's last process exits. Forcing the unmount leaves that region
    with no pager, and a later exec that lands on it dies of SIGBUS in dyld
    ("Object has no pager because the backing vnode was force unmounted").
    So a busy mount is left to drain and retried."""
    for m in mounts.under(root):
        subprocess.run(["/sbin/umount", m.on], capture_output=True, text=True)
    return [m.on for m in mounts.under(root)]


def remove_tree(path: str) -> None:
    """rm -rf that never follows a symlink and never leaves path's device,
    so a mount we failed to remove keeps its contents."""
    try:
        top = os.lstat(path)
    except FileNotFoundError:
        return

    def rm(p: str, dev: int):
        st = os.lstat(p)
        if st.st_dev != dev:
            raise JailError(f"{p}: still mounted, not removing")
        if stat.S_ISDIR(st.st_mode):
            for name in os.listdir(p):
                rm(os.path.join(p, name), dev)
            os.rmdir(p)
        else:
            os.unlink(p)

    rm(path, top.st_dev)


def stop(st: State, state_dir: str, untag=None) -> list[str]:
    """Kill everything in the jail and untag it. Returns problems."""
    problems = []
    if st.asid is not None and not st.stopped:
        if not kill_session(st.asid):
            problems.append(f"asid {st.asid}: processes survived")
        if untag:
            try:
                untag(st.asid)
            except Exception as e:
                problems.append(f"untag asid {st.asid}: {e}")
    st.stopped = True
    st.save(state_dir)
    for p in problems:
        logger.warning("jail %s: %s", st.id, p)
    return problems


def release(st: State, state_dir: str) -> bool:
    """Unmount and delete a stopped jail. False while mounts are still busy
    (the caller retries later); the state file stays until it's all gone."""
    busy = unmount_all(st.root)
    if busy:
        return False
    try:
        remove_tree(st.base)
    except (OSError, JailError) as e:
        logger.warning("jail %s: remove %s: %s", st.id, st.base, e)
        return False
    try:
        os.unlink(os.path.join(state_dir, st.id + ".json"))
    except FileNotFoundError:
        pass
    return True
