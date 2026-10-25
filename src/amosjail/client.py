"""`amosjail run`: the unprivileged side of a jail (PLAN T-04).

It asks the daemon for a jail, mounts the binds itself with mosbind (as the
user, D-4), then hands over its terminal: a pty it relays when stdin and
stdout are terminals (build plan Δ1), its own stdio otherwise. It exits
with the jail's status. The daemon unmounts and deletes at the end (Δ2).
"""

from __future__ import annotations

import fcntl
import json
import os
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import tty

from amosjail._vendor import protocol

EXIT_ERROR = 125  # amosjail itself failed, as with `docker run`
BUSY = "Resource busy"
MAX_SPELLINGS = 256  # draining jails keep their mounts for a while


class ClientError(RuntimeError):
    pass


class Channel:
    def __init__(self, path: str):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self.sock.connect(path)
        except OSError as e:
            raise ClientError(f"amosjaild isn't running ({path}: {e.strerror})") from None
        self.buf = b""

    def send(self, msg: dict, fds: list[int] | None = None) -> None:
        data = protocol.encode(msg)
        if fds:
            socket.send_fds(self.sock, [data], fds)
        else:
            self.sock.sendall(data)

    def ready(self) -> list[dict] | None:
        """Messages available now (call when the socket is readable);
        None once the daemon has closed the connection."""
        data = self.sock.recv(65536)
        if not data:
            return None
        self.buf += data
        out = []
        while b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
            out.append(protocol.decode(line))
        return out

    def recv(self) -> dict:
        while b"\n" not in self.buf:
            data = self.sock.recv(65536)
            if not data:
                raise ClientError("amosjaild closed the connection")
            self.buf += data
        line, self.buf = self.buf.split(b"\n", 1)
        return protocol.decode(line)


def spellings(source: str):
    """FSKit won't mount a source it already has mounted, and dedupes on
    the URL string, so another jail's /usr is mounted here as /usr/.
    (spike S-9; goes away with mosbind T-08)."""
    yield source
    s = source.rstrip("/") or "/"
    for i in range(1, MAX_SPELLINGS):
        yield s + "/." * i


def mount_one(m: dict, mount_tool: str) -> None:
    opts = []
    if m["fstype"] == "mosoverlay":
        opts += ["-o", "lowerdir=" + ":".join(m["lower"])]
        if m.get("workdir"):
            opts += ["-o", "workdir=" + m["workdir"]]
    if m["readonly"]:
        opts.append("-r")
    err = ""
    for spelled in spellings(m["source"]):
        r = subprocess.run([mount_tool, "-t", m["fstype"], *opts, spelled, m["target"]],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return
        err = (r.stderr or r.stdout).strip()
        if BUSY not in err:
            break
    raise ClientError(f"mount {m['source']} on {m['target']}: {err}")


def start_notifiers(mounts: list[dict], notify_tool: str) -> list[subprocess.Popen]:
    procs = []
    for m in mounts:
        n = m.get("notify")
        if n:
            procs.append(subprocess.Popen([notify_tool, m["target"], n["match"], *n["command"]]))
    return procs


def _winsize(fd: int) -> bytes:
    return fcntl.ioctl(fd, termios.TIOCGWINSZ, struct.pack("HHHH", 0, 0, 0, 0))


def run(socket_path: str, role: str, argv: list[str], params: dict[str, str], binds: list[str],
        report: bool) -> int:
    use_pty = os.isatty(0) and os.isatty(1)
    ch = Channel(socket_path)
    ch.send({"op": "spawn", "role": role, "argv": argv, "cwd": os.path.realpath(os.getcwd()),
             "env": dict(os.environ), "params": params, "binds": binds, "report": report})
    reply = ch.recv()
    if not reply.get("ok"):
        raise ClientError(reply.get("error", "spawn refused"))
    notifiers: list[subprocess.Popen] = []
    try:
        for m in reply["mounts"]:
            mount_one(m, reply["mount_tool"])
        notifiers = start_notifiers(reply["mounts"], reply["notify_tool"])
        if use_pty:
            return _run_pty(ch, report)
        return _run_stdio(ch, report)
    finally:
        for p in notifiers:
            p.terminate()
        ch.sock.close()


def _handle(msgs, state: dict) -> None:
    for m in msgs:
        if "error" in m:
            state["error"] = m["error"]
        elif "report" in m:
            state["report"] = m["report"]
        elif "exit" in m:
            state["code"] = m["exit"]
        elif "signal" in m:
            state["code"] = 128 + m["signal"]
        elif m.get("ok") is False:
            state["error"] = m.get("error")


def _finish(state: dict) -> int:
    if state.get("report") is not None:
        print_report(state["report"])
    if "code" in state:
        if state.get("error"):
            print(f"amosjail: {state['error']}", file=sys.stderr)
        return state["code"]
    print(f"amosjail: {state.get('error') or 'amosjaild closed the connection'}", file=sys.stderr)
    return EXIT_ERROR


def _started(ch: Channel) -> None:
    m = ch.recv()
    if m.get("error") or m.get("ok") is False:
        raise ClientError(m.get("error"))
    if not m.get("started"):
        raise ClientError(f"unexpected reply {m}")


def _run_stdio(ch: Channel, report: bool) -> int:
    ch.send({"op": "go", "tty": False}, [0, 1, 2])
    _started(ch)
    state: dict = {}

    def forward(signum, frame):
        try:
            ch.send({"op": "signal", "sig": signum})
        except OSError:
            pass

    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2):
        signal.signal(s, forward)
    # The jail shares the terminal without being in its session: stopping
    # us would leave it reading the terminal behind the shell's back.
    signal.signal(signal.SIGTSTP, signal.SIG_IGN)
    while True:
        try:
            msgs = ch.ready()
        except InterruptedError:
            continue
        if msgs is None:
            return _finish(state)
        _handle(msgs, state)


def _run_pty(ch: Channel, report: bool) -> int:
    master, slave = os.openpty()
    try:
        termios.tcsetattr(slave, termios.TCSANOW, termios.tcgetattr(0))
        fcntl.ioctl(slave, termios.TIOCSWINSZ, _winsize(0))
        ch.send({"op": "go", "tty": True}, [slave])
    finally:
        os.close(slave)
    _started(ch)
    saved = termios.tcgetattr(0)
    state: dict = {}
    rfd, wfd = os.pipe()  # self-pipe for SIGWINCH and termination signals
    os.set_blocking(wfd, False)
    pending: list[int] = []

    def on_signal(signum, frame):
        pending.append(signum)
        try:
            os.write(wfd, b"!")
        except OSError:
            pass

    for s in (signal.SIGWINCH, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, on_signal)
    tty.setraw(0)
    master_open = True
    try:
        while True:
            fds = [ch.sock, rfd] + ([0, master] if master_open else [])
            try:
                ready, _, _ = select.select(fds, [], [])
            except InterruptedError:
                continue
            if rfd in ready:
                os.read(rfd, 64)
                while pending:
                    s = pending.pop()
                    if s == signal.SIGWINCH:
                        fcntl.ioctl(master, termios.TIOCSWINSZ, _winsize(0))
                    else:
                        ch.send({"op": "kill"})
            if master_open and master in ready:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    data = b""
                if data:
                    os.write(1, data)
                else:
                    master_open = False
            if master_open and 0 in ready:
                data = os.read(0, 65536)
                if data:
                    os.write(master, data)
            if ch.sock in ready:
                msgs = ch.ready()
                if msgs is None:
                    break
                _handle(msgs, state)
                if "code" in state:
                    _drain(master)
    finally:
        termios.tcsetattr(0, termios.TCSAFLUSH, saved)
        os.close(master)
    return _finish(state)


def _drain(master: int) -> None:
    os.set_blocking(master, False)
    while True:
        try:
            data = os.read(master, 65536)
        except OSError:
            return
        if not data:
            return
        os.write(1, data)


def print_report(lines: list[str]) -> None:
    """What report mode saw, de-duplicated: the input to a role (D-11)."""
    seen: dict[str, int] = {}
    for ln in lines:
        # "comm(pid) allow op target" -> "op target"
        parts = ln.split(" ", 2)
        key = parts[2] if len(parts) == 3 and parts[1].startswith(("allow", "deny")) else ln
        key = f"{parts[1]} {key}" if len(parts) == 3 else key
        seen[key] = seen.get(key, 0) + 1
    print(f"amosjail: report: {len(seen)} distinct operations", file=sys.stderr)
    for k in sorted(seen):
        print("  " + k, file=sys.stderr)


def request(socket_path: str, msg: dict) -> dict:
    ch = Channel(socket_path)
    try:
        ch.send(msg)
        return ch.recv()
    finally:
        ch.sock.close()


def dumps(o) -> str:
    return json.dumps(o, indent=2)
