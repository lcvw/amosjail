"""amosjaild: builds jails for callers and runs their commands in them
(PLAN §4, D-3, D-12).

One thread per client connection. The caller is whoever the kernel says is
on the other end of the socket (LOCAL_PEERTOKEN); nothing in a request
names a uid. The conversation:

    client                                  daemon
    {"op":"spawn", role, argv, ...}  ->     resolve role, create jail root
                                     <-     {"ok", jail, root, mounts}
    (mounts each bind itself)
    {"op":"go"} + SCM_RIGHTS stdio   ->     verify mounts, devfs, sockets,
                                            spawn amosjail-enter
                                     <-     {"started", asid}
    {"op":"signal", sig} ...         ->     (forwarded to the jail)
                                     <-     {"exit": n} | {"signal": n} | {"error"}
                                            teardown, close

A client that disconnects takes its jail down with it.
"""

from __future__ import annotations

import fcntl
import logging
import os
import pwd
import signal
import socket
import subprocess
import threading
import time
from dataclasses import asdict

from amosjail import amosproxy, compile, config, jails, mounts
from amosjail._vendor import protocol
from amosjail._vendor.darwin import peer_token

logger = logging.getLogger("amosjaild")

FORWARDED_SIGNALS = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT,
                     signal.SIGCONT, signal.SIGUSR1, signal.SIGUSR2, signal.SIGWINCH}


class Conn:
    """Line-delimited JSON over a unix socket, with fds alongside."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""
        self.fds: list[int] = []
        self.wlock = threading.Lock()

    def recv(self) -> dict | None:
        while b"\n" not in self.buf:
            try:
                data, fds, _flags, _addr = socket.recv_fds(self.sock, 65536, 8)
            except OSError:
                return None
            for fd in fds:
                fcntl.fcntl(fd, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
            self.fds += fds
            if not data:
                return None
            self.buf += data
            if len(self.buf) > protocol.MAX_LINE:
                raise ValueError("request too long")
        line, self.buf = self.buf.split(b"\n", 1)
        return protocol.decode(line)

    def take_fds(self) -> list[int]:
        fds, self.fds = self.fds, []
        return fds

    def send(self, msg: dict) -> None:
        with self.wlock:
            try:
                self.sock.sendall(protocol.encode(msg))
            except OSError:
                pass

    def close(self) -> None:
        for fd in self.take_fds():
            os.close(fd)
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class Jail:
    def __init__(self, st: jails.State, spec: config.Spec, report: bool):
        self.st = st
        self.spec = spec
        self.report = report
        self.started = time.time()
        self.pids: set[int] = set()  # sampled members, for report mode
        self.conn: Conn | None = None
        self.lock = threading.Lock()
        self.down = False


class Daemon:
    def __init__(self, path: str | None = None):
        self.config_path = path or config.config_path()
        cfg = config.privileged(config.load(self.config_path))
        # Root's settings are fixed at startup; roles are re-read per spawn.
        self.settings = cfg.daemon
        self.proxy = cfg.amosproxy
        self.jails: dict[str, Jail] = {}
        self.draining: dict[str, jails.State] = {}  # stopped, waiting to unmount
        self.lock = threading.Lock()

    # --- lifecycle -------------------------------------------------------

    def run(self) -> int:
        if os.geteuid() != 0:
            logger.error("amosjaild must run as root")
            return 1
        jails.check_root_dir(self.settings.jail_dir)
        jails.check_root_dir(self.settings.state_dir)
        st = os.stat(self.settings.enter)
        if st.st_uid != 0 or st.st_mode & 0o022:
            logger.error("%s must be root-owned and not writable by others", self.settings.enter)
            return 1
        self.reap()
        self.apply_exemptions()
        path = self.settings.socket
        if os.path.lexists(path):
            os.unlink(path)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        os.chmod(path, 0o666)  # anyone may ask; each request is checked
        srv.listen(64)
        threading.Thread(target=self.monitor, daemon=True).start()
        logger.info("listening on %s (config %s)", path, self.config_path)
        stop = threading.Event()

        def on_term(signum, frame):
            stop.set()
            srv.close()

        signal.signal(signal.SIGTERM, on_term)
        signal.signal(signal.SIGINT, on_term)
        while not stop.is_set():
            try:
                sock, _ = srv.accept()
            except OSError:
                break
            threading.Thread(target=self.handle, args=(sock,), daemon=True).start()
        for j in list(self.jails.values()):
            self.teardown(j, "daemon stopping")
        # Mounts still busy are left for the next start's reaper.
        if os.path.lexists(path):
            os.unlink(path)
        return 0

    def reap(self) -> None:
        """Jails left by a daemon that died: kill and remove them."""
        sd = self.settings.state_dir
        for name in os.listdir(sd):
            if not (name.startswith("j") and name.endswith(".json")):
                continue
            try:
                st = jails.State.load(os.path.join(sd, name))
            except (OSError, ValueError, TypeError) as e:
                logger.warning("reaper: unreadable state %s: %s", name, e)
                continue
            logger.info("reaper: removing jail %s (uid %d)", st.id, st.uid)
            jails.stop(st, sd, untag=lambda a: amosproxy.untag(self.proxy, a))
            if not jails.release(st, sd):
                self.draining[st.id] = st

    def apply_exemptions(self) -> None:
        try:
            amosproxy.reconcile_exemptions(self.proxy, self.settings.state_dir)
        except amosproxy.AmosproxyError as e:
            if self.proxy.exempt:
                logger.warning("exemptions not applied: %s", e)

    def monitor(self) -> None:
        """Tear down jails whose volumes vanished (a fskitd restart drops
        every FSKit mount, and execs then die in dyld), and sample members
        for report mode."""
        last_drain = 0.0
        while True:
            time.sleep(1.0)
            if time.time() - last_drain > 5:
                last_drain = time.time()
                for st in list(self.draining.values()):
                    if jails.release(st, self.settings.state_dir):
                        logger.info("jail %s: unmounted and removed after %.0fs", st.id, time.time() - st.created)
                        self.draining.pop(st.id, None)
            for j in list(self.jails.values()):
                if j.down or j.st.asid is None:
                    continue
                for m in j.st.mounts:
                    try:
                        ok = mounts.statfs(m.target).on == m.target
                    except OSError:
                        ok = False
                    if not ok:
                        logger.warning("jail %s: %s is no longer mounted", j.st.id, m.target)
                        if j.conn:
                            j.conn.send({"error": f"{m.target} is no longer mounted; jail stopped"})
                        self.teardown(j, "volume vanished")
                        break
                if j.report and not j.down:
                    j.pids.update(jails.asid_members(j.st.asid))

    # --- requests --------------------------------------------------------

    def handle(self, sock: socket.socket) -> None:
        conn = Conn(sock)
        try:
            token = peer_token(sock)
            while (msg := conn.recv()) is not None:
                op = msg.get("op")
                if op == "spawn":
                    self.spawn(conn, token, msg)
                    return  # spawn owns the connection until the jail ends
                elif op == "status":
                    conn.send(self.status(token))
                elif op == "kill":
                    conn.send(self.kill(token, msg.get("jail")))
                else:
                    conn.send({"ok": False, "error": f"unknown op {op!r}"})
        except Exception as e:
            logger.exception("connection failed")
            conn.send({"ok": False, "error": str(e)})
        finally:
            conn.close()

    def status(self, token) -> dict:
        out = []
        for j in list(self.jails.values()):
            if token.euid in (0, j.st.uid):
                out.append({"jail": j.st.id, "role": j.st.role, "uid": j.st.uid, "pid": j.st.pid,
                            "asid": j.st.asid, "root": j.st.root, "created": j.st.created})
        return {"ok": True, "jails": out}

    def kill(self, token, jid) -> dict:
        j = self.jails.get(jid) if isinstance(jid, str) else None
        if j is None or token.euid not in (0, j.st.uid):
            return {"ok": False, "error": f"no jail {jid!r}"}
        if j.conn:
            j.conn.send({"error": "killed by amosjail kill"})
        self.teardown(j, "killed")
        return {"ok": True}

    def caller(self, token, msg: dict) -> config.Caller:
        uid = token.euid
        if uid == 0:
            raise ValueError("run amosjail as the user the jail is for, not root")
        pw = pwd.getpwuid(uid)
        cwd = msg.get("cwd")
        env = msg.get("env") or {}
        if not isinstance(cwd, str) or not cwd.startswith("/"):
            raise ValueError("cwd must be an absolute path")
        if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
            raise ValueError("env must map strings to strings")
        return config.Caller(uid=uid, gid=pw.pw_gid, user=pw.pw_name, home=pw.pw_dir, cwd=cwd,
                             groups=tuple(os.getgrouplist(pw.pw_name, pw.pw_gid)), env=env)

    def spawn(self, conn: Conn, token, msg: dict) -> None:
        argv = msg.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
            raise ValueError("argv must be a non-empty list of strings")
        caller = self.caller(token, msg)
        cfg = config.load(self.config_path)
        binds = [config.parse_cli_bind(b) for b in msg.get("binds") or []]
        params = msg.get("params") or {}
        spec = config.resolve(cfg, str(msg.get("role")), caller, params=params, cli_binds=binds)
        if spec.network == "proxy":
            amosproxy.request(self.proxy.socket, {"op": "status"})  # fail before building anything
            self.apply_exemptions()
        st = jails.create(spec, caller.uid, caller.gid, self.settings.jail_dir)
        j = Jail(st, spec, bool(msg.get("report")))
        j.conn = conn
        with self.lock:
            self.jails[st.id] = j
        st.save(self.settings.state_dir)
        logger.info("jail %s: role %s for uid %d", st.id, spec.role, caller.uid)
        try:
            conn.send({"ok": True, "jail": st.id, "root": st.root,
                       "mounts": [asdict(m) for m in st.mounts], "mount_tool": cfg.mosbind.mount,
                       "notify_tool": cfg.mosbind.notify})
            go = conn.recv()
            if go is None or go.get("op") != "go":
                return
            fds = conn.take_fds()
            try:
                pid = self.start(j, caller, argv, fds, bool(go.get("tty")))
            finally:
                for fd in fds:
                    os.close(fd)
            conn.send({"started": True, "jail": st.id, "asid": st.asid})
            threading.Thread(target=self.wait, args=(j, pid), daemon=True).start()
            while (m := conn.recv()) is not None:
                if m.get("op") == "signal":
                    sig = m.get("sig")
                    if isinstance(sig, int) and sig in FORWARDED_SIGNALS and not j.down:
                        try:
                            os.killpg(pid, sig)
                        except ProcessLookupError:
                            pass
                elif m.get("op") == "kill":
                    break
        except Exception as e:
            logger.warning("jail %s: %s", st.id, e)
            conn.send({"error": str(e)})
        finally:
            self.teardown(j, "client gone")

    def start(self, j: Jail, caller: config.Caller, argv: list[str], fds: list[int], pty: bool) -> int:
        st, spec = j.st, j.spec
        if len(fds) != (1 if pty else 3):
            raise ValueError("go: expected 1 fd (pty) or 3 (stdio)")
        stdio = fds * 3 if pty else fds
        jails.verify(st)
        jails.finish(st, spec)
        tty = None
        if os.isatty(stdio[0]):
            name = os.path.basename(os.ttyname(stdio[0]))
            tty = name if name.startswith("ttys") else None
        profile = compile.render(spec, st.root, tty=tty, report=j.report)

        args = [self.settings.enter, "--root", st.root, "--uid", str(st.uid), "--gid", str(st.gid),
                # setgroups takes at most 16 (NGROUPS); the kernel resolves
                # further memberships through opendirectoryd.
                "--groups", ",".join(str(g) for g in caller.groups[:16]), "--cwd", spec.cwd]
        if pty:
            args.append("--tty")
        if spec.network == "proxy":
            args += ["--tag", spec.proxy_label, "--amosproxy", self.proxy.socket]
        for k, v in spec.rlimits.items():
            args += ["--rlimit", f"{k}={v}"]
        args += ["--", *argv]

        prof_r, prof_w = os.pipe()
        stat_r, stat_w = os.pipe()
        ctl_r, ctl_w = os.pipe()
        # Lift every source above the target numbers so the dup2s can't clobber each other.
        srcs = [fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 64) for fd in [*stdio, prof_r, stat_w, ctl_r]]
        try:
            pid = os.posix_spawn(
                self.settings.enter, args, spec.env,
                file_actions=[(os.POSIX_SPAWN_DUP2, fd, i) for i, fd in enumerate(srcs)],
                **({} if pty else {"setpgroup": 0}))
        finally:
            for fd in (*srcs, prof_r, stat_w, ctl_r):
                os.close(fd)
        st.pid = pid
        with os.fdopen(prof_w, "w") as f:
            f.write(profile)
        status = os.fdopen(stat_r, "r")
        try:
            line = status.readline().strip()
            if not line.startswith("asid "):
                raise jails.JailError(f"amosjail-enter: {line or 'exited early'}")
            st.asid = int(line.split()[1])
            st.save(self.settings.state_dir)
            if spec.network == "proxy":
                line = status.readline().strip()
                if not line.startswith("tag "):
                    raise jails.JailError(f"amosjail-enter: {line or 'exited early'}")
                amosproxy.check_tag_reply(line[4:], st.asid, self.proxy)
            os.write(ctl_w, b"y")
            rest = status.read().strip()
            if rest:
                raise jails.JailError(f"amosjail-enter: {rest.removeprefix('error ')}")
        finally:
            status.close()
            os.close(ctl_w)
        logger.info("jail %s: pid %d asid %d: %s", st.id, pid, st.asid, argv[0])
        return pid

    def wait(self, j: Jail, pid: int) -> None:
        _, ws = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(ws)
        if j.report and j.conn:
            j.conn.send({"report": self.collect_report(j)})
        if j.conn:
            j.conn.send({"exit": code} if code >= 0 else {"signal": -code})
        self.teardown(j, f"exited {code}")
        if j.conn:
            # wakes the connection thread blocked in recv
            try:
                j.conn.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def collect_report(self, j: Jail) -> list[str]:
        """Sandbox log lines for the jail's processes (D-11), best effort:
        short-lived processes the sampler missed show up only when their
        target names the jail root."""
        start = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(j.started - 1))
        r = subprocess.run(["/usr/bin/log", "show", "--style", "compact", "--start", start,
                            "--predicate", 'sender == "Sandbox"'], capture_output=True, text=True)
        pids = {str(p) for p in j.pids | {j.st.pid}}
        out = []
        for line in r.stdout.splitlines():
            i = line.find("Sandbox: ")
            if i < 0:
                continue
            msg = line[i + 9:]
            pid = msg.split("(", 1)[1].split(")", 1)[0] if "(" in msg else ""
            if pid in pids or j.st.root in msg:
                out.append(msg.replace(j.st.root, ""))
        return out

    def teardown(self, j: Jail, why: str) -> None:
        with j.lock:
            if j.down:
                return
            j.down = True
        logger.info("jail %s: teardown (%s)", j.st.id, why)
        untag = (lambda a: amosproxy.untag(self.proxy, a)) if j.spec.network == "proxy" else None
        jails.stop(j.st, self.settings.state_dir, untag=untag)
        with self.lock:
            self.jails.pop(j.st.id, None)
            if not jails.release(j.st, self.settings.state_dir):
                logger.info("jail %s: mounts busy, draining", j.st.id)
                self.draining[j.st.id] = j.st


def main(path: str | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    return Daemon(path).run()
