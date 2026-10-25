"""A resolved role (config.Spec) as an SBPL profile (PLAN D-5, D-7, D-8).

Inside a chroot, Seatbelt matches the host spelling of a path (spike S-1),
so every jail path is emitted under the jail root's host path, in its
/private form. The daemon renders the profile per jail with the real root;
`amosjail profile` renders it with an example root.

SBPL is last-match-wins. Sections are emitted in a fixed order, so nothing a
fragment allows can undo a deny that comes later:

  1. (deny default)              or, in report mode, allow-and-report
  2. allows                      binds, exec, devices, mach, network, ...
  3. fragment sbpl
  4. denies                      per-bind deny lists (D-9), loopback
  5. exceptions                  allowed loopback ports and unix sockets
  6. the mandatory block         process isolation, TIOCSTI (always)
  7. fragment sbpl_final
"""

from __future__ import annotations

import posixpath
import re

from amosjail.config import DEFAULT_RW_DENY_WRITE, Spec, norm

TIOCSTI = 0x80017472

# Operations every jail gets. Fork and exec of allowed paths are useless
# without them, and sysctl-read is separately limited by the mandatory block.
BASELINE = """(allow process-fork)"""

# Not covered by (deny default) on macOS 27 (spike S-3): process info must
# be denied by name. Emitted after everything but sbpl_final.
MANDATORY = f"""\
(deny process-info*)
(deny sysctl-read (sysctl-name-prefix "kern.proc"))
(deny signal)
(deny mach-priv-task-port)
(deny mach-task-name)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(deny file-ioctl (ioctl-command #x{TIOCSTI:08x}))"""

PROC_NAMES = """\
(allow process-info-listpids)
(allow sysctl-read (sysctl-name "kern.proc.all"))"""

DEBUG = """\
(allow mach-priv-task-port (target same-sandbox))
(allow mach-task-name (target same-sandbox))"""


def host_path(p: str) -> str:
    """The spelling Seatbelt matches: /var, /tmp and /etc are firmlinks
    into /private on macOS."""
    p = norm(p)
    for top in ("/var", "/tmp", "/etc"):
        if p == top or p.startswith(top + "/"):
            return "/private" + p
    return p


def q(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rx(pattern: str) -> str:
    return '#"' + pattern.replace('"', '\\"') + '"'


def glob_to_regex(glob: str) -> str:
    """'**' crosses directories, '*' and '?' don't."""
    out, i = [], 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out.append("(.*/)?")
            i += 3
            continue
        if glob.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        out.append({"*": "[^/]*", "?": "[^/]"}.get(c, re.escape(c)))
        i += 1
    return "".join(out)


class Profile:
    def __init__(self, root: str):
        # root: the jail root's host path, e.g. /private/var/amosjail/501/j1/root
        self.root = host_path(root)

    def j(self, p: str) -> str:
        p = norm(p)
        return self.root if p == "/" else self.root + p

    def lit(self, p: str) -> str:
        return f"(literal {q(self.j(p))})"

    def sub(self, p: str) -> str:
        return f"(subpath {q(self.j(p))})"

    def pattern(self, p: str) -> str:
        """An exec or deny pattern in jail terms: 'dir/**' is a subpath,
        a path with no wildcard is that path and anything below it, anything
        else a regex."""
        if p.endswith("/**") and not re.search(r"[*?]", p[:-3]):
            return self.sub(p[:-3])
        if not re.search(r"[*?]", p):
            return self.sub(p)
        return f"(regex {rx('^' + re.escape(self.j('/')).rstrip('/') + glob_to_regex(norm(p)) + '$')})"


def _ancestors(p: str) -> list[str]:
    out = []
    p = posixpath.dirname(norm(p))
    while p != "/":
        out.append(p)
        p = posixpath.dirname(p)
    return out


def _anchor(target: str, pattern: str) -> list[str]:
    """Directories between a bind target and the first wildcard of one of
    its deny patterns. Renaming one of these would move the protected path
    out from under its rule (mv .git x; write x/hooks; mv x .git), so the
    directories themselves are made unwritable too."""
    fixed = []
    for part in pattern.split("/"):
        if re.search(r"[*?]", part):
            break
        fixed.append(part)
    else:
        fixed = fixed[:-1]  # the last component is the protected path itself
    out, cur = [], target
    for part in fixed:
        cur = posixpath.join(cur, part)
        out.append(cur)
    return out


def render(spec: Spec, root: str, tty: str | None = None, report: bool = False) -> str:
    """tty: the device name of the jail's terminal ("ttys005"), if any."""
    pr = Profile(root)
    out: list[str] = ["(version 1)"]
    if report:
        out.append("; report mode: anything not allowed below is allowed and logged")
        out.append("(allow default (with report))")
    else:
        out.append("(deny default)")
    out.append(BASELINE)

    # The jail root, the directories leading to every path we create, and
    # the links themselves.
    meta = {"/"}
    paths = [b.target for b in spec.binds] + list(spec.scratch) + list(spec.links) \
        + [s.target for s in spec.unix_sockets] + list(spec.devices) + ["/dev"]
    for p in paths:
        meta.update(_ancestors(p))
    meta.update(spec.links)
    meta.add("/dev")
    out.append("\n; jail root, directories on the way to every bind, and links")
    out.append("(allow file-read* " + " ".join(pr.lit(p) for p in sorted(meta)) + ")")

    out.append("\n; binds")
    for b in spec.binds:
        ops = "file-read*" if b.mode == "ro" else "file-read* file-write*"
        out.append(f"(allow {ops} {pr.sub(b.target)})  ; {b.fstype} {b.source}")
    if spec.scratch:
        out.append("(allow file-read* file-write* " + " ".join(pr.sub(s) for s in spec.scratch) + ")")

    if spec.exec:
        out.append("\n; exec")
        out.append("(allow process-exec* " + " ".join(pr.pattern(e) for e in spec.exec) + ")")

    out.append("\n; devices: /dev/fd only reopens the process's own fds")
    out.append(f"(allow file-read* file-write-data {pr.sub('/dev/fd')} "
               + " ".join(pr.lit(f"/dev/std{x}") for x in ("in", "out", "err")) + ")")
    if spec.devices:
        out.append("(allow file-read* file-write-data " + " ".join(pr.lit(d) for d in spec.devices) + ")")
    if tty:
        if not re.match(r"^ttys[0-9]+$", tty):
            raise ValueError(f"bad tty name {tty!r}")
        nodes = [q("/dev/" + tty), q(pr.j("/dev/" + tty)), q(pr.j("/dev/tty"))]
        out.append("(allow file-read* file-write-data file-ioctl "
                   + " ".join(f"(literal {n})" for n in nodes) + ")")

    if spec.sysctl_read:
        out.append("\n(allow sysctl-read)")
    if spec.mach:
        out.append("\n; mach services")
        out.append("(allow mach-lookup " + " ".join(f"(global-name {q(m)})" for m in spec.mach) + ")")
    if spec.iokit:
        out.append("(allow iokit-open " + " ".join(f"(iokit-user-client-class {q(c)})" for c in spec.iokit) + ")")

    if spec.network in ("proxy", "open"):
        out.append(f"\n; network = {spec.network}: outbound TCP, never UDP")
        out.append('(allow network-outbound (remote tcp "*:*"))')

    if spec.sbpl:
        out.append("\n; fragment sbpl")
        out.extend(s.strip() for s in spec.sbpl)

    denies = []
    for b in spec.binds:
        pats = list(b.deny_write)
        if b.mode == "rw" and b.deny_defaults:
            pats += DEFAULT_RW_DENY_WRITE
        anchors = sorted({a for pat in pats + list(b.deny) for a in _anchor(b.target, pat)})
        if anchors:
            denies.append("(deny file-write* " + " ".join(pr.lit(a) for a in anchors) + ")")
        if pats:
            denies.append("(deny file-write* " + " ".join(pr.pattern(posixpath.join(b.target, x)) for x in pats) + ")")
        if b.deny:
            denies.append("(deny file-read* file-write* process-exec* "
                          + " ".join(pr.pattern(posixpath.join(b.target, x)) for x in b.deny) + ")")
    if spec.network in ("proxy", "open"):
        # SBPL's localhost also covers 0.0.0.0, ::1 and the machine's own
        # addresses (measured).
        denies.append('(deny network-outbound (remote ip "localhost:*"))')
    if denies:
        out.append("\n; denies (D-9, D-10)")
        out.extend(denies)

    exc = []
    for lb in spec.loopback:
        # SBPL only takes "*" or "localhost" as the host: a loopback port
        # is open on every local address at once.
        exc.append(f"(allow network-outbound (remote tcp {q('localhost:' + lb.rsplit(':', 1)[1])}))")
    for s in spec.unix_sockets:
        exc.append(f"(allow network-outbound (remote unix-socket (path-literal {q(s.host)}) (path-literal {q(pr.j(s.target))})))")
        exc.append(f"(allow file-read* {pr.lit(s.target)})")
    if exc:
        out.append("\n; exceptions")
        out.extend(exc)

    out.append("\n; mandatory: process isolation and TIOCSTI (D-6, D-7)")
    out.append(MANDATORY)
    if spec.proc_visibility == "names":
        out.append(PROC_NAMES)
    if spec.debug:
        out.append(DEBUG)

    if spec.sbpl_final:
        out.append("\n; fragment sbpl_final")
        out.extend(s.strip() for s in spec.sbpl_final)
    return "\n".join(out) + "\n"
