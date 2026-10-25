"""The one config file (PLAN D-13, D-15) and role resolution.

`/etc/amosjail/amosjail.toml` holds amosjail's own settings and those of the
two components it drives: `[amosproxy]` (the daemon's flags and the
exemptions amosjail keeps applied) and `[mosbind]` (the tools it mounts
with). Fragments and roles say what a jail sees and may do.

The file may be owned by anyone, so nothing in it is authority: a role only
ever narrows what the caller's own uid could do, and the daemon acts only
inside its root-owned `jail_dir`. Every table and key is checked; an unknown
key is an error, not a silent no-op.
"""

from __future__ import annotations

import os
import posixpath
import re
import tomllib
from dataclasses import dataclass, field, replace

DEFAULT_PATH = "/etc/amosjail/amosjail.toml"


def config_path() -> str:
    # The override is for tests; the daemon's path is fixed (D-13).
    return os.environ.get("AMOSJAIL_CONFIG", DEFAULT_PATH)


class ConfigError(ValueError):
    pass


# --- component settings ---------------------------------------------------


@dataclass(frozen=True)
class DaemonSettings:
    socket: str = "/var/run/amosjaild.sock"
    jail_dir: str = "/var/amosjail"
    state_dir: str = "/var/db/amosjail"
    enter: str = "/usr/local/libexec/amosjail-enter"


@dataclass(frozen=True)
class AmosproxySettings:
    """amosproxy's daemon flags, so `amosjail amosproxy` can start it the
    way the jails expect, plus the exemptions amosjaild keeps applied."""

    command: tuple[str, ...] = ("amosproxy",)
    socket: str = "/var/run/amosproxy.sock"
    ext_socket: str = "/var/run/amosproxy-ext.sock"
    socks_port: int = 0
    confdir: str = "/var/db/amosproxy"
    flowlog: str = "/var/log/amosproxy/flows.jsonl"
    public_dir: str = "/Library/Application Support/amosproxy"
    gc_interval: float = 30.0
    exempt: tuple[str, ...] = ()

    def ca_paths(self) -> dict[str, str]:
        # Names published by amosproxy's catrust.publish.
        return {
            "bundle": posixpath.join(self.public_dir, "ca-bundle.pem"),
            "cert": posixpath.join(self.public_dir, "mitmproxy-ca.pem"),
        }

    def ca_env(self) -> dict[str, str]:
        # Same variables as amosproxy's catrust.environment.
        p = self.ca_paths()
        env = {v: p["bundle"] for v in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT")}
        env["NODE_EXTRA_CA_CERTS"] = p["cert"]
        return env

    def daemon_argv(self, exempt_file: str | None) -> list[str]:
        argv = [*self.command, "--socket", self.socket, "daemon",
                "--ext-socket", self.ext_socket, "--socks-port", str(self.socks_port),
                "--confdir", self.confdir, "--flowlog", self.flowlog,
                "--public-dir", self.public_dir, "--gc-interval", str(self.gc_interval)]
        if exempt_file:
            argv += ["--exempt-file", exempt_file]
        return argv


@dataclass(frozen=True)
class MosbindSettings:
    mount: str = "/sbin/mount"
    umount: str = "/sbin/umount"
    notify: str = "mosbind-notify"


# --- fragments and roles --------------------------------------------------


@dataclass(frozen=True)
class Notify:
    """Run `mosbind-notify <mount> <match> <command...>` for the jail's
    lifetime: the command allows or denies each matching open and exec."""

    match: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class Bind:
    source: str  # host path (the overlay's upper for type = "overlay")
    target: str  # path inside the jail
    mode: str = "ro"  # ro | rw
    type: str = "bind"  # bind (mosbind) | overlay (mosoverlay)
    lower: tuple[str, ...] = ()
    workdir: str | None = None
    deny: tuple[str, ...] = ()  # no access at all (secrets)
    deny_write: tuple[str, ...] = ()  # readable, never writable (E13)
    deny_defaults: bool = True
    notify: Notify | None = None

    @property
    def fstype(self) -> str:
        return "mosbind" if self.type == "bind" else "mosoverlay"


@dataclass(frozen=True)
class Socket:
    """A host unix socket hard-linked into the jail root (FSKit volumes
    can't carry sockets), and allowed by the profile."""

    host: str
    target: str


# D-9: rw binds make these read-only unless deny_defaults = false.
DEFAULT_RW_DENY_WRITE = (".git/hooks/**", ".git/config", ".envrc", ".direnv/**",
                   ".vscode/**", ".idea/**", "**/.husky/**")

DNS_SOCKET = Socket(host="/private/var/run/mDNSResponder", target="/private/var/run/mDNSResponder")

NETWORK_MODES = ("none", "proxy", "open")
PROC_VISIBILITY = ("jail", "names")
RLIMITS = {"nproc": "RLIMIT_NPROC", "nofile": "RLIMIT_NOFILE", "core": "RLIMIT_CORE",
           "cpu": "RLIMIT_CPU", "fsize": "RLIMIT_FSIZE", "data": "RLIMIT_DATA",
           "stack": "RLIMIT_STACK", "as": "RLIMIT_AS"}
LABEL_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass(frozen=True)
class Fragment:
    """What a fragment (or a role's own body) contributes. Lists add up
    across fragments; env and links merge with later fragments winning;
    cwd is the last one set."""

    binds: tuple[Bind, ...] = ()
    scratch: tuple[str, ...] = ()  # empty dirs in the jail root, owned by the caller
    links: tuple[tuple[str, str], ...] = ()  # jail path -> symlink text
    exec: tuple[str, ...] = ()
    mach: tuple[str, ...] = ()
    iokit: tuple[str, ...] = ()
    devices: tuple[str, ...] = ()
    sysctl_read: bool | None = None
    unix_sockets: tuple[Socket, ...] = ()
    env_set: tuple[tuple[str, str], ...] = ()
    env_pass: tuple[str, ...] = ()
    cwd: str | None = None
    sbpl: tuple[str, ...] = ()
    sbpl_final: tuple[str, ...] = ()


@dataclass(frozen=True)
class Role:
    name: str
    body: Fragment
    fragments: tuple[str, ...] = ()
    network: str = "none"
    proxy_label: str | None = None
    ca_env: bool = True
    dns: bool = False
    loopback: tuple[str, ...] = ()
    proc_visibility: str = "jail"
    debug: bool = False
    allowed_users: tuple[str, ...] = ()  # empty: anyone
    cli_binds: str = "none"  # none | ro | rw: what `run --bind` may add
    cli_params: tuple[str, ...] = ()
    params: tuple[tuple[str, str], ...] = ()  # defaults, may use ${CWD} etc.
    rlimits: tuple[tuple[str, int], ...] = ()


@dataclass(frozen=True)
class Config:
    path: str
    daemon: DaemonSettings
    amosproxy: AmosproxySettings
    mosbind: MosbindSettings
    fragments: dict[str, Fragment]
    roles: dict[str, Role]


# --- parsing --------------------------------------------------------------


class _T:
    """A TOML table being consumed, so leftover keys can be reported."""

    def __init__(self, data, where: str):
        if not isinstance(data, dict):
            raise ConfigError(f"{where}: expected a table")
        self.data = dict(data)
        self.where = where

    def _get(self, key, kind, default, check=None):
        if key not in self.data:
            return default
        v = self.data.pop(key)
        if kind is float and isinstance(v, int) and not isinstance(v, bool):
            v = float(v)
        if not isinstance(v, kind) or (kind is int and isinstance(v, bool)):
            raise ConfigError(f"{self.where}.{key}: expected {kind.__name__}")
        if check and not check(v):
            raise ConfigError(f"{self.where}.{key}: invalid value {v!r}")
        return v

    def str(self, key, default=None, choices=None):
        return self._get(key, str, default, (lambda v: v in choices) if choices else None)

    def bool(self, key, default=None):
        return self._get(key, bool, default)

    def int(self, key, default=None):
        return self._get(key, int, default)

    def float(self, key, default=None):
        return self._get(key, float, default)

    def strs(self, key, default=()):
        v = self._get(key, list, None)
        if v is None:
            return tuple(default)
        if not all(isinstance(x, str) for x in v):
            raise ConfigError(f"{self.where}.{key}: expected a list of strings")
        return tuple(v)

    def table(self, key):
        if key not in self.data:
            return _T({}, f"{self.where}.{key}")
        return _T(self.data.pop(key), f"{self.where}.{key}")

    def tables(self, key):
        v = self._get(key, list, [])
        return [_T(x, f"{self.where}.{key}[{i}]") for i, x in enumerate(v)]

    def str_map(self, key):
        t = self.table(key)
        out = {}
        for k in list(t.data):
            out[k] = t.str(k)
        return out

    def done(self):
        if self.data:
            raise ConfigError(f"{self.where}: unknown key(s) {', '.join(sorted(self.data))}")


def _absolute(where: str, p: str, allow_vars: bool = True) -> str:
    if not (p.startswith("/") or (allow_vars and p.startswith("${"))):
        raise ConfigError(f"{where}: {p!r} must be an absolute path")
    return p


def _parse_bind(t: _T) -> Bind:
    source = _absolute(t.where + ".source", t.str("source") or "")
    target = _absolute(t.where + ".target", t.str("target") or "")
    b = Bind(
        source=source,
        target=target,
        mode=t.str("mode", "ro", choices=("ro", "rw")),
        type=t.str("type", "bind", choices=("bind", "overlay")),
        lower=t.strs("lower"),
        workdir=t.str("workdir"),
        deny=t.strs("deny"),
        deny_write=t.strs("deny_write"),
        deny_defaults=t.bool("deny_defaults", True),
    )
    nt = t.data.get("notify")
    if nt is not None:
        n = t.table("notify")
        match, command = n.str("match"), n.strs("command")
        if not match or not command:
            raise ConfigError(f"{n.where}: needs match and command")
        n.done()
        b = replace(b, notify=Notify(match=match, command=command))
    t.done()
    if b.type == "overlay":
        if not b.lower:
            raise ConfigError(f"{t.where}: an overlay needs lower = [...]")
        if b.mode == "rw" and not b.workdir:
            raise ConfigError(f"{t.where}: a rw overlay needs workdir")
    elif b.lower or b.workdir:
        raise ConfigError(f"{t.where}: lower and workdir are for type = \"overlay\"")
    return b


_FRAGMENT_KEYS = ("binds", "scratch", "links", "exec", "mach", "iokit", "devices",
                  "sysctl_read", "unix_sockets", "env", "cwd", "sbpl", "sbpl_final")


def _parse_fragment_body(t: _T) -> Fragment:
    binds = tuple(_parse_bind(b) for b in t.tables("binds"))
    sockets = []
    for s in t.tables("unix_sockets"):
        sockets.append(Socket(host=_absolute(s.where, s.str("host") or ""),
                              target=_absolute(s.where, s.str("target") or "")))
        s.done()
    env = t.table("env")
    env_set = env.str_map("set")
    env_pass = env.strs("pass")
    env.done()
    links = t.str_map("links")
    for k in links:
        _absolute(f"{t.where}.links", k)
    return Fragment(
        binds=binds,
        scratch=tuple(_absolute(t.where + ".scratch", p) for p in t.strs("scratch")),
        links=tuple(links.items()),
        exec=tuple(_absolute(t.where + ".exec", p) for p in t.strs("exec")),
        mach=t.strs("mach"),
        iokit=t.strs("iokit"),
        devices=tuple(_absolute(t.where + ".devices", p) for p in t.strs("devices")),
        sysctl_read=t.bool("sysctl_read"),
        unix_sockets=tuple(sockets),
        env_set=tuple(env_set.items()),
        env_pass=env_pass,
        cwd=t.str("cwd"),
        sbpl=(t.str("sbpl"),) if "sbpl" in t.data else (),
        sbpl_final=(t.str("sbpl_final"),) if "sbpl_final" in t.data else (),
    )


def _parse_role(name: str, t: _T) -> Role:
    proxy = t.table("proxy")
    label = proxy.str("label", name)
    if not LABEL_RE.match(label):
        raise ConfigError(f"{proxy.where}.label: use letters, digits, '.', '_', '-'")
    ca_env = proxy.bool("ca_env", True)
    proxy.done()
    cli = t.table("cli")
    cli_binds = cli.str("binds", "none", choices=("none", "ro", "rw"))
    cli_params = cli.strs("params")
    cli.done()
    params = t.str_map("params")
    rl = t.table("rlimits")
    rlimits = {}
    for k in list(rl.data):
        if k not in RLIMITS:
            raise ConfigError(f"{rl.where}: unknown limit {k!r} (one of {', '.join(RLIMITS)})")
        rlimits[k] = rl.int(k)
    role = Role(
        name=name,
        body=Fragment(),
        fragments=t.strs("fragments"),
        network=t.str("network", "none", choices=NETWORK_MODES),
        proxy_label=label,
        ca_env=ca_env,
        dns=t.bool("dns", False),
        loopback=t.strs("loopback"),
        proc_visibility=t.str("proc_visibility", "jail", choices=PROC_VISIBILITY),
        debug=t.bool("debug", False),
        allowed_users=t.strs("allowed_users"),
        cli_binds=cli_binds,
        cli_params=cli_params,
        params=tuple(params.items()),
        rlimits=tuple(rlimits.items()),
    )
    for lb in role.loopback:
        if not re.match(r"^(\*|[0-9.]+|localhost):(\*|[0-9]{1,5})$", lb):
            raise ConfigError(f"{t.where}.loopback: {lb!r} is not host:port")
    return replace(role, body=_parse_fragment_body(t))


def parse(text: str, path: str = "<string>") -> Config:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None
    top = _T(data, path)

    d = top.table("daemon")
    daemon = DaemonSettings(
        socket=d.str("socket", DaemonSettings.socket),
        jail_dir=d.str("jail_dir", DaemonSettings.jail_dir),
        state_dir=d.str("state_dir", DaemonSettings.state_dir),
        enter=d.str("enter", DaemonSettings.enter),
    )
    d.done()
    for k in ("socket", "jail_dir", "state_dir", "enter"):
        _absolute(f"{path}.daemon.{k}", getattr(daemon, k), allow_vars=False)

    a = top.table("amosproxy")
    dflt = AmosproxySettings()
    amosproxy = AmosproxySettings(
        command=a.strs("command", dflt.command),
        socket=a.str("socket", dflt.socket),
        ext_socket=a.str("ext_socket", dflt.ext_socket),
        socks_port=a.int("socks_port", dflt.socks_port),
        confdir=a.str("confdir", dflt.confdir),
        flowlog=a.str("flowlog", dflt.flowlog),
        public_dir=a.str("public_dir", dflt.public_dir),
        gc_interval=a.float("gc_interval", dflt.gc_interval),
        exempt=a.strs("exempt"),
    )
    a.done()
    if not amosproxy.command:
        raise ConfigError(f"{path}.amosproxy.command: must not be empty")

    m = top.table("mosbind")
    mosbind = MosbindSettings(
        mount=m.str("mount", MosbindSettings.mount),
        umount=m.str("umount", MosbindSettings.umount),
        notify=m.str("notify", MosbindSettings.notify),
    )
    m.done()

    fragments = {}
    ft = top.table("fragments")
    for name in list(ft.data):
        if not NAME_RE.match(name):
            raise ConfigError(f"{ft.where}: bad fragment name {name!r}")
        t = ft.table(name)
        fragments[name] = _parse_fragment_body(t)
        t.done()

    roles = {}
    rt = top.table("roles")
    for name in list(rt.data):
        if not NAME_RE.match(name):
            raise ConfigError(f"{rt.where}: bad role name {name!r}")
        t = rt.table(name)
        roles[name] = _parse_role(name, t)
        t.done()
        for f in roles[name].fragments:
            if f not in fragments:
                raise ConfigError(f"{t.where}.fragments: no fragment named {f!r}")
    top.done()
    return Config(path=path, daemon=daemon, amosproxy=amosproxy, mosbind=mosbind,
                  fragments=fragments, roles=roles)


def load(path: str | None = None) -> Config:
    path = path or config_path()
    try:
        with open(path, "rb") as f:
            text = f.read().decode()
    except OSError as e:
        raise ConfigError(f"{path}: {e.strerror}") from None
    return parse(text, path)


# --- resolution -----------------------------------------------------------


@dataclass(frozen=True)
class Caller:
    """Who the jail is for, from the kernel's view of the socket peer."""

    uid: int
    gid: int
    user: str
    home: str
    cwd: str
    groups: tuple[int, ...] = ()
    env: dict[str, str] = field(default_factory=dict)  # the client's, for env.pass only


@dataclass(frozen=True)
class Spec:
    """A role resolved for one caller: everything the daemon, the client
    and the compiler need, with all ${VARS} substituted."""

    role: str
    binds: tuple[Bind, ...]
    scratch: tuple[str, ...]
    links: dict[str, str]
    exec: tuple[str, ...]
    mach: tuple[str, ...]
    iokit: tuple[str, ...]
    devices: tuple[str, ...]
    sysctl_read: bool
    unix_sockets: tuple[Socket, ...]
    env: dict[str, str]
    cwd: str
    sbpl: tuple[str, ...]
    sbpl_final: tuple[str, ...]
    network: str
    proxy_label: str | None
    ca_env: bool
    dns: bool
    loopback: tuple[str, ...]
    proc_visibility: str
    debug: bool
    rlimits: dict[str, int]


def norm(p: str) -> str:
    """Normalise a jail or host path: absolute, no '.', '..' or '//'."""
    n = posixpath.normpath(p)
    if n.startswith("//"):
        n = "/" + n.lstrip("/")
    return n


def within(path: str, parent: str) -> bool:
    return parent == "/" or path == parent or path.startswith(parent.rstrip("/") + "/")


def _subst(s: str, vars: dict[str, str], where: str) -> str:
    def one(m):
        k = m.group(1)
        if k not in vars:
            raise ConfigError(f"{where}: ${{{k}}} is not defined (have {', '.join(sorted(vars))})")
        return vars[k]

    return VAR_RE.sub(one, s)


def parse_cli_bind(arg: str) -> Bind:
    parts = arg.split(":")
    if len(parts) == 2:
        parts.append("ro")
    if len(parts) != 3 or parts[2] not in ("ro", "rw") or not parts[0] or not parts[1]:
        raise ConfigError(f"--bind {arg!r}: expected SRC:DST[:ro|rw]")
    return Bind(source=parts[0], target=parts[1], mode=parts[2])


def resolve(cfg: Config, role_name: str, caller: Caller,
            params: dict[str, str] | None = None, cli_binds: list[Bind] | None = None) -> Spec:
    role = cfg.roles.get(role_name)
    if role is None:
        raise ConfigError(f"no role {role_name!r} (have {', '.join(sorted(cfg.roles)) or 'none'})")
    if role.allowed_users and caller.user not in role.allowed_users:
        raise ConfigError(f"role {role_name!r} is not available to {caller.user}")
    params = params or {}
    for k in params:
        if k not in role.cli_params:
            raise ConfigError(f"role {role_name!r} does not take --param {k}")
    cli_binds = cli_binds or []
    if cli_binds and role.cli_binds == "none":
        raise ConfigError(f"role {role_name!r} does not take --bind")
    for b in cli_binds:
        if b.mode == "rw" and role.cli_binds != "rw":
            raise ConfigError(f"role {role_name!r} allows only read-only --bind")

    vars = {"HOME": caller.home, "USER": caller.user, "CWD": caller.cwd,
            "UID": str(caller.uid)}
    for k, v in role.params:
        vars[k] = _subst(v, vars, f"roles.{role_name}.params.{k}")
    vars.update(params)

    parts = [cfg.fragments[f] for f in role.fragments] + [role.body]
    binds: list[Bind] = []
    scratch, exec_, mach, iokit, devices, sockets = [], [], [], [], [], []
    links: dict[str, str] = {}
    env: dict[str, str] = {}
    env_pass: list[str] = []
    sbpl, sbpl_final = [], []
    sysctl_read = False
    cwd = None
    where = f"roles.{role_name}"

    def p(path, what):
        return norm(_subst(path, vars, f"{where} ({what})"))

    for fr in parts:
        for b in fr.binds:
            binds.append(replace(
                b, source=p(b.source, "bind source"), target=p(b.target, "bind target"),
                lower=tuple(p(x, "overlay lower") for x in b.lower),
                workdir=p(b.workdir, "overlay workdir") if b.workdir else None,
                notify=replace(b.notify, command=tuple(_subst(c, vars, where) for c in b.notify.command))
                if b.notify else None))
        scratch += [p(x, "scratch") for x in fr.scratch]
        links.update({p(k, "link"): v for k, v in fr.links})
        exec_ += [p(x, "exec") for x in fr.exec]
        mach += fr.mach
        iokit += fr.iokit
        devices += [p(x, "device") for x in fr.devices]
        sockets += [Socket(host=p(s.host, "socket"), target=p(s.target, "socket")) for s in fr.unix_sockets]
        env.update({k: _subst(v, vars, f"{where} env.{k}") for k, v in fr.env_set})
        env_pass += fr.env_pass
        sbpl += fr.sbpl
        sbpl_final += fr.sbpl_final
        if fr.sysctl_read is not None:
            sysctl_read = fr.sysctl_read
        if fr.cwd is not None:
            cwd = p(fr.cwd, "cwd")

    for b in cli_binds:
        src = b.source if b.source.startswith("/") else posixpath.join(caller.cwd, b.source)
        binds.append(replace(b, source=norm(src), target=norm(b.target)))

    if role.dns:
        sockets.append(DNS_SOCKET)
    if role.network == "proxy" and role.ca_env:
        env.update(cfg.amosproxy.ca_env())
        if not any(b.mode == "ro" and within(cfg.amosproxy.public_dir, b.target)
                   and norm(b.source) == norm(b.target) for b in binds):
            binds.append(Bind(source=cfg.amosproxy.public_dir, target=cfg.amosproxy.public_dir))
    for k in env_pass:
        if k in caller.env and k not in env:
            env[k] = caller.env[k]

    spec = Spec(
        role=role_name, binds=tuple(binds), scratch=tuple(dict.fromkeys(scratch)), links=links,
        exec=tuple(dict.fromkeys(exec_)), mach=tuple(dict.fromkeys(mach)),
        iokit=tuple(dict.fromkeys(iokit)), devices=tuple(dict.fromkeys(devices)),
        sysctl_read=sysctl_read, unix_sockets=tuple(dict.fromkeys(sockets)), env=env,
        cwd=cwd or "/", sbpl=tuple(sbpl), sbpl_final=tuple(sbpl_final),
        network=role.network, proxy_label=role.proxy_label, ca_env=role.ca_env, dns=role.dns,
        loopback=role.loopback, proc_visibility=role.proc_visibility, debug=role.debug,
        rlimits=dict(role.rlimits),
    )
    check(spec)
    return spec


def check(spec: Spec) -> None:
    """Layout rules the daemon relies on when it builds the jail root."""
    seen: dict[str, str] = {}

    def claim(path: str, what: str):
        if path == "/":
            raise ConfigError(f"{what}: can't be the jail root itself")
        if within(path, "/dev"):
            raise ConfigError(f"{what} {path}: /dev is the daemon's devfs")
        if path in seen:
            raise ConfigError(f"{what} {path}: already used by {seen[path]}")
        seen[path] = what

    for b in spec.binds:
        claim(b.target, "bind target")
    for s in spec.scratch:
        claim(s, "scratch dir")
    for k in spec.links:
        claim(k, "link")
    for s in spec.unix_sockets:
        claim(s.target, "unix socket")
    # Δ3: nothing may live inside a bind: its mountpoint would have to be
    # created in the host source directory.
    for b in spec.binds:
        for path, what in seen.items():
            if path != b.target and within(path, b.target):
                raise ConfigError(f"{what} {path} is inside bind {b.target}; nested binds aren't supported")
        for lk in spec.links:
            if within(b.target, lk):
                raise ConfigError(f"bind {b.target} is under link {lk}; bind the real path instead")
