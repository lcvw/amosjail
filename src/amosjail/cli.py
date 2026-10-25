"""amosjail CLI (PLAN §5). Stdlib only."""

from __future__ import annotations

import argparse
import os
import pwd
import sys

from amosjail import config
from amosjail.client import EXIT_ERROR, ClientError


def _cfg(args) -> config.Config:
    return config.load(args.config)


def _settings(args) -> config.Config:
    # The socket path a client trusts follows the same rule as the daemon's.
    return config.privileged(_cfg(args))


def _caller() -> config.Caller:
    pw = pwd.getpwuid(os.getuid())
    return config.Caller(uid=pw.pw_uid, gid=pw.pw_gid, user=pw.pw_name, home=pw.pw_dir,
                         cwd=os.path.realpath(os.getcwd()), env=dict(os.environ))


def _params(items: list[str]) -> dict[str, str]:
    out = {}
    for it in items:
        k, sep, v = it.partition("=")
        if not sep or not k:
            raise config.ConfigError(f"--param {it!r}: expected KEY=VALUE")
        out[k] = v
    return out


def cmd_run(args) -> int:
    from amosjail import client

    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not cmd:
        print("amosjail run: missing command", file=sys.stderr)
        return 2
    cfg = _settings(args)
    return client.run(cfg.daemon.socket, args.role, cmd, _params(args.param), args.bind, args.report)


def cmd_profile(args) -> int:
    from amosjail import compile

    cfg = _cfg(args)
    spec = config.resolve(cfg, args.role, _caller(), params=_params(args.param),
                          cli_binds=[config.parse_cli_bind(b) for b in args.bind])
    root = os.path.join(cfg.daemon.jail_dir, str(os.getuid()), "jEXAMPLE", "root")
    sys.stdout.write(compile.render(spec, root, tty="ttys000" if args.tty else None, report=args.report))
    return 0


def cmd_check(args) -> int:
    from amosjail import compile

    cfg = _cfg(args)
    caller = _caller()
    bad = 0
    for name in sorted(cfg.roles):
        try:
            spec = config.resolve(cfg, name, caller)
            compile.render(spec, "/private/var/amosjail/0/jCHECK/root")
            print(f"ok    {name}")
        except config.ConfigError as e:
            bad += 1
            print(f"error {name}: {e}")
    if not config.trusted(cfg.path):
        print(f"note: {cfg.path} is writable by non-root users, so the daemon ignores its "
              "[daemon] and [amosproxy] settings")
    return 1 if bad else 0


def cmd_roles(args) -> int:
    cfg = _cfg(args)
    user = pwd.getpwuid(os.getuid()).pw_name
    for name, role in sorted(cfg.roles.items()):
        if not role.allowed_users or user in role.allowed_users:
            print(f"{name:16} network={role.network} fragments={','.join(role.fragments)}")
    return 0


def cmd_status(args) -> int:
    from amosjail import client

    reply = client.request(_settings(args).daemon.socket, {"op": "status"})
    if args.json:
        print(client.dumps(reply["jails"]))
        return 0
    for j in reply["jails"]:
        print(f"{j['jail']}  role={j['role']} uid={j['uid']} pid={j['pid']} asid={j['asid']}")
    return 0


def cmd_kill(args) -> int:
    from amosjail import client

    reply = client.request(_settings(args).daemon.socket, {"op": "kill", "jail": args.jail})
    if not reply.get("ok"):
        print(f"amosjail kill: {reply.get('error')}", file=sys.stderr)
        return 1
    return 0


def cmd_daemon(args) -> int:
    from amosjail import daemon

    return daemon.main(args.config)


def cmd_amosproxy(args) -> int:
    """Start amosproxy's daemon with the flags from [amosproxy]."""
    from amosjail import amosproxy

    if os.geteuid() != 0:
        print("amosjail amosproxy: must be root", file=sys.stderr)
        return 1
    cfg = config.privileged(_cfg(args))
    os.makedirs(cfg.daemon.state_dir, mode=0o755, exist_ok=True)
    exempt = amosproxy.write_exempt_file(cfg.amosproxy, cfg.daemon.state_dir)
    argv = cfg.amosproxy.daemon_argv(exempt)
    if args.print:
        print(" ".join(argv))
        return 0
    os.execvp(argv[0], argv)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="amosjail")
    p.add_argument("--config", help=argparse.SUPPRESS)  # tests; same as AMOSJAIL_CONFIG
    sub = p.add_subparsers(dest="cmd", required=True)

    def role_args(sp):
        sp.add_argument("--role", required=True)
        sp.add_argument("--param", action="append", default=[], metavar="KEY=VALUE")
        sp.add_argument("--bind", action="append", default=[], metavar="SRC:DST[:ro|rw]")
        sp.add_argument("--report", action="store_true",
                        help="allow and log what the profile would deny (to build a role)")

    r = sub.add_parser("run", help="run COMMAND in a jail")
    role_args(r)
    r.add_argument("command", nargs=argparse.REMAINDER)
    r.set_defaults(fn=cmd_run)

    pr = sub.add_parser("profile", help="print a role's compiled SBPL")
    role_args(pr)
    pr.add_argument("--tty", action="store_true", help="as if run from a terminal")
    pr.set_defaults(fn=cmd_profile)

    sub.add_parser("check", help="validate the config").set_defaults(fn=cmd_check)
    sub.add_parser("roles", help="list the roles you can use").set_defaults(fn=cmd_roles)
    s = sub.add_parser("status", help="list running jails")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_status)
    k = sub.add_parser("kill", help="stop a jail")
    k.add_argument("jail")
    k.set_defaults(fn=cmd_kill)
    sub.add_parser("daemon", help="(root) run amosjaild").set_defaults(fn=cmd_daemon)
    a = sub.add_parser("amosproxy", help="(root) start amosproxy's daemon with [amosproxy] settings")
    a.add_argument("--print", action="store_true", help="print the command instead")
    a.set_defaults(fn=cmd_amosproxy)

    args = p.parse_args(argv)
    if args.config:
        os.environ["AMOSJAIL_CONFIG"] = args.config
    try:
        return args.fn(args)
    except (config.ConfigError, ClientError) as e:
        print(f"amosjail: {e}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
