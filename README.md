# amosjail

Runs agent process trees on macOS in a jail: a chroot assembled from
mosbind bind mounts (`../mosbind`) and confined by a deny-default Seatbelt
profile, tagged for amosproxy (`../amosproxy`) when its role uses the proxy.
The jail runs as the invoking user, with their terminal and exit status.
Design and status are in `PLAN.md`.

**Status: M1 built.** The jail holds against every escape row tested on
macOS 27.0.1: the outside filesystem, other processes (signals, task ports,
ptrace, argv/env), launchd delegation, loopback and unix sockets, inherited
fds, `TIOCSTI`, rw-bind poisoning, and mounting from inside. Teardown is
clean (`tests/e2e/m1.sh`, 57 checks). Common tools run unmodified
(`tests/compat`). Proxy roles are tagged and fail closed; the traffic checks
still need amosproxy's extension connected (`tests/e2e/m2.sh`).

```sh
amosjail run --role agent -- claude          # as yourself, no sudo
amosjail run --role shell --bind data:/data -- sh
amosjail run --role agent --report -- make   # allow and list what's missing
amosjail profile --role agent                # the compiled SBPL
amosjail check                               # validate the config
amosjail roles | status | kill <jail>
sudo amosjail daemon                         # amosjaild
sudo amosjail amosproxy                      # amosproxy's daemon, with [amosproxy] flags
```

## How a run works

1. `amosjail run` asks amosjaild (root) for a jail of the role. The daemon
   identifies the caller from the socket's audit token, resolves the role
   from `/etc/amosjail/amosjail.toml`, and creates the jail root under
   `/var/amosjail/<uid>/<id>/root`.
2. The client mounts each bind there itself, with mosbind, as the user.
3. The daemon verifies the mounts, mounts devfs and links in the allowed
   unix sockets, then starts `amosjail-enter`:
   1. a new audit session;
   2. the amosproxy tag;
   3. compile the profile;
   4. chroot;
   5. take the pty;
   6. drop to the user;
   7. close fds;
   8. apply the profile;
   9. exec.
4. When the command exits, or the client goes away, the daemon kills the
   whole audit session, untags it, and unmounts and deletes the jail.

## Config

One file, `/etc/amosjail/amosjail.toml`, for amosjail and the two
components it drives. See `etc/amosjail.toml`:

- `[daemon]` sets amosjaild's socket, jail and state directories, and the
  `amosjail-enter` path.
- `[amosproxy]` holds its daemon flags, the socket jails are tagged
  through, the CA directory, and the exemptions amosjaild keeps applied.
- `[mosbind]` names the mount and `mosbind-notify` tools.
- Binds are `type = "bind"` or `"overlay"`, with optional
  `notify = { match, command }`.
- `[fragments.*]` and `[roles.*]` say what a jail sees and may do.

The file may be owned by anyone. When anyone but root can change it, the
daemon ignores its `[daemon]` and `[amosproxy]` sections (they decide what
root runs and writes) and uses the defaults.

## Building and testing

```sh
PYTHONPATH=src python3 -m unittest discover -s tests/unit   # any OS
scripts/sync.sh                     # push to the test Mac, build amosjail-enter
ssh mac sh amosjail/tests/e2e/m1.sh       # M1 gate (sudo; mosbind installed)
ssh mac sh amosjail/tests/compat/run.sh   # workloads (--report: what each needs)
ssh mac sh amosjail/tests/e2e/m2.sh       # M2 gate (amosproxy + extension running)
```

The gates start a private amosjaild from `tests/e2e/test.toml`, installed
root-owned under `/var/db/amosjail-test`. They need Python ≥ 3.12 (uv's
CPython is used if present) and leave nothing behind.
