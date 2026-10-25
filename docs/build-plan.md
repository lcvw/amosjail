# Build plan: the Seatbelt wrapper (M1 + M2)

**Status:** draft for review, 2026-10-25. This file covers how we build it and
in what order. The design itself is in `PLAN.md`, and ids (D-, T-, S-, E-)
refer to it. Anything here that changes a decision is marked **Δ**.

## Scope

This build delivers:

- **M1, a working jail:** `amosjail run --role R -- CMD` gives a mosbind chroot
  under a compiled deny-default profile, running as the caller's uid with a
  real terminal and exit status.
- **M2, proxy integration:** `network = "proxy"` tags the jail's audit
  session with amosproxy and fails closed.
- **A thin report mode:** `--report` compiles the same profile with every
  deny made an allow `(with report)`, then dumps the Sandbox log lines for
  the jail. We need it to derive the `base` and harness fragments (S-5,
  T-06, T-07). The fragment *suggester* stays in M3.

Out of scope: the fragment suggester (T-30), `enroll` (T-32), packaging (M4),
the OSC-filtering relay, and the mosbind fix for binding one source twice
(T-08). Until T-08 lands, the path-spelling workaround stands in for it.

## Changes to the design I'm proposing

- **Δ1. A pty when stdin is a terminal (revises D-6).** With plain stdio
  passing, the jail has no controlling terminal. The jail is spawned by the
  daemon, not inside the user's terminal session, which causes three
  problems:
  - `open("/dev/tty")` fails with `ENXIO`, which breaks password prompts in
    ssh, git and sudo-style tools, and pagers that read from the terminal;
  - Ctrl-C and Ctrl-Z reach the client instead of the jail;
  - window-size changes (`SIGWINCH`) never reach it.

  Making the user's own terminal the jail's controlling terminal would
  detach it from the user's shell. The fix:
  1. The client opens a pty itself (unprivileged), puts its own terminal
     in raw mode and relays bytes locally.
  2. It sends the slave end to the daemon over `SCM_RIGHTS`.
  3. `amosjail-enter` runs `setsid` + `TIOCSCTTY` on the slave.

  Job control, `/dev/tty` and Ctrl-C then all work inside the jail. Resizes
  are a `TIOCSWINSZ` on the master. The profile allows only that one slave
  node, through a `TTY` parameter, and keeps the `TIOCSTI` deny. When stdin
  isn't a terminal (pipes, CI), fds are passed through as D-6 describes.
  This also gives the later OSC filter a place to live.
- **Δ2. The daemon unmounts at teardown.** The client still mounts (D-4),
  but root unmounts. Cleanup then works when the client is killed or the
  terminal closes, and the reaper can unmount after a crash.
- **Δ3. v1 refuses a bind target inside another bind** (e.g. `/usr/local`
  under a `/usr` bind). Its mountpoint would have to be created in the host
  source directory, and mounting on top of a mosbind vnode is untested
  ground next to the mount-of-mount hang. A role that needs it gets an
  error naming both binds.
- **Δ4. Reuse amosproxy by copying its small Darwin helpers.** Copy
  `session.py` (asid), `darwin.py` (peer token, `scan_sessions`) and
  `protocol.py` (framing) into `src/amosjail/_vendor/`, with their origin
  commit noted. Depending on the amosproxy package would pull in its
  project, and D-14 is stdlib only. If we later merge the two daemons
  (Q-5), the copies go away.
- **Δ5. New escape row E14, unmount and mount from inside the jail.**
  jailed code owns its bind mounts, so it can try `umount /work` or
  `mount -t mosbind` from inside. Unmounting only *loses* access (the
  mountpoint under it is empty), but we test both anyway.

## Components and order

Unit tests run on Linux; everything else is gated on the Mac.

1. **Skeleton.**
   - `git init`.
   - `pyproject.toml` (uv, Python ≥ 3.12, stdlib only, pytest in dev).
   - The `src/amosjail/` layout from PLAN §6.
   - `scripts/sync.sh`, which rsyncs the tree to `~/amosjail` on the Mac and
     builds `amosjail-enter` there.
2. **`config.py` (T-01).**
   - Loads the config with `tomllib` and validates every field, with errors
     that name the table and key.
   - Loads fragments and resolves roles.
   - Substitutes `${HOME}`, `${USER}` and `${CWD}` (from `getpwuid` of the
     **peer** uid, never the client's environment) and `--param` values,
     only for keys the role's `cli.params` allows.
   - Applies `required` fragments and `allowed_users`.
   - `amosjail check` validates the file.
3. **`compile.py` (T-01).** A resolved role becomes SBPL in a fixed order:
   1. header, `(deny default)`, `JAIL` and `TTY` parameters;
   2. read-metadata on every ancestor of every target;
   3. bind rules: `ro` gets `file-read*`, `rw` also gets `file-write*`;
   4. exec allowlist, devices, Mach allowlist, sysctl, network (D-10);
   5. raw SBPL from fragments;
   6. **all denies:** each bind's deny list plus the D-9 defaults, loopback,
      UDP;
   7. the mandatory block from D-7;
   8. `final = true` raw SBPL.

   Paths are normalised to the `/private` form at compile time (D-8).
   Golden-file tests cover every rule kind, and one golden file is `spikes/jail.sb`'s
   semantics rebuilt from TOML. `amosjail profile` prints the compiled
   profile.
4. **`enter/amosjail-enter.c` (T-02).** Grows from `spikes/enter.c`.
   - **Inputs:** argv `--root --uid --gid --cwd [--tty] [--rlimit k=v] --
     CMD…`. The profile arrives on fd 3. fd 4 is a close-on-exec status
     pipe.
   - **Environment:** exactly what the daemon passes, nothing inherited.
   - **Sequence:**
     1. `setaudit_addr(AU_ASSIGN_ASID)`, then write the new asid to fd 4;
     2. M2 only: tag the asid in amosproxy;
     3. compile the profile with parameters;
     4. `chroot`, then `chdir`;
     5. M2 only: confirm the tag (see M2 below);
     6. `setsid` + `TIOCSCTTY` when there's a pty;
     7. `setgroups` (the caller's real group list), `setgid`, `setuid`,
        then check that `setuid(0)` fails;
     8. apply rlimits, `closefrom(3)` except fd 4, `sandbox_apply`,
        `execve`.

     Each step that fails writes `step: errno` to fd 4 and exits 127.
     EOF on fd 4 with no error means exec succeeded.
5. **`jails.py` + `control.py` + daemon (T-03).**
   - The control socket is `0666`, and every request is checked against
     `LOCAL_PEERTOKEN`.
   - `spawn` does this:
     1. re-read the config and resolve the role;
     2. create `/var/amosjail/<uid>/<id>/root` (root-owned `0755`) with
        mountpoints `chown`ed to the caller;
     3. choose a source spelling not currently mounted (from `getmntinfo`
        sources, then `/usr/.`, `/usr/./.`, and so on);
     4. reply with the mount list.
   - `go` does this:
     1. verify the mounts (fs type `mosbind`, owner = caller, source
        realpath, `ro` flag);
     2. refuse any source that is itself on mosbind;
     3. mount devfs and hard-link the mDNSResponder socket;
     4. spawn `amosjail-enter` with the passed fds and read the asid;
     5. relay exit and signals.
   - Teardown follows D-12, with Δ2.
   - State lives in `/var/db/amosjail/<id>.json`, and the reaper reads it at
     startup.
   - A watcher tears down any jail whose mosbind mounts disappear (the
     SIGBUS case).
6. **`client.py` (T-04).**
   - Requests `spawn`, runs `mount -t mosbind [-r]` per bind, then requests
     `go` with the pty slave or the stdio fds.
   - Runs the raw-mode relay loop.
   - Forwards `SIGWINCH` and passes the jail's signals and exit code
     through: it exits with the jail's status, or 128 plus the signal.
   - Restores the terminal on every exit path.
7. **CLI (T-05).** `run`, `profile`, `check`, `status`, `kill`, `roles` and
   `daemon`. `run --report` dumps
   `log show --predicate 'sender=="Sandbox"'` for the jail's pids when it
   exits.
8. **The `base` fragment (T-06, S-5).** Each workload runs under
   `--report`, and each entry we keep gets a written reason. The workloads:
   `sh`, `ls`, `git` (status, commit, clone over https), `python3`, `node`,
   `curl`, `less`, `vim`.
9. **Tests.**
   - `tests/escape/`: probe programs ported from `spikes/`, one script per
     row E1–E14.
   - `tests/compat/`: the step 8 workloads.
   - `tests/e2e/m1.sh`, the gate, as in PLAN M1, which adds two checks:
     - no mount and no process is left in the asid after teardown;
     - teardown also works when the client is `kill -9`ed.
10. **M2 (T-20, T-21).**
    - Before `chroot`, `amosjail-enter` sends one JSON `tag` line to
      `/var/run/amosproxy.sock`. It is root in its own fresh asid at that
      point, which is what amosproxy's `tag` op tags.
    - It requires the reply's asid to match its own, and refuses to exec
      otherwise.
    - If amosproxy isn't running, `network = "proxy"` refuses to start.
    - Teardown untags the asid.
    - Escape tests E7 and E8 run with the proxy provider both up and stopped.
11. **Claude Code fragment (T-07).** Derived with `--report`, running
    `claude` in a jail end to end. This is the "it actually works" check.

## How it runs on the Mac during development

- The Mac has no `uv` on its PATH, but it has uv's CPython 3.15 (used by
  `~/amosproxy/.venv`).
- During development the daemon runs as
  `sudo <that python> -m amosjail daemon` from the synced tree.
- **This is dev only.** Running root code from a user-writable directory
  means any jail with that directory bound rw could replace the daemon's
  code. The daemon refuses to start from a path that's inside any role's rw
  bind, and M4 installs to a root-owned prefix.
- **Shared-machine rules for tests:** jail roots live under `/var/amosjail`
  only, no broad `pkill`, mounts are checked before each run, and a mosbind
  path is never used as a source (enforced in code by step 5).

## Risks to watch while building

- **AMFI.** Not testable on this Mac (AMFI is off). Every gate passes here
  without telling us anything about it. Can you give me access to an
  AMFI-on machine, or should this stay a known gap until M4?
- **The pty approach (Δ1)** is unmeasured. It's the first thing I'll spike,
  before the client is written.
- **The size of the Claude Code fragment.** The keychain (OAuth
  credentials) and trustd are the likely Mach needs. If Claude Code needs
  `SecurityServer`, the jail can read keychain items the ACLs allow; I'll
  report what it needs rather than silently allowing it.

## For you to decide

1. Δ1: a pty by default for terminals?
2. Δ2–Δ5 as written?
3. Scope: M1 + M2 + thin report mode now, M3 and M4 later?
4. `git init` the repo, with commits like `T-02: …`?
5. An AMFI-on test machine, or leave it as a known gap?
