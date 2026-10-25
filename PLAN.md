# amosjail — Implementation Plan

**Status:** M1 built and passing on macOS 27.0.1 (`tests/e2e/m1.sh`, 57
checks; `tests/compat`, 13 workloads). M2 is built; its fail-closed checks
pass, and its traffic checks wait on amosproxy's extension (`tests/e2e/m2.sh`).
Spike results are in `docs/spike-results.md`, the build plan in
`docs/build-plan.md`.
**Last updated:** 2026-10-25

Decisions are `D-nn`, tasks `T-nn`, spikes `S-nn`, open questions `Q-nn`; all
are referenceable in commits. Same conventions as `../amosproxy/PLAN.md`,
whose audit-session tag this plan shares. The Endpoint Security design that
preceded this one is in `docs/es-alternative.md`.

## 1. Purpose

Run agent process trees on macOS in a **jail**: a chroot assembled from
mosbind bind mounts and confined by a Seatbelt profile, where the tree

- cannot touch the filesystem outside what its role binds in,
- cannot ptrace, inspect or signal anything outside the jail,
- cannot leave its amosproxy tag or get around the proxy's controls.

Two goals shape everything below:

- **Seamless.** `amosjail run --role agent -- claude` works unprivileged, as
  the user's own uid, with their terminal, cwd and exit status. There's no
  sudo and no uid switching.
- **Maximally configurable.** Roles are composed from fragments, can be
  parameterised, have a raw-SBPL escape hatch, and can be learned from a
  report-only run (D-11).

A caller **enrolls** with a **role** id from the TOML config, over a unix
socket. There is one config file, in a fixed location,
`/etc/amosjail/amosjail.toml` (D-13). The daemon identifies the caller by the kernel's view of the
socket peer (`LOCAL_PEERTOKEN`), never by anything in the request.

### Non-goals

Kernel or Sandbox.kext bugs, side channels, resource fairness beyond
rlimits, protecting the jail *from* the user's other processes, a GUI.

## 2. Threat model

The jailed tree runs arbitrary code as **the invoking user's uid**. It is
hostile and knows how amosjail works. Because it shares a uid with the user's
other processes, the kernel's cross-uid checks no longer help: **Seatbelt is
the whole boundary** for E2–E4 and E6, and those rows must be proven by
tests, not assumed.

| # | Escape | Control |
|---|---|---|
| E1 | read/write/exec a host path outside the binds | chroot over mosbind (view) + Seatbelt file rules (enforcement) |
| E2 | signal or suspend an outside process | `(allow signal (target same-sandbox))`, everything else denied |
| E3 | ptrace or get a task port of an outside process | Seatbelt `process-info*` / task-port operations (S-3) |
| E4 | see outside processes (`ps`, args, env) | `process-info*` limited to `same-sandbox` (configurable) |
| E5 | become root → new audit session, chroot out | jail runs as the user; mosbind is `nosuid`; `process-exec` allowlist |
| E6 | delegate to launchd/XPC (`launchctl submit`, `open`, `osascript`, background `NSURLSession`) | `mach-lookup` allowlist + deny job creation (S-4) |
| E7 | reach a local service (ssh-agent, docker, amosproxy's sockets, a local proxy) | `network-outbound` denies loopback and unix sockets except an allowlist |
| E8 | send traffic amosproxy doesn't see (UDP, loopback, provider restart) | Seatbelt network rules per role; amosproxy for the rest |
| E9 | tamper with amosjail/amosproxy (config, sockets, daemon) | outside the view; file, signal and unix-socket rules |
| E10 | use an fd opened outside the jail | only stdin/stdout/stderr are passed in; everything else closed (D-6) |
| E11 | inject keystrokes into the user's terminal (`TIOCSTI`) | `TIOCSTI` denied by ioctl command in every profile (D-6, measured) |
| E12 | persist after the jail ends (launchd jobs, LaunchAgents, cron) | no writes outside rw binds; no job creation; teardown kills the session |
| E13 | **poison a rw bind** so the user's own tools run its code later (`.git/hooks`, `.git/config`, `.envrc`, `Makefile`, `.vscode/tasks.json`) | per-bind `deny` lists, with a default set (D-9); some of this is inherent (§8) |

## 3. What we already know

From amosproxy (verified on macOS 27.0.1, arm64):

1. The audit session id (asid) is inherited across fork, exec, `posix_spawn`,
   `vfork`, `setsid` and reparenting. An unprivileged process can't leave it
   or create a new one.
2. Root can create a fresh session with `setaudit_addr(AU_ASSIGN_ASID)`
   (`amosproxy/src/amosproxy/session.py`).
3. `launchctl submit` from a tagged session escapes to launchd's session
   (amosproxy §6). That's E6, and the reason for the `mach-lookup` and
   job-creation rules.

From mosbind (`../mosbind/README.md`):

4. Mounting needs no root. The extension runs as the mounting user, and
   `refuse()` admits only the mounting user and root. **Because the jail runs
   as the user who mounts, mosbind needs no change.**
5. FSKit forces `nosuid`, `nodev`, `noowners`, `noatime`.

About Seatbelt:

6. Profiles are inherited across fork and exec and can't be removed, even by
   root.
7. **A process that is already sandboxed can't apply another profile**
   (measured: `sandbox_apply` → `EPERM`). That's D-2.

Measured on macOS 27.0.1 (`docs/spike-results.md`):

8. **Running as the user's own uid, Seatbelt alone stops** signals, suspend,
   task ports, ptrace, pidinfo, path, and argv/env reads against outside
   processes, including debuggable ones that unsandboxed same-uid code *can*
   take over. **But `(deny default)` does not deny process info.** It must be
   denied by name (D-7).
9. Separate jails are separate sandboxes even with identical profiles.
10. launchd job submission and LaunchServices `open` are refused for
    sandboxed callers whatever the Mach rules. Pasteboard and Spotlight are
    stopped only by the `mach-lookup` allowlist.
11. Inside a chroot, Seatbelt matches the **host path of the mount**
    (`/private/<jail root>/work/...`), not the chroot path and not the bind
    source (D-8).
12. chroot + exec over mosbind works (on this AMFI-off machine). `/dev`
    can't come from mosbind (FSKit forces `nodev`); it needs devfs. FSKit
    won't mount one source twice. A mosbind mount used as a mosbind source
    hangs the machine's mount table (D-4).
13. `SBPL localhost` also matches `0.0.0.0`, `::1` and the machine's own
    interface addresses. DNS needs only the `mDNSResponder` socket.
14. `TIOCSTI` injects into the controlling terminal on macOS 27, and
    `(deny file-ioctl (ioctl-command #x80017472))` blocks it alone (D-6).
15. Report mode (`(with report)`) logs operations with comm, pid, operation
    and target, so learning works (D-11).

## 4. Architecture

```
 user shell (uid 501)
   amosjail run --role agent [--bind …] [--param …] -- claude …     unprivileged client
     │ 1. mounts the role's binds itself with mosbind (as the user; D-4)
     │ 2. /var/run/amosjaild.sock {"op":"spawn","role":"agent",argv,cwd,env,…}
     │    + SCM_RIGHTS: its stdin, stdout, stderr
     │ 3. forwards signals, exits with the jail's status
     ▼
 amosjaild (root, launchd)
   ├─ re-reads /etc/amosjail/amosjail.toml
   ├─ LOCAL_PEERTOKEN → caller uid, gid, asid, pid
   ├─ checks the caller may use the role; resolves fragments + params → SBPL
   ├─ verifies the caller's mosbind mounts (getmntinfo: type, owner, source, target)
   ├─ mounts devfs at <root>/dev; hard-links mDNSResponder if dns = true
   └─ spawns amosjail-enter (root, fresh process) with the compiled profile
          1. setaudit_addr(AU_ASSIGN_ASID)                   fresh asid
          2. amosproxy tag {label}                           if role.network = "proxy"
          3. sandbox_compile_string(profile, JAIL=<root>)     before chroot (D-5)
          4. chroot(jail root); chdir(cwd)
          5. stdio = the caller's fds
          6. setgroups/setgid/setuid → caller's uid           not a new uid; every gid set
          7. closefrom(3); env from role; rlimits
          8. sandbox_apply → execve                           first sandboxed instruction is the target
   jailed tree (asid N, uid 501, sandboxed)
```

`enroll` is the same thing for a caller that is already root and wants to
jail itself (for other tools that embed amosjail). amosjaild returns the
compiled profile and the jail root, records the caller's asid against the
role, and the caller runs steps 3–8 itself.

### Decisions

- **D-1 Enforcement is Seatbelt; the view is chroot + mosbind.** Neither is
  enough alone. The chroot makes paths look right to unmodified tools (the
  project at `/work`, a normal `/usr`). The profile stops whatever gets past
  the chroot (fds, Mach services, sockets). It also covers what a chroot
  never could: signals, process info, task ports and network.
- **D-2 amosjail's profile is the only Seatbelt layer.** Seatbelt can't nest
  (§3.7), so the harness inside the jail must run with its own sandbox off:
  Claude Code's sandbox setting disabled, Codex with
  `--sandbox danger-full-access`. Tools that sandbox themselves need their
  opt-out flags (`swift build --disable-sandbox`, Bazel
  `--spawn_strategy=local`, Nix `sandbox = false`). Roles can ship these as
  env and config presets (T-07). The harness's own permission prompts still
  work; they just aren't the security boundary any more.
- **D-3 The daemon spawns; the client relays.** Creating an audit session
  and chrooting need root. Doing them in the daemon instead of sudo or a
  setuid binary keeps `amosjail run` unprivileged and keeps the privileged
  code in one place. The jail runs as the **caller's uid** (from the peer
  token), so files it writes in rw binds are the user's, mosbind admits it,
  and nothing needs accounts.
- **D-4 The client mounts; the daemon verifies.** mosbind is per-user and
  unprivileged (§3.4), so the client mounts each bind at
  `<jail>/root/<target>` under a jail root the daemon created. Before
  spawning, the daemon checks every expected mountpoint with `getmntinfo`:
  - the filesystem type is mosbind;
  - the mount is owned by the caller;
  - the source and read-only flag match the role.

  Anything unexpected under the jail root aborts the spawn. Jail roots live
  at `/var/amosjail/<uid>/<id>/root`. The directory is root-owned `0755`; the
  mountpoints inside it are owned by the user. Three constraints measured on
  macOS 27:
  - **FSKit won't mount the same source twice** ("Resource busy"), so two
    jails can't both bind `/usr`. Until mosbind makes each mount's resource
    unique (T-08), the client spells each source uniquely per jail
    (`/usr/./`, `//usr`, …); FSKit dedupes on the URL string.
  - **A source must never be inside a mosbind mount.** Mounting a mosbind
    path with mosbind hung the extension in an uninterruptible wait and
    blocked `getfsstat` machine-wide. The daemon refuses any bind source
    whose `statfs` type is mosbind.
  - **`/dev` is a devfs mount made by the daemon** (root), not a bind:
    FSKit forces `nodev`. Seatbelt then limits which device nodes the jail
    can open.

  The daemon also hard-links `/private/var/run/mDNSResponder` into the jail
  root when `dns = true`. The socket can't cross into a mosbind volume, but
  the jail root itself is on the same APFS volume.
- **D-5 Compile before chroot, apply just before exec.** The profile is
  compiled while the host filesystem is still visible, so it imports nothing
  from inside the jail. It is applied as the last step before `execve`, so
  `amosjail-enter`'s own setup (chroot, setuid) isn't constrained by it.
  Measured with `spikes/enter.c`, linked with `-lsandbox`.
  The compiled profile is self-contained. It doesn't import
  `/System/Library/Sandbox/Profiles/*.sb`: Apple's profiles change across
  releases, and an import would silently widen a role.
- **D-6 A pty from a terminal, the user's stdio otherwise; nothing else.**
  No other inherited fds (E10). When stdin and stdout are terminals, the
  client opens a pty, relays it in raw mode and passes the slave over
  `SCM_RIGHTS`; `amosjail-enter` makes it the controlling terminal
  (`setsid` + `TIOCSCTTY`). So `/dev/tty`, Ctrl-C, Ctrl-Z and job control
  work inside the jail, and resizes are a `TIOCSWINSZ` on the master. The
  user's own terminal can't be the jail's controlling terminal: the jail
  isn't in the terminal's session, and taking it would detach the user's
  shell. Otherwise (pipes, files) the client's fds 0–2 are passed as they
  are, and the profile allows metadata reads of exactly the files they
  point at (clang `fstat`s stderr and exits 1 silently without that).
  `(deny file-ioctl (ioctl-command #x80017472))` blocks `TIOCSTI` either way
  (measured). Ctrl-Z in pty mode stops the jailed process inside the jail;
  without a shell in there, nothing can resume it.
- **D-7 Default deny, then compose.** Every profile starts `(deny default)`.
  A role is an ordered list of fragments, and a fragment contributes
  structured rules (binds, exec, mach, network, sysctl, iokit, ipc) and
  optionally raw SBPL. Later fragments can't remove an earlier `deny`: SBPL
  is last-match-wins, so the compiler emits all `deny` rules after all
  `allow` rules. Raw SBPL is emitted in the allow section unless marked
  `final = true`.

  **`(deny default)` is not enough on its own.** Process info isn't covered
  by it (measured). The compiler always emits this block after the role's
  allows, whatever the role says:

  ```scheme
  (deny process-info*)
  (deny sysctl-read (sysctl-name-prefix "kern.proc"))   ; argv + environment
  (allow process-info* (target same-sandbox))
  (allow signal (target same-sandbox))
  (deny file-ioctl (ioctl-command #x80017472))          ; TIOCSTI
  ```

  `proc_visibility = "names"` adds `process-info-listpids` and
  `kern.proc.all` (pids and names, never args). `debug = true` adds
  `mach-priv-task-port` / `mach-task-name` for `same-sandbox`. Each of these
  rules has an escape test in `tests/escape/`, because Apple can change what
  the default covers.
- **D-8 Paths are written in jail terms and compiled to host paths.**
  Inside a chroot, Seatbelt matches the host spelling of the mount path
  (measured, S-1), so `/work/x` compiles to
  `/private/var/amosjail/501/j7/root/work/x`. The daemon renders the
  profile per jail with its real root (regexes can't take a parameter);
  `amosjail profile --role R` renders it with an example root for review.
  `/var`, `/tmp` and `/etc` are normalised to `/private/...`.
- **D-9 rw binds carry a default deny list** against E13: `.git/hooks/**`,
  `.git/config`, `.envrc`, `.direnv/**`, `.vscode/**`, `.idea/**` and
  `**/.husky/**` become read-only. Per bind, `deny_write = [...]` adds more,
  `deny = [...]` removes all access (secrets such as `.env`), and
  `deny_defaults = false` opts out. The directories between the bind and
  each pattern (`.git` itself) are made unwritable too: otherwise
  `mv .git x; write x/hooks/...; mv x .git` gets around the rule. The cost
  is that `git init` in a fresh rw bind fails. This narrows E13 but can't
  close it (§8).
- **D-10 Network policy per role** (E7, E8):
  - `none` — no network at all;
  - `proxy` — outbound TCP to non-loopback only, an amosproxy tag is
    required before exec, and `amosjail run` fails if amosproxy isn't
    running;
  - `open` — anything but loopback and unix sockets.

  In every mode, loopback and unix sockets are denied except
  `loopback = ["127.0.0.1:8080"]` and `unix_sockets = [...]`. SBPL's
  `localhost` also covers `0.0.0.0`, `::1` and the machine's own addresses
  (measured). UDP is always denied: `dns = true` allows only the
  `mDNSResponder` socket, which is all `getaddrinfo` needs (measured).
- **D-11 Report mode.** `amosjail run --report` compiles the same profile with
  every deny turned into `(allow (with report) …)` (S-6). It collects the
  Sandbox violations from the unified log for the jail's pid set and prints
  a role fragment that would have allowed them, for the user to review and
  paste. This is the main configuration tool; nothing is applied
  automatically.
- **D-12 Jail lifetime = audit session membership.** When the first process
  exits, or the client disconnects, or `amosjail kill` runs, the daemon:
  1. repeatedly `SIGSTOP`s and then `SIGKILL`s every process whose audit
     token has the jail's asid, until none is left (enumerated as root via
     task name ports);
  2. untags the asid in amosproxy;
  3. unmounts everything under the jail root itself (the client's mounts
     too, so a killed client still gets cleaned up), **never forcibly**;
  4. removes the jail root and its state file.

  A chroot gets its own dyld shared region, backed by the jail's `/System`
  mount, and the kernel keeps it about 120 s after the last process exits.
  Until then `/System` is busy. Forcing the unmount (the first version did)
  leaves the region with no pager, and a later jail's exec dies of SIGBUS
  in dyld, about 1 run in 8 ("Object has no pager because the backing vnode
  was force unmounted"). So a busy jail is left *draining* and retried
  every 5 s. A monitor tears down any running jail whose mounts vanish (a
  fskitd restart). A startup reaper handles jails left by a daemon crash,
  from `state_dir`.
- **D-13 One config file, in a fixed place: `/etc/amosjail/amosjail.toml`.**
  It may be owned by root or by a user. It has no layering and no per-user
  roles for now. `AMOSJAIL_CONFIG` (or `--config`) overrides the path, for
  tests. The daemon re-reads roles and fragments on every `spawn`, so edits
  take effect for the next jail without a restart. Every table and key is
  checked; an unknown key is an error.
- **D-15 The config covers amosproxy and mosbind too, and root-relevant
  settings need a root-owned file.** Sections:
  - `[daemon]` sets amosjaild's socket, `jail_dir`, `state_dir` and the
    `amosjail-enter` path;
  - `[amosproxy]` has the daemon's flags (`sudo amosjail amosproxy` starts
    it with them), the socket jails are tagged through, the CA
    `public_dir` that becomes `SSL_CERT_FILE` and friends, and `exempt`,
    which amosjaild keeps applied (adding its rules and removing only those
    it added before);
  - `[mosbind]` names the mount, umount and `mosbind-notify` tools. Each
    bind picks `type = "bind"` (mosbind) or `"overlay"` (mosoverlay, with
    `lower` and `workdir`), and can carry `notify = { match, command }`,
    which runs `mosbind-notify` on it for the jail's lifetime;
  - `[fragments.*]` and `[roles.*]` are as in §5.

  `[daemon]` and `[amosproxy]` name programs root runs, paths root writes
  and destinations amosproxy stops inspecting. If the file or its
  directory is writable by anyone but root, the daemon ignores both
  sections and uses the defaults (logged; `amosjail check` says so). Roles
  and fragments apply either way, since a jail only ever has the caller's
  own uid. The daemon still acts only inside a root-owned `jail_dir`.
- **D-14 Languages.** amosjaild and the client in Python, stdlib only
  (`tomllib`), reusing amosproxy's `session.py`, `darwin.py` and framing.
  `amosjail-enter` is small C, so the code between `chroot` and `execve` has
  no interpreter, no imports and no dyld surprises inside the jail.

## 5. Config

The annotated example is `etc/amosjail.toml`; `tests/e2e/test.toml` is the
one the gates run. In short:

```toml
[daemon]      # amosjaild: socket, jail_dir, state_dir, enter
[amosproxy]   # amosproxy's daemon flags, socket, public_dir, exempt
[mosbind]     # mount, umount, notify tools

[fragments.base]        # what any CLI process needs
binds = [{ source = "/usr", target = "/usr" }, ...]   # ro unless mode = "rw"
scratch = ["/private/tmp", "/home"]   # empty, caller-owned, per jail
links = { "/tmp" = "private/tmp" }
exec = ["/usr/bin/**", ...]
devices = ["/dev/null", ...]
mach = ["com.apple.system.logger", ...]
sysctl_read = true
env = { set = { HOME = "/home" }, pass = ["TERM"] }
sbpl = "..."                          # raw SBPL; sbpl_final goes after everything

[fragments.project]
binds = [{ source = "${PROJECT}", target = "/work", mode = "rw", deny = [".env"] }]
cwd = "/work"

[roles.agent]
fragments = ["base", "devtools", "homebrew", "project"]
network = "proxy"                     # none | proxy | open
proxy = { label = "agent", ca_env = true }
dns = true
loopback = []                         # e.g. "127.0.0.1:8080"
unix_sockets = []                     # { host, target }: hard-linked in
proc_visibility = "jail"              # jail | names
params = { PROJECT = "${CWD}" }       # defaults; --param may override if listed
cli = { binds = "ro", params = ["PROJECT"] }
allowed_users = []                    # empty: anyone
rlimits = { nproc = 1024 }
```

### CLI

```
aamosjail run --role R [--bind SRC:DST[:ro|rw]] [--param K=V] [--report] -- CMD…
amosjail profile --role R [--param …]          print the compiled SBPL
amosjail status | kill <jail>
amosjail roles                                  list roles available to the caller
```

### Wire protocol

Line-delimited JSON on `/var/run/amosjaild.sock`, like amosproxy's control
socket.

```
{"op":"spawn","role":"agent","argv":[…],"cwd":"…","env":{…},"params":{…},"binds":[…]}
  → {"ok":true,"jail":"j7","root":"/var/amosjail/501/j7/root","mounts":[…]}   client mounts, then:
{"op":"go","jail":"j7"} + stdio fds via SCM_RIGHTS → a stream of {"exit":…} / signal frames
{"op":"enroll","role":"agent"}   root caller only → {"ok":true,"profile":"…","root":"…"}
{"op":"status"} / {"op":"kill","jail":"j7"} / {"op":"compile","role":"agent","params":{…}}
```

## 6. Layout

```
src/amosjail/
  cli.py          run / profile / status / kill / roles / daemon
  client.py       mounting, stdio passing, signal forwarding
  config.py       tomllib load and validation (D-13)
  compile.py      fragments + params → SBPL; path normalisation (D-7, D-8)
  report.py       unified-log violations → suggested fragment (D-11)
  control.py      control socket; peer token; role authorisation
  jails.py        jail roots, mount verification, teardown, reaper (D-4, D-12)
  amosproxy.py    client for amosproxy's control socket
enter/
  amosjail-enter.c the pre-exec sequence (§4); no dependencies beyond libSystem
profiles/
  fragments/      shipped fragments: base, homebrew, python, node, git, claude-code, codex
tests/
  escape/         one script per §2 row; each must fail to escape
  compat/         workloads that must run unmodified (git, python, node, cargo, a harness)
  e2e/            milestone gates
```

## 7. Milestones

### M0 — spikes

Done for S-1, S-2, S-3, S-4 (all but one row), S-6, S-7 and most of S-9
(`docs/spike-results.md`). None sank the design. S-5 and S-8 remain, and
S-5 is really T-06.

### M1 — a working jail, no proxy

- **T-01** Config loader with layering and fragments; compiler; golden-file
  tests of compiled SBPL.
- **T-02** `amosjail-enter` (C): the §4 sequence, which refuses to continue
  if any step fails.
- **T-03** Daemon: `spawn`/`go`, mount verification, devfs, mDNSResponder
  link, teardown, reaper.
- **T-04** Client: mounting, stdio passing, signals, exit status.
- **T-05** `amosjail profile`, `status`, `kill`, `roles`.
- **T-06** Shipped `base` fragment, derived from S-5 and S-9.
- **T-08** *(mosbind)* Make each mount's FSKit resource unique, so one source
  can be bound by several jails at once without the path-spelling trick
  (D-4).
- **T-07** Harness fragments for Claude Code and Codex that turn their
  sandboxes off and allow what they need (D-2).

**Gate:** `tests/e2e/m1.sh`. The `tests/compat/` workloads run unmodified
inside a jail. Every `tests/escape/` row except E8 fails to escape. Teardown
leaves no process in the asid and no mosbind mount behind.

### M2 — proxy integration

- **T-20** `network = "proxy"`: tag the asid via amosproxy before exec, and
  fail closed if amosproxy is down or the tag isn't confirmed.
- **T-21** Loopback, unix-socket and UDP rules (D-10); escape tests E7 and
  E8, run both with amosproxy's provider up and stopped.

### M3 — configuration tooling

- **T-30** Report mode and the fragment suggester (D-11).
- **T-31** `required` fragments and CLI limits (D-13, `cli = {…}`).
- **T-32** `enroll` for root callers embedding amosjail.

### M4 — packaging

`amosjail install`: launchd plist for amosjaild, `/etc/amosjail` skeleton,
shipped fragments. No system extension, no entitlement, no approval prompts.

## 8. Known gaps

- **Same uid.** Seatbelt is the only thing between the jail and the user's
  other processes. Any Seatbelt operation we miss is an escape, and Apple
  can add operations on any release (risk 1).
- **Root daemons acting on the jail's behalf** for Mach services that are
  allowed. The allowlist keeps this small; every entry in a shipped fragment
  needs a reason written next to it.
- **E13 can't be fully closed.** Any rw bind the user later builds, runs or
  opens in an IDE is a way to get code running outside the jail. The deny
  list covers the well-known hooks; the rest is the user's call.
- **DNS** through `mDNSResponder` is unattributed and is an exfiltration
  channel when `dns = true` (Q-3). The hard-linked socket also goes stale
  if mDNSResponder restarts, and the jail loses DNS until it's re-linked.
- **No `ps` inside a jail.** `/bin/ps` is setuid root, and its exec is
  denied (EPERM) under the profile even though `/bin` is an exec path.
- **Report mode can change behaviour.** It allows what enforcement would
  deny, so a tool may take a different path: allowed, `dirhelper` hands
  out a `/var/folders` temp dir the jail doesn't have, and clang fails
  where it works when enforced. Read reports as hints.
- **A finished jail keeps `/System` mounted for about 2 minutes** (D-12),
  and FSKit's same-source rule means each draining jail uses up a spelling
  of every source; the client tries 256.
- **No lldb inside a jail.** `debug = true` grants task ports within the
  jail, but `ptrace(PT_ATTACHEXC)` stays denied and no rule to allow it has
  been found.
- **Unverified with AMFI on.** Every measurement was on a machine with
  `amfi_get_out_of_my_way=1`. Whether platform binaries still launch from a
  mosbind chroot with AMFI enforcing is unknown, and nfswrap's NFS
  experience suggests it may not.
- **Jails must not outlive their volumes.** A fskitd restart drops every
  FSKit mount; the monitor then stops the affected jails (D-12).
- **No nesting** (D-2). Some tools have no way to turn their sandbox off;
  they can't run in a jail.
- **Private API.** `sandbox_compile_string`/`sandbox_apply` and SBPL are
  undocumented; `sandbox_init` with a profile string is deprecated.
- **amosproxy's fail-open window** (its S-5) is narrowed only by D-10's
  rules, not closed.

## 9. Spikes

Results are in `docs/spike-results.md`; sources and profiles in `spikes/`.

- **S-1 (done)** Seatbelt matches the host path of the mount inside a
  chroot; not the chroot path, not the bind source. Symlink and `..`
  behaviour not yet tested beyond the basics.
- **S-2 (done)** Compile as root → chroot → drop → close fds → apply →
  exec works with `sandbox_compile_string`/`sandbox_apply` (`-lsandbox`).
- **S-3 (done)** Every same-uid route to an outside process is deniable,
  but process info needs explicit denies (D-7). No uid switch needed.
- **S-4 (mostly done)** `launchctl submit`/`bootstrap` and `open` fail under
  any profile; `pbcopy`/`mdfind` need the Mach allowlist; separate jails are
  separate sandboxes. Still open: the `osascript` baseline (it hung on an
  Automation prompt) and an `NSURLSession` background task.
- **S-5 (done)** The `base` fragment's Mach, ipc and device set, found with
  report mode over `tests/compat`: notify(3), `logd`, `/dev/tty`, `/dev/fd`,
  and the stdio metadata rule (D-6).
- **S-6 (done)** `(with report)` works for single rules and for `default`;
  log lines carry comm and pid. Signal denials aren't logged.
- **S-7 (done)** `TIOCSTI` is live on macOS 27 and blockable by ioctl
  command; no pty needed.
- **S-8** Teardown race: can a fork-heavy jail outrun the `SIGSTOP` sweep?
  Is `proc_listallpids` + audit token as root reliable for a whole session?
- **S-9 (mostly done)** With AMFI off, binding `/usr /bin /sbin /System
  /Library /private/etc` was enough; the dyld cache is reached through the
  `/System` bind, so no host path outside the jail root is needed. **Still
  open: the same test with AMFI enforcing.**
- **S-10 (half done)** `ps` fails because `/bin/ps` is setuid and its exec
  is denied. Still open: what (if anything) lets `PT_ATTACHEXC` work within
  the same sandbox.

## 10. Open questions

- **Q-1** *(answered: one config file in a fixed place, any owner; D-13)*
- **Q-2** Should `amosjail run` without `--role` pick a default role, or
  infer one from the command (`claude` → `agent`)? That's more seamless but
  more magic.
- **Q-3** DNS: allow `mDNSResponder` and accept the gap, or route jail DNS
  through mitmproxy's DNS mode?
- **Q-4** Should the daemon spawn (D-3), or should amosjail offer a
  setuid-root `amosjail-enter` as well, for environments without a daemon?
- **Q-5** One daemon or two? amosjaild and amosproxyd share the tag and the
  framing. With `network = "proxy"` as the common case, merging removes a
  failure mode.
- **Q-6** Default `proc_visibility`: `jail` hides `ps` output a harness may
  rely on (e.g. checking its parent).
- **Q-7** Should a denial also produce a structured event (for a later
  human-in-the-loop approval, like amosproxy M5), or only EPERM plus the
  Sandbox log line?

## 11. Risk register

1. **A missing SBPL operation (medium, high).** With no uid separation, an
   operation Seatbelt doesn't cover or we didn't deny is a direct escape.
   Mitigation: `(deny default)`, `tests/escape/` on every macOS release,
   S-3 and S-4 before anything else.
2. **Seatbelt deprecation (low, high).** If Apple removes runtime profile
   application, the fallback is `docs/es-alternative.md`.
3. **Harness compatibility (high, medium).** Harnesses change their sandbox
   flags and their Mach needs between releases. Mitigation: harness
   fragments are versioned, and `tests/compat/` pins harness versions.
4. **Mount verification gaps (medium, medium).** D-4 trusts `getmntinfo`'s
   view of who mounted what. A user-owned mountpoint could be swapped after
   verification and before chroot. Mitigation: verify again in
   `amosjail-enter` after chroot, by `fstatfs` on each bind target.

## 12. Conventions

- Test machine: macOS 27; mosbind installed and enabled; passwordless sudo
  for e2e scripts. SIP and AMFI need no changes for amosjail itself.
- Python ≥ 3.12 via uv; stdlib only. `amosjail-enter` builds with `cc` from
  the Command Line Tools.
- Every gate is a script under `tests/e2e/` that exits non-zero on failure.
- Commit messages reference ids (`T-02: …`).
