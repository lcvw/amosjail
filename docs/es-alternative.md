# mosjail — Endpoint Security alternative (not pursued)

> Superseded by `../PLAN.md` (Seatbelt). Kept because it is the fallback if
> Seatbelt nesting or a missing SBPL operation rules Seatbelt out.

**Status:** design only; nothing built or measured yet.
**Last updated:** 2026-10-25

Decisions are `D-nn`, tasks `T-nn`, spikes `S-nn`, open questions `Q-nn`; all
are referenceable in commits. Same conventions as `../amosproxy/PLAN.md`,
which this plan builds on and shares its tag with.

## 1. Purpose

Confine agent process trees on macOS to a **jail**: a chroot assembled from
mosbind bind mounts, where the tree

- cannot touch the filesystem outside the jail,
- cannot ptrace, inspect, suspend or signal anything outside the jail,
- cannot leave its amosproxy tag or get around the proxy's controls.

A process **enrolls** with a **role** from `mosjaild`'s TOML config. The role
says what is bound in, what may run and what it may reach. Enrollment is
bound to the caller's audit session, which the kernel reports over the
enrollment socket (`LOCAL_PEERTOKEN`) — never to anything in the request.

**Enforcement is an Endpoint Security (ES) system extension**, not Seatbelt.
See D-1.

### Non-goals

Kernel exploits, ES or XNU bugs, timing side channels, resource fairness
beyond rlimits, multi-machine policy, a GUI.

## 2. Threat model

The jailed tree runs arbitrary code as an unprivileged, per-jail uid (D-4).
It is assumed hostile and knows how mosjail works. It wins if it does any of:

| # | Escape | Primary control | Backstop |
|---|---|---|---|
| E1 | read/write/exec a host path outside the jail | chroot over mosbind (view) | ES file events (D-7) |
| E2 | signal, suspend or kill an outside process | per-jail uid (kernel) | ES `AUTH_SIGNAL`, `AUTH_PROC_SUSPEND_RESUME` |
| E3 | ptrace or get a task port of an outside process | per-jail uid (kernel) | ES `AUTH_GET_TASK*`; `NOTIFY_TRACE` kills the tracer |
| E4 | see outside processes (`ps`, args, env) | ES `AUTH_PROC_CHECK` | — |
| E5 | become root (setuid binary, sudo) → new audit session, chroot out | mosbind is `nosuid` (FSKit forces it) | ES denies exec of setuid/setgid files and exec as any uid but the jail's (D-5) |
| E6 | delegate work to launchd/XPC (`launchctl submit`, `open`, LaunchAgents) so it runs untagged | per-jail uid: the job runs as that uid; ES denies exec for that uid outside the jail's session (D-6) | `NOTIFY_XPC_CONNECT` audit; bootstrap domain switch (D-12) |
| E7 | reach a local service that acts for it (ssh-agent, docker, amosproxy's sockets, a local proxy) | ES `AUTH_UIPC_CONNECT` allowlist | pf `user` rules on `lo0` for TCP/UDP loopback (D-13) |
| E8 | send traffic amosproxy doesn't see (UDP, loopback, provider restart window) | amosproxy | pf per-uid backstop (D-13) |
| E9 | tamper with mosjail/amosproxy (config, sockets, binaries, kill the extension) | outside the jail's view; uid | ES deny |
| E10 | use a file descriptor opened outside the jail | `mosjail run` closes every fd ≥ 3 | `UIPC_CONNECT` limits fd-passing peers |
| E11 | inject keystrokes into the invoking terminal (`TIOCSTI`) after exit | jail gets its own pty (D-11) | — |
| E12 | outlive teardown (stray processes, launchd jobs, files) | teardown kills by uid and boots out the uid's launchd domain (D-10) | — |

Residual gaps that are known to be open are listed in §8.

## 3. What we already know

From amosproxy (verified on macOS 27.0.1, arm64):

1. The audit session id (asid) is inherited across fork, exec, `posix_spawn`,
   `vfork`, `setsid` and reparenting. An unprivileged process can't leave it
   or create a new one (amosproxy §2).
2. A root process can put itself in a fresh session with
   `setaudit_addr(AU_ASSIGN_ASID)` (`amosproxy/src/amosproxy/session.py`).
3. `launchctl submit` from a tagged session yields a process in launchd's
   session, with ppid 1 (amosproxy §6). That's E6.
4. Our own system extensions load ad-hoc signed with restricted entitlements
   on a machine with SIP off, `systemextensionsctl developer on` and
   `amfi_get_out_of_my_way=1`.

From mosbind (`../mosbind/README.md`):

5. FSKit forces `nosuid`, `nodev`, `noowners`, `noatime` on every mount.
6. The kernel does **no** permission enforcement on a mosbind volume. The
   module's `refuse()` admits only the mounting user and root, so a jail uid
   is refused today (T-03).
7. The extension runs as the mounting user, in the App Sandbox, and does the
   host-side I/O itself.

Assumed, not yet written down anywhere: chroot + exec into a mosbind tree
works (the dyld shared cache / platform binary problem has been worked
around). S-9 records exactly which host paths that workaround needs, because
the ES path policy must allow them.

## 4. Architecture

```
 sudo mosjail run --role agent -- claude …
   │ supervisor (root, NOT jailed): owns the pty, forwards signals, reports exit
   │ fork ──► child
   │           1. setaudit_addr(AU_ASSIGN_ASID)                 fresh asid
   │           2. amosproxy tag {label}                          if role.proxy = "required"
   │           3. mosjaild enroll {role}  ───────────────────┐
   │                ◄── {jail, root, uid, gid} after ext ack  │
   │           4. chroot(root); chdir                         │ allowed once, to root only
   │           5. setgroups/setgid/setuid(jail uid)           │
   │           6. closefrom(3); reset env; rlimits            │
   │           7. execve  ── first exec must be as jail uid ──┤ (D-5)
   ▼                                                          ▼
 jailed tree (asid N, uid U) ── every AUTH event ──► MosJail.systemextension (ES client)
                                                       jailed(token)?  asid ∈ jails or uid ∈ jail uids
                                                         no  → allow       (one lookup)
                                                         yes → evaluate the compiled role
                                                       ▲ jail table, compiled roles
                                                       │ (extension channel, unix socket)
 mosjaild (root, launchd) ─────────────────────────────┘
   ├─ config        /etc/mosjail/mosjail.toml   (root-owned, refused if not)
   ├─ control       /var/run/mosjaild.sock      enroll / status / kill
   ├─ ext channel   /var/run/mosjaild-ext.sock
   ├─ jail builder  uid allocation, jail root, mosbind mounts, teardown
   └─ state         /var/db/mosjail/            survives daemon and extension restarts
```

### Decisions

- **D-1 Use ES, not Seatbelt.** Agent harnesses (Claude Code, Codex, …)
  already sandbox themselves with Seatbelt, and a sandboxed process can't
  apply a second profile. Anything that nests (the harness, SwiftPM, Bazel)
  would break. ES sits outside the process, so it composes with whatever
  Seatbelt profile the harness applies inside the jail. The cost: no
  `mach-lookup` control (E6 needs D-6 and D-12 instead), an entitlement, and
  two approvals at install (§5 M4).
- **D-2 The tag is the audit session, shared with amosproxy.** One asid
  carries both the network tag (amosproxy) and the jail (mosjail). ES gives
  `audit_token` on every `es_process_t`, so matching is
  `audit_token_to_asid` plus a set lookup, the same as amosproxy D-1.
- **D-3 Enrollment is bound to the kernel's view of the caller.** `enroll`
  reads `LOCAL_PEERTOKEN` (asid, pid, pidversion, euid). Note that
  `LOCAL_PEERCRED` (xucred) carries no pid or asid. Request fields are never
  trusted for identity. The daemon refuses when:
  - the asid is already jailed — roles never widen, and there is no
    re-enrollment;
  - the asid is the daemon's own or launchd's;
  - **the caller is not alone in its asid.** The extension tracks session
    membership from `NOTIFY_FORK`/`NOTIFY_EXIT` (D-9). Without this check,
    enrolling from a Terminal shell would jail the user's whole login
    session;
  - the caller's uid isn't in `role.allowed_callers`.
- **D-4 One uid per running jail**, allocated from a configured range (e.g.
  600–699) and never shared by two live jails. The kernel then blocks
  cross-uid ptrace and signals, and blocks cross-user keychain, pasteboard and
  per-user launchd services, before ES is consulted (E2, E3, E6). It also
  makes teardown exact (D-10), makes RLIMIT_NPROC a per-jail fork-bomb limit,
  and lets pf match the jail (D-13).
- **D-5 Nothing runs as root in a jail.** Root inside could make a new asid
  (leaving both tags), chroot out, or mount. Enforced three ways:
  - mosbind is `nosuid` and the jail root contains only mountpoints;
  - ES `AUTH_EXEC` in a jailed session is denied unless euid = ruid = the
    jail uid, and denied for any target with the setuid or setgid bit;
  - `NOTIFY_SETUID`/`SETEUID`/… to uid 0 in a jailed session is a tripwire
    that kills the jail.

  The enrolling root process may chroot once, into its jail root only
  (`AUTH_CHROOT`), and drop privileges before its first exec.
- **D-6 The uid is an alias tag.** A process whose uid is a live jail's uid
  counts as in that jail, whatever its asid. A process with that uid in a
  *different* asid is denied `AUTH_EXEC` and logged. This turns
  `launchctl submit`, LaunchAgents and on-demand per-user XPC services into
  failed execs instead of escapes. amosproxy should match on uid the same way
  (T-41).
- **D-7 File policy is an allowlist over host paths.** The role is written in
  jail paths (`/work`). mosjaild compiles it against the jail root
  (`/var/mosjail/j7/root/work`), plus the host paths the chroot workaround
  needs (S-9), into a path trie the extension evaluates. Covered events:
  - `AUTH_OPEN` (read-only via `es_respond_flags_result` stripping `FWRITE`)
  - `CREATE`, `UNLINK`, `RENAME` and `LINK` (both ends), `CLONE`,
    `COPYFILE`, `EXCHANGEDATA`, `TRUNCATE`
  - `SETATTRLIST`, `SETEXTATTR`, `DELETEEXTATTR`, `SETMODE`, `SETOWNER`,
    `SETFLAGS`, `SETACL`, `UTIMES`
  - `READDIR`, `CHDIR`, `GETATTRLIST`, `FSGETPATH`, `EXEC`
  - `MOUNT`, `REMOUNT` (always denied), `CHROOT` (D-5), `UIPC_BIND`,
    `UIPC_CONNECT`

  The chroot already confines the view, so the allowlist is the backstop for
  fds and paths that reach past it. The ES path spelling for FSKit volumes
  and chrooted callers is S-2. Path normalisation (case, NFD, firmlinks,
  `/private`) happens once, at compile time.
- **D-8 The hot path never blocks.** The extension evaluates every AUTH
  event locally from its own copy of the policy. It never calls the daemon
  during an event, mutes itself and mosjaild (`es_mute_process`), and on
  internal error answers deny for jailed processes and allow for the rest.
  Untagged events cost one asid lookup and one uid range check.
- **D-9 The extension owns session membership.** It tracks
  `{asid → pids}` and `{uid → pids}` from `NOTIFY_FORK`/`EXEC`/`EXIT`, seeded
  at start by enumerating processes. This feeds D-3's "alone" check and
  D-10's lifetime, and answers amosproxy S-2 (when a session is empty). How
  accurate this is depends on S-3.
- **D-10 Jail lifetime = membership.** When the last process of the jail's
  asid *and* uid exits, the daemon tears down:
  1. kill whatever is left as the jail uid (`kill(-1, SIGKILL)` from a
     helper that setuids to it, looped until `proc_listpids` by uid is empty);
  2. `launchctl bootout user/<uid>`;
  3. unmount the binds in reverse order and remove the jail root;
  4. untag the asid in amosproxy and the extension;
  5. release the uid.

  `mosjail kill <jail>` (root only) forces the same path. A startup reaper
  replays `/var/db/mosjail/` to clean up after a crashed daemon.
- **D-11 The jail never inherits the invoking terminal.** The supervisor
  allocates a pty when stdin is a tty and relays it. The child does `setsid`
  and makes the pty slave its controlling tty. Without a tty, stdin, stdout
  and stderr are pipes. This closes E11, and keeps job control and Ctrl-C.
- **D-12 The jail gets the jail uid's bootstrap domain**, not the invoker's
  GUI session (the effect of `launchctl asuser <uid>`). Mach lookups then
  reach the jail user's own (empty) per-user services instead of the real
  user's. ES can't gate `mach-lookup`, so this, D-4 and D-6 together are the
  E6 defence. Exact mechanism: S-4.
- **D-13 pf backstop keyed on uid.** mosjaild loads an anchor with
  `block out quick on lo0 … user { <range> }` (loopback is invisible to the
  transparent proxy) and, when `role.proxy = "required"`, blocks non-TCP
  for those uids. This also covers amosproxy's provider-restart window
  (amosproxy S-5). It needs pf's `user` matching to work on macOS 27 (S-5).
- **D-14 Fail closed.**
  - `enroll` replies only after the extension acks the new jail (as in
    amosproxy D-10). No extension means no jail.
  - The extension persists the jail table and reloads it before
    subscribing, with `NSEndpointSecurityEarlyBoot`.
  - If the extension channel drops, mosjaild kills every live jail by uid
    (`on_extension_loss = "kill"`, the default).
  - `role.proxy = "required"` and no amosproxy tag → enrollment refused.
- **D-15 ES auth caching is off for jailed processes.** ES's cache key does
  not include the asid. For untagged processes it may be on, but only if S-1
  shows the key is the executable's vnode and jailed executables never share
  a vnode with host executables (they come through mosbind). Until then,
  cache nothing.
- **D-16 Languages.** Extension in Swift (SwiftPM + Command Line Tools, the
  build already proven in amosproxy). mosjaild and `mosjail` in Python,
  stdlib only (`tomllib`), reusing amosproxy's `session.py`, `darwin.py`
  peer-token code and wire framing. Revisit if the CLI's pre-exec sequence
  is cleaner in Swift (Q-8).

## 5. Config

```toml
[daemon]
jail_dir = "/var/mosjail"
uids = { first = 600, count = 100 }
on_extension_loss = "kill"
amosproxy_socket = "/var/run/amosproxy.sock"

[roles.agent]
allowed_callers = { uids = [0] }
proxy = "required"                  # required | optional | none
proxy_label = "agent"
binds = [                           # mosbind, mounted under the jail root
  { source = "/Users/liam/src/proj", target = "/work",          mode = "rw" },
  { source = "/opt/homebrew",        target = "/opt/homebrew",  mode = "ro" },
]
deny = ["/work/.git/hooks/**"]      # jail paths, beats binds
exec = ["/usr/bin/**", "/bin/**", "/opt/homebrew/bin/**", "/work/.venv/bin/**"]
unix_sockets = ["/private/var/run/mDNSResponder"]   # host paths; see Q-5
proc_visibility = "jail"            # jail | all
rlimits = { nproc = 512, nofile = 4096 }
env = { keep = ["TERM", "LANG"], set = { HOME = "/work" } }
```

Roles are immutable for a live jail. A config reload affects new jails only
(and calls `es_clear_cache` if D-15 allows caching).

### Wire protocol

Line-delimited JSON on `/var/run/mosjaild.sock`, like amosproxy's control
socket. The extension channel uses 4-byte big-endian length + JSON (amosproxy
D-5).

```
{"op":"enroll","role":"agent"}
  → {"ok":true,"jail":"j7","root":"/var/mosjail/j7/root","uid":607,"gid":607}
{"op":"status"}                → {"ok":true,"jails":[…]}
{"op":"kill","jail":"j7"}      → root only
```

## 6. Layout

```
src/mosjail/
  cli.py          run / status / kill / daemon; stdlib only
  enter.py        child pre-exec sequence (§4 steps 1–7)
  pty.py          supervisor pty relay (D-11)
  config.py       tomllib load, validation, root-ownership check
  compile.py      role → compiled policy (path trie, exec set, flags)
  jails.py        uid allocation, jail root, mosbind mounts, teardown, reaper
  control.py      control socket; enroll checks (D-3)
  extchannel.py   extension channel server
  amosproxy.py    client for amosproxy's control socket
  pf.py           anchor management (D-13)
macos/
  Sources/MosJailCore/       policy evaluation, jail table, membership,
                             persistence, channel client   unit-tested
  Sources/MosJailExtension/  ES client: subscribe, dispatch, respond
  Sources/MosJailApp/        activate / deactivate / status
  build.sh
tests/
  escape/         one script per §2 row; each must fail to escape
  e2e/            milestone gates
```

## 7. Milestones

### M0 — spikes

S-1 to S-9 (§9). M1 can start once S-1, S-2 and S-3 are answered.

### M1 — observe only

Everything through the verdict, with the extension still allowing all, so
the policy can be checked with zero risk to the machine.

- **T-01** Config load and validation; role compiler; unit tests.
- **T-02** Jail builder: uid allocation, jail root, mosbind mounts
  (`--rdonly` for `ro`), teardown, reaper.
- **T-03** *(mosbind)* Admit an extra uid per mount (e.g. `-o admit=607`), so
  the jail uid isn't refused by `refuse()`.
- **T-04** Control socket: `enroll` with D-3 checks, `status`, `kill`.
- **T-05** `mosjail run`: supervisor + child sequence, closefrom, env, pty.
- **T-06** Extension: ES client, membership tracking (D-9), jail table and
  persistence, channel with ack. Subscribes to every event in D-5/D-7 and
  §2, logs `allow|deny <event> <jail> <path>` and always responds allow.

**Gate:** `tests/e2e/m1-verdicts.sh` runs a realistic workload (git, python,
node, curl, a harness that applies its own Seatbelt profile) plus every
`tests/escape/` script. It passes when:
- the workload logs zero denies;
- every escape attempt logs at least one deny;
- untagged processes log no verdicts at all;
- the measured overhead of uncached `AUTH_OPEN` is acceptable (S-6).

### M2 — enforce

- **T-10** Respond with the verdicts; fail-closed paths (D-14).
- **T-11** Tripwires: root in a jailed session, `NOTIFY_TRACE`, uid alias
  outside its session (D-5, D-6).
- **T-12** Teardown by membership (D-10).

**Gate:** every `tests/escape/` script fails to escape; the M1 workload
still passes; killing the extension kills the jails; the daemon refuses to
enroll with the extension down.

### M3 — proxy and delegation

- **T-40** `role.proxy`: tag via amosproxy before enroll; daemon confirms
  the asid is tagged before acking.
- **T-41** *(amosproxy)* Match flows by jail uid as well as asid (D-6).
- **T-42** pf anchor (D-13).
- **T-43** Bootstrap domain switch (D-12), per S-4's findings.
- **T-44** `NOTIFY_XPC_CONNECT` audit log; optional per-role denylist of
  service names that kills the connecting process.

**Gate:** `tests/escape/e6-*`, `e7-*`, `e8-*` with amosproxy running and with
the amosproxy provider stopped.

### M4 — packaging

`mosjail install`: hidden `_mosjailNNN` accounts (Q-3), launchd plist,
container app, then guiding the two approvals (system extension and Full
Disk Access for the ES client, without which `es_new_client` returns
`ERR_NOT_PERMITTED`). `docs/SETUP.md` covers SIP, developer mode and the
AMFI boot-arg.

## 8. Known gaps

- **Root daemons acting on a jail's behalf** — Spotlight (`mds`), LaunchServices
  and other system services that run as root and do work for whoever asks.
  They read with their own rights, so ES sees *them*, untagged. D-4 and D-12
  shrink the reachable set; S-4 lists what remains. Seatbelt's `mach-lookup`
  would have closed this; it's the price of D-1.
- **DNS is unattributed** and goes through `mDNSResponder`, which makes it a
  low-bandwidth exfiltration channel if allowed (Q-5).
- **Already-open fds** aren't seen by ES. Covered for the jail's own start
  (closefrom), not for fds a reachable outside service chooses to send.
- **Extension death window.** Between the extension dying and mosjaild
  killing the jails (D-14), jailed processes are unrestricted.
- **Shared rw binds** between jails are a channel between them, by
  configuration.
- **Hard links.** A host file hard-linked into a bound directory is visible
  through it. ES and mosbind both report one name for it.
- **Deprecated BSM audit APIs** (amosproxy risk 4); shared fate.

## 9. Spikes

- **S-1** ES auth-cache key: what exactly is keyed (executable vnode? path?
  process?), and whether a jailed and an untagged process can ever share an
  entry. Decides D-15.
- **S-2** What ES reports for a chrooted process opening a file on a mosbind
  volume: host path or chroot-relative path? Do FSKit volumes deliver every
  event in D-7? How do hard links and `path_truncated` show up? Decides D-7's
  compiler.
- **S-3** Does `NOTIFY_FORK` always reach our client before the child's
  first AUTH event? If yes, membership (D-9) is exact and pid-tree tagging
  becomes a possible fallback to asids.
- **S-4** Delegation inventory, run as a jail uid in a jail: `launchctl
  submit`, `launchctl bootstrap`, `open`, `osascript`, an `NSURLSession`
  background download, `mdfind`, `pbcopy`, `security`. For each: does it
  escape after D-4, D-6 and D-12? And how do we switch the bootstrap port to
  the jail uid's domain from our own code?
- **S-5** pf `user` rules on `lo0` and for UDP on macOS 27: do they match
  per socket owner, and are they reliable for the whole socket lifetime?
- **S-6** Cost of uncached system-wide `AUTH_OPEN` with a compiled trie:
  latency per event, and wall time for a build in and out of a jail.
- **S-7** Cross-uid ptrace: confirm `PT_ATTACH` and `task_for_pid` fail, and
  that `NOTIFY_TRACE` fires for same-uid attaches inside a jail.
- **S-8** `TIOCSTI` on macOS 27: still available? Under what rules?
- **S-9** Which host paths outside the jail root the chroot workaround
  needs (dyld shared cache, cryptexes, `/dev` nodes), so D-7 can allow
  exactly those.

## 10. Open questions

- **Q-1** Who mounts the binds, and as whom? mosbind's extension runs as the
  mounting user, inside the App Sandbox. Does a root mount by mosjaild work,
  and can it reach arbitrary sources?
- **Q-2** Should enrollment without root and without a chroot be supported
  (ES policy only, for a caller already alone in its asid)? D-3 allows it;
  M1 only builds `mosjail run`.
- **Q-3** Jail uids: hidden directory-services accounts (so `getpwuid`, git
  and ssh work), or bare uids with `HOME`/`USER` set?
- **Q-4** One daemon or two? mosjaild and amosproxyd share the tag and the
  framing. Merging them removes a round-trip and a failure mode (D-14's
  proxy check) but couples releases.
- **Q-5** DNS: allow `mDNSResponder` and accept the gap, or route jail DNS
  through mitmproxy's DNS mode, at the cost of tools that bypass
  `/etc/resolv.conf`?
- **Q-6** Default `proc_visibility`: `jail` breaks nothing obvious but may
  surprise tools that inspect their parent.
- **Q-7** What happens when a role is denied something at runtime: EPERM
  only, or also a structured event other tools can consume (for later
  human-in-the-loop approval, like amosproxy M5)?
- **Q-8** Language for `mosjail run`'s pre-exec sequence: Python (reuses
  amosproxy) or Swift (shares types with the extension)?

## 11. Risk register

1. **Approvals and entitlements (certain, high for distribution).**
   `com.apple.developer.endpoint-security.client` is restricted; ad-hoc works
   only on a weakened test machine. Distribution needs Apple's grant.
2. **Per-event cost (medium, high).** Every file open on the machine goes
   through us. The untagged path must stay one lookup and no allocation, or
   the whole machine slows down.
3. **ES deadline kills (low, high).** Missing a deadline gets the client
   killed, which triggers D-14 and kills every jail. Keep the hot path pure
   (D-8); watch `es_message_t.deadline` in tests.
4. **Delegation gap (high, medium).** §8's first item may be larger than
   expected. S-4 decides whether it's acceptable or needs a bootstrap
   filter (a mach bootstrap server that allowlists lookups; possible but
   private-protocol work).
5. **Platform drift (medium, medium).** BSM, FSKit and ES event semantics can
   change across releases. Every spike becomes a test under `tests/` and is
   re-run per macOS release.

## 12. Conventions

- Test machine: SIP off, `systemextensionsctl developer on`,
  `amfi_get_out_of_my_way=1`, passwordless sudo for e2e scripts.
- Python ≥ 3.12 via uv; CLI stdlib only. Swift via SwiftPM, no Xcode project.
- Every gate is a script under `tests/e2e/` that exits non-zero on failure.
- Commit messages reference ids (`T-04: …`).
