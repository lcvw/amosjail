# Spike results — 2026-10-25

Measured on the test Mac: macOS 27.0.1 (26A434), arm64, SIP off,
`amfi_get_out_of_my_way=1`. The jail ran as the invoking user (uid 501), not a
separate uid. Probes and profiles are in `spikes/`; each section names the
script.

## Process isolation (S-3) — works, with explicit rules

`spikes/probe.c` tries every way of reaching another process.

| Attempt on an outside same-uid process | unsandboxed | jailed |
|---|---|---|
| `kill(0)`, `kill(SIGCONT)`, `kill(SIGKILL)` | allowed | **denied** |
| `pid_suspend` | denied (kernel) | denied |
| `task_for_pid` / `task_read_for_pid` / `task_inspect_for_pid` on a `get-task-allow` target | **allowed** | **denied** |
| `task_name_for_pid` | allowed | **denied** |
| `ptrace(PT_ATTACHEXC)` on a `get-task-allow` target | **allowed** | **denied** |
| `proc_pidinfo`, `proc_pidpath` | allowed | **denied**, but only with explicit rules (below) |
| `sysctl KERN_PROCARGS2` (argv **and environment**) | allowed | **denied**, but only with explicit rules (below) |
| `proc_listallpids` | allowed | configurable |

Same-uid code with no sandbox can take the task port of, and ptrace, any
debuggable process (dev builds signed with `get-task-allow`). Running as the
user's uid, Seatbelt is the only thing in the way, and it holds.

**`(deny default)` does not deny process info.** `proc_pidinfo`,
`proc_pidpath` and `proc_listallpids` on outside processes succeed under a
deny-default profile. Args and environment leak through `sysctl` whenever
`sysctl-read` is allowed, and most programs need it. The rules that work:

```scheme
(allow sysctl-read)
(deny process-info*)
(deny sysctl-read (sysctl-name-prefix "kern.proc"))
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
; optional: let the jail list pids and names (not args/env) of everything
(allow process-info-listpids)
(allow sysctl-read (sysctl-name "kern.proc.all"))
; optional: debugging inside the jail
(allow mach-priv-task-port (target same-sandbox))
(allow mach-task-name (target same-sandbox))
```

With these, a jail can signal and inspect its own processes (including argv
and environment) and nothing else.

- **Separate jails are separate sandboxes.** Two processes started under two
  `sandbox-exec` invocations with the same profile file cannot signal or
  inspect each other. `same-sandbox` means the same application of a profile,
  not the same profile text.
- **ptrace inside the jail stays denied** even with the task-port rules, so
  lldb inside a jail won't work fully. No allowing operation found yet.
- `ps` prints nothing under these profiles, even with listing allowed; the
  cause wasn't investigated.

## Delegation to launchd and other services (S-4) — mostly closed

`spikes/deleg.sh` asks things outside the sandbox to act for it.

| Attempt | unsandboxed | jailed, minimal Mach | jailed, all `mach-lookup` allowed |
|---|---|---|---|
| `launchctl submit` (job runs, writes a marker) | **escaped** | blocked | blocked |
| `launchctl bootstrap gui/501 plist` | **escaped** | blocked | blocked |
| `open -a Calculator` | **escaped** | blocked | blocked (`-54`, can't issue sandbox extension) |
| `pbcopy` to the real clipboard | works | blocked | **works** |
| `mdfind` (Spotlight, host-wide) | works | blocked | **works** |
| `osascript` → System Events `do shell script` | timed out (Automation prompt) | blocked | blocked (`-54`) |

launchd and LaunchServices refuse sandboxed callers whatever the Mach rules
say. Services that don't check (pasteboard, Spotlight) are stopped only by the
`mach-lookup` allowlist, so the allowlist matters. The unsandboxed `osascript`
baseline hung on an Automation permission prompt, so that row is unproven.

## Network (E7, E8) — works

`spikes/net.c` against listeners on loopback, the Tailscale address, a unix
socket and the internet.

```scheme
(allow network-outbound (remote tcp "*:*"))
(deny network-outbound (remote ip "localhost:*"))
(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))
```

- `localhost` in SBPL also matches `0.0.0.0`, `::1` **and the machine's own
  interface address** (`100.78.179.107`), so the loopback block can't be
  bypassed by dialling the machine's own IP.
- Unix sockets are allowed per path.
- DNS (`getaddrinfo`) works with only the `mDNSResponder` socket allowed. No
  UDP rule is needed, and UDP to `1.1.1.1:53` stays denied.

## Path matching inside a chroot (S-1) — host path of the mount

`spikes/run-s1.sh` chroots into a mosbind tree and runs `sandbox-exec` inside.
The rule that bites is the **host spelling of the mount path**, e.g.
`/private/tmp/mj2/root/work/...`. Neither the chroot path (`/work/...`) nor the
bind's source path matches. The compiler must emit every jail path prefixed
with the jail root's host path, in its `/private/...` form.

## chroot + mosbind (S-9) — worked once, then broke

- **It worked.** With `/usr /bin /sbin /System /Library /private/etc` bound
  read-only, `chroot` + exec of `/bin/echo`, `/bin/sh` and an ad-hoc-signed
  binary all succeeded. `/System/Volumes/Preboot/Cryptexes` is visible
  through the `/System` bind (mosbind follows host submounts), so dyld found
  its cache. This was with AMFI disabled; whether platform binaries still
  launch from mosbind with AMFI on is unknown.
- **`/dev` can't come from mosbind**: FSKit forces `nodev`, so `/dev/null`
  is unusable. A real `mount -t devfs devfs <root>/dev` (root) works.
- **Transient SIGBUS after a mosbind reinstall.** Another session
  reinstalled mosbind, which restarted fskitd and dropped every mount. For a
  few minutes afterwards, every exec inside a chroot died with SIGBUS
  (rc 138), even for a brand-new jail root with fresh mounts. The crash is in
  dyld, `hasExistingDyldCache` → `DyldSharedCache::dynamicRegion`
  (`KERN_MEMORY_ERROR`), reading a shared-region page. Memory-mapped reads of
  the cache files through the mount from outside succeeded. Once the system
  settled, the same jail worked with no changes. The cause is unknown; the
  likeliest suspect is a dyld shared region whose backing volume was torn
  down. Jails must not outlive their mosbind volumes, and a jail whose
  volumes vanish should be torn down.
- **Never use a mosbind mount as a mosbind source.** Mounting
  `/tmp/mj2/root/usr` (itself a mosbind mount) hung the new extension
  instance in an uninterruptible wait. That blocked `mount`/`getfsstat` for
  every process on the machine, including another session's unmount. Only
  `kill -9` of that `MosBindFS` instance recovered it.
- **FSKit refuses to mount the same source twice** ("Probing resource: Resource
  busy"), so two jails can't both bind `/usr`. A subdirectory of a bound
  source mounts fine, and so do different spellings of the same path
  (`/usr/.`, `//usr`, `/private/../usr`): FSKit dedupes on the URL string.
- `chroot -u USER` leaves `egid=0(wheel)`. Set every gid explicitly.

## Entry sequence (S-2) — works

`spikes/enter.c`, linked with `-lsandbox`:
1. `sandbox_compile_string` with params, as root, before dropping
   privileges;
2. `setgroups`, `setgid`, `setuid`, and check that `setuid(0)` now fails;
3. close fds ≥ 3;
4. `sandbox_apply`, then `execv`.

The exec'd process runs as 501:20, is sandboxed, and can't reach outside
processes. An fd open in the parent (7) is gone. The full supplementary group
list reappears after `setgroups(1)`, which is harmless when the jail is the
same user.

**Nesting is impossible, confirmed.** A second `sandbox_apply` in an
already-sandboxed process fails with `Operation not permitted`, whether the
first profile came from `sandbox-exec` or `sandbox_apply`, and whether it was
allow-default or deny-default.

## Report mode (S-6) — works

- `(allow (with report) default)` and `(allow default (with report))` are
  both valid. Under either, every operation is logged as
  `Sandbox: <comm>(<pid>) allow <operation> <target>`, which is the input a
  learning mode needs.
- Denials log as `deny(1) <operation> <target>`. A signal denial (`kill -0 1`)
  produced no log line, so not every denial is reported.
- The kernel collapses repeats into "N duplicate reports", so learning is
  best-effort.
- On the Mac, run `/usr/bin/log`: zsh's `log` builtin shadows it over ssh.

## Terminal injection (E11) — real, and blockable

- `ioctl(0, TIOCSTI)` **injects input into the controlling terminal** on
  macOS 27, unsandboxed and under an allow-default profile.
- `(deny file-ioctl (ioctl-command #x80017472))` blocks just `TIOCSTI`; other
  tty ioctls (`stty size`) keep working. The filter takes an integer;
  `"TIOCSTI"` is rejected.
- So a jail can keep the user's real terminal. A pty relay is optional (it
  would still help to filter escape sequences such as OSC 52 clipboard
  writes).

## End to end (`spikes/run-e2e.sh`) — works

`enter` (compile → chroot → drop to 501:20 → close fds → apply → exec), with
`spikes/jail.sb`: deny-default, every path prefixed with the jail root's
`/private/...` host path. The jail root has mosbind binds for `/usr /bin
/sbin /System /Library /private/etc`, a rw `/work`, and devfs on `/dev`.

| Check inside the jail | Result |
|---|---|
| `/bin/sh`, `ls`, `tty`, `stty` | work |
| write `/work/out.txt` | ok |
| write `/work/.git/hooks/pre-commit` | denied |
| write `/usr/x` | denied (Seatbelt; mosbind is ro too) |
| `task_for_pid`, `proc_pidpath`, `PROCARGS2`, ptrace, SIGKILL on an outside `get-task-allow` process holding `SECRET_TOKEN` | all denied; target survives |
| signal own child | ok |
| TCP to `127.0.0.1`, to the Mac's own address, UDP to loopback | denied |
| TCP to `1.1.1.1:80` | connected |
| `TIOCSTI` on the real tty | denied |
| `getaddrinfo` | fails until `/var/run/mDNSResponder` is visible in the chroot; **works with a hard link** of the host socket into `<root>/private/var/run/` (same APFS volume) |

The hard-linked socket goes stale if mDNSResponder restarts and recreates
it. Jails need to re-link it, or accept losing DNS until they're restarted.
