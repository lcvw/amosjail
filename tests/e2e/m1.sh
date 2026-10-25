#!/bin/sh
# M1 gate (PLAN §7): a working jail, every escape row but E8 closed, clean
# teardown. Run on the test Mac after scripts/sync.sh:  sh tests/e2e/m1.sh
cd "$(dirname "$0")/../.." || exit 1
. tests/e2e/lib.sh
make -s -C tests/escape || exit 1
P=$HOME/aj-m1
rm -rf "$P"; mkdir -p "$P/.git/hooks"
cp tests/escape/probe tests/escape/net tests/escape/sti "$P/"
daemon_up || exit 1
cd "$P" || exit 1
MYIP=$(ipconfig getifaddr en0 2>/dev/null || echo 100.78.179.107)

echo "== basics"
out=$(aj run --role test -- /bin/sh -c 'pwd; id -u; echo hi > /work/new.txt && echo wrote' 2>&1)
check "cwd is /work" /work "$(echo "$out" | sed -n 1p)"
check "runs as the caller" "$(id -u)" "$(echo "$out" | sed -n 2p)"
check "rw bind writes reach the host" hi "$(cat new.txt 2>/dev/null)"
aj run --role test -- /bin/sh -c 'exit 7'; check "exit status" 7 $?
aj run --role test -- /bin/sh -c 'kill -TERM $$'; check "signal status" 143 $?

echo "== E1 filesystem"
check "host home invisible" no "$(aj run --role test -- /bin/sh -c "ls $HOME >/dev/null 2>&1 && echo yes || echo no")"
check "/etc read-only" denied "$(aj run --role test -- /bin/sh -c 'echo x > /etc/aj-x 2>/dev/null && echo written || echo denied')"
check "/usr read-only" denied "$(aj run --role test -- /bin/sh -c 'touch /usr/aj-x 2>/dev/null && echo written || echo denied')"
check "chroot holds at /.." "$(aj run --role test -- /bin/sh -c 'ls /')" "$(aj run --role test -- /bin/sh -c 'cd /../../..; ls')"
check "jail root not writable" denied "$(aj run --role test -- /bin/sh -c 'mkdir /evil 2>/dev/null && echo made || echo denied')"

echo "== E2-E4 outside processes"
SECRET_TOKEN=hunter2 "$OLDPWD/tests/escape/sleeper-gta" & T=$!
sleep 0.3
probe=$(aj run --role test -- /work/probe $T kill 2>&1)
for what in "kill(0)" "kill(SIGCONT)" "task_for_pid" "task_read_for_pid" "task_inspect_for_pid" \
    "task_name_for_pid" "proc_pidinfo(BSD)" "proc_pidpath" "sysctl(PROCARGS2)" "ptrace(PT_ATTACHEXC)" "kill(SIGKILL)"; do
  got=$(echo "$probe" | grep -F "$what " | head -1 | awk '{print $2}')
  check "$what on outside process" denied "$got"
done
check "no argv/env leak" "" "$(echo "$probe" | grep -o hunter2)"
check "outside target survives" yes "$(kill -0 $T 2>/dev/null && echo yes || echo no)"
check "can signal its own child" ok "$(aj run --role test -- /bin/sh -c 'sleep 5 & kill $! && echo ok')"
kill $T 2>/dev/null

echo "== E5 privilege"
check "sudo fails" fail "$(aj run --role test -- /bin/sh -c 'sudo -n true 2>/dev/null && echo root || echo fail')"

echo "== E6/E12 delegation and persistence"
check "launchctl submit" fail "$(aj run --role test -- /bin/sh -c 'launchctl submit -l aj.escape -- /usr/bin/true 2>/dev/null && echo escaped || echo fail')"
launchctl remove aj.escape 2>/dev/null
check "open -a" fail "$(aj run --role test -- /bin/sh -c 'open -a Calculator 2>/dev/null && echo escaped || echo fail')"
echo clean | pbcopy
aj run --role test -- /bin/sh -c 'echo jailed | pbcopy 2>/dev/null'
check "pasteboard" clean "$(pbpaste)"

echo "== E7/E8 network"
python3 -c 'import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0",18081)); s.listen(8)
t=socket.socket(); t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); t.bind(("127.0.0.1",18080)); t.listen(8)
time.sleep(30)' & L=$!
sleep 0.5
net=$(aj run --role test -- /work/net "$MYIP" /var/run/amosjaild-test.sock 2>&1)
kill $L 2>/dev/null
check "tcp 127.0.0.1 denied" no "$(echo "$net" | grep -q 'tcp 127.0.0.1 .*CONNECTED' && echo yes || echo no)"
check "tcp own address denied" no "$(echo "$net" | grep -q "tcp $MYIP .*CONNECTED" && echo yes || echo no)"
check "tcp 0.0.0.0 denied" no "$(echo "$net" | grep -q 'tcp 0.0.0.0 .*CONNECTED' && echo yes || echo no)"
check "udp denied" no "$(echo "$net" | grep -q 'SENT' && echo yes || echo no)"
check "daemon socket unreachable" no "$(echo "$net" | grep -q 'amosjaild-test.sock *CONNECTED' && echo yes || echo no)"
check "internet tcp (network=open)" yes "$(echo "$net" | grep -q 'tcp 1.1.1.1 .*CONNECTED' && echo yes || echo no)"
check "dns via mDNSResponder" yes "$(echo "$net" | grep -q 'getaddrinfo example.com RESOLVED' && echo yes || echo no)"
check "network=none" no "$(aj run --role offline -- /work/net "$MYIP" /x 2>&1 | grep -q 'tcp 1.1.1.1 .*CONNECTED' && echo yes || echo no)"

echo "== E10 inherited fds"
# sh and ls hold a couple of fds of their own: compare with the same command
# outside, before fd 7 is opened here.
base=$(/bin/sh -c 'ls /dev/fd' | tr '\n' ' ')
exec 7</etc/hosts
check "fd 7 is open out here" yes "$(/bin/sh -c 'ls /dev/fd' | grep -qx 7 && echo yes || echo no)"
check "only stdio inside" "$base" "$(aj run --role test -- /bin/sh -c 'ls /dev/fd' | tr '\n' ' ')"
exec 7<&-

echo "== E11 terminal"
sti=$(in_pty "aj run --role test -- /work/sti")
check "TIOCSTI (pty)" "TIOCSTI on stdin tty: Operation not permitted" "$sti"
check "/dev/tty (pty)" ok "$(in_pty "aj run --role test -- /bin/sh -c 'echo ok > /dev/tty'")"
check "job control (pty)" "fg-ok" "$(in_pty "aj run --role test -- /bin/sh -c 'set -m; sleep 0.2 & fg >/dev/null; echo fg-ok'")"

echo "== E13 rw-bind poisoning"
check "write .git/hooks" denied "$(aj run --role test -- /bin/sh -c 'echo x > .git/hooks/pre-commit 2>/dev/null && echo written || echo denied')"
check "rename .git away" denied "$(aj run --role test -- /bin/sh -c 'mv .git .git2 2>/dev/null && echo moved || echo denied')"
check "rename trick" absent "$( [ -e .git/hooks/pre-commit ] || [ -e .git2 ] && echo present || echo absent)"
check "write .envrc" denied "$(aj run --role test -- /bin/sh -c 'echo x > .envrc 2>/dev/null && echo written || echo denied')"
check "ordinary files" ok "$(aj run --role test -- /bin/sh -c 'mkdir -p src && echo x > src/a && mv src/a src/b && rm src/b && echo ok')"

echo "== E14 mounts from inside"
check "umount /work" fail "$(aj run --role test -- /bin/sh -c 'umount /work 2>/dev/null && echo unmounted || echo fail')"
check "mount -t mosbind" fail "$(aj run --role test -- /bin/sh -c 'mkdir -p /work/m && mount -t mosbind /usr /work/m 2>/dev/null && echo mounted || echo fail')"
rmdir "$P/m" 2>/dev/null

echo "== jails are separate"
aj_bg run --role test -- /bin/sh -c 'sleep 20'; A=$!
sleep 1.5
B_PID=$(pgrep -f "^sleep 20$" | head -1)
check "two jails at once (same /usr)" ok "$(aj run --role test -- /bin/sh -c 'echo ok')"
check "jail B can't signal jail A" denied "$(aj run --role test -- /bin/sh -c "kill -0 $B_PID 2>/dev/null && echo allowed || echo denied")"
kill $A 2>/dev/null; wait $A 2>/dev/null

echo "== teardown"
aj run --role test -- /bin/sh -c 'sleep 3001 & echo started' >/dev/null
sleep 1
check "background process killed with the jail" 0 "$(pgrep -f 'sleep 3001' | wc -l | tr -d ' ')"
aj_bg run --role test -- /bin/sh -c 'sleep 3002'; C=$!
sleep 1.5
kill -9 $C
sleep 2
check "client kill -9 ends the jail" 0 "$(pgrep -f 'sleep 3002' | wc -l | tr -d ' ')"
# Only /System may linger: the kernel keeps a chroot's dyld shared region
# (backed by that mount) for ~2 minutes, and the daemon never forces it.
check "only /System left draining" "" "$(mount | grep amosjail-test | grep -v '/root/System ' )"
echo "  (waiting for draining jails to unmount, up to 180s)"
for _ in $(seq 1 36); do [ "$(mount | grep -c amosjail-test)" = 0 ] && break; sleep 5; done
check "no mounts left" 0 "$(mount | grep -c amosjail-test)"
check "no jail dirs left" "" "$(ls /var/amosjail-test/$(id -u) 2>/dev/null)"
check "no state left" "" "$(sudo ls /var/db/amosjail-test/state | grep '^j')"
check "never forced an unmount" 0 "$(grep -c 'umount -f' "$LOG")"

daemon_down
echo
[ $fails -eq 0 ] && echo "M1: all checks passed" || echo "M1: $fails check(s) failed"
exit $fails
