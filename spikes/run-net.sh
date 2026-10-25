#!/bin/sh
cd "$(dirname "$0")"; cc -o net net.c || exit 1
ip=100.78.179.107
python3 -c '
import socket, os, time, threading
socks = []
for fam, addr in [(socket.AF_INET, ("127.0.0.1", 18080)), (socket.AF_INET, ("0.0.0.0", 18081)), (socket.AF_INET6, ("::1", 18082))]:
    s = socket.socket(fam); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(addr); s.listen(); socks.append(s)
u = socket.socket(socket.AF_UNIX); p = "/tmp/mj-agent.sock"
try: os.unlink(p)
except OSError: pass
u.bind(p); u.listen(); socks.append(u)
time.sleep(30)' & srv=$!
sleep 1
echo "== unsandboxed (lan ip $ip)"; ./net $ip /private/tmp/mj-agent.sock
for p in "$@"; do echo "== $p"; sandbox-exec -f $p ./net $ip /private/tmp/mj-agent.sock; done
kill $srv
