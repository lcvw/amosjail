#!/bin/sh
# M2 gate (PLAN T-20, T-21): network = "proxy" jails are tagged in amosproxy
# before exec, their TCP goes through it, and they fail closed without it.
# Needs amosproxy's daemon and extension running (uses the default socket);
# only tags and untags its own sessions. Run after scripts/sync.sh.
cd "$(dirname "$0")/../.." || exit 1
. tests/e2e/lib.sh
make -s -C tests/escape || exit 1
[ -S /var/run/amosproxy.sock ] || { echo "amosproxy isn't running"; exit 1; }
FLOWS=/var/log/amosproxy/flows.jsonl
P=$HOME/aj-m2
rm -rf "$P"; mkdir -p "$P"; cp tests/escape/net "$P/"
daemon_up || exit 1
cd "$P" || exit 1
MYIP=$(ipconfig getifaddr en0 2>/dev/null || echo 100.78.179.107)
ap() { /usr/local/amosproxy/venv/bin/amosproxy "$@"; }

echo "== tagging"
aj_bg run --role proxied -- /bin/sh -c 'sleep 4'; C=$!
sleep 2
st=$(ap status 2>&1)
check "jail's session is tagged" yes "$(echo "$st" | grep -q amosjail-e2e && echo yes || echo no)"
asid=$(aj status | sed -n 's/.*asid=\([0-9]*\).*/\1/p' | head -1)
check "tag is the jail's asid" yes "$(echo "$st" | grep amosjail-e2e | grep -q "$asid" && echo yes || echo no)"
wait $C
sleep 1
check "untagged at teardown" no "$(ap status 2>&1 | grep -q amosjail-e2e && echo yes || echo no)"

echo "== traffic"
before=$(wc -l < $FLOWS 2>/dev/null || echo 0)
out=$(aj run --role proxied -- /usr/bin/curl -s -o /dev/null -w '%{http_code}' https://example.com/ 2>&1)
check "https through the proxy" 200 "$out"
sleep 1
check "flow logged under the jail's label" yes "$(tail -n +$((before + 1)) $FLOWS 2>/dev/null | grep -q amosjail-e2e && echo yes || echo no)"
check "CA env set" "/Library/Application Support/amosproxy/ca-bundle.pem" "$(aj run --role proxied -- /bin/sh -c 'echo $SSL_CERT_FILE')"
net=$(aj run --role proxied -- /work/net "$MYIP" /var/run/amosproxy.sock 2>&1)
check "udp denied" no "$(echo "$net" | grep -q SENT && echo yes || echo no)"
check "loopback denied" no "$(echo "$net" | grep -q 'tcp 127.0.0.1 .*CONNECTED' && echo yes || echo no)"
check "amosproxy control socket unreachable" no "$(echo "$net" | grep -q 'amosproxy.sock *CONNECTED' && echo yes || echo no)"
socks=$(sudo lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk '/python|mitm/ && /127.0.0.1/ {sub(/.*:/, "", $9); print $9; exit}')
if [ -n "$socks" ]; then
  check "mitmproxy's loopback port unreachable" fail "$(aj run --role proxied -- /bin/sh -c "/usr/bin/nc -z -G 2 127.0.0.1 $socks 2>/dev/null && echo reached || echo fail")"
fi

echo "== fail closed"
sudo sh -c "sed 's|^\[daemon\]|[amosproxy]@socket = \"/var/run/amosproxy-missing.sock\"@@[daemon]|' $SRC/tests/e2e/test.toml | tr @ '\n' > $T/amosjail.toml"
daemon_up_keep_conf() { daemon_down; sudo sh -c "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$SRC/src AMOSJAIL_CONFIG=$CONF nohup '$PY' -m amosjail daemon > $LOG 2>&1 &"; sleep 1.5; }
daemon_up_keep_conf
out=$(aj run --role proxied -- /bin/echo ran 2>&1)
check "refuses without amosproxy" yes "$(echo "$out" | grep -q "amosproxy isn't running" && echo yes || echo no)"
check "command didn't run" no "$(echo "$out" | grep -qx ran && echo yes || echo no)"
check "offline roles still run" ran "$(aj run --role offline -- /bin/echo ran)"

daemon_down
echo
[ $fails -eq 0 ] && echo "M2: all checks passed" || echo "M2: $fails check(s) failed"
exit $fails
