#!/bin/sh
cd "$(dirname "$0")"
SECRET_TOKEN=hunter2 ./sleeper & t=$!; sleep 0.2
for p in b-*.sb; do
  echo "== $p: outside target"; sandbox-exec -f $p ./args $t 2>&1
  echo "== $p: same-sandbox target"; sandbox-exec -f $p /bin/sh -c 'SECRET_TOKEN=inside ./sleeper & c=$!; sleep 0.2; ./args $c; ./probe $c | grep -E "pidinfo|pidpath|listall"; kill $c'
  echo "== $p: ps"; sandbox-exec -f $p /bin/ps -axo pid,comm 2>&1 | wc -l
done
kill $t
