#!/bin/sh
cd "$(dirname "$0")"; cc -o args args.c || exit 1
SECRET_TOKEN=hunter2 ./sleeper & t=$!; sleep 0.2
echo "== unsandboxed"; ./args $t
for p in a-*.sb; do echo "== $p"; sandbox-exec -f $p ./args $t 2>&1; done
kill $t
