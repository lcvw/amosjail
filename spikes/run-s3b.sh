#!/bin/sh
cd "$(dirname "$0")"
./sleeper & tgt=$!
sleep 0.2
echo "== unsandboxed, non-platform target $tgt"; ./probe $tgt
for p in "$@"; do echo "== sandboxed: $p"; sandbox-exec -f "$p" ./probe $tgt; done
kill $tgt
