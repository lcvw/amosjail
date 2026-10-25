#!/bin/sh
# S-3: same-uid process access, unsandboxed vs sandboxed.
cd "$(dirname "$0")"
cc -o probe probe.c || exit 1
sleep 600 & tgt=$!
echo "== unsandboxed, target $tgt"; ./probe $tgt
echo "== sandboxed: $1, target $tgt"; sandbox-exec -f "$1" ./probe $tgt
echo "== sandboxed: same-sandbox target (child of the sandboxed shell)"
sandbox-exec -f "$1" /bin/sh -c './sleeper & c=$!; ./probe $c kill'
kill $tgt 2>/dev/null
