#!/bin/sh
cd "$(dirname "$0")"
t='for f in /etc/hosts /etc/services; do cat $f >/dev/null 2>&1 && echo "  $f readable" || echo "  $f DENIED"; done'
echo "== outer only"; sandbox-exec -f outer.sb /bin/sh -c "$t"
echo "== inner only"; sandbox-exec -f inner.sb /bin/sh -c "$t"
echo "== sandbox-exec outer, then sandbox-exec inner"; sandbox-exec -f outer.sb sandbox-exec -f inner.sb /bin/sh -c "$t"; echo "  rc=$?"
echo "== enter outer, then sandbox-exec inner"; ./enter outer.sb 501 20 /usr/bin/sandbox-exec -f inner.sb /bin/sh -c "$t"; echo "  rc=$?"
echo "== deny-default outer (no process-exec of sandbox-exec target?)"; sandbox-exec -D JAIL_ID=x -f e.sb sandbox-exec -f inner.sb /bin/sh -c "$t"; echo "  rc=$?"
