#!/bin/sh
# Run each workload in tests/compat/workloads.tsv in a jail of $ROLE
# (default: test), enforced. With --report, also list what report mode
# says each one was missing: the input for the base fragment (S-5).
cd "$(dirname "$0")/../.." || exit 1
. tests/e2e/lib.sh
ROLE=${ROLE:-test}
REPORT=$1
P=$HOME/aj-compat
mkdir -p "$P"
cd "$P" || exit 1
[ -d .git ] || git init -q .
daemon_up || exit 1
tab=$(printf '\t')
while IFS="$tab" read -r name cmd; do
  case $name in ''|'#'*) continue ;; esac
  out=$(aj run --role "$ROLE" -- /bin/sh ${SHX:+-x} -c "$cmd" 2>/tmp/aj-compat-err </dev/null); rc=$?
  if [ "$(echo "$out" | tail -1)" = ok ]; then
    pass "$name"
  else
    fail "$name (rc=$rc): $(tail -c 300 /tmp/aj-compat-err | tr '\n' ' ')"
  fi
  if [ -n "$REPORT" ]; then
    aj run --report --role "$ROLE" -- /bin/sh -c "$cmd" 2>&1 >/dev/null </dev/null \
      | grep '^  ' | sed "s/^ */      [$name] /"
  fi
done < "${WORKLOADS:-$SRC/tests/compat/workloads.tsv}"
daemon_down
echo
[ $fails -eq 0 ] && echo "compat: all passed" || echo "compat: $fails failed"
exit $fails
