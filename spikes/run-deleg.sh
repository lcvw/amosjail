#!/bin/sh
cd "$(dirname "$0")"; mkdir -p markers
for p in "$@"; do
  rm -f markers/*; launchctl remove mj.submit 2>/dev/null; launchctl bootout gui/501/mj.bootstrap 2>/dev/null
  pkill -x Calculator; pbcopy < /dev/null
  echo "== $p"; sandbox-exec -f $p /bin/sh ./deleg.sh
  sleep 2
  echo "  markers: $(ls markers | tr '\n' ' ')"
  echo "  jobs: $(launchctl list | grep -c 'mj\.')  calculator: $(pgrep -x Calculator >/dev/null && echo RUNNING || echo no)  clipboard: '$(pbpaste)'"
done
launchctl remove mj.submit 2>/dev/null; launchctl bootout gui/501/mj.bootstrap 2>/dev/null; pkill -x Calculator
