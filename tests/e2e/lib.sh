# Sourced by the e2e scripts on the test Mac (after scripts/sync.sh).
# Starts a test amosjaild from ~/amosjail with tests/e2e/test.toml.
PY=${AMOSJAIL_PYTHON:-$(ls -d ~/.local/share/uv/python/cpython-3.1[2-9]*/bin/python3.1? 2>/dev/null | head -1)}
SRC=$HOME/amosjail
T=/var/db/amosjail-test
CONF=$T/amosjail.toml
SOCK=/var/run/amosjaild-test.sock
LOG=/tmp/amosjaild-test.log
aj() { PYTHONPATH=$SRC/src "$PY" -m amosjail --config "$CONF" "$@"; }
# aj_bg ...: aj in the background, with $! the client itself
aj_bg() { (PYTHONPATH=$SRC/src exec "$PY" -m amosjail --config "$CONF" "$@") & }
# in_pty CMD: run CMD with a terminal (script(1)), output without \r and ^D
in_pty() { script -q /dev/null sh -c ". $SRC/tests/e2e/lib.sh; cd '$PWD'; $1" < /dev/null | tr -d '\r\010' | sed 's/^^D//'; }

daemon_up() {
  sudo install -d -o root -g wheel -m 755 $T $T/state /var/amosjail-test
  sudo install -o root -g wheel -m 755 $SRC/enter/amosjail-enter $T/amosjail-enter
  sudo install -o root -g wheel -m 644 $SRC/tests/e2e/test.toml $CONF
  daemon_down
  sudo sh -c "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=$SRC/src AMOSJAIL_CONFIG=$CONF nohup '$PY' -m amosjail daemon > $LOG 2>&1 &"
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S $SOCK ] && return 0; sleep 0.3; done
  echo "daemon didn't start:"; cat $LOG; return 1
}

daemon_down() {
  pid=$(pgrep -f "amosjail daemon" | head -1)
  [ -n "$pid" ] && sudo kill "$pid" && sleep 0.5
  return 0
}

fails=0
pass() { echo "  ok    $1"; }
fail() { echo "  FAIL  $1"; fails=$((fails + 1)); }
check() { # check NAME EXPECTED ACTUAL
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected '$2', got '$3')"; fi
}
