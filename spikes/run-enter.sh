#!/bin/sh
cd "$(dirname "$0")"
exec 7</dev/null
./sleeper & t=$!; sleep 0.2
echo "== root -> 501:20 via enter (fd 7 open in parent)"
sudo ./enter e.sb 501 20 /bin/sh -c "perl -e 'print \"  uid=\$< euid=\$> gid=\$( egid=\$)\n\"'; echo \"  fds: \$(ls /dev/fd | tr '\n' ' ')\"; ./probe $t | grep -E 'kill|task_for|pidinfo|ptrace' | sed 's/^/  /'"
kill $t
