#!/bin/sh
# End to end: mosbind chroot + deny-default profile, applied by enter.
cd ~/mosjail-spike; R=/tmp/mj2/root
cc -o enter enter.c -lsandbox 2>&1 | grep -v -i warning
cp probe sti net $R/work/ 2>/dev/null; mkdir -p $R/work/.git/hooks
SECRET_TOKEN=hunter2 ./sleeper-gta & t=$!; sleep 0.3
echo "== jailed shell"
sudo JAIL=/private$R ./enter jail.sb $R 501 20 /bin/sh -c "
  echo \"  pwd=\$(pwd) ls /: \$(ls / | tr '\n' ' ')\"
  echo hi > /work/out.txt && echo '  write /work: ok' || echo '  write /work: DENIED'
  echo x > /work/.git/hooks/pre-commit 2>/dev/null && echo '  write hook: ALLOWED' || echo '  write hook: denied'
  echo x > /usr/x 2>/dev/null && echo '  write /usr: ALLOWED' || echo '  write /usr: denied'
  /work/probe $t kill | grep -E 'kill\\(SIGKILL|task_for_pid|ptrace|PROCARGS|pidpath' | sed 's/^/  /'
  /work/net 100.78.179.107 /x | grep -E '127.0.0.1|100.78|1.1.1.1  *80|getaddrinfo' | sed 's/^/  /'
  echo \"  self-signal: \$(sh -c 'sleep 5 & kill \$!' && echo ok)\"
"
echo "  rc=$?  outside target alive: $(kill -0 $t 2>/dev/null && echo yes || echo NO)"
kill $t; rm -f $R/work/out.txt
