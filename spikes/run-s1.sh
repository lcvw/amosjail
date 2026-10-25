#!/bin/sh
cd ~/mosjail-spike; R=/tmp/mj/root
mkdir -p work; echo secret > work/secret.txt; cp /bin/echo work/tool
mount | grep -q " on /private$R/work " || mount -t mosbind ~/mosjail-spike/work $R/work
cp p-*.sb $R/private/tmp/
for p in p-jail p-host p-src; do
  echo "== $p"
  sudo chroot -u liamwisehart $R /usr/bin/sandbox-exec -f /tmp/$p.sb /bin/sh -c '
    cat /work/secret.txt >/dev/null 2>&1 && echo "  read  ALLOWED" || echo "  read  denied"
    (echo x > /work/new.txt) 2>/dev/null && echo "  write ALLOWED" || echo "  write denied"
    /work/tool hi >/dev/null 2>&1 && echo "  exec  ALLOWED" || echo "  exec  denied"
    cd /work 2>/dev/null && cat secret.txt >/dev/null 2>&1 && echo "  relative read ALLOWED" || echo "  relative read denied"
    cat /tmp/../work/secret.txt >/dev/null 2>&1 && echo "  ../ read ALLOWED" || echo "  ../ read denied"'
  rm -f work/new.txt
done
