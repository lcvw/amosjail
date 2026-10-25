#!/bin/sh
# Build /tmp/mj/root from mosbind binds (as the user) plus devfs (sudo).
# Usage: chroot-setup.sh up|down   (up is idempotent: re-mounts what is missing)
R=/tmp/mj/root
binds="/usr /bin /sbin /System /Library /private/etc"
mounted() { mount | grep -q " on /private$1 "; }
case $1 in
up)
  mkdir -p $R/dev $R/private/tmp $R/work
  for b in $binds; do mkdir -p $R$b; mounted $R$b || mount -t mosbind -o rdonly $b $R$b; done
  mounted $R/work || mount -t mosbind ~/mosjail-spike/work $R/work
  mounted $R/dev || sudo mount -t devfs devfs $R/dev
  ln -sfn private/etc $R/etc; ln -sfn private/tmp $R/tmp
  ;;
down)
  umount $R/work 2>/dev/null; sudo umount $R/dev 2>/dev/null
  for b in $binds; do umount $R$b 2>/dev/null; done
  ;;
esac
mount | grep -c " on /private/tmp/mj/root"
