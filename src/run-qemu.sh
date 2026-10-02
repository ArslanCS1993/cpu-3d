#!/bin/bash
# Boot the lab kernel in QEMU with the GDB stub, paused at reset.
#
#   -S                    freeze CPU at startup so GDB attaches before any code runs
#   -gdb tcp:127.0.0.1:1234   bind the stub to LOOPBACK ONLY.
#                         `-s` / `-gdb tcp::1234` is shorthand for 0.0.0.0 and
#                         that is an UNAUTHENTICATED remote debugger: anyone who
#                         can reach the port can dump and rewrite guest memory.
#   -no-reboot            don't loop on triple fault (we want to see the fault)
#
# No `-d int,cpu_reset -D qemu.log`: that log grew to 4.1 GB on a previous run.
# Enable it only when debugging boot, and delete the file afterwards.
set -euo pipefail
cd "$(dirname "$0")"

rm -f qemu.log
exec qemu-system-x86_64 \
  -kernel   bzImage \
  -initrd   initramfs.cpio.gz \
  -append   "console=ttyS0 rdinit=/init panic=1 oops=panic loglevel=7" \
  -m        512M \
  -smp      1 \
  -nographic \
  -no-reboot \
  -S -gdb tcp:127.0.0.1:1234
