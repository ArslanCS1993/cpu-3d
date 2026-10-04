#!/usr/bin/env python3
"""Assert the source-context reader only ever opens files inside a known
kernel build root. A trace is data: its DWARF file paths must not be able to
steer the build into reading an arbitrary file on this machine."""
import importlib.util, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
# the module is named build-viewer.py, which is not a legal import name
spec = importlib.util.spec_from_file_location("bv", os.path.join(HERE, "build-viewer.py"))
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)

REJECT = ["/etc/shadow", "/etc/passwd", "/root/.ssh/id_ed25519_ghpages",
          "/tmp/somewhere-else/x.c", "../../etc/shadow", "", None, "relative.c"]
ACCEPT = [
    "/tmp/ksrc64/linux-source-6.8.0/arch/x86/entry/entry_64.S",
    "/tmp/ksrc64/linux-source-6.8.0/kernel/sched/core.c",
    "/tmp/kobj64/./arch/x86/include/generated/asm/syscalls_64.h",
]

fails = 0
for p in REJECT:
    got = B.source_file(p)
    if got is not None:
        print(f"  LEAK   {p!r} resolved to {got}")
        fails += 1
for p in ACCEPT:
    got = B.source_file(p)
    if got is None:
        print(f"  MISS   {p!r} was refused but is a real build file")
        fails += 1

print(f"{'FAILED' if fails else 'ok'}: {fails} problem(s), "
      f"{len(REJECT)} rejected, {len(ACCEPT)} accepted")
sys.exit(1 if fails else 0)
