# Rebuilding the traces from scratch

The committed `../*.html` pages embed the trace data, so you do not need any of
this to view the site. To trace a *different* symbol, or regenerate after
changing `x86sem.py`:

## 1. A kernel built with DWARF

```bash
tar xf /usr/src/linux-source-6.8.0.tar.bz2
cd linux-source-6.8.0
make defconfig
scripts/config --enable-debug-info          # DWARF is what makes addr2line work
make -j$(nproc) bzImage vmlinux
```

**Gotcha:** `make` can leave a *32-bit* `vmlinux` behind (ELF32, i386, zero
`.debug_*` sections). Check before using it:

```bash
readelf -h vmlinux | grep -E 'Class|Machine'   # want: ELF64 / x86-64
readelf -S vmlinux | grep -c debug_            # want: > 0
```

A 32-bit image makes GDB negotiate `i386` against an x86-64 stub and fail with
`Remote 'g' packet reply is too long`, which looks like a broken gdbstub.

## 2. A bootable initramfs

`/init` should be a statically linked asm program that issues the syscalls you
want to trace, then parks in a `jmp .` loop so QEMU stays alive for the debugger.

## 3. Trace

```bash
cp vmlinux bzImage initramfs.cpio.gz ./
python3 trace-kernel.py --symbol entry_SYSCALL_64 --steps 120 -o trace.json
python3 build-viewer.py trace.json -o ../syscall-viewer.html
```

`trace-kernel.py` boots QEMU **paused**, binds the GDB stub to
`127.0.0.1:1234` only, single-steps N instructions dumping registers + memory
before each one, and re-traces a second time with a fixed absolute memory
window (the syscall switches to a kernel stack ~127 TB away, so a window
anchored to `%rsp` slides on every push and everything looks changed).

## 4. Never expose the gdbstub

`-s` is shorthand for `-gdb tcp::1234`, i.e. **0.0.0.0** — an unauthenticated
remote debugger that anyone reachable can use to dump and rewrite guest memory.
Always bind explicitly:

```bash
qemu-system-x86_64 ... -S -gdb tcp:127.0.0.1:1234
```

Avoid `-d int,cpu_reset -D qemu.log` on long runs: one such log grew to 4.1 GB.
