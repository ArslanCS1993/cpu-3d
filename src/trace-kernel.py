#!/usr/bin/env python3
"""
trace-kernel.py - single-step a REAL Linux kernel in QEMU and record the
complete machine state after every instruction.

Nothing here is modelled or invented. The register values come straight out of
QEMU's GDB stub while the CPU is running the real kernel image, and the source
lines come from the DWARF that was compiled into that same kernel.

  python3 trace-kernel.py --symbol entry_SYSCALL_64 --steps 120 -o trace.json
"""
import argparse, json, os, re, shutil, signal, socket, subprocess, sys, time

LAB = os.path.dirname(os.path.abspath(__file__))

# x86-64 EFLAGS bit positions
FLAG_BITS = [
    (0,  "CF"), (2,  "PF"), (4,  "AF"), (6,  "ZF"), (7,  "SF"),
    (8,  "TF"), (9,  "IF"), (10, "DF"), (11, "OF"), (12, "IOPL"),
    (16, "NT"), (17, "RF"), (18, "VM"), (19, "AC"), (20, "VIF"), (21, "VIP"),
]
REGS = ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp",
        "r8","r9","r10","r11","r12","r13","r14","r15",
        "rip","eflags","cs","ss","ds","es","fs","gs"]


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def port_open(port, timeout=0.4):
    s = socket.socket(); s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port)); return True
    except OSError:
        return False
    finally:
        s.close()


def wait_for_port(port, seconds=30):
    t0 = time.time()
    while time.time() - t0 < seconds:
        if port_open(port):
            return True
        time.sleep(0.2)
    return False


def build_gdb_script(symbol, steps, mem_bytes, mem_before, mem_fixed=None):
    # label every register in the format string so parsing can never drift
    fmt = "@@S %d " + " ".join(f"{r}=%llx" for r in REGS) + "\\n"
    args = ", ".join(["$n"] + [f"${r}" for r in REGS])
    if mem_fixed is not None:
        mem_addr = f"({hex(mem_fixed)})"
    else:
        mem_addr = f"($rsp-{mem_before})"
    dump = f"x/{mem_bytes}xb {mem_addr}\n" if mem_bytes else ""
    return f"""set pagination off
set confirm off
set height 0
set width 0
set print address on
file vmlinux
target remote :1234
break {symbol}
continue
set $n = 0
while $n < {steps}
  printf "{fmt}", {args}
{dump}  printf "@@I "
  x/1i $pc
  stepi
  set $n = $n + 1
end
detach
quit
"""


KV = re.compile(r'([a-z0-9]+)=([0-9a-f]+)')


def parse(raw):
    """Turn GDB's output into structured per-step records."""
    steps, cur = [], None
    mem_re = re.compile(r'0x([0-9a-f]{2})(?![0-9a-f])')
    for line in raw.splitlines():
        line = line.rstrip()
        if line.startswith("@@S "):
            cur = {"n": int(line.split()[1]),
                   "regs": {k: int(v, 16) for k, v in KV.findall(line)},
                   "mem": []}
            steps.append(cur)
        elif line.startswith("@@I ") and cur is not None:
            cur["insn"] = line[4:].strip()
        elif cur is not None and re.match(r'^0x[0-9a-f]+:\t', line):
            cur["mem"] += [int(b, 16) for b in mem_re.findall(line)]
    return steps


def flags_of(eflags):
    return {name: bool(eflags & (1 << bit)) for bit, name in FLAG_BITS}


def addr2line_map(addrs):
    """Resolve virtual addresses to file:line using the kernel's own DWARF."""
    out = {}
    if not addrs:
        return out
    cmd = ["addr2line", "-e", "vmlinux", "-f", "-C"] + [hex(a) for a in addrs]
    res = subprocess.run(cmd, cwd=LAB, capture_output=True, text=True)
    lines = res.stdout.splitlines()
    # addr2line -f prints 2 lines per address: function, then file:line
    for i, a in enumerate(addrs):
        fn = lines[2 * i] if 2 * i < len(lines) else "?"
        loc = lines[2 * i + 1] if 2 * i + 1 < len(lines) else "?:0"
        loc = loc.split(" (discriminator")[0]
        file, _, line = loc.rpartition(":")
        out[a] = {"fn": fn.strip(), "file": file.strip(), "line": int(line or 0)}
    return out


def source_lines(wanted):
    """Read the C/asm sources so the viewer can show the real line text."""
    cache, out = {}, {}
    for (f, ln) in wanted:
        if f not in cache:
            try:
                cache[f] = open(f, errors="replace").read().splitlines()
            except OSError:
                cache[f] = None
        src = cache[f]
        out[(f, ln)] = src[ln - 1].strip() if src and 0 < ln <= len(src) else ""
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--symbol", default="entry_SYSCALL_64")
    ap.add_argument("--steps", type=int, default=120)
    ap.add_argument("--mem-bytes", type=int, default=512)
    ap.add_argument("--mem-before", type=int, default=64)
    ap.add_argument("--mem-fixed", type=lambda s: int(s, 0), default=None,
                    help="absolute address for the memory window; discovered "
                         "automatically when omitted")
    ap.add_argument("-o", "--out", default="trace.json")
    args = ap.parse_args()

    for f in ("vmlinux", "bzImage", "initramfs.cpio.gz"):
        if not os.path.exists(os.path.join(LAB, f)):
            die(f"missing {f}")

    gdb_script = os.path.join(LAB, "trace.gdb")

    def run_gdb(mem_bytes, mem_fixed):
        open(gdb_script, "w").write(build_gdb_script(
            args.symbol, args.steps, mem_bytes, args.mem_before, mem_fixed))
        res = subprocess.run(["gdb", "-q", "-batch", "-x", "trace.gdb"],
                             cwd=LAB, capture_output=True, text=True, timeout=600)
        raw = res.stdout + "\n" + res.stderr
        open(os.path.join(LAB, "trace.raw.txt"), "w").write(raw)
        steps = parse(raw)
        if not steps:
            print(raw[-3000:], file=sys.stderr)
            die("no steps captured - did the breakpoint hit?")
        return steps

    def boot():
        subprocess.run(["pkill", "-f", "[q]emu-system-x86_64"], capture_output=True)
        time.sleep(1)
        qemu = subprocess.Popen(["setsid", "./run-qemu.sh"], cwd=LAB,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)
        if not wait_for_port(1234, 30):
            die("QEMU gdb stub never came up on :1234")
        return qemu

    print(f"stepping {args.steps} instructions from {args.symbol} ...", flush=True)
    boot()
    steps = run_gdb(0, None)          # pass 1: registers only

    if args.mem_fixed is None:
        # The syscall switches from the user stack to a kernel stack ~127 TB
        # away, so a window anchored to %rsp would slide on every push and
        # every byte would look "changed". Find the kernel stack once, then
        # re-trace with one fixed window there.
        KERNEL = 0xFFFF000000000000
        kstack = [s["regs"]["rsp"] for s in steps if s["regs"]["rsp"] >= KERNEL]
        if not kstack:
            die("no kernel-stack rsp seen - cannot anchor a fixed memory window")
        args.mem_fixed = min(kstack) - args.mem_before
        print(f"kernel stack {hex(min(kstack))}..{hex(max(kstack))}; "
              f"fixed window at {hex(args.mem_fixed)} ({args.mem_bytes} bytes) "
              f"- re-tracing", flush=True)
        boot()
        steps = run_gdb(args.mem_bytes, args.mem_fixed)

    print(f"captured {len(steps)} steps")

    # resolve every address we actually executed through the kernel's DWARF
    addrs = sorted({s["regs"]["rip"] for s in steps})
    info = addr2line_map(addrs)
    want = {(v["file"], v["line"]) for v in info.values() if v["line"]}
    src = source_lines(want)

    prev_mem = None
    for s in steps:
        r = s["regs"]
        s["flags"] = flags_of(r["eflags"])
        srcinfo = info.get(r["rip"], {"fn": "?", "file": "?", "line": 0})
        s["symbol"] = srcinfo["fn"]
        s["file"] = srcinfo["file"]
        s["line"] = srcinfo["line"]
        s["source"] = src.get((srcinfo["file"], srcinfo["line"]), "")

        mem = s.get("mem", [])
        base = args.mem_fixed if args.mem_fixed is not None else r["rsp"] - args.mem_before
        s["mem_base"] = base
        s["mem"] = mem
        # which bytes changed since the previous instruction?
        if prev_mem is not None and len(mem) == len(prev_mem):
            delta = [{"off": s["mem_base"] + i, "from": a, "to": b}
                     for i, (a, b) in enumerate(zip(prev_mem, mem)) if a != b]
            s["mem_delta"] = delta
        else:
            s["mem_delta"] = []
        prev_mem = mem

    doc = {
        "meta": {
            "symbol": args.symbol,
            "steps": len(steps),
            "mem_bytes": args.mem_bytes,
            "mem_before": args.mem_before,
            "registers": REGS,
            "source": "real Linux kernel vmlinux, executed in QEMU, read via the GDB stub",
            "kernel": "6.8.0 x86_64, CONFIG_DEBUG_INFO=y (DWARF)",
        },
        "steps": steps,
    }
    outp = os.path.join(LAB, args.out)
    json.dump(doc, open(outp, "w"))
    size = os.path.getsize(outp)
    print(f"wrote {outp} ({size/1024:.0f} KB)")

    files = {}
    for s in steps:
        files.setdefault(s["file"], set()).add(s["line"])
    print("\nfiles touched:")
    for f, lns in sorted(files.items(), key=lambda kv: -len(kv[1])):
        print(f"  {len(lns):4d} lines  {f}")


if __name__ == "__main__":
    main()
