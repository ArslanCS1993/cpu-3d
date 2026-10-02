# Linux internals, in 3D

Step a **real** Linux kernel one instruction at a time and watch what each
instruction does to the hardware — CPU blocks in 3D, the actual machine code
sitting in memory cells, and a register bank with live values.

Everything here is traceable back to a real kernel: Linux **v6.8.0** booted in
QEMU, stepped one instruction at a time over the GDB stub, with the CPU state
sampled **before** every instruction.

## Live demo

<https://ArslanCS1993.github.io/cpu-3d/> — or open `index.html` locally.

Served by GitHub Pages straight from `main`. The pages are self-contained: no
build step, no CDN, no network access needed at view time.

## What you get per instruction

| Layer | What it shows |
|---|---|
| Glyph + emoji | an SVG picture *and* an emoji of what the instruction does — 🧱 stack, ⚖️ compare, 🔀 branch, 🛡️ interrupts off |
| Hardware table | one row per piece of hardware with a direction: **R** read, **W** write, **–** explicitly preserved |
| 3D die | the CPU blocks the ISA requires, lit green and raised |
| Memory cells | the **real kernel bytes at that PC**, read from the vmlinux image |
| Register bank | 16 registers with live values; the ones the instruction touches are prominent |
| Truth check | ISA claims cross-checked against the real trace — a `conflict` badge fires when the ISA said "preserved" but the hardware changed it anyway |

### Flags are per-bit, not one "EFLAGS" row

This is the part one word cannot answer:

| Instruction | Flags |
|---|---|
| `mov rbp,rsp` | all 7 **preserved** |
| `test eax,0x7fffffff` | writes CF PF ZF SF OF, preserves DF |
| `cmp` | writes all six arithmetic flags, result discarded |
| `je 0x21` | **reads** ZF to decide the branch |
| `cmovne rax,rbx` | reads ZF, **does not move RIP** — a branch in disguise |
| `inc rax` | leaves **CF alone** (unlike `add`) |

## How it works

- **One source of truth.** The floorplan, the 2D map, the 3D die and the
  hardware table all derive from `x86sem.BLOCKS`, and the highlighted set comes
  from `x86sem.classify()`. They cannot drift apart.
- **Zero dependencies in the browser.** The 3D is hand-rolled WebGL, not
  three.js, so the page opens from `file://` with no network and no server.
- **Numeric safety.** Every 64-bit value is emitted as a hex *string* and handled
  as `BigInt`; a JS `Number` silently rounds `0xffffffff81200040`.
- **Build gate.** `build-viewer.py` runs `node --check` on the generated script,
  because a stray semicolon once shipped a page that rendered nothing.

## Layout

```
index.html              landing page (GitHub Pages serves this)
syscall-viewer.html     120 instructions, entry_SYSCALL_64
sched-viewer.html        90 instructions, __schedule
scene-push.html         one static frame of the full 3D scene
src/
  x86sem.py             instruction classifier: glyph, emoji, caption,
                        hardware blocks, per-flag effects, hardware table
  build-viewer.py       trace.json -> single-file HTML (embeds trace + renderer)
  die3d.js              the WebGL scene: die, memory cells, register bank
  trace-kernel.py       QEMU + GDB tracer (any kernel symbol with DWARF)
  gen-scene-preview.py  full-window scene page, used as a visual smoke test
  test-x86sem.py        654 assertions over the classifier
  build.sh              rebuild every generated page
```

## Build it yourself

The tool is **not** syscall-specific — any kernel symbol with DWARF traces the
same way:

```bash
python3 trace-kernel.py --symbol __schedule --steps 90 -o t.json
python3 build-viewer.py t.json -o sched.html
```

Re-tracing from scratch needs a kernel built with DWARF plus a GDB stub; see
`src/README.md`.

## Honest limits

- The floorplan is **conceptual** — blocks are arranged for legibility, matching
  the teaching diagram, not a photograph of a specific CPU die. There are no
  wires between units, because the model has none.
- Register values are sampled from the VM, so they are the real 64-bit register
  contents, not invented values.
- The memory strip shows a **24-byte contiguous window at each PC**. Because the
  trace jumps between functions, the window jumps too — that is the PC moving,
  which is the point.
