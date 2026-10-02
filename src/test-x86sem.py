#!/usr/bin/env python3
"""
test-x86sem.py - verification suite for the instruction classifier.

Every case states a ground truth that is checkable against the Intel SDM, not
against the code. Run: python3 test-x86sem.py
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import x86sem as X

PASS = FAIL = 0
FAILS = []


def ck(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1
    else:
        FAIL += 1
        FAILS.append(f"{name}: got {got!r}, want {want!r}")


# --------------------------------------------------------------- parse
PARSE = [
    ("swapgs", ("swapgs", [], "intel")),
    ("6a da   push   0xffffffffffffffda", ("push", ["0xffffffffffffffda"], "intel")),
    ("=> 0xffffffff81200040 <entry_SYSCALL_64>:\tswapgs", ("swapgs", [], "intel")),
    ("0x40101c <_start>:  mov    $0x1,%eax", ("mov", ["$0x1", "%eax"], "att")),
    ("48 8b 44 24 15   mov    rax,QWORD PTR [rsp+0x15]",
     ("mov", ["rax", "QWORD PTR [rsp+0x15]"], "intel")),
    ("call   0xffffffff81156a5f <do_syscall_64>", ("call", ["0xffffffff81156a5f"], "intel")),
    ("48 cf  iretq", ("iretq", [], "intel")),
    ("", ("", [], "intel")),
    ("\tmov\t%rsp,%rbp\t# comment", ("mov", ["%rsp", "%rbp"], "att")),
]
for text, want in PARSE:
    ck(f"parse({text[:38]!r})", X.parse(text), want)

# ------------------------------------------------------- bare_mnemonic
BARE = [("testb", "test"), ("cmpb", "cmp"), ("sbb", "sbb"), ("sub", "sub"),
        ("movzbl", "movzbl"), ("movslq", "movslq"), ("jbe", "jbe"),
        ("push", "push"), ("cltq", "cltq"), ("cmpxchg8b", "cmpxchg8b"),
        ("nopl", "nopl"), ("sete", "sete"), ("mov", "mov"), ("jmp", "jmp")]
for a, b in BARE:
    ck(f"bare({a})", X.bare_mnemonic(a), b)

# ------------------------------------------- AT&T / Intel must agree
# Each pair is the SAME machine instruction written both ways.
# (att_text, intel_text, mnemonic, glyph, mem_read, mem_write, indirect)
PAIRS = [
 ("mov    0x8(%rax),%rdx",  "mov    rdx,QWORD PTR [rax+0x8]",      "mov",   "move",    True,  False, False),
 ("mov    0xffffffff8160c014,%rax", "mov rax,QWORD PTR ds:0xffffffff8160c014", "mov", "move", True, False, False),
 ("mov    %rsp,0xffffffff8160c014", "mov QWORD PTR ds:0xffffffff8160c014,rsp", "mov", "move", False, True, False),
 ("mov    %esi,%esi",      "mov    esi,esi",                       "mov",   "move",    False, False, False),
 ("mov    %cr3,%rax",      "mov    rax,cr3",                       "mov",   "ctrlreg", False, False, False),
 ("mov    %fs:0x28,%rax",  "mov    rax,QWORD PTR fs:[0x28]",       "mov",   "move",    True,  False, False),
 ("push   $0xffffffffffffffda", "push   0xffffffffffffffda",      "push",  "stack",   False, False, False),
 # memory-form push: 'ff 34 25' is PUSH r/m64. Only the raw bytes distinguish
 # it from an immediate, so the RESOLVED (Intel) form is what we assert on;
 # the bare AT&T spelling is reported as ambiguous instead of guessed.
 ("push QWORD PTR ds:0xffffffff8160c014", "push QWORD PTR ds:0xffffffff8160c014", "push", "stack", True, False, False),
 ("push   %rbp",           "push   rbp",                           "push",  "stack",   False, False, False),
 ("pop    %rbx",           "pop    rbx",                           "pop",   "stack",   False, False, False),
 ("lea    (%rax,%rdi,8),%rax", "lea  rax,[rax+rdi*8]",              "lea",   "decode",  False, False, False),
 ("jmp    *-0x7ebffe60(,%rsi,8)", "jmp QWORD PTR [rax+rsi*8-0x7ebffe60]", "jmp", "jump", True, False, True),
 ("testb  $0x80,0x11(%rdi)", "test   BYTE PTR [rdi+0x11],0x80",    "test",  "cmp",     True,  False, False),
 ("cmp    $0x3,%rax",      "cmp    rax,0x3",                       "cmp",   "cmp",     False, False, False),
 ("nopl   0x0(%rax,%rax,1)", "nop    DWORD PTR [rax+rax*1+0x0]",    None,    "zero",    False, False, False),
 ("call   0xffffffff81156a5f", "call   0xffffffff81156a5f",        "call",  "call",    False, False, False),
 ("movslq %eax,%rsi",      "movsxd rsi,eax",                       None,     "signext", False, False, False),
 ("ret",                   "ret",                                  "ret",   "ret",     False, False, False),
 ("and    0x10(%rax),%edx", "and    edx,DWORD PTR [rax+0x10]",      "and",   "logic",   True,  False, False),
 ("dec    %ecx",           "dec    ecx",                           "dec",   "logic",   False, False, False),
 ("sub    $0x10,%rsp",     "sub    rsp,0x10",                      "sub",   "alu",     False, False, False),
 ("xor    %esi,%esi",      "xor    esi,esi",                       "xor",   "logic",   False, False, False),
 ("mov    %rsi,(%rsp)",    "mov    QWORD PTR [rsp],rsi",           "mov",   "move",    False, True,  False),
 ("sti",                   "sti",                                  "sti",   "shield",  False, False, False),
 ("swapgs",                "swapgs",                               "swapgs", "swap",   False, False, False),
 ("je     0xffffffff81156a80", "je  0xffffffff81156a80",           "je",    "branch",  False, False, False),
 ("jbe    0xffffffff81156a96", "jbe 0xffffffff81156a96",           "jbe",   "branch",  False, False, False),
]
for att, intel, mn, glyph, mr, mw, ind in PAIRS:
    ca, cb = X.classify(att), X.classify(intel)
    if mn is not None:            # None = the two dialects spell it differently
        ck(f"att mn {att[:30]!r}", ca["mnemonic"], mn)
        ck(f"int mn {intel[:30]!r}", cb["mnemonic"], mn)
    ck(f"att glyph {att[:30]!r}", ca["glyph"], glyph)
    ck(f"int glyph {intel[:30]!r}", cb["glyph"], glyph)
    ck(f"att r {att[:30]!r}", ca["mem_read"], mr)
    ck(f"int r {intel[:30]!r}", cb["mem_read"], mr)
    ck(f"att w {att[:30]!r}", ca["mem_write"], mw)
    ck(f"int w {intel[:30]!r}", cb["mem_write"], mw)
    ck(f"att indirect {att[:30]!r}", ca["indirect"], ind)
    ck(f"int indirect {intel[:30]!r}", cb["indirect"], ind)
    ck(f"att matched {att[:30]!r}", ca["matched"], True)
    ck(f"int matched {intel[:30]!r}", cb["matched"], True)

# ------------------------------------------- architectural invariants
# Facts from the SDM, checked as properties rather than single cases.
INV = [
    # PUSH/POP/CALL/RET always drive the stack pointer, even with a memory operand
    ("push   %rbp",         lambda c: "rsp" in c["units"]),
    ("pop    %rbp",         lambda c: "rsp" in c["units"]),
    ("call   0x1234",       lambda c: "rsp" in c["units"] and "mem" in c["units"]),
    ("ret",                 lambda c: "rsp" in c["units"] and "ctrl" in c["units"]),
    ("leave",               lambda c: "rsp" in c["units"]),
    # every instruction goes through the front end
    ("swapgs",              lambda c: all(u in c["units"] for u in X.FRONT_END)),
    ("nop",                 lambda c: all(u in c["units"] for u in X.FRONT_END)),
    # flag-setting ops must list EFLAGS; flag-free ops must not
    ("add    %eax,%ebx",    lambda c: "flags" in c["units"]),
    ("xor    %esi,%esi",    lambda c: "flags" in c["units"]),
    ("cmp    $1,%rax",      lambda c: "flags" in c["units"] and "gpr" not in c["units"]),
    ("test   %al,%al",      lambda c: "flags" in c["units"] and "gpr" not in c["units"]),
    ("mov    %rax,%rbx",    lambda c: "flags" not in c["units"]),
    ("lea    (%rax,%rdi,1),%rax", lambda c: "flags" not in c["units"]),
    # a memory touch always pulls in the whole path to DRAM
    ("mov    0x8(%rax),%rdx", lambda c: {"bus", "mem", "agutlb", "cache"} <= set(c["units"])),
    ("mov    %rax,(%rbx)",  lambda c: {"bus", "mem", "agutlb", "cache"} <= set(c["units"])),
    # LEA and NOP must never claim a memory access
    ("lea    (%rax,%rdi,1),%rax", lambda c: not c["is_mem"]),
    ("nopl   0x0(%rax,%rax,1)", lambda c: not c["is_mem"]),
    ("nop",                 lambda c: not c["is_mem"]),
    # a memory-form push READS memory (it fetches the value to push)
    ("push QWORD PTR ds:0xffffffff8160c014", lambda c: c["mem_read"] and not c["mem_write"]),
    # the ambiguous bare-AT&T spelling is flagged, never silently guessed
    ("push   0xffffffff8160c014",            lambda c: c.get("ambiguous") is True),
    ("push   $0x2b",                         lambda c: not c.get("ambiguous")),
    # ...while an immediate push touches no memory at all
    ("push   $0x2b",                         lambda c: not c["is_mem"]),
    # a call to a literal address is direct: no memory read
    ("call   0xffffffff81156a5f",            lambda c: not c["mem_read"] and not c["indirect"]),
    # CMP/TEST/conditional jumps can never store
    ("cmp    $1,%rax",      lambda c: not c["mem_write"]),
    ("testb  $0x80,0x11(%rdi)", lambda c: not c["mem_write"]),
    ("je     0x1234",       lambda c: not c["mem_write"]),
    # privilege transitions
    ("syscall",             lambda c: {"cpl", "seg", "msr"} <= set(c["units"])),
    ("swapgs",              lambda c: {"cpl", "seg", "msr"} <= set(c["units"])),
    ("iretq",               lambda c: {"cpl", "seg", "rsp", "intc"} <= set(c["units"])),
    ("sti",                 lambda c: "intc" in c["units"] and "flags" in c["units"]),
    # segment / control register moves
    ("mov    %cr3,%rax",    lambda c: "cr" in c["units"]),
    ("mov    %rax,%cr3",    lambda c: "cr" in c["units"]),
    ("mov    %fs,%rax",     lambda c: "seg" in c["units"]),
    # vector ops hit the SIMD block
    ("vmovdqu %ymm0,(%rdi)", lambda c: "xmm" in c["units"]),
    # multiply uses the dedicated unit
    ("imul   %rdi,%rsi",    lambda c: "alu" in c["units"] and "gpr" in c["units"]),
    # a caption and a glyph always exist
    ("ud2",                 lambda c: bool(c["caption"]) and bool(c["glyph_svg"])),
    ("vaddpd %ymm1,%ymm2,%ymm3", lambda c: bool(c["caption"]) and bool(c["glyph_svg"])),
]
for text, pred in INV:
    c = X.classify(text)
    ck(f"invariant {text!r}", pred(c), True)

# every unit named anywhere must exist as a drawable block
ids = {b[0] for b in X.BLOCKS}
extra = ["syscall", "sysretq", "iretq", "vmovdqu %ymm0,(%rdi)", "imul %rdi,%rsi"]
for text in [a for a, *_ in PAIRS] + extra:
    u = set(X.classify(text)["units"])
    ck(f"units exist {text!r}", u - ids, set())

# every glyph named anywhere must have an SVG
for text in [a for a, *_ in PAIRS] + extra + ["ud2", "movd", "lcall", "sti", "hlt"]:
    g = X.classify(text)["glyph"]
    ck(f"glyph svg {text!r}", g in X.G, True)

# BLOCKS geometry must not overlap and must stay on the canvas
for i, (bid, lab, sub, x, y, w, h) in enumerate(X.BLOCKS):
    ck(f"block {bid} on canvas", x >= 0 and y >= 0 and x + w <= 1000 and y + h <= 500, True)
    for bid2, _, _, x2, y2, w2, h2 in X.BLOCKS[i + 1:]:
        overlap = not (x + w <= x2 or x2 + w2 <= x or y + h <= y2 or y2 + h2 <= y)
        ck(f"blocks {bid}/{bid2} disjoint", overlap, False)

# ------------------------------------------- the real 120-instruction trace
trace = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trace.json")
if os.path.exists(trace):
    steps = json.load(open(trace))["steps"]
    ck("trace length", len(steps), 120)
    unmatched = [s["n"] for s in steps if not X.classify(s.get("insn", ""))["matched"]]
    ck("every real instruction is classified", unmatched, [])
    badunits = set()
    for s in steps:
        badunits |= set(X.classify(s.get("insn", ""))["units"]) - ids
    ck("no unknown units in the real trace", badunits, set())
    # spot-check the ones that taught us the most
    ck("step 0 is swapgs", X.classify(steps[0]["insn"])["mnemonic"], "swapgs")
    ck("step 13 is the ENOSYS push", X.classify(steps[13]["insn"])["mnemonic"], "push")
    ck("step 96 lea reads no memory", X.classify(steps[96]["insn"])["is_mem"], False)
    ck("step 60 is the indirect syscall-table jmp",
       X.classify(steps[60]["insn"])["indirect"], True)
    ck("step 60 reads the table from memory",
       X.classify(steps[60]["insn"])["mem_read"], True)
else:
    print("note: trace.json not found, skipping the real-trace checks")

# ------------------------------------------- observed_units mapping
ck("rsp maps to rsp",  X.observed_units({"regs": [{"name": "rsp"}]}), ["rsp"])
ck("rax maps to gpr",  X.observed_units({"regs": [{"name": "rax"}]}), ["gpr"])
ck("cs maps to seg",   X.observed_units({"segs": [{"name": "CS"}]}), ["seg"])
ck("flags map to flags", X.observed_units({"flags": [{"name": "ZF"}]}), ["flags"])
ck("mem maps to bus+mem", X.observed_units({"mem": [{"off": "0x0"}]}), ["bus", "mem"])
ck("rip jump maps to ctrl",
   X.observed_units({"regs": [{"name": "rip"}], "rip_changed": True}), ["ctrl", "rip"])
ck("ring change maps to cpl", X.observed_units({"ring_changed": True}), ["cpl"])

print(f"\n{'='*56}\n  {PASS} passed, {FAIL} failed\n{'='*56}")
for f in FAILS:
    print("  FAIL", f)
sys.exit(1 if FAIL else 0)
