#!/usr/bin/env python3
"""
x86sem.py - classify a single x86-64 instruction into

  * a glyph   - small inline SVG picture of what the instruction DOES
  * a caption - one plain-English sentence naming the operation
  * units     - which pieces of hardware it drives
  * operands  - what it reads and what it writes, with direction

Handles BOTH disassembler dialects, because they disagree about operand
order and that is a real source of wrong answers:

  AT&T  (gdb default)   : mov  0x8(%rax),%rdx     src, dst   (src first)
  Intel (objdump -M intel): mov  rdx,QWORD PTR [rax+0x8]   dst, src  (dst first)

Dialect is detected per instruction, not assumed.

The unit list is deliberately two-layered:

  expect  - what the ISA says MUST be touched (derived from the mnemonic)
  observe - what the trace actually shows changed (derived from the state
            diff between this step and the next)

The viewer shows `expect` as the headline hardware map and marks `observe`
separately, so a disagreement between architecture and reality is visible
instead of hidden. That disagreement is how bugs in a mental model get
caught.
"""
import re

# --------------------------------------------------------------- glyphs
# 24x24 viewBox, stroke=currentColor, fill=none. Kept deliberately crude so
# they stay legible at 15px in the list and 46px in the detail pane.
G = {
 "fetch":  '<path d="M2 12h12"/><path d="M14 7l7 5-7 5z"/>',
 "decode": '<path d="M3 4h5l3 4-3 4H3z"/><path d="M11 12h10"/><path d="M17 7l5 5-5 5"/>',
 "move":   '<path d="M3 8h13"/><path d="M16 8l-4-4M16 8l-4 4"/><rect x="16" y="3" width="6" height="10" rx="1.5"/>',
 "alu":    '<path d="M5 4l6 8-6 8"/><path d="M12 4l7 8-7 8"/><path d="M2 12h20"/>',
 "logic":  '<circle cx="7" cy="12" r="4"/><path d="M14 4v16"/><path d="M19 7v10"/><path d="M17 10h4M17 14h4"/>',
 "cmp":    '<path d="M4 9h11"/><path d="M4 15h11"/><path d="M18 6v12"/><path d="M21 9v6"/>',
 "flagset":'<path d="M5 21V4"/><path d="M5 5h13l-3 4 3 4H5z"/>',
 "stack":  '<path d="M3 20h18"/><path d="M6 20V9"/><path d="M18 20V9"/><path d="M12 17V4"/><path d="M8 8l4-4 4 4"/>',
 "load":   '<path d="M2 12h9"/><path d="M11 8l5 4-5 4"/>',
 "store":  '<path d="M13 12H4"/><path d="M6 8l-5 4 5 4"/>',
 "jump":   '<path d="M4 20h5a4 4 0 0 0 4-4V4"/><path d="M9 8l4-4 4 4"/>',
 "branch": '<path d="M3 12h7"/><circle cx="14" cy="12" r="4"/><path d="M18 12h4"/><path d="M3 6v12"/>',
 "call":   '<path d="M3 8h8"/><path d="M11 4l5 4-5 4"/><path d="M16 5h5v14h-5"/><path d="M18.5 9v6"/>',
 "ret":    '<path d="M9 12H2"/><path d="M6 8l-4 4 4 4"/><rect x="9" y="5" width="5" height="14"/><path d="M18 12h4"/>',
 "ring":   '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/><path d="M12 3v5M12 16v5"/>',
 "sysc":   '<path d="M3 20h18"/><path d="M8 20V9l4-5 4 5v11"/><path d="M12 15v-6"/><path d="M9.5 11.5L12 9l2.5 2.5"/>',
 "swap":   '<path d="M4 8a8 8 0 0 1 13-3"/><path d="M17 2v4h-4"/><path d="M20 16a8 8 0 0 1-13 3"/><path d="M7 22v-4h4"/>',
 "shield": '<path d="M12 2l8 3v7c0 5-4 8-8 10-4-2-8-5-8-10V5z"/><path d="M9 12l2 2 4-4"/>',
 "moon":   '<path d="M20 14A8.5 8.5 0 1 1 10 4a7 7 0 0 0 10 10z"/>',
 "zero":   '<circle cx="12" cy="12" r="8"/><path d="M7 7l10 10"/>',
 "signext":'<rect x="2" y="8" width="7" height="8" rx="1.5"/><path d="M11 12h3"/><rect x="16" y="5" width="6" height="14" rx="1.5"/><path d="M18.5 8v8"/>',
 "clock":  '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
 "lock":   '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
 "ctrlreg":'<rect x="6" y="6" width="12" height="12" rx="2"/><path d="M10 2v4M14 2v4M10 18v4M14 18v4M2 10h4M2 14h4M18 10h4M18 14h4"/>',
 "msr":    '<circle cx="12" cy="13" r="7"/><path d="M12 10v3l2 2"/><path d="M9 3h6"/>',
 "mul":    '<path d="M4 4l16 16M20 4L4 20"/>',
 "div":    '<circle cx="6" cy="6" r="2"/><circle cx="6" cy="18" r="2"/><path d="M6 9v7"/><path d="M15 6h6M15 12h6M15 18h6"/>',
 "retire": '<path d="M4 8l8 8 8-8"/><path d="M4 14l8 8 8-8"/>',
 "table":  '<path d="M3 5h18v14H3z"/><path d="M3 10h18M3 14h18M9 5v14M15 5v14"/>',
 "zap":    '<path d="M13 2L5 13h5l-1 9 8-11h-5z"/>',
}

# --------------------------------------------------------------- emoji
# Same 27 glyph IDs, one emoji each. The SVG is the precise picture (only
# meaningful inside an HTML page); the emoji is the portable one -- it survives
# a Telegram message, a terminal, a git commit message and a phone screen.
# Chosen for the SHAPE of the operation, not a cute analogy: a stack glyph is a
# down-arrow into a box because the stack grows DOWN.
E = {
 "fetch":  "📥", "decode": "🔀", "move":   "➡️", "alu":    "➕",
 "logic":  "🔣", "cmp":    "⚖️", "flagset":"🚩", "stack":  "🧱",
 "load":   "📖", "store":  "📝", "jump":   "⤴️", "branch": "🔀",
 "call":   "📞", "ret":    "📥", "ring":   "⭕", "sysc":   "🚪",
 "swap":   "🔄", "shield": "🛡️", "moon":   "🌙", "zero":   "0️⃣",
 "signext":"↔️", "clock":  "⏱️", "lock":   "🔒", "ctrlreg":"🎛️",
 "msr":    "📟", "mul":    "✖️", "div":    "➗", "retire": "📤",
 "table":  "🗂️", "zap":    "⚡",
}

# ------------------------------------------------------- hardware blocks
# id, label, sublabel, rect(x,y,w,h) on a 1000x500 canvas
BLOCKS = [
 ("fetch",   "Fetch",         "next bytes @ RIP",          24,  24, 172, 58),
 ("rip",     "RIP",           "program counter",           24,  94, 172, 58),
 ("decode",  "Decode",        "mnemonic to micro-ops",     24, 164, 172, 58),
 ("retire",  "Retire",        "update arch state",         24, 234, 172, 58),
 ("gpr",     "Register File", "rax .. r15, 16 x 64-bit",  220,  24, 224, 58),
 ("rsp",     "RSP",           "stack pointer engine",     220,  94, 224, 58),
 ("ctrl",    "Control Unit",  "micro-op sequencer",       220, 164, 224, 58),
 ("alu",     "ALU",           "add / logic / shift",       468,  24, 196, 58),
 ("flags",   "EFLAGS",        "CF PF ZF SF OF IF ...",     468,  94, 196, 58),
 ("cache",   "Cache",         "L1I / L1D, TLB tags",      468, 164, 196, 58),
 ("agutlb",  "AGU + TLB",     "effective address",        468, 234, 196, 58),
 ("seg",     "Segments",      "cs ss ds es fs gs",        688,  24, 196, 58),
 ("cpl",     "CPL",           "ring 0 / ring 3",          688,  94, 196, 58),
 ("msr",     "MSRs",          "swapgs / fs base",         688, 164, 196, 58),
 ("cr",      "Ctrl Regs",     "cr0 .. cr4",               688, 234, 196, 58),
 ("bus",     "Data Bus",      "load / store transfer",     24, 316, 540, 56),
 ("mem",     "Memory",        "kernel stack + objects",    24, 384, 540, 56),
 ("intc",    "Interrupts",    "IF flag, PIC / APIC",     588, 316, 296, 56),
 ("xmm",     "SIMD / FPU",    "xmm0-15, sse / avx",       588, 384, 296, 56),
]

# EVERY instruction passes through the front end. Stated once, so the rules
# below only have to list the interesting parts.
FRONT_END = ["fetch", "rip", "decode", "retire"]

GPR64 = ("rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15 "
         "eax ecx edx ebx esp ebp esi edi r8d r9d r10d r11d r12d r13d r14d r15d "
         "ax cx dx bx sp bp si di al cl dl bl ah ch dh bh "
         "r8w r9w r10w r11w r12w r13w r14w r15w ax cx dx bx sp bp si di").split()
GPRSET = set(GPR64)
SEGSET = {"cs", "ss", "ds", "es", "fs", "gs"}
CRSET = {"cr0", "cr2", "cr3", "cr4", "cr8"}
# AT&T writes src first; Intel writes dst first. The rule is per-opcode, so
# record it explicitly rather than guessing from the mnemonic.
NO_DST = {"cmp", "test", "push", "call", "jmp", "bt", "bts", "btr", "btc"}

# mnemonic regex -> (glyph, caption, units, flags)
RULES = [
 # ---- data movement
 (r"^swapgs$",        "swap",  "SWAPGS - exchange the GS base MSR, so GS now points at the *other* world (user GS / kernel GS)",
                    ["seg", "cpl", "msr", "ctrl"], 0),
 (r"^movabs$",        "move",  "MOVABS - MOV of a 64-bit immediate too big for a sign-extended 32-bit field",
                    ["gpr", "decode"], 0),
 (r"^movq?$",         "move",  "MOV - copy bits from source to destination. Pure data movement: no arithmetic, and the FLAGS are left alone",
                    ["gpr"], 0),
 (r"^(movs[xi]?q?|movslq|movsxd|cltq)$",   "signext", "MOVSX/MOVSLQ - move, then SIGN-extend a narrower value out to 64 bits",
                    ["alu", "gpr"], 1),
 (r"^movz[xi]?q?$",  "signext", "MOVZX - move, then ZERO-extend a narrower value out to 64 bits",
                    ["alu", "gpr"], 1),
 (r"^lea$",           "decode","LEA - compute an effective address only. It reads NO memory; the 'L' is 'load-address', not load",
                    ["agutlb", "gpr", "alu"], 1),
 (r"^xchg$",          "swap",  "XCHG - atomically exchange two operands (LOCK is implied for memory operands)",
                    ["gpr", "bus", "ctrl"], 0),
 (r"^bswap$",         "mul",   "BSWAP - reverse the byte order of a register (endianness fix-up)",
                    ["gpr"], 0),
 (r"^xlat$",          "load",  "XLAT - byte table lookup through RBX:AL (legacy string op)",
                    ["gpr", "bus", "mem", "agutlb"], 0),
 # ---- stack
 (r"^pushq?$",        "stack", "PUSH - RSP -= 8, then store 8 bytes at the new RSP (the stack grows DOWN)",
                    ["rsp", "bus", "mem", "agutlb", "cache"], 16),
 (r"^popq?$",         "stack", "POP - load 8 bytes from RSP into the destination, then RSP += 8 (the stack unwinds UP)",
                    ["rsp", "bus", "mem", "agutlb", "cache", "gpr"], 16),
 (r"^leave$",         "stack", "LEAVE - RSP = RBP, then POP RBP: tear a whole frame down in two steps",
                    ["rsp", "gpr", "mem", "bus", "agutlb"], 16),
 (r"^enter$",         "stack", "ENTER - build a stack frame in one instruction (older compilers emitted it)",
                    ["rsp", "gpr", "mem", "bus", "frame", "flags"], 16),
 # ---- arithmetic / logic
 (r"^(add|adc|adcx|adox)$", "alu","ADD - integer addition into the destination",
                    ["alu", "gpr", "flags"], 9),
 (r"^(sub|sbb|sbbx|subx)$", "alu","SUB - integer subtraction; SBB subtracts WITH the carry-in, for multi-precision arithmetic",
                    ["alu", "gpr", "flags"], 9),
 (r"^(inc|dec|neg|not)$",   "logic","INC/DEC/NEG/NOT - one-operand ALU op (note: DEC preserves CF, INC does not touch flags at all)",
                    ["alu", "gpr", "flags"], 10),
 (r"^(and|or|xor)$",  "logic", "AND/OR/XOR - bitwise logic into the destination",
                    ["alu", "gpr", "flags"], 10),
 (r"^(cmp|test)$",    "cmp",   "CMP/TEST - subtract or AND *discarding* the result: only the FLAGS change, no register moves",
                    ["alu", "flags"], 4),
 (r"^(shl|shr|sar|sal|rol|ror|rcl|rcr|shld|shrd|shlx|shrx|sarx)$", "alu",
                    "SHL/SHR/SAR - shift left/right, logical or arithmetic; the count is masked to 0-63",
                    ["alu", "gpr", "flags"], 9),
 (r"^(imul|mul|div|idiv)$", "mul","MUL/IMUL/DIV/IDIV - the dedicated multiplier/divider; RDX:RAX is an implicit operand",
                    ["alu", "gpr", "flags", "ctrl"], 9),
 (r"^(cqo|cdq|cwd|cdqe|cqo)$", "signext","CDQ/CQO - sign-extend RAX into RDX:RAX, preparing a 128-bit dividend",
                    ["alu", "gpr"], 1),
 (r"^(popcnt|tzcnt|lzcnt|bsf|bsr|blsi|blsr|blsmsk)$", "cmp",
                    "BSF/BSR/POPCNT/TZCNT/LZCNT - count or locate set bits; flags are only a side effect",
                    ["alu", "gpr", "flags"], 4),
 (r"^cmov",           "cmp",   "CMOVcc - move only if the condition flag says so: a branch that never touches RIP",
                    ["alu", "gpr", "flags", "ctrl"], 4),
 (r"^(set[a-z]+)$",   "cmp",   "SETcc - write a 0/1 byte based on the condition flags, without branching",
                    ["alu", "flags", "gpr"], 4),
 (r"^(movs[bst]|cmps[bst]|stos[bst]|lods[bst]|scas[bst]|ins[bwd]|outs[bwd])$", "load",
                    "String instruction - the CPU repeats REP over a whole buffer internally, one element per iteration",
                    ["gpr", "rsp", "flags", "bus", "mem", "agutlb", "cache", "ctrl"], 0),
 # ---- control flow
 (r"^jmpq?$",         "jump",  "JMP - unconditional jump: RIP takes the target, nothing is pushed",
                    ["ctrl"], 0),
 (r"^j[a-z]+$",       "branch","Jcc - jump if condition: read the FLAGS, then maybe override RIP",
                    ["flags", "ctrl"], 0),
 (r"^(callq?|lcall)$","call",  "CALL - push the return address, then jump: this is how a C call frame is built",
                    ["rsp", "bus", "mem", "agutlb", "cache", "ctrl"], 16),
 (r"^(retq?|lret|retf)$", "ret","RET - pop the return address into RIP and jump to it: unwind one C frame",
                    ["rsp", "bus", "mem", "agutlb", "cache", "ctrl"], 16),
 (r"^(loop|loope|loopne)$", "branch","LOOP - decrement the counter and jump while it is non-zero",
                    ["gpr", "flags", "ctrl"], 0),
 # ---- privilege / system
 (r"^syscall$",       "sysc",  "SYSCALL - the ring 3 to ring 0 door: load RCX/R11, load the kernel CS, and swap GS plus the stack",
                    ["seg", "cpl", "msr", "rsp", "bus", "mem", "agutlb", "gpr", "flags", "ctrl", "intc"], 0),
 (r"^sysretq?$",      "sysc",  "SYSRET - the ring 0 to ring 3 door: restore the user CS/SS and the user stack",
                    ["seg", "cpl", "rsp", "bus", "mem", "agutlb", "gpr", "ctrl"], 0),
 (r"^iretq?$",        "sysc",  "IRET - return from an interrupt: pop RIP/CS/RFLAGS/RSP/SS and change privilege level",
                    ["seg", "cpl", "rsp", "bus", "mem", "agutlb", "gpr", "flags", "ctrl", "intc"], 0),
 (r"^sti$",           "shield","STI - set the interrupt-enable flag: unmask maskable interrupts",
                    ["flags", "intc"], 8),
 (r"^cli$",           "shield","CLI - clear the interrupt-enable flag: mask maskable interrupts",
                    ["flags", "intc"], 8),
 (r"^hlt$",           "moon",  "HLT - stop the CPU until the next interrupt arrives",
                    ["ctrl", "intc"], 0),
 (r"^pause$",         "clock", "PAUSE - yield pipeline resources to a sibling SMT thread; a spin-wait hint",
                    ["ctrl"], 0),
 (r"^int[0-9]?$",     "zap",   "INT - software interrupt: the CPU pushes a frame and dispatches through the IDT",
                    ["intc", "seg", "cpl", "rsp", "mem", "bus", "agutlb", "ctrl"], 0),
 (r"^ud2$",           "zap",   "UD2 - deliberately undefined opcode; the classic 'this must never happen' trap",
                    ["intc", "ctrl"], 0),
 (r"^cpuid$",         "ctrlreg","CPUID - read the CPU's feature bits into EAX/EBX/ECX/EDX",
                    ["gpr", "ctrl", "bus"], 0),
 (r"^rdtsc[p]?$",     "clock", "RDTSC - read the timestamp counter: how the kernel does cheap cycle-accurate timing",
                    ["gpr", "ctrl", "bus"], 0),
 (r"^(pushf|popf)[qwl]?$", "flagset","PUSHFQ/POPFQ - save or restore the whole flags register, like a manual PUSH",
                    ["rsp", "flags", "mem", "bus", "agutlb"], 24),
 # ---- misc / barriers / atomics
 (r"^nop",            "zero",  "NOP - deliberately do nothing: alignment padding, or a site to be patched later",
                    [], 0),
 (r"^(endbr32|endbr64)$", "zero","ENDBR64 - a NOP that CET uses as a landing pad for indirect branches",
                    ["ctrl"], 0),
 (r"^lfence$",        "lock",  "LFENCE - order earlier loads before later loads and stores (a memory barrier)",
                    ["ctrl", "cache"], 0),
 (r"^mfence$",        "lock",  "MFENCE - order all earlier loads and stores before later ones (a memory barrier)",
                    ["ctrl", "cache", "bus"], 0),
 (r"^sfence$",        "lock",  "SFENCE - order earlier stores before later stores (a memory barrier)",
                    ["ctrl", "cache"], 0),
 (r"^(rdfsbase|rdgsbase|wrfsbase|wrgsbase)$", "msr",
                    "FSGSBASE - read/write the FS or GS base MSR (this is how thread-local storage is reached)",
                    ["msr", "gpr", "seg"], 0),
 (r"^(rdfsbase|rdgsbase)$", "msr", "RDFSBASE/RDGSBASE - read the FS/GS base MSR",
                    ["msr", "gpr", "seg"], 0),
 (r"^clts$",          "ctrlreg","CLTS - clear the task-switched flag in CR0, used when returning to user mode",
                    ["cr", "ctrl"], 0),
 (r"^(lmsw|smsw|lmsw)$", "ctrlreg","Load/store the machine status word from CR0",
                    ["cr", "gpr", "ctrl"], 0),
 (r"^(ldt|sgdt|lgdt|lidt|lldt|ltr)$", "seg",
                    "Load/store a segment descriptor table - how CS/SS and the GDT/IDT themselves get set up",
                    ["seg", "cpl", "ctrl", "bus", "mem", "agutlb"], 0),
 (r"^(str|sltr|sldt|lar|lsr|lss|lfs|lgs)$", "seg",
                    "MOV to/from a segment register: load a selector, then walk the descriptor table",
                    ["seg", "cpl", "gpr", "ctrl", "bus", "mem", "agutlb"], 0),
 (r"^(cmpxchg8b|cmpxchg16b|xadd)$", "lock",
                    "LOCK-prefixed read-modify-write: atomic against other cores, the bus is held exclusive",
                    ["bus", "cache", "gpr", "ctrl", "agutlb"], 0),
 (r"^rdmsr$",         "msr",   "RDMSR - read a model-specific register (TSC, topology, perf counters)",
                    ["msr", "gpr", "ctrl", "bus"], 0),
 (r"^wrmsr$",         "msr",   "WRMSR - write a model-specific register",
                    ["msr", "gpr", "ctrl", "bus"], 0),
 (r"^rdrand$",        "clock", "RDRAND - read the hardware random-number generator",
                    ["gpr", "ctrl", "bus"], 0),
 (r"^vmcall$",        "sysc",  "VMCALL - hypervisor call: a deliberate trap from guest into the host",
                    ["cpl", "seg", "ctrl", "intc"], 0),
 (r"^v[a-z0-9]+$",    "alu",   "AVX/vector instruction - operates on 128/256/512-bit xmm/ymm/zmm registers",
                    ["xmm", "gpr", "alu", "flags"], 0),
 (r"^(crt[0-9]?|clts|lmsw)$", "ctrlreg",
                    "MOV to/from a control register CR0-CR4: page tables, paging mode, protection",
                    ["cr", "gpr", "ctrl"], 0),
]

# mnemonics that read memory but never write it
READ_ONLY = {"cmp", "test", "bt", "jmp", "call", "push", "pushf"}
# mnemonics that are pure address arithmetic, memory never touched
NO_MEMORY = {"lea", "nop", "endbr32", "endbr64", "pause", "endbr64"}


# ---------------------------------------------------------------- parsing
def _strip_preamble(t):
    """Drop gdb's '=> 0xADDR <sym>:' prefix and any raw byte column.

    Only the '=> ' arrow marks the current instruction. A bare '<...>' is an
    *operand* annotation ('call 0x... <do_syscall_64>') and must be dropped
    with the angle brackets left intact.
    """
    t = (t or "").strip()
    if not t:
        return ""
    if t.startswith("=>"):               # gdb's 'current instruction' marker
        t = t[2:]
        t = re.sub(r"^\s*0x[0-9a-f]+", "", t)   # the address it pointed at
        t = re.sub(r"^\s*<[^>]*>:?", "", t)    # and the symbol, if any
    else:
        # '0x40101c <_start>:  mov ...' - a leading address+symbol+colon
        m = re.match(r"^\s*0x[0-9a-f]+\s*<[^>]*>:?\s*", t)
        if m and not re.match(r"^\s*0x[0-9a-f]+\s+[a-z]", t):
            t = t[m.end():]
    t = t.lstrip(" \t:")
    t = re.sub(r"^\s*0x[0-9a-f]+\s+", "", t)        # bare address column
    t = re.sub(r"^\s*(?:[0-9a-f]{2}\s+)+", "", t)    # raw bytes column
    t = re.sub(r"\s*<[^>]*>", "", t)                # <symbol+off> annotation
    t = re.split(r"\s*;|\s*#|\s*//|\s*\|\s*", t)[0]
    return t.strip()


def parse(text):
    """(mnemonic, operands, dialect) from a disassembly line.

    Dialect is 'att' or 'intel'. Handles every shape the input arrives in:
      'swapgs'
      '6a da   push   0x...'
      '=> 0xffffffff81200040 <entry_SYSCALL_64>:\tswapgs'
      '0x40101c <_start>:  mov    $0x1,%eax'
      '48 8b 44 24 15   mov    rax,QWORD PTR [rsp+0x15]'
    """
    t = _strip_preamble(text)
    if not t:
        return "", [], "intel"
    # Dialect detection. '%' and '$' are AT&T-only, but absolute addressing
    # in AT&T prints neither ('push 0xffffffff8160c014'), so those two are not
    # sufficient. 'PTR' and '[...]' are Intel-only and unambiguous, so check
    # them first and use them to override a missing '%'.
    intel_markers = ("PTR" in t) or re.search(r"\[[^\]]*\]", t) is not None
    att_markers = ("%" in t) or ("$" in t)
    if intel_markers:
        dialect = "intel"
    elif att_markers:
        dialect = "att"
    else:
        # No marker either way. AT&T prints '(%rip)' and '(%reg)' for the
        # common memory forms, so a bare literal is Intel style; but for
        # absolute forms the two are identical, and Intel is the safer default
        # because 'PTR' would have been present had it been Intel.
        dialect = "intel"
    parts = t.split(None, 1)
    mn = parts[0].lower()
    ops = [o.strip() for o in parts[1].split(",")] if len(parts) > 1 else []
    return mn, ops, dialect


def bare_mnemonic(mn):
    """Strip a trailing operand-size suffix: 'testb'->'test', 'sbb'->'sbb'.

    Only a real size letter is stripped, and only when what remains is a known
    opcode prefix. 'sbb' must NOT become 'sb', and 'mov' must never be treated
    as a CR0-CR4 move.
    """
    if not mn:
        return mn
    if re.fullmatch(r"(nop[a-z]*|endbr32|endbr64|cltq|cmpxchg\w*|xlatb?)", mn):
        return mn
    for size in ("b", "w", "l", "q"):
        if mn.endswith(size) and len(mn) > 1:
            base = mn[:-1]
            # keep it only if the base is a plausible opcode, not a fragment
            if base in _KNOWN_BASE or re.fullmatch(r"(v|p)[a-z0-9]+", base):
                return base
    return mn


_KNOWN_BASE = {
    "mov", "movs", "movz", "lea", "add", "sub", "adc", "sbb", "cmp", "test",
    "and", "or", "xor", "not", "neg", "inc", "dec", "push", "pop", "call",
    "ret", "jmp", "je", "jne", "jz", "jnz", "ja", "jb", "jae", "jbe", "jg",
    "jl", "jge", "jle", "js", "jns", "jo", "jno", "jp", "jnp", "jc", "jnc",
    "shl", "shr", "sar", "sal", "rol", "ror", "xchg", "bt", "imul", "mul",
    "div", "idiv", "set", "cmov", "movs", "stos", "lods", "scas", "cmps",
    "ins", "outs", "in", "out", "loop", "shld", "shrd", "pushf", "popf",
    "bswap", "bsf", "bsr", "popcnt", "tzcnt", "lzcnt", "cqo", "cdq", "cdqe",
    "cwd", "leave", "nop", "pause", "hlt", "cli", "sti", "int", "lgdt",
    "lidt", "lldt", "ltr", "sgdt", "sidt", "sldt", "str", "sltr", "smsw",
    "lmsw", "lar", "lsr", "lss", "lfs", "lgs", "swapgs", "syscall",
    "sysret", "iret", "xadd", "shlx", "shrx", "sarx", "blsi", "blsr",
}


def is_reg(op):
    o = op.strip().lstrip("%*").lower()
    return o in GPRSET or o in SEGSET or o in CRSET or re.fullmatch(r"x?mm\d+|st\(\d+\)|[xyz]mm\d+", o)


def is_indirect_op(op):
    """True only for a dereferenced pointer: *mem, (mem), or [mem] in Intel.

    A bare '0xffffffff81156a5f' is an immediate branch target that happens to
    look like an address - the CPU never reads memory to get it.
    """
    o = op.strip()
    if o.startswith("*"):
        return True
    return ("[" in o) or ("(" in o)


def is_mem(op):
    o = op.strip()
    if o.startswith("*"):                       # AT&T indirect: *(%rax,%rsi,8)
        return True
    if "[" in o or "(" in o:                    # Intel [..] or AT&T (..)
        return True
    if re.search(r"\bPTR\b", o) or re.search(r"\b[a-z]{2}:0x", o):  # Intel PTR / seg override
        return True
    if re.search(r"%(fs|gs|cs|ss|ds|es):", o):                # AT&T '%fs:0x28'
        return True
    o2 = o.lstrip("%")
    if o2 in GPRSET or o2 in SEGSET or o2 in CRSET:
        return False
    # a bare 64-bit number is a memory reference in Intel syntax, immediate in
    # AT&T (where immediates carry a '$')
    if re.fullmatch(r"-?0x[0-9a-f]{9,}", o2):
        return True
    return False


def is_imm(op):
    o = op.strip()
    if o.startswith("$"):
        return True
    if is_mem(o) or is_reg(o):
        return False
    return bool(re.fullmatch(r"-?(0x[0-9a-f]+|\d+)", o.strip().lstrip("0x") if not o.strip().startswith("0x") else o.strip()))


def _immish(op):
    o = op.strip().lstrip("$").strip()
    return bool(re.fullmatch(r"-?(0x[0-9a-fA-F]+|\d+)", o))


def _is_bare_literal(op):
    """True for a plain address/number with no '$', brackets, '*' or 'PTR'.

    The dangerous case: in AT&T, 'push 0xffffffff8160c014' looks identical to
    an immediate but is really a memory load through a SIB byte. Whether it is
    memory depends on the opcode, so callers must check the mnemonic too.
    """
    o = op.strip()
    if not o or o.startswith("$") or o.startswith("*"):
        return False
    if any(t in o for t in ("[", "]", "(", ")", "PTR", ":")):
        return False
    return bool(re.fullmatch(r"-?(0x[0-9a-fA-F]+|\d+)", o))


def operand_kinds(text):
    """-> dict with src/dst/mem_read/mem_write/imm flags, dialect-aware."""
    mn, ops, dia = parse(text)
    base = bare_mnemonic(mn)
    out = {"mnemonic": base, "dialect": dia, "operands": ops,
           "src": None, "dst": None, "mem_read": False, "mem_write": False,
           "imm": False, "indirect": False}
    if not ops:
        return out

    # reorder into a canonical (src, dst) pair regardless of dialect
    if dia == "intel":
        dst, src = ops[0], (ops[1] if len(ops) > 1 else None)
    else:
        src, dst = ops[0], (ops[1] if len(ops) > 1 else None)
    out["src"], out["dst"] = src, dst

    if src and src.startswith("*"):
        out["indirect"] = True
        out["mem_read"] = True
    # Intel has no '*' marker, but 'jmp QWORD PTR [rax+rsi*8]' loads the target
    # from memory exactly like AT&T's 'jmp *-0x...(,%rsi,8)'. The only
    # difference is the dialect spelling of the same instruction.
    if base in ("jmp", "call"):
        # 'call 0xffffffff81156a5f'  -> DIRECT: the address is encoded in the
        #   instruction, no memory is touched to get the target.
        # 'jmp *-0x7e...(,%rsi,8)'  -> INDIRECT: the target is LOADED.
        # 'jmp QWORD PTR [rax+rsi*8]'-> INDIRECT (Intel puts it in the dst slot).
        # Only brackets/parentheses/an asterisk mark an indirect operand.
        if src and is_indirect_op(src) and not dst:
            out["indirect"] = True
        elif dst and is_indirect_op(dst) and not src:
            out["indirect"] = True
        if out["indirect"]:
            out["mem_read"] = True
    if src and is_mem(src):
        out["mem_read"] = True
    if dst and is_mem(dst):
        out["mem_write"] = True
    if (_immish(src) if src else False) or (_immish(dst) if dst else False):
        out["imm"] = True

    # LEA computes an address and loads nothing: kill the memory access.
    if base in NO_MEMORY:
        out["mem_read"] = out["mem_write"] = False
    # NOP with an addressing operand is a multi-byte NOP, still no access.
    if base.startswith("nop"):
        out["mem_read"] = out["mem_write"] = False
    # CMP/TEST/BT write only the flags register - they can never store, but
    # they absolutely can READ memory. In Intel syntax the memory operand sits
    # in the destination slot, so it would otherwise look like a store.
    if base in ("cmp", "test", "bt"):
        if dst and is_mem(dst) and not out["mem_read"]:
            out["mem_read"] = True
        out["mem_write"] = False
    # Intel prints 'push 0x2b' for push imm8 and 'push QWORD PTR [...]' for the
    # memory form, so a bare number here is an immediate unless it is 64-bit
    # wide AND the opcode has a memory form at all.
    if dia == "intel" and out["imm"] and not any(("[" in o or "(" in o) for o in ops) \
            and "PTR" not in " ".join(ops):
        # Intel prints a bare number for a true immediate ('push 0x2b') and
        # always decorates a real memory operand with PTR or brackets.
        out["mem_read"] = out["mem_write"] = False
    # A jump/call/push/ret that names memory READS it: the target or the value
    # to push comes from the bus. It never stores.
    #
    # A BARE literal is not automatically memory. Verified against objdump for
    # the same bytes in both dialects:
    #     6a 2b           push $0x2b            | push 0x2b                 imm
    #     ff 34 25 <disp> push 0xffffffff...    | push QWORD PTR ds:0x...   MEM
    #     ff 35 <disp>    push -0x7e9...(%rip)  | push QWORD PTR [rip+...]  MEM
    #     e8 <rel32>      call 0xffffffffff55   | call 0xffffffffff55       DIRECT
    #     ff 14 25 <disp> call *0xffffffff...   | call QWORD PTR ds:0x...   INDIRECT
    # So in AT&T: '$' means immediate, '*' means indirect, bare means DIRECT
    # for call/jmp -- but for PUSH a bare literal can only be memory, because
    # PUSH has no imm64 encoding (only imm8 and sign-extended imm32).
    if base in ("jmp", "call", "push", "ret", "retf"):
        out["mem_write"] = False
        for cand in (src, dst):
            if cand is None:
                continue
            if cand.strip().startswith("$"):
                continue                 # AT&T '$' is always an immediate
            if _is_bare_literal(cand):
                # A bare literal is the one case the two dialects genuinely
                # disagree on, and only the raw bytes can settle it:
                #   ff 34 25 <disp>  AT&T 'push 0x...'  = MEMORY
                #                    Intel 'push 0x...' = immediate
                # objdump -M intel always emits 'PTR', so when the caller hands
                # us Intel text (as the viewer does) the ambiguity is already
                # resolved. If it reaches us unresolved, say so rather than
                # silently picking the wrong one.
                if base not in ("jmp", "call") and dia != "intel":
                    out["mem_read"] = True
                    out["ambiguous"] = True
                elif base not in ("jmp", "call"):
                    out["ambiguous"] = True
                continue
            if base in ("jmp", "call") and not is_indirect_op(cand):
                continue                 # a bare literal is a direct target
            if is_mem(cand):
                out["mem_read"] = True
    return out


# --------------------------------------------------------------- classify
def classify(text):
    """-> {glyph, glyph_svg, caption, units, mnemonic, operands, ...}"""
    ok = operand_kinds(text)
    mn, ops, dia = ok["mnemonic"], ok["operands"], ok["dialect"]
    base = mn

    glyph, caption, units, fl = "decode", "unclassified instruction", list(FRONT_END), 0
    matched = False
    for rx, g, cap, u, f in RULES:
        if re.match(rx, base):
            glyph, caption, units, fl, matched = g, cap, list(u), f, True
            break
    if not matched:
        caption = f"{base.upper()} - no classifier rule matched, so the hardware map below is only the front end. See the raw disassembly."
    units = FRONT_END + units if units else list(FRONT_END)

    # MOV is a shape, not a destination: dispatch on the operands.
    if base in ("mov", "movq", "movl") and matched and glyph == "move":
        joined = " ".join(o.lower() for o in ops)
        if re.search(r"\bcr[0-4]\b", joined):
            glyph, caption = "ctrlreg", ("MOV to/from a control register CR0-CR4 - page tables, paging mode, "
                                          "protection. These are the switches the whole MM depends on")
            units = units + ["cr", "ctrl"]
        elif re.search(r"\b(cr0|cr2|cr3|cr4)\b", joined) or re.search(r"%cr\d", joined):
            units = units + ["cr", "ctrl"]
        elif any(re.fullmatch(r"[%]?(cs|ss|ds|es|fs|gs)", o.strip()) for o in ops):
            glyph, caption = "seg", ("MOV to/from a segment register - write a selector, then the CPU walks the "
                                     "descriptor table to find the base/limit/privilege")
            units = units + ["seg", "cpl", "ctrl", "bus", "mem", "agutlb"]
        elif re.search(r"[%(](fs|gs)base\b", joined):
            units = units + ["msr", "seg"]

    # opcode-implicit hardware
    if base in ("push", "pop", "call", "ret", "retf", "leave", "enter", "pushfq", "popfq"):
        if "rsp" not in units:
            units += ["rsp"]
    if base in ("mul", "imul", "div", "idiv"):
        units += ["gpr", "ctrl"]
    if base in ("cqo", "cdq", "cwd", "cdqe", "movslq", "movsxd", "movzx", "movsx", "movzb", "movzw"):
        units = units + ["alu"] if "alu" not in units else units
    if base in ("sysret", "sysretq", "iretq", "iret"):
        units = sorted(set(units + ["cpl", "seg"]))
    if base in ("movs", "stos", "lods", "scas", "cmps", "rep", "repe", "repne"):
        units = sorted(set(units + ["rsp"]))

    # memory access drags in the whole path to DRAM
    if ok["mem_read"] or ok["mem_write"]:
        units = sorted(set(units + ["bus", "mem", "agutlb", "cache"]))

    # ---------------------------------------------------- readable summary
    extra = []
    if ok["mem_read"] and ok["mem_write"]:
        extra.append("reads memory and writes memory")
    elif ok["mem_write"]:
        extra.append("writes memory")
    elif ok["mem_read"]:
        extra.append("reads memory")
    elif ok["imm"]:
        extra.append("immediate constant only, no register read")
    elif any(is_reg(o) for o in ops):
        extra.append("register to register")
    if base == "lea":
        extra = ["reads NO memory: the 'L' is load-address, not load"]
    if ok["indirect"]:
        extra.append("target comes from memory, not from the instruction")
    if base.startswith("j") and base not in ("jmp",):
        extra.append("the decision is made by the FLAGS")
    if fl & 16:
        extra.append("RSP moves")
    if base in ("mov", "movabs", "lea"):
        extra.append("FLAGS are NOT touched")

    return {
        "glyph": glyph,
        "glyph_svg": G.get(glyph, G["decode"]),
        "emoji": E.get(glyph, "❓"),
        "caption": caption,
        "units": sorted(set(units)),
        "mnemonic": base,
        "operands": ops,
        "src": ok["src"],
        "dst": ok["dst"],
        "dialect": dia,
        "is_mem": bool(ok["mem_read"] or ok["mem_write"]),
        "mem_read": ok["mem_read"],
        "mem_write": ok["mem_write"],
        "indirect": ok["indirect"],
        "imm": ok["imm"],
        "access": " · ".join(extra),
        "matched": matched,
        # True when the text alone cannot tell an immediate from a memory
        # operand (bare-literal push/call/jmp). Only the raw bytes settle it.
        "ambiguous": bool(ok.get("ambiguous")),
    }


# which observed diffs map onto which hardware block
UNIT_FROM_REG = {}


def _init_units():
    for r in ("rax", "rcx", "rdx", "rbx", "rsi", "rdi", "rbp",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"):
        UNIT_FROM_REG[r] = "gpr"
    UNIT_FROM_REG["rsp"] = "rsp"
    UNIT_FROM_REG["rip"] = "rip"
    for g in ("cs", "ss", "ds", "es", "fs", "gs"):
        UNIT_FROM_REG[g] = "seg"


_init_units()


# =============================================================== hw_table
# The per-instruction hardware table. classify() answers "what kind of thing is
# this"; hw_table() answers "name the exact pieces, one row each".
#
# Every row is a real, checkable claim with a direction:
#     R  read  - the CPU consumes the old value
#     W  write - the CPU produces a new value
#     RW - read-modify-write (the ALU consumed the old bits to make new ones)
#     -  untouched - explicitly preserved, which is the interesting fact for
#        MOV/LEA and for the flags that an instruction does NOT define
#
# Flags are broken out individually rather than as one "EFLAGS" row, because
# "which flags does this set" is the single most-asked question about x86 and
# one word cannot answer it: CMP writes six, MOV writes none, INC leaves CF
# alone, and XOR forces CF and OF to zero.

# which FLAGS a conditional branch/jump READS. This is the answer to "what is
# the CPU actually looking at when it decides whether to jump".
COND_FLAG_READS = {
    "jo": ["OF"], "jno": ["OF"],
    "jb": ["CF"], "jnae": ["CF"], "jc": ["CF"], "jnb": ["CF"], "jae": ["CF"], "jnc": ["CF"],
    "je": ["ZF"], "jz": ["ZF"], "jne": ["ZF"], "jnz": ["ZF"],
    "jbe": ["CF", "ZF"], "jna": ["CF", "ZF"],
    "ja": ["CF", "ZF"], "jnbe": ["CF", "ZF"],
    "js": ["SF"], "jns": ["SF"],
    "jp": ["PF"], "jpe": ["PF"], "jnp": ["PF"], "jpo": ["PF"],
    "jl": ["SF", "OF"], "jnge": ["SF", "OF"],
    "jge": ["SF", "OF"], "jnl": ["SF", "OF"],
    "jle": ["ZF", "SF", "OF"], "jng": ["ZF", "SF", "OF"],
    "jg": ["ZF", "SF", "OF"], "jnle": ["ZF", "SF", "OF"],
}

# CMOVcc reads flags without ever touching RIP.
CMOV_MEANING = {
    "e": "equal (ZF=1)", "z": "zero (ZF=1)", "ne": "not equal (ZF=0)",
    "l": "less, signed (SF!=OF)", "ge": "greater/equal, signed",
    "g": "greater, signed", "le": "less/equal, signed",
    "b": "below/carry (CF=1)", "ae": "above/equal, no carry",
    "a": "above, no carry", "be": "below/equal", "s": "sign (SF=1)",
    "ns": "no sign", "p": "parity", "np": "no parity", "o": "overflow",
    "no": "no overflow",
}

FLAG_ROWS = [
    ("CF", 0, "carry / borrow out of the ALU"),
    ("PF", 2, "parity of the low byte (even=1)"),
    ("AF", 4, "carry/borrow out of bit 3 (BCD only)"),
    ("ZF", 6, "result was exactly zero"),
    ("SF", 7, "copied from the top bit - result negative"),
    ("DF", 10, "string ops step forward (0) or backward (1)"),
    ("OF", 11, "signed overflow"),
]

# mnemonic regex -> {flag: 'W'|'RW'|'-'|None}
FLAG_RULES = [
    (r"^(add|adc|sub|sbb|neg)$", {"CF": "W", "PF": "W", "AF": "W", "ZF": "W", "SF": "W", "OF": "W"}),
    (r"^inc$", {"CF": "-", "PF": "W", "AF": "W", "ZF": "W", "SF": "W", "OF": "W"}),
    (r"^dec$", {"CF": "-", "PF": "W", "AF": "W", "ZF": "W", "SF": "W", "OF": "W"}),
    (r"^(and|or|xor|test)$", {"CF": "W", "OF": "W", "SF": "W", "ZF": "W", "PF": "W", "AF": None}),
    (r"^(cmp)$", {"CF": "W", "PF": "W", "AF": "W", "ZF": "W", "SF": "W", "OF": "W"}),
    (r"^(shl|shr|sal|sar|rol|ror|rcl|rcr|shld|shrd|shlx|shrx|sarx)$",
        {"CF": "W", "OF": "RW", "SF": "W", "ZF": "W", "PF": "W", "AF": None}),
    (r"^(imul|mul|div|idiv)$", {"CF": "W", "OF": "W", "SF": None, "ZF": None, "PF": None, "AF": None}),
    (r"^(bt|bts|btr|btc)$", {"CF": "W", "OF": "-", "SF": "-", "ZF": "-", "PF": "-", "AF": "-"}),
    (r"^(cmov|set[a-z]+|cmovel|movzx|movsx|bswap|xchg)$",
        {"CF": "-", "PF": "-", "AF": "-", "ZF": "-", "SF": "-", "OF": "-", "DF": "-"}),
    (r"^(mov|movabs|lea|xlat|pop|call|ret|jmp|push|nop|endbr\d+|cli|sti|hlt|"
     r"swapgs|syscall|sysret\w*|iret\w*|lfence|mfence|sfence|pause|cpuid|"
     r"rdtsc\w*|lgdt|lidt|lldt|ltr|invlpg|wbinvd)$",
        {"CF": "-", "PF": "-", "AF": "-", "ZF": "-", "SF": "-", "OF": "-", "DF": "-"}),
    (r"^(btr|bts)$", {"CF": "W", "OF": "-", "SF": "-", "ZF": "-", "PF": "-", "AF": "-"}),
    (r"^(bsf|bsr|popcnt|tzcnt|lzcnt)$", {"CF": "-", "OF": "-", "SF": "-", "ZF": "-", "PF": "-", "AF": "-"}),
]


def flag_effects(base):
    """-> {flag_name: 'W'|'RW'|'-'|None} for the 7 tracked flags."""
    out = {n: "-" for n, _, _ in FLAG_ROWS}
    for rx, eff in FLAG_RULES:
        if re.match(rx, base):
            for k, v in eff.items():
                out[k] = v
            return out
    # No rule matched: the only safe claim is that the front end ran. Say
    # "unknown" rather than asserting "-" (preserved), which would be a lie.
    return {n: None for n, _, _ in FLAG_ROWS}


def _regname(op):
    """Strip dialect decoration to a bare register name, or None."""
    o = op.strip().lstrip("%").strip()
    o = o.rstrip(",")
    if is_mem(op):
        return None
    n = o.lower()
    if n in GPRSET or n in SEGSET or n in CRSET:
        return n
    if re.fullmatch(r"x?mm\d+|st\(\d\)|[xyz]?mm\d+", n):
        return n
    return None


def hw_table(text, diff=None):
    """-> ordered rows describing exactly which hardware this instruction touches.

    `diff` is the viewer's observed state delta (regs/flags/segs/mem changed
    between step i and i+1). When given, every row is cross-checked against what
    actually happened in the trace, so the table can mark agreement or
    disagreement between architecture and reality.
    """
    sem = classify(text)
    base = sem["mnemonic"]
    ok = sem
    rows = []

    def row(part, item, access, why, expect=None, observe=None):
        r = {"part": part, "item": item, "access": access, "why": why,
             "expect": expect, "observe": observe}
        rows.append(r)
        return r

    obs_regs = {}
    if diff:
        for d in diff.get("regs", []):
            obs_regs[d["name"].lower()] = d

    # ---- front end: every instruction, no exceptions
    row("Front end", "RIP", "R",
        "the address of THIS instruction is read to fetch its bytes")
    row("Front end", "Instruction bytes", "R",
        "fetched from L1I through the AGU/TLB; already decoded before the ALU runs")
    row("Front end", "Decode / control unit", "R",
        "turns the mnemonic into micro-ops the sequencer issues")

    ops = sem["operands"]
    src, dst = ok.get("src"), ok.get("dst")

    # ---- operand registers, direction depends on dialect + opcode
    sn, dn = _regname(src) if src else None, _regname(dst) if dst else None
    writes_dst = base not in NO_DST

    if dn and not is_mem(dst or ""):
        if writes_dst:
            obs = obs_regs.get(dn)
            row("Register file", dn, "W",
                f"destination operand - the CPU writes a new value into {dn}",
                expect="W", observe="W" if obs else None)
        else:
            # NO_DST mixes three different reasons. Say the right one, because
            # "the result is discarded" is only true of CMP/TEST - PUSH writes
            # memory and CALL/RET write RIP, neither of which is a "result".
            if base in ("cmp", "test"):
                why = (f"{base.upper()} computes a result only to derive the FLAGS from it, "
                       f"so {dn} is read and never written")
            elif base in ("call", "lcall"):
                why = f"CALL has no register destination - it pushes RIP and jumps; {dn} is only the argument"
            elif base in ("push",):
                why = f"PUSH has no register destination - {dn} is the value stored to the stack, never modified"
            elif base in ("jmp",):
                why = f"JMP has no register destination; {dn} is read only if the jump is indirect"
            else:
                why = f"{base.upper()} does not write {dn}"
            row("Register file", dn, "R", why,
                expect="R", observe="W" if dn in obs_regs else None)
    if sn and not is_mem(src or ""):
        row("Register file", sn, "R",
            f"source operand - supplies the bits {base.upper()} works with",
            expect="R", observe="W" if sn in obs_regs else ("R" if sn in obs_regs else None))

    # implicit register operands that the text never mentions
    if base in ("mul", "imul", "div", "idiv"):
        for r, why in (("rax", "implicit operand"),
                       ("rdx", "implicit high half / high dividend")):
            if r not in (sn, dn):
                row("Register file", r, "RW" if base.startswith("m") else "R", why)
    if base in ("cqo", "cdq", "cwd", "cdqe"):
        row("Register file", "rdx", "W", "written by the sign-extension (CQO/CQO sign-extends RAX into RDX)")
    if base.startswith("mul") and sn is None:
        row("Register file", "rax", "RW", "the low half of the product always lands here")
    if base.startswith("div"):
        row("Register file", "rax", "W", "quotient")
        row("Register file", "rdx", "W", "remainder")

    # ---- RIP as a DESTINATION for control transfer
    ctrl_to_rip = (base == "jmp" or base.startswith("j")
                   or base in ("call", "ret", "retf", "lcall", "lret",
                               "syscall", "sysretq", "sysret", "iretq", "iret"))
    if base in COND_FLAG_READS:
        for f in COND_FLAG_READS[base]:
            bit = {"CF": 0, "PF": 2, "ZF": 6, "SF": 7, "OF": 11}[f]
            row("EFLAGS", f, "R",
                f"READ to decide the branch - {base.upper()} jumps when this condition holds",
                expect="R",
                observe="R" if (diff or {}).get("flags") is not None else None)
    if base.startswith("cmov"):
        cond = base[4:]
        meaning = CMOV_MEANING.get(cond, cond)
        row("Control unit", "RIP", "-",
            f"CMOVcc is a branch that does NOT move RIP - it conditionally writes {dn or 'the destination'}")
        for f in COND_FLAG_READS.get("j" + cond, []):
            row("EFLAGS", f, "R", f"READ to decide whether the move happens ({meaning})")

    if ctrl_to_rip:
        row("Control unit", "RIP", "W",
            "control transfers here: the CPU overwrites the program counter",
            expect="W", observe=("W" if (diff or {}).get("rip_changed") else None))

    # ---- stack engine
    if "rsp" in sem["units"]:
        obs = obs_regs.get("rsp")
        row("Stack engine", "RSP", "RW",
            "the stack pointer moves - this instruction pushes, pops or reads a frame",
            expect="RW", observe="W" if obs else None)
        # The stack row's direction must come from the OPCODE, not from
        # operand_kinds(). PUSH has no explicit memory operand, so
        # mem_write is False for it - yet a push unambiguously STORES 8 bytes
        # at RSP-8. Deriving the direction from the flags alone therefore
        # reports every push as a stack READ, which is exactly backwards.
        if base in ("push", "call", "lcall", "enter"):
            st_acc, st_why = ("W", "stores 8 bytes: PUSH/CALL write the value (or the return "
                                   "address) at RSP-8, then RSP moves down")
        elif base in ("pop", "ret", "retf", "lret", "leave", "popfq", "popf"):
            st_acc, st_why = ("R", "loads 8 bytes from RSP, then RSP moves back up")
        else:
            st_acc = "RW" if ok["mem_write"] else "R"
            st_why = "the bytes at RSP are what actually change; RSP is just the pointer"
        row("Bus + Memory", "kernel/user stack", st_acc, st_why)
    elif base not in ("lea",) and ok["mem_read"]:
        row("Bus + Memory", "memory", "R", "reads through the bus (AGU/TLB/cache resolved the address)")

    # ---- ALU + flags
    fe = flag_effects(base)
    alu_touched = any(v in ("W", "RW") for k, v in fe.items() if k not in ("DF",))
    if base in ("mov", "movabs", "movzx", "movsx", "movslq", "movsxd", "lea",
                "pop", "call", "ret", "jmp", "push", "nop", "xchg", "bswap"):
        why = ("LEA only COMPUTES an address - no arithmetic happens and no flags move"
               if base == "lea" else
               f"{base.upper()} moves bits; it performs no arithmetic, so the ALU result path is bypassed and the FLAGS are preserved")
        row("ALU", "Arithmetic unit", "-", why)
    elif base in ("cmp", "test"):
        row("ALU", "Arithmetic unit", "RW",
            f"{base.upper()} runs the operation to produce the FLAGS, then THROWS THE RESULT AWAY - no register or memory is written")

    for name, bit, desc in FLAG_ROWS:
        eff = fe.get(name)
        if eff is None:
            continue
        if eff == "-":
            why = "preserved - this instruction does not define it"
        elif eff == "W":
            why = f"written by {base.upper()} ({desc})"
        elif eff == "RW":
            why = f"written, and the old value fed the operation ({desc})"
        else:
            why = "left in an UNDEFINED state by the architecture - do not read it"
        obs = None
        if diff is not None:
            obs = "W" if (name in (diff.get("flags") or {})) else "-"
        row("EFLAGS", name, eff, why, expect=eff, observe=obs)

    # ---- memory
    if ok["mem_read"]:
        row("Bus + Memory", "Memory (read)", "R",
            "address resolved by AGU + TLB, found in L1D or DRAM, brought back over the data bus")
    if ok["mem_write"]:
        row("Bus + Memory", "Memory (write)", "W",
            "store: the value is written through L1D toward DRAM")

    # ---- privilege / system
    if base in ("cli", "sti"):
        row("Interrupts", "IF (in EFLAGS)", "W",
            "interrupts masked off" if base == "cli" else "interrupts unmasked again")
        row("Control unit", "Interrupt enable", "W", "the sequencer stops accepting timer/IRQ events")
    if base == "swapgs":
        row("MSR", "MSR_IA32_GS_BASE", "RW",
            "exchanges the GS base between the user value and the kernel value")
        row("Segments", "GS base", "RW", "GS:0x60 now resolves to per-CPU kernel data")
    if base in ("syscall", "sysretq", "sysret", "iretq", "iret"):
        row("Privilege level", "CPL / ring", "RW" if base != "sysretq" else "RW",
            "crosses the user/kernel boundary")
        row("Privilege level", "CS selector", "W", "a different code segment is loaded")
    if base.startswith("mov") and re.search(r"\bcr[0-4]\b", " ".join(ops).lower()):
        row("Control registers", "CR0-CR4", "RW", "changes paging / protection mode machine-wide")

    if diff:
        for seg in diff.get("segs", []):
            n = seg.get("name", "?").lower()
            row("Segments", n, "W", f"observed change: {seg.get('before')} -> {seg.get('after')}",
                observe="W")
        if diff.get("ring_changed"):
            row("Privilege level", "CPL", "W", "observed: ring changed", observe="W")
        for m in diff.get("mem", []):
            row("Bus + Memory", f"memory @ {m.get('addr','?')}", "W",
                f"observed write: {m.get('before')} -> {m.get('after')}", observe="W")

    # ---- mark disagreements: where the ISA and the trace part company
    for r in rows:
        if r["expect"] and r["observe"] and r["expect"] != r["observe"]            and not (r["expect"] == "RW" and r["observe"] == "W"):
            r["conflict"] = True
    return {"glyph": sem["glyph"], "emoji": sem["emoji"],
            "glyph_svg": sem["glyph_svg"], "caption": sem["caption"],
            "mnemonic": base, "operands": ops, "rows": rows}


def observed_units(diff):
    """diff (as the viewer builds it) -> hardware blocks that really changed."""
    u = []
    for r in diff.get("regs", []):
        n = r["name"].lower()
        b = UNIT_FROM_REG.get(n)
        if b and b not in u:
            u.append(b)
    if diff.get("flags"):
        if "flags" not in u:
            u.append("flags")
    if diff.get("segs") and "seg" not in u:
        u.append("seg")
    if diff.get("mem"):
        for b in ("bus", "mem"):
            if b not in u:
                u.append(b)
    if diff.get("rip_changed") and "ctrl" not in u:
        u.append("ctrl")
    if diff.get("ring_changed") and "cpl" not in u:
        u.append("cpl")
    return sorted(set(u))
