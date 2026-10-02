#!/usr/bin/env python3
"""
build-viewer.py - turn a kernel trace (trace-kernel.py output) into a single
self-contained HTML page: a clickable list of real Linux instructions, and
what each one did to the hardware.

Every numeric value that can exceed 2**53 (kernel addresses, segment
selectors, anything from a real CPU) is emitted as a HEX STRING. JavaScript
numbers are IEEE doubles and would silently round 0xffffffff81200040 down to
0xffffffff81200000.
"""
import argparse, json, os, re, struct, subprocess, sys, tempfile

LAB = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, LAB)
import x86sem
GPRS = ["rax","rcx","rdx","rbx","rsi","rdi","rbp","rsp",
        "r8","r9","r10","r11","r12","r13","r14","r15"]
FLAG_ORDER = ["CF","PF","AF","ZF","SF","TF","IF","DF","OF","NT","RF","VM","AC","VIF","VIP"]
SSEGS = ["cs","ss","ds","es","fs","gs"]

CODE_WINDOW = 24   # bytes of real kernel code shown per PC

INSN_RE = re.compile(
    r'(?:=>\s*)?(0x[0-9a-f]+)\s*(?:<[^>]*>:\s*)?'
    r'((?:[0-9a-f]{2}\s)+)?\s*(.*)$')

H = lambda v: "0x%x" % (v & 0xFFFFFFFFFFFFFFFF)


def short(path):
    m = re.search(r'linux-source-[0-9.]+/(.*)$', path or "")
    return m.group(1) if m else (path or "?")


# ---------------------------------------------------------------- ELF access
def elf_segments(path):
    """[(vaddr, filesz, file_off)] for every PT_LOAD, so we can read raw bytes."""
    segs = []
    with open(path, "rb") as f:
        f.seek(0x20)
        phoff, = struct.unpack("<Q", f.read(8))
        f.seek(0x36)
        phentsize, phnum = struct.unpack("<HH", f.read(4))
        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            ph = f.read(phentsize)
            p_type = struct.unpack("<I", ph[0:4])[0]
            if p_type != 1:          # PT_LOAD
                continue
            p_offset, p_vaddr, _p_paddr, p_filesz = struct.unpack("<QQQQ", ph[8:40])
            segs.append((p_vaddr, p_filesz, p_offset))
    return segs


def read_bytes(segs, path, vaddr, n=16):
    for va, fsz, off in segs:
        if va <= vaddr < va + fsz:
            delta = vaddr - va
            with open(path, "rb") as f:
                f.seek(off + delta)
                return f.read(min(n, fsz - delta))
    return b""


def disassemble(raw):
    """Exact instruction length + text from raw bytes (objdump, binary mode)."""
    if not raw:
        return 0, ""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as t:
        t.write(raw); tmp = t.name
    try:
        out = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
             "-M", "intel", tmp],
            capture_output=True, text=True).stdout
    finally:
        os.unlink(tmp)
    m = re.search(r'^\s*0:\s+((?:[0-9a-f]{2} )+)\s*(.+)$', out, re.M)
    if not m:
        return 0, ""
    return len(m.group(1).split()), m.group(2).strip()


# ------------------------------------------------------------------- trace
def build(trace, vmlinux):
    steps = trace["steps"]
    segs = elf_segments(vmlinux)
    cache = {}

    for i, s in enumerate(steps):
        r = s["regs"]

        m = INSN_RE.match(s.get("insn", "") or "")
        addr = int(m.group(1), 16) if m else 0
        text = re.sub(r'\s*<[^>]*>', '', (m.group(3) if m else "")).rstrip()

        raw = read_bytes(segs, vmlinux, addr, 16)
        key = bytes(raw)
        if key not in cache:
            cache[key] = disassemble(raw)
        length, dis_text = cache[key]

        s["insn_parsed"] = {
            "addr": H(addr),
            "length": length,
            "bytes": list(raw[:length]) if length else [],
            "text": dis_text or text,
        }
        # A contiguous window of REAL kernel-image bytes starting at this PC.
        # This is what the 3D memory cells render: the code genuinely sitting
        # at that address, not an invented list. PC is at window offset 0.
        win = read_bytes(segs, vmlinux, addr, CODE_WINDOW)
        s["code"] = {"base": H(addr), "bytes": list(win)}
        s["sem"] = x86sem.classify(dis_text or text)
        s["hwt"] = x86sem.hw_table(dis_text or text)["rows"]
        s["file_short"] = short(s.get("file"))
        # Which instruction owns each byte of the fetch window. Computed here so
        # clicking a memory cell selects a real instruction instead of guessing
        # from the length of the one at PC.
        s["code_map"] = []
        s["cpl"] = r.get("cs", 0) & 3
        # hex strings everywhere: JS numbers cannot hold these
        s["regs_h"] = {k: H(v) for k, v in r.items()}
        s["eflags_h"] = H(r["eflags"])
        s["mem_base_h"] = H(r["rsp"] - trace["meta"]["mem_before"])
        s["mem_delta_h"] = [{"off": H(d["off"]), "from": d["from"], "to": d["to"]}
                            for d in s.get("mem_delta", [])]
        # NB: never store a back-reference to the neighbouring step here -
        # it chains the objects and json.dumps expands it exponentially.
    # Byte -> step index for every fetch window. `nearest` keeps the most
    # recent occurrence of an address, so a loop body maps to the iteration
    # actually on screen rather than the first time through.
    nearest = {}
    for i, s in enumerate(steps):
        base = int(s["insn_parsed"]["addr"], 16)
        win = s["code"]["bytes"]
        # Register the start BEFORE filling, so the instruction at PC owns its
        # own bytes. Ownership then runs forward to the end of the window: a
        # byte in the middle of a multi-byte encoding belongs to the
        # instruction that STARTED there, which is not itself a start address.
        nearest[base] = i
        owner, cm = -1, []
        for off in range(len(win)):
            a = base + off
            if a in nearest:
                owner = nearest[a]
            cm.append(owner)
        s["code_map"] = cm
    return trace


HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Linux kernel - instruction by instruction</title>
<style>
  :root{
    --bg:#0d1117; --panel:#161b22; --panel2:#1c2128; --edge:#30363d;
    --fg:#c9d1d9; --dim:#8b949e; --accent:#58a6ff; --good:#3fb950;
    --warn:#d29922; --bad:#f85149; --hi:#bc8cff; --code:#7ee787;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);
       font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  header{display:flex;flex-wrap:wrap;gap:14px;align-items:center;
         padding:9px 16px;background:var(--panel);border-bottom:1px solid var(--edge);
         position:sticky;top:0;z-index:5}
  header h1{font-size:14px;margin:0;color:var(--accent);font-weight:600}
  header .kv{color:var(--dim);font-size:12px}
  header .kv b{color:var(--fg);font-weight:600}
  .bar{display:flex;gap:6px;margin-left:auto}
  button{background:var(--panel2);color:var(--fg);border:1px solid var(--edge);
         border-radius:5px;padding:5px 10px;cursor:pointer;font:inherit;font-size:12px}
  button:hover{border-color:var(--accent);color:#fff}
  main{display:grid;grid-template-columns:minmax(440px,45%) 1fr;
       height:calc(100vh - 46px)}
  #left{display:flex;flex-direction:column;min-height:0;min-width:0}
  #tabs{display:flex;gap:4px;padding:6px 8px;background:var(--panel);
        border-bottom:1px solid var(--edge);flex:0 0 auto}
  #tabs button{flex:1;font-size:11px;padding:4px 6px}
  #tabs button.on{border-color:var(--accent);color:#fff;background:#1b2735}
  #list{border-right:1px solid var(--edge);overflow-y:auto;background:var(--panel);
        flex:1 1 auto;min-height:0}
  /* flex item that must both grow AND scroll: without min-height:0 a flex
     child refuses to shrink below its content and the pane is squeezed */
  #detail{overflow-y:auto;padding:0 18px 60px;flex:1 1 auto;min-height:0}
  .row{display:flex;gap:8px;padding:2px 10px;cursor:pointer;
       border-left:3px solid transparent;white-space:nowrap;align-items:baseline}
  .row:hover{background:#1f2630}
  .row.sel{background:#1b2735;border-left-color:var(--accent)}
  .row .n{color:#4d5566;min-width:34px;text-align:right;user-select:none}
  .row.sel .n{color:var(--accent)}
  .row .a{color:#6e7681;min-width:84px;font-size:11px}
  .row .i{color:var(--code)}
  .gap{color:#4d5566;background:#0b0f14;padding:2px 10px;font-size:10px;
       text-align:center;font-style:italic;border-left:2px solid #21262d}
  .gap.overlap{color:var(--warn);border-left-color:var(--warn)}
  /* address mode puts the address first and the step number last */
  #list .row .a{flex:0 0 84px}
  #list .row .n{margin-left:auto;min-width:26px}
  .row.wrote{background:#101a14}
  .row.wrote.sel{background:#16301f}
  .row.jumped{border-left-color:var(--warn)}
  .ring{font-size:10px;padding:0 4px;border-radius:3px;min-width:26px;text-align:center}
  .ring0{background:#3d1f2b;color:#ff7b72}
  .ring3{background:#12351f;color:#7ee787}
  .srcgrp{background:#11161d;color:var(--dim);padding:4px 10px;font-size:11px;
          border-top:1px solid var(--edge);position:sticky;top:0;z-index:1;
          white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  h2{font-size:12px;text-transform:uppercase;letter-spacing:.6px;color:var(--dim);
     margin:22px 0 8px;padding-bottom:5px;border-bottom:1px solid var(--edge)}
  .card{background:var(--panel);border:1px solid var(--edge);border-radius:7px;
        padding:12px 14px;margin-bottom:12px}
  .srcline{font-size:14px;color:#fff;white-space:pre-wrap;word-break:break-word}
  .srcline .ln{color:#4d5566;user-select:none;margin-right:10px}
  .path{color:var(--dim);font-size:11px;margin-bottom:8px}
  .path b{color:var(--hi)}
  table{border-collapse:collapse;width:100%;font-size:12px}
  td,th{text-align:left;padding:3px 8px;border-bottom:1px solid #21262d;vertical-align:top}
  th{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase}
  .reg{color:var(--accent)}
  .old{color:#6e7681;text-decoration:line-through}
  .new{color:var(--good);font-weight:600}
  .unch{color:#4d5566}
  .chip{display:inline-block;padding:1px 7px;border-radius:10px;font-size:11px;
        margin:0 4px 4px 0;border:1px solid var(--edge)}
  .f-on{background:#12351f;border-color:#2ea043;color:#7ee787}
  .f-off{background:#1c1416;border-color:#6e2224;color:#8b949e}
  .tag{display:inline-block;padding:1px 7px;border-radius:4px;font-size:11px;
       border:1px solid var(--edge);color:var(--dim)}
  .none{color:#4d5566;font-style:italic}
  .why{color:var(--fg);font-size:12.5px;line-height:1.7}
  .why b{color:var(--accent)}
  kbd{background:var(--panel2);border:1px solid var(--edge);border-bottom-width:2px;
      border-radius:4px;padding:1px 5px;font-size:11px;color:var(--dim)}
  .sticky{position:sticky;top:0;background:var(--bg);padding-top:8px;z-index:2}
  .big{font-size:15px;color:#fff}
  .bytes{color:#79c0ff;letter-spacing:1px}
  .legend{color:var(--dim);font-size:11px;margin-top:6px}
  .sw{display:inline-block;width:10px;height:10px;border-radius:2px;
      vertical-align:-1px;margin-right:4px}
  /* --- glyph column in the list --- */
  .row .g{flex:0 0 26px;height:26px;display:flex;align-items:center;
         justify-content:center;align-self:center;opacity:.62}
  .row.sel .g{opacity:1}
  .row .g svg{width:21px;height:21px;stroke:var(--code);stroke-width:1.7;
              fill:none;stroke-linecap:round;stroke-linejoin:round}
  .row.sel .g svg{stroke:#fff;stroke-width:2.1}
  .row.mem .g svg{stroke:#ffa657}
  .row.branch .g svg{stroke:#d2a8ff}
  .row.stackop .g svg{stroke:#7ee787}
  .row.sysc .g svg{stroke:#ff7b72}
  .row.jumped .g svg{stroke:#ff7b72}
  /* --- big glyph in the detail pane --- */
  .heroband{display:flex;gap:16px;align-items:flex-start}
  .heroglyph{flex:0 0 74px;height:74px;border-radius:12px;display:flex;
             align-items:center;justify-content:center;
             background:linear-gradient(160deg,#1d2530,#141a21);
             border:1px solid var(--edge)}
  .heroglyph svg{width:56px;height:56px;stroke:#7ee787;stroke-width:1.8;
                 fill:none;stroke-linecap:round;stroke-linejoin:round}
  /* --- hardware map --- */
  #hmap{width:100%;height:auto;background:#0a0e13;border:1px solid var(--edge);
        border-radius:9px;display:block}
  #hmap .blk rect{fill:#141a22;stroke:#2a323d;stroke-width:1.2;
                  transition:fill .16s,stroke .16s}
  #hmap .blk text{fill:#5d6a7a;font:600 12px ui-monospace,Menlo,monospace;
                  text-anchor:middle;pointer-events:none}
  #hmap .blk .sub{fill:#454f5c;font:9px ui-monospace,Menlo,monospace}
  #hmap .blk.on rect{fill:#14312a;stroke:#3fb950;stroke-width:2}
  #hmap .blk.on text{fill:#7ee787}
  #hmap .blk.on .sub{fill:#4e9a68}
  #hmap .blk.seen rect{fill:#2b2410;stroke:#d29922;stroke-width:1.6;
                       stroke-dasharray:4 2}
  #hmap .blk.seen text{fill:#e3b341}
  #hmap .blk.seen .sub{fill:#8a7638}
  #hmap .wires{stroke:#1e2530;stroke-width:1.4;fill:none}
  .maplegend{display:flex;gap:14px;flex-wrap:wrap;margin-top:9px;font-size:11px}
  .maplegend i{display:inline-block;width:11px;height:11px;border-radius:3px;
               margin-right:5px;vertical-align:-1px}
  .ulist{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px}
  .ubox{font-size:11px;padding:2px 8px;border-radius:5px;border:1px solid #2ea043;
        background:#0f2419;color:#7ee787}
  .ubox.seen{border-color:#d29922;background:#241d0e;color:#e3b341}
  .emo{font-size:13px;line-height:1;margin-left:5px;opacity:.95}
  .emo.big{font-size:30px;display:block;margin:6px auto 0;width:56px;text-align:center}

  /* --- per-instruction hardware table --- */
  table.hwt{width:100%;border-collapse:collapse;font-size:12.5px}
  table.hwt th{text-align:left;font:600 10.5px ui-monospace,Menlo,monospace;
    text-transform:uppercase;letter-spacing:.6px;color:#5d6a7a;
    padding:7px 9px;border-bottom:1px solid var(--edge)}
  table.hwt td{padding:7px 9px;border-bottom:1px solid #1b222c;vertical-align:top}
  table.hwt tr:last-child td{border-bottom:none}
  table.hwt td.part{color:#7d8b9c;font-weight:600;white-space:nowrap}
  table.hwt td.item{font:600 12.5px ui-monospace,Menlo,monospace;color:#c9d1d9;white-space:nowrap}
  table.hwt td.why{color:#8b98a8}
  table.hwt .acc{display:inline-block;min-width:19px;text-align:center;
    font:700 10.5px ui-monospace,Menlo,monospace;padding:2px 4px;border-radius:4px}
  .acc.R {background:#12283f;color:#79c0ff}
  .acc.W {background:#3a2410;color:#ffa657}
  .acc.RW{background:#3d1220;color:#ff7b72}
  .acc.- {background:#161b22;color:#484f58}
  .acc.None{background:#161b22;color:#8b949e;font-style:italic;font-weight:400}
  .obsbadge{display:inline-block;margin-left:6px;font:600 9.5px ui-monospace,monospace;
    padding:1px 5px;border-radius:3px;background:#12283f;color:#79c0ff}
  .confbadge{display:inline-block;margin-left:6px;font:600 9.5px ui-monospace,monospace;
    padding:1px 5px;border-radius:3px;background:#3d1220;color:#ff7b72}
  .hwtlegend{display:flex;flex-wrap:wrap;gap:12px;margin-top:10px;
    font-size:11px;color:#6e7b8a}

  /* --- 3D die panel (WebGL, no libraries) --- */
  #right{display:flex;flex-direction:column;min-height:0;overflow:hidden}
  #die3dhost{flex:0 0 auto;padding:0 18px 18px}
  #die3dhost:empty{display:none}
  #die3dhost h2{margin:14px 0 10px}
  /* clamp, not a fixed height: the die sits BELOW the scrolling detail pane in
     a flex column, so a fixed 340px starves the detail pane on a short window
     (measured: a 577px-tall viewport left only 99px for the text). */
  #die3dwrap{position:relative;border:1px solid var(--edge);border-radius:10px;
    overflow:hidden;background:#04060a;height:clamp(190px,32vh,340px)}
  #die3d{width:100%;height:100%;display:block;cursor:grab}
  #die3d:active{cursor:grabbing}
  #die3dfallback{position:absolute;inset:0;display:none;align-items:center;
    justify-content:center;text-align:center;color:#8b98a8;font-size:13px;padding:20px}
  .die3dlegend{position:absolute;left:10px;top:9px;font:11px ui-monospace,monospace;
    color:#8b98a8;background:rgba(4,6,10,.72);padding:4px 8px;border-radius:5px;
    pointer-events:none;line-height:1.7}
  .die3dlegend b{color:#7ee787}
  #die3dreset,#die3dcode{position:absolute;top:9px;font:11px ui-monospace,monospace;
    color:#8b98a8;background:rgba(4,6,10,.72);border:1px solid var(--edge);
    border-radius:5px;padding:4px 9px;cursor:pointer;z-index:3}
  #die3dreset{right:10px}
  #die3dcode{right:96px}
  #die3dreset:hover,#die3dcode:hover{color:#c9d1d9;border-color:#3d4753}
  #die3dpick{margin-top:9px;font:12px ui-monospace,monospace;color:#8b98a8;
    min-height:17px}
  #die3dpick b{color:#79c0ff}

  /* 3D projected labels: one <div> per register and per code byte, moved
     each frame by projecting the 3D point to screen space */
  .lbl3d{position:absolute;transform:translate(-50%,-50%);pointer-events:none;
    font:600 9.5px ui-monospace,Menlo,monospace;white-space:nowrap;
    text-shadow:0 0 4px #04060a,0 0 8px #04060a}
  .lbl3d.reg{color:#7b8a9c}
  .lbl3d.reg.q{opacity:.42;font-size:8.5px;background:none;border-color:transparent}
  .lbl3d.reg.f{font-size:10.5px;background:rgba(4,6,10,.8)}
  .lbl3d.reg.f.r{color:#79c0ff;border-color:#1d4a7a}
  .lbl3d.reg.w{color:#ffa657;font-size:10.5px}
  .lbl3d.byt{color:#6e7b8a;font-size:9px}
  .lbl3d.byt.pc{color:#7ee787}
  #die3dlab{position:absolute;inset:0;pointer-events:none;overflow:hidden}
</style>
</head>
<body>
<header>
  <h1>Linux kernel, one instruction at a time</h1>
  <span class="kv">start <b id="m-sym"></b></span>
  <span class="kv"><b id="m-steps"></b> instructions</span>
  <span class="kv"><b id="m-kernel"></b></span>
  <div class="bar">
    <button id="first">&#9198;</button>
    <button id="prev">&#9664; prev</button>
    <button id="next">next &#9654;</button>
    <button id="last">&#9197;</button>
  </div>
</header>
<main>
  <div id="left">
    <div id="tabs">
      <button id="tab-exec" class="on">execution order</button>
      <button id="tab-addr">by address in memory</button>
    </div>
    <div id="list"></div>
  </div>
  <div id="right">
    <div id="detail"></div>
    <div id="die3dhost"></div>
  </div>
</main>

<script id="trace-data" type="application/json">__TRACE__</script>
<script>
const T   = JSON.parse(document.getElementById('trace-data').textContent);
const GPRS = __GPRS__, FLAGS = __FLAGS__, SSEGS = __SEGS__;
const BLOCKS = __BLOCKS__, GLYPHS = __GLYPHS__;
const BLABEL = Object.fromEntries(BLOCKS.map(b=>[b[0], {label:b[1], sub:b[2]}]));
let cur = 0;
const svgOf = (g, cls) => '<svg viewBox="0 0 24 24" class="'+(cls||'')+'">'+(GLYPHS[g]||GLYPHS.decode)+'</svg>';

const esc = t => String(t).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const big = h => BigInt(h);                                   // hex string -> BigInt
function signed(h){ const v = BigInt.asIntN(64, big(h)); return v.toString(); }
function pad(h, n){ return h.replace('0x','0x').padStart(n, '0'); }

/* integer-ish values are all hex strings; show decimal too when interesting */
function val(h){
  const v = big(h);
  return (v >= 0x100000n || (v > 0xffn && v < 0x1000n)) ? signed(h)+' ('+h+')' : h;
}

/* ---------------- instruction list ---------------- */
/* Instructions sorted by ADDRESS, i.e. how the code lies in memory rather
   than how the CPU walked it. Gaps between runs are marked, because the jump
   from one function to the next is the thing this view exists to show. */
let MEMORDER = [];
function buildMemMap(){
  MEMORDER = T.steps.map((s,i)=>i)
    .sort((a,b)=> BigInt(T.steps[a].insn_parsed.addr) < BigInt(T.steps[b].insn_parsed.addr) ? -1
            : BigInt(T.steps[a].insn_parsed.addr) > BigInt(T.steps[b].insn_parsed.addr) ? 1
            : a-b);
  let html = '', lastAddr = null, lastFile = null;
  MEMORDER.forEach((i,k)=>{
    const s = T.steps[i], sem = s.sem || {}, a = s.insn_parsed.addr;
    if(lastAddr !== null){
      const prev = T.steps[MEMORDER[k-1]].insn_parsed.addr;
      const gap = BigInt(a) - BigInt(prev) - BigInt(s.insn_parsed.length);
      if(gap > 0n)
        html += `<div class="gap">&mdash; ${gap.toString()} bytes not in this trace &mdash;</div>`;
      else if(gap < 0n)
        html += `<div class="gap overlap">&#8617; back to an earlier address</div>`;
    }
    const key = s.file_short+':'+s.line;
    if(key !== lastFile && s.file_short !== lastFile){
      html += `<div class="srcgrp">${esc(s.file_short)}</div>`; lastFile = s.file_short;
    }
    const cat = [ sem.is_mem?'mem':'',
                  ['stack'].includes(sem.glyph)?'stackop':'',
                  ['jump','branch','call','ret'].includes(sem.glyph)?'branch':'' ]
                .filter(Boolean).join(' ');
    html += `<div class="row ${cat}" data-i="${i}" id="arow-${i}"
        title="${esc(sem.caption||key)}">
      <span class="a">${esc(a.replace('0x','').slice(-10))}</span>
      <span class="g">${svgOf(sem.glyph)}</span><span class="emo">${sem.emoji||''}</span>
      <span class="i">${esc(s.insn_parsed.text)}</span>
      <span class="n">${i}</span></div>`;
    lastAddr = a;
  });
  return html;
}

function showList(){
  const addrMode = document.getElementById('tab-addr').classList.contains('on');
  const L = document.getElementById('list');
  L.innerHTML = addrMode ? buildMemMap() : execListHTML();
  L.querySelectorAll('.row').forEach(r => r.onclick = () => select(+r.dataset.i));
}

function buildList(){ showList(); }

function execListHTML(){
  let html = '', last = null;
  T.steps.forEach((s,i)=>{
    const key = s.file_short+':'+s.line;
    if(key !== last){ html += `<div class="srcgrp">${esc(key)}</div>`; last = key; }
    /* the trace samples state BEFORE each instruction, so the effect of
       instruction i is the step from i to i+1 */
    const next = T.steps[i+1];
    const jumped = next && next.insn_parsed.addr !== s.regs_h.rip;
    const wrote   = next && next.mem_delta_h.length > 0;
    const sem     = s.sem || {};
    const cat = [ jumped ? 'jumped' : '',
                  wrote   ? 'wrote'  : '',
                  sem.is_mem ? 'mem'  : '',
                  ['stack'].includes(sem.glyph) ? 'stackop' : '',
                  ['sysc','swap','shield','zap'].includes(sem.glyph) ? 'sysc' : '',
                  ['jump','branch','call','ret'].includes(sem.glyph) ? 'branch' : '' ]
                .filter(Boolean).join(' ');
    html += `<div class="row ${cat}"
        data-i="${i}" id="row-${i}" title="${esc(sem.caption || key)}">
      <span class="n">${i}</span>
      <span class="ring ${s.cpl===0?'ring0':'ring3'}">r${s.cpl}</span>
      <span class="g">${svgOf(sem.glyph)}</span><span class="emo">${sem.emoji||''}</span>
      <span class="a">${esc(s.insn_parsed.addr.replace('0x','').slice(-10))}</span>
      <span class="i">${esc(s.insn_parsed.text)}</span></div>`;
  });
  return html;
}

/* ---------------- per-instruction effect ---------------- */
function diffs(i){
  const before = T.steps[i], after = T.steps[i+1];
  if(!after) return {regs:[],flags:[],segs:[],mem:[],before,after:null};
  const regs = GPRS.filter(r => before.regs_h[r] !== after.regs_h[r])
                   .map(r => ({name:r, from:before.regs_h[r], to:after.regs_h[r]}));
  const flags = FLAGS.filter(f => !!before.flags[f] !== !!after.flags[f])
                   .map(f => ({name:f, from:before.flags[f]?1:0, to:after.flags[f]?1:0}));
  const segs = SSEGS.filter(s => before.regs_h[s] !== after.regs_h[s])
                   .map(s => ({name:s.toUpperCase(), from:before.regs_h[s], to:after.regs_h[s]}));
  /* hardware blocks whose state ACTUALLY moved - computed here from the raw
     diff, never from sem.units, so the two layers stay independent */
  const REG2UNIT = {};
  ['rax','rcx','rdx','rbx','rsi','rdi','rbp','r8','r9','r10','r11','r12','r13','r14','r15']
    .forEach(r => REG2UNIT[r] = 'gpr');
  REG2UNIT.rsp = 'rsp'; REG2UNIT.rip = 'rip';
  SSEGS.forEach(s => REG2UNIT[s] = 'seg');
  const observed = new Set();
  regs.forEach(r => { if(REG2UNIT[r.name]) observed.add(REG2UNIT[r.name]); });
  if(flags.length) observed.add('flags');
  if(segs.length)  observed.add('seg');
  if(after.mem_delta_h.length){ observed.add('bus'); observed.add('mem'); }
  const straight = '0x' + (big(before.insn_parsed.addr)
                  + BigInt(before.insn_parsed.length)).toString(16);
  const ripChanged = after.regs_h.rip !== straight;
  if(ripChanged) observed.add('ctrl');
  const ringChanged = (big(before.regs_h.cs) & 3n) !== (big(after.regs_h.cs) & 3n);
  if(ringChanged){ observed.add('cpl'); observed.add('seg'); }
  return {regs, flags, segs, mem: after.mem_delta_h, before, after,
          observed:[...observed], rip_changed:ripChanged, ring_changed:ringChanged};
}

/* ---------------- hardware map ----------------
   Two independent layers, deliberately not merged:
     on   = what the ISA says this instruction must drive (sem.units)
     seen = what the trace actually shows changing (diffs -> observed units)
   When they disagree, the block turns amber. That gap is the interesting
   part, so it is shown rather than smoothed over.                        */
const WIRES = [
  ['fetch','decode'], ['rip','fetch'], ['decode','ctrl'], ['retire','ctrl'],
  ['gpr','alu'], ['gpr','rsp'], ['alu','flags'], ['ctrl','alu'],
  ['alu','agutlb'], ['cache','bus'], ['agutlb','bus'], ['seg','ctrl'],
  ['cpl','seg'], ['msr','seg'], ['cr','ctrl'], ['bus','mem'], ['intc','ctrl'],
  ['xmm','alu'], ['retire','alu'],
];
const GEO = Object.fromEntries(BLOCKS.map(b=>[b[0], {x:b[3], y:b[4], w:b[5], h:b[6]}]));
const mid = (a,b) => [ (a.x+a.w/2 + b.x+b.w/2)/2, (a.y+a.h/2 + b.y+b.h/2)/2 ];

function hardwareMap(on, seen){
  const seenSet = new Set(seen||[]);
  let wires = WIRES.filter(([a,b]) => GEO[a] && GEO[b] &&
      (on.includes(a)||on.includes(b)) && (on.includes(b)||on.includes(a)))
    .map(([a,b]) => { const p = mid(GEO[a], GEO[b]);
      return `<path class="wires" d="M${GEO[a].x+GEO[a].w/2},${GEO[a].y+GEO[a].h/2}
                                L${p[0]},${p[1]}
                                L${GEO[b].x+GEO[b].w/2},${GEO[b].y+GEO[b].h/2}"/>`; }).join('');
  let boxes = BLOCKS.map(([id,label,sub,x,y,w,h]) => {
    const onIt   = on.includes(id);
    const seenIt = onIt && seenSet.has(id);
    return `<g class="blk ${onIt?'on':''} ${seenIt?'seen':''}" id="hb-${id}"
              data-unit="${id}">
      <rect x="${x}" y="${y}" width="${w}" height="${h}" rx="7"/>
      <text x="${x+w/2}" y="${y+h/2-1}">${esc(label)}</text>
      <text class="sub" x="${x+w/2}" y="${y+h/2+11}">${esc(sub)}</text></g>`;
  }).join('');
  return `<svg id="hmap" viewBox="0 0 1000 500" preserveAspectRatio="xMidYMid meet">
    ${wires}${boxes}</svg>`;
}


/* ---------------- per-instruction hardware table ----------------
   One row per physical thing the instruction touches, with a direction:
   R read, W write, RW read-modify-write, "-" explicitly preserved.
   The ISA claim and the observed trace state are shown side by side, so a
   wrong mental model shows up as a red conflict instead of staying hidden. */
function hwtTable(rows, d){
  if(!rows || !rows.length) return '';
  const changedRegs = new Set((d.regs||[]).map(r=>r.name.toLowerCase()));
  const changedFlags = new Set((d.flags||[]).map(f=>f.name));
  const hasNext = !!d.after;

  const acc = a => {
    const k = (a===null||a===undefined) ? 'None' : String(a);
    const lbl = (a===null||a===undefined) ? '?' : a;
    return `<span class="acc ${k}">${esc(lbl)}</span>`;
  };

  /* A conflict is a FALSIFIED claim, and only one kind really counts: the ISA
     says "preserved" (or "no register is written") and the trace shows the
     thing changing anyway. The reverse - ISA says "writes CF", trace shows CF
     unchanged - is NOT a conflict: writing a flag the value it already held is
     invisible in a diff. Flagging that would teach a lie. */
  let conflicts = 0;
  const body = rows.map(r => {
    let badge = '';
    if(hasNext){
      const it = (r.item||'').toLowerCase();
      const isFlag = r.part === 'EFLAGS';
      const isReg  = r.part === 'Register file' || r.part === 'Stack engine';
      const moved  = isFlag ? changedFlags.has(r.item)
                  : isReg  ? changedRegs.has(it)
                  : false;
      const claimedUntouched = (r.access === '-')
                            || (isReg && r.access === 'R' && /preserv|never writ|no register|never modified/i.test(r.why||''));
      if(moved && claimedUntouched){
        conflicts++;
        badge = '<span class="confbadge">conflict</span>';
      } else if(moved){
        badge = '<span class="obsbadge">changed</span>';
      }
    }
    return `<tr>
      <td class="part">${esc(r.part)}</td>
      <td class="item">${esc(r.item)}</td>
      <td>${acc(r.access)}</td>
      <td class="why">${esc(r.why)}${badge}</td>
    </tr>`;
  }).join('');

  const confirmed = document.querySelectorAll('#detail table.hwt .obsbadge').length;
  const parts = new Set(rows.map(r=>r.part)).size;
  const writes = rows.filter(r=>r.access==='W'||r.access==='RW').length;
  const reads  = rows.filter(r=>r.access==='R'||r.access==='RW').length;
  const kept   = rows.filter(r=>r.access==='-').length;

  return `<h2>Hardware table &mdash; exactly what this touches</h2><div class="card">
    <table class="hwt">
      <tr><th>part of the CPU</th><th>item</th><th>R/W</th><th>why</th></tr>
      ${body}
    </table>
    <div class="hwtlegend">
      <span><b style="color:#7ee787">${parts}</b> parts &middot;
        <b style="color:#ffa657">${writes}</b> written &middot;
        <b style="color:#79c0ff">${reads}</b> read &middot;
        <b style="color:#484f58">${kept}</b> explicitly preserved</span>
      <span><span class="obsbadge">changed</span> the trace confirms this piece moved &middot;
        ${conflicts ? `<span class="confbadge">${conflicts} conflict${conflicts>1?'s':''}</span> the ISA said "preserved" but it changed` : 'no conflicts: every claim matched the real hardware'}</span>
    </div>
  </div>`;
}


/* ---------------- 3D CPU die (WebGL) ----------------
   The die shares GEO/BLOCKS with the 2D map above, and is lit from the same
   sem.units, so stepping an instruction updates both views together. */
__DIE3D_JS__


/* ---------------- detail pane ---------------- */
let DIE = null;
function dieMount(sem){
  const host = document.getElementById('die3dhost');
  if (!host) return;
  if (!DIE) {
    host.innerHTML = `<h2>The die, in 3D</h2>
      <div id="die3dwrap">
        <canvas id="die3d"></canvas>
        <div id="die3dlab"></div>
        <div id="die3dfallback">WebGL is unavailable in this browser, so the 3D
          die cannot be drawn. The 2D hardware map above shows the same
          information.</div>
        <div class="die3dlegend"></div>
        <button id="die3dreset">reset view</button>
        <button id="die3dcode">zoom to memory</button>
      </div>
      <div id="die3dpick"></div>`;
  }
  // the legend is cheap text, so it can change every step; the CANVAS cannot
  // be rewritten, so it lives in this host and is created exactly once.
  const lg = host.querySelector('.die3dlegend');
  if (lg) lg.innerHTML = `<b>${(sem.units||[]).length}</b> of ${BLOCKS.length} blocks driven`
    + ' &middot; drag to orbit, wheel to zoom, click a block';
  if (DIE) return;
  const cv = document.getElementById('die3d');
  if (!cv) return;
  try {
    DIE = new Die3D(cv, GEO, BLABEL);
    if (!DIE.gl) {
      document.getElementById('die3dfallback').style.display = 'flex';
      return;
    }
    DIE.ids = BLOCKS.map(b => b[0]);
    // label elements live in the persistent host, created exactly once
    const lab = document.getElementById('die3dlab');
    if (lab) {
      lab.innerHTML = DIE.REGS.map(r => `<div class="lbl3d reg" data-reg="${r}"></div>`).join('')
        + Array.from({length: 24}, (_, i) => `<div class="lbl3d byt" data-byte="${i}"></div>`).join('');
      DIE.labelHost = lab;
    }
    DIE.onPick = id => {
      const box = document.getElementById('die3dpick');
      if (!box) return;
      box.innerHTML = id
        ? `block <b>${esc(id)}</b> &mdash; ${esc(BLABEL[id].label)}: ${esc(BLABEL[id].sub)}`
          + (DIE.hot.has(id) ? ' &nbsp;<b>driven by this instruction</b>' : '')
        : '';
    };
    document.getElementById('die3dreset').addEventListener('click', () => DIE.reset());
    document.getElementById('die3dcode').addEventListener('click', () => DIE.focusCode());
    /* Clicking a memory cell selects the instruction that owns that byte, so
       you can navigate by pointing at code in memory rather than reading a
       list. code_map is built from the trace, so it is a real ownership
       relation, not a guess from the length of the instruction at PC. */
    DIE.onCell = k => {
      const box = document.getElementById('die3dpick');
      const st = T.steps[cur];
      const owner = st && st.code_map ? st.code_map[k] : -1;
      if (box) {
        box.innerHTML = k < 0 ? ''
          : `byte <b>+${k}</b> of the window at <b>${esc(st.code.base)}</b>`
            + (owner >= 0
                ? ` &mdash; belongs to step <b>${owner}</b>: ${esc(T.steps[owner].insn_parsed.text)}`
                : ' &mdash; no instruction in this trace starts here');
      }
      if (owner >= 0 && owner !== cur) select(owner);
    };
    window.addEventListener('resize', () => DIE.render());
    DIE.render();
  } catch (e) {
    document.getElementById('die3dfallback').style.display = 'flex';
    document.getElementById('die3dfallback').textContent = '3D die failed: ' + e.message;
  }
}

function render(){
  const s = T.steps[cur], d = diffs(cur), p = s.insn_parsed, sem = s.sem || {};
  const a = d.after || s;                 /* state once the instruction ran */
  let h = '';

  h += `<div class="sticky"><div class="card">
    <div class="path"><b>${esc(s.symbol)}</b> &nbsp;&middot;&nbsp; ${esc(s.file_short)}:${s.line}</div>
    <div class="heroband">
      <div class="heroglyph" title="${esc(sem.mnemonic||'')}">${svgOf(sem.glyph)}<span class="emo big">${sem.emoji||''}</span></div>
      <div style="flex:1;min-width:0">
        <div class="srcline"><span class="ln">${s.line}</span>${esc(s.source || '(no source text)')}</div>
        <div style="margin-top:9px" class="big">
          <span class="bytes">${p.bytes.map(b=>b.toString(16).padStart(2,'0')).join(' ')}</span>
          &nbsp;<span style="color:var(--code)">${esc(p.text)}</span></div>
        <div class="legend">${p.length} bytes at ${esc(p.addr)} &nbsp;&middot;&nbsp;
          executes at CPL ${s.cpl} (${s.cpl===0?'kernel / ring 0':'user / ring 3'})${
          d.after ? '' : ' &nbsp;&middot;&nbsp; <b style="color:var(--warn)">last traced instruction</b>'}</div>
      </div>
    </div>
  </div></div>`;

  /* --- the picture, in words --- */
  h += `<h2>What this instruction does</h2><div class="card">
    <div class="why" style="font-size:13.5px">${esc(sem.caption||'unclassified')}</div>`;
  if(sem.access) h += `<div class="legend" style="margin-top:7px">${esc(sem.access)}</div>`;
  if(!sem.matched) h += `<div class="legend" style="margin-top:7px;color:var(--warn)">
      no classifier rule matched &mdash; treat the hardware map below as front-end only</div>`;
  h += `</div>`;

  /* --- the picture, as a table: one row per hardware item --- */
  h += hwtTable(s.hwt, d);

  /* --- the picture, as a chip --- */
  const on = sem.units || [], seen = d.observed || [];
  h += `<h2>Hardware it drives</h2><div class="card">
    ${hardwareMap(on, seen)}
    <div class="maplegend">
      <span><i style="background:#14312a;border:1px solid #3fb950"></i>
        <b style="color:#7ee787">driven</b> &mdash; the ISA requires this unit</span>
      <span><i style="background:#2b2410;border:1px solid #d29922"></i>
        <b style="color:#e3b341">also observed changing</b> &mdash; confirmed by the trace</span>
      <span><i style="background:#141a22;border:1px solid #2a323d"></i>idle</span>
    </div>
    <div class="ulist">${on.map(u=>{
      const m = BLABEL[u]||{label:u,sub:''};
      return `<span class="ubox${seen.includes(u)?' seen':''}"
        title="${esc(m.sub)}">${esc(m.label)}</span>`;}).join('')}</div>
    <div class="legend" style="margin-top:10px">
      ${on.length} of ${BLOCKS.length} blocks involved &nbsp;&middot;&nbsp;
      ${seen.length} independently confirmed by observed state change
    </div></div>`;

  h += `<h2>What changed, in hardware terms</h2><div class="card"><div class="why">${why(d, sem)}</div></div>`;

  h += `<h2>Registers</h2><div class="card"><table>
    <tr><th>register</th><th>before</th><th>after</th></tr>`;
  if(d.regs.length){
    h += d.regs.map(r=>`<tr><td class="reg">${r.name}</td>
      <td class="old">${esc(val(r.from))}</td><td class="new">${esc(val(r.to))}</td></tr>`).join('');
  } else {
    h += GPRS.map(r=>`<tr><td class="reg">${r}</td>
      <td class="unch">${esc(val(s.regs_h[r]))}</td>
      <td class="unch">unchanged</td></tr>`).join('');
  }
  h += `</table></div>`;

  h += `<h2>EFLAGS</h2><div class="card">
    <div style="margin-bottom:9px;color:var(--dim);font-size:11px">full word
      <b style="color:var(--fg)">${esc(a.eflags_h)}</b>${
      d.after && d.after.eflags_h !== s.eflags_h ? ` &nbsp;&larr; was ${esc(s.eflags_h)}`:''}</div>` + FLAGS.map(f=>{
    const on = !!a.flags[f], ch = d.flags.some(x=>x.name===f);
    return `<span class="chip ${on?'f-on':'f-off'}"${
      ch?' style="outline:2px solid var(--warn)"':''}>${f}=${on?1:0}</span>`;
  }).join('') + `</div>`;

  h += `<h2>Segments &amp; privilege level</h2><div class="card"><table>
    <tr><th>segment</th><th>before</th><th>after</th><th>meaning</th></tr>` +
    SSEGS.map(g=>{
      const ch = d.segs.some(x=>x.name===g.toUpperCase());
      const mean = g==='cs' ? (big(a.regs_h[g]) & 3n) === 0n ? 'ring 0 - kernel' : 'ring 3 - user' : '';
      return `<tr><td class="reg">${g.toUpperCase()}</td>
        <td class="${ch?'old':'unch'}">${esc(s.regs_h[g])}</td>
        <td class="${ch?'new':'unch'}">${esc(a.regs_h[g])}</td>
        <td class="${ch?'':'unch'}">${mean||'&mdash;'}</td></tr>`;
    }).join('') + `</table></div>`;

  h += `<h2>Memory writes</h2><div class="card">`;
  if(d.mem.length){
    const groups = [];
    d.mem.forEach(m => {
      const lastg = groups[groups.length-1];
      if(lastg && big(m.off) === big(lastg.off) + BigInt(lastg.after.length))
        lastg.after.push(m.to);
      else groups.push({off:m.off, before:[m.from], after:[m.to]});
    });
    h += `<table><tr><th>address</th><th>was</th><th>became</th></tr>` +
      groups.map(g=>`<tr><td class="reg">${esc(g.off)}</td>
        <td class="old">${g.before.map(b=>b.toString(16).padStart(2,'0')).join(' ')}</td>
        <td class="new">${g.after.map(b=>b.toString(16).padStart(2,'0')).join(' ')}</td></tr>`).join('') +
      `</table><div class="legend" style="margin-top:10px">watched window
        ${esc(a.mem_base_h)} &ndash; ${esc('0x'+(big(a.mem_base_h)+BigInt(a.mem.length)).toString(16))}
        (the kernel stack)</div>`;
  } else {
    h += `<span class="none">nothing in the watched window changed on this instruction</span>`;
  }
  h += `</div>`;

  h += `<h2>Every general register after this instruction</h2><div class="card">
    <table><tr>` + GPRS.map(r=>{
      const ch = d.regs.some(x=>x.name===r);
      return `<td style="border:none"><div class="unch" style="font-size:10px">${r}</div>
        <div class="${ch?'new':'reg'}">${esc(a.regs_h[r])}</div></td>`;
    }).join('') + `</tr></table></div>`;

  h += `<h2>Keyboard</h2><div class="card why">
    <kbd>&darr;</kbd>/<kbd>J</kbd> next &nbsp; <kbd>&uarr;</kbd>/<kbd>K</kbd> previous &nbsp;
    <kbd>Home</kbd>/<kbd>End</kbd> jump &nbsp;&middot;&nbsp; click any instruction on the left.</div>`;

  document.getElementById('detail').innerHTML = h;
  dieMount(sem);
  if (DIE && DIE.gl) {
    DIE.setHot(sem.units || []);
    // real kernel bytes at this PC, plus how many of them this instruction owns
    DIE.setCode(s.code || null, (s.insn_parsed || {}).length || 0);
    // register VALUES and which ones actually moved - the 3D twin of the
    // hardware table's R/W column, driven by the same observed diff
    const vals = {};
    GPRS.forEach(r => { vals[r] = (s.regs_h || {})[r]; });
    vals.rip = (s.regs_h || {}).rip;
    // focus = registers the hardware table says this instruction touches
    const focus = (s.hwt || [])
      .filter(r => r.part === 'Register file' || r.part === 'Stack engine')
      .map(r => (r.item || '').toLowerCase())
      .filter(n => /^(r[a-d]x|[re]sp|r(8|9|1[0-5])|[re]ip)$/.test(n));
    DIE.setRegs(vals, (d.regs || []).map(r => r.name.toLowerCase()), focus);
  }
}

function why(d, sem){
  const s = d.before, p = s.insn_parsed, a = d.after, b = [];
  b.push(`Executes <b>${esc(p.text)}</b> (${p.length} bytes) at ${esc(p.addr)}.`);
  if(!a) return b.join(' ') + ' This is the last instruction in the trace.';
  if(d.observed && d.observed.length)
    b.push('Hardware that visibly moved: <b>' +
      d.observed.map(u => esc((BLABEL[u]||{label:u}).label)).join('</b>, <b>') + '</b>.');
  if(d.ring_changed) b.push('<b style="color:var(--bad)">Privilege level changed: ring ' +
    (s.cpl) + ' to ring ' + (a.cpl) + '.</b>');
  if(d.regs.length)
    b.push('Writes ' + d.regs.map(r=>`<b>${r.name}</b> ${esc(r.from)} &rarr; ${esc(r.to)}`).join(', ') + '.');
  else b.push('No general-purpose register changed.');
  if(d.flags.length)
    b.push('Flags: ' + d.flags.map(f=>`<b>${f.name}</b> ${f.from}&rarr;${f.to}`).join(', ') + '.');
  if(d.segs.length)
    b.push('<b>Segment changed:</b> ' + d.segs.map(x=>`${x.name} ${esc(x.from)} &rarr; ${esc(x.to)}`).join(', ') + '.');
  if(d.mem.length) b.push(`Wrote <b>${d.mem.length}</b> byte${d.mem.length>1?'s':''} to memory.`);
  const straight = '0x' + (big(p.addr) + BigInt(p.length)).toString(16);
  b.push(a.regs_h.rip !== straight
    ? `PC jumps ${esc(s.regs_h.rip)} &rarr; ${esc(a.regs_h.rip)}.`
    : `PC advances ${esc(s.regs_h.rip)} &rarr; ${esc(a.regs_h.rip)}.`);
  return b.join(' ');
}

function select(i){
  cur = Math.max(0, Math.min(T.steps.length-1, i));
  document.querySelectorAll('.row').forEach(r=>r.classList.remove('sel'));
  // two row id schemes: execution mode uses row-N, address mode arow-N
  const el = document.getElementById('row-'+cur) || document.getElementById('arow-'+cur);
  if(el){ el.classList.add('sel'); el.scrollIntoView({block:'nearest'}); }
  render();
}

document.getElementById('m-sym').textContent   = T.meta.symbol;
document.getElementById('m-steps').textContent  = T.meta.steps;
document.getElementById('m-kernel').textContent = T.meta.kernel;
document.getElementById('prev').onclick  = ()=>select(cur-1);
document.getElementById('next').onclick  = ()=>select(cur+1);
document.getElementById('first').onclick = ()=>select(0);
document.getElementById('last').onclick  = ()=>select(T.steps.length-1);
document.getElementById('tab-exec').onclick = () => {
  document.getElementById('tab-exec').classList.add('on');
  document.getElementById('tab-addr').classList.remove('on');
  showList(); select(cur);
};
document.getElementById('tab-addr').onclick = () => {
  document.getElementById('tab-addr').classList.add('on');
  document.getElementById('tab-exec').classList.remove('on');
  showList(); select(cur);
};
document.addEventListener('keydown', e=>{
  if(e.key==='ArrowDown'||e.key==='j'){select(cur+1);e.preventDefault();}
  if(e.key==='ArrowUp'  ||e.key==='k'){select(cur-1);e.preventDefault();}
  if(e.key==='Home'){select(0);e.preventDefault();}
  if(e.key==='End') {select(T.steps.length-1);e.preventDefault();}
});
buildList();
select(0);
</script>
</body>
</html>
"""


def _die3d_js():
    """Inline die3d.js into the page.

    The escape is applied to THIS string only. Doing `html.replace("</", "<\\/")`
    on the whole template would corrupt every real closing tag (</script>,
    </div>, </html>), and `</` inside a <script> block would end the tag early.
    """
    src = open(os.path.join(LAB, "die3d.js")).read()
    return src.replace("</", "<\\/")


def _verify_js(outp):
    """Fail the build if the generated page has a JS syntax error.

    A stray semicolon inside a ternary shipped as a page that rendered NOTHING,
    with the error only visible in the browser console as an empty message.
    Catching it here turns a silent white page into a build failure.
    """
    import re as _re
    html = open(outp).read()
    m = _re.search(r'<script>\n(const T.*?)</script>', html, _re.S)
    if not m:
        sys.exit("[verify] could not locate the page script to verify")
    tmp = os.path.join(LAB, ".verify.js")
    open(tmp, "w").write(m.group(1))
    r = subprocess.run(["node", "--check", tmp], capture_output=True, text=True)
    os.unlink(tmp)
    if r.returncode != 0:
        sys.exit("[verify] generated page has a JS syntax error:\n" + r.stderr[:1200])

    # node --check cannot see a ReferenceError. Renaming buildList() while
    # leaving its call behind shipped a page whose instruction list was simply
    # EMPTY, with the browser reporting only empty-message exceptions. So
    # assert the entry points are actually defined, not merely parseable.
    src = m.group(1)
    required = ["buildList", "showList", "execListHTML", "buildMemMap",
                "select", "render", "diffs", "hwtTable", "dieMount", "svgOf", "esc"]
    # a binding counts as defined whether it is a declaration or a const arrow
    defs = {f: (re.search(r'function\s+%s\s*\(' % re.escape(f), src)
                or re.search(r'\b(?:const|let|var)\s+%s\s*=' % re.escape(f), src))
            for f in required}
    missing = [f for f, d in defs.items() if not d]
    if missing:
        sys.exit("[verify] page script calls but never defines: %s\n"
                 "         (a missing definition is a runtime ReferenceError, which "
                 "node --check cannot detect)" % ", ".join(missing))
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace", nargs="?", default="trace.json")
    ap.add_argument("-o", "--out", default="linux-step-viewer.html")
    ap.add_argument("--vmlinux", default="vmlinux")
    args = ap.parse_args()

    trace = build(json.load(open(os.path.join(LAB, args.trace))),
                  os.path.join(LAB, args.vmlinux))

    html = (HTML
            .replace("__TRACE__", json.dumps(trace, separators=(",", ":")).replace("</", "<\\/"))
            .replace("__BLOCKS__", json.dumps(x86sem.BLOCKS))
            .replace("__GLYPHS__", json.dumps(x86sem.G))
            .replace("__GPRS__", json.dumps(GPRS))
            .replace("__FLAGS__", json.dumps(FLAG_ORDER))
            .replace("__SEGS__", json.dumps(SSEGS))
            .replace("__DIE3D_JS__", _die3d_js()))

    outp = os.path.join(LAB, args.out)
    open(outp, "w").write(html)
    _verify_js(outp)
    nb = sum(len(s["insn_parsed"]["bytes"]) for s in trace["steps"])
    print(f"wrote {outp} ({os.path.getsize(outp)/1024:.0f} KB, "
          f"{len(trace['steps'])} instructions, {nb} instruction bytes decoded)")


if __name__ == "__main__":
    main()
