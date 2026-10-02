#!/usr/bin/env python3
"""
gen-scene-preview.py - full-window 3D preview of the WHOLE study scene:
CPU die + real code bytes in memory cells + the register bank with live values.

This is also the visual smoke test for the viewer. Screenshot tooling captures
from scroll 0, so a canvas sitting at the bottom of a scroll pane can never be
inspected; this page puts the canvas at the top of the window.

It reuses `build-viewer.build()` so the preview is driven by exactly the same
enriched steps the real viewer uses (same `code` windows, same `sem`, same
register diff) rather than a parallel implementation that could drift.

    python3 gen-scene-preview.py --trace trace.json --step 4 -o /root/scene.html
"""
import argparse
import importlib.util
import json
import os
import sys

LAB = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, LAB)
import x86sem


def load_builder():
    """Import build-viewer.py as a module so build() is shared, not copied."""
    spec = importlib.util.spec_from_file_location(
        "buildviewer", os.path.join(LAB, "build-viewer.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace", default="trace.json")
    ap.add_argument("--vmlinux", default="vmlinux")
    ap.add_argument("--step", type=int, default=0)
    ap.add_argument("-o", "--out", default="scene-preview.html")
    args = ap.parse_args()

    bv = load_builder()
    trace = bv.build(json.load(open(os.path.join(LAB, args.trace))),
                     os.path.join(LAB, args.vmlinux))
    steps = trace["steps"]
    step = max(0, min(args.step, len(steps) - 1))
    st = steps[step]
    sem = st["sem"]

    # register values, and which ones actually move on THIS instruction --
    # the same next-step diff the viewer uses
    vals = {r: st["regs_h"][r] for r in bv.GPRS if r in st["regs_h"]}
    vals["rip"] = st["regs_h"]["rip"]
    changed = []
    if step + 1 < len(steps):
        a, b = st["regs_h"], steps[step + 1]["regs_h"]
        changed = [r for r in bv.GPRS if a.get(r) != b.get(r)]

    focus = [r["item"].lower() for r in st.get("hwt", [])
             if r["part"] in ("Register file", "Stack engine")]
    code = st.get("code", {"base": "", "bytes": []})
    pc_len = (st.get("insn_parsed") or {}).get("length", 0)
    js = open(os.path.join(LAB, "die3d.js")).read().replace("</", "<\\/")

    boot = """const cv = document.getElementById('die3d');
const die = new Die3D(cv, GEO, BLABEL);
if (!die.gl) { document.getElementById('fb').style.display = 'flex'; }
else {
  die.ids = BLOCKS.map(b => b[0]);
  const lab = document.getElementById('lab');
  lab.innerHTML = die.REGS.map(r => `<div class="lbl3d reg" data-reg="${r}"></div>`).join('')
    + Array.from({length: 24}, (_, i) => `<div class="lbl3d byt" data-byte="${i}"></div>`).join('');
  die.labelHost = lab;
  die.setHot(UNITS);
  die.setCode(CODE, PCLEN);
  die.setRegs(VALS, CHANGED, FOCUS);
  window.addEventListener('resize', () => die.render());
}
"""
    boot = (boot.replace("UNITS", json.dumps(sem["units"]))
                .replace("CODE", json.dumps(code))
                .replace("PCLEN", str(pc_len))
                .replace("VALS", json.dumps(vals))
                .replace("CHANGED", json.dumps(changed)))

    html = """<!doctype html>
<html><head><meta charset="utf-8"><title>CPU scene</title>
<style>
 html,body{{margin:0;height:100%;background:#04060a;color:#c9d1d9;overflow:hidden;
   font:12px ui-monospace,Menlo,monospace}}
 #die3d{{width:100vw;height:100vh;display:block;cursor:grab}}
 #lab{{position:fixed;inset:0;pointer-events:none;overflow:hidden}}
 .lbl3d{{position:absolute;transform:translate(-50%,-50%);pointer-events:none;
   font:600 10px ui-monospace,Menlo,monospace;white-space:nowrap;
   background:rgba(4,6,10,.72);padding:1px 4px;border-radius:3px;
   border:1px solid rgba(33,38,45,.9)}}
 .lbl3d.reg{{color:#8b98a8}} .lbl3d.reg.w{{color:#ffa657;font-size:11px;
   background:rgba(58,36,16,.9);border-color:#7a4a12}}
 .lbl3d.byt{{color:#7b8a9c;font-size:9.5px;padding:0 2px;border-color:transparent}}
 .lbl3d.byt.pc{{color:#7ee787;border-color:#1d5c36}}
 #hud{{position:fixed;left:12px;top:10px;line-height:1.75;max-width:640px;
   background:rgba(4,6,10,.84);padding:9px 12px;border:1px solid #21262d;border-radius:7px}}
 #hud b{{color:#7ee787}} #hud .w{{color:#ffa657}} #hud .dim{{color:#7b8a9c}}
 #fb{{position:fixed;inset:0;display:none;align-items:center;justify-content:center}}
</style></head>
<body>
<canvas id="die3d"></canvas>
<div id="lab"></div>
<div id="hud">
  <div><b>{emoji}  {mn}</b> &nbsp; <span class="w">{text}</span></div>
  <div class="dim">{file}:{line} &middot; PC {addr} &middot; {nbytes} bytes &middot; step {step}/{total}</div>
  <div class="dim">code at PC: <span class="w">{hexbytes}</span></div>
  <div class="w">registers changed: {changed}</div>
  <div class="dim">blocks driven: {units}</div>
</div>
<div id="fb">WebGL unavailable</div>
<script>
const BLOCKS = {blocks};
const BLABEL = Object.fromEntries(BLOCKS.map(b=>[b[0],{{label:b[1],sub:b[2]}}]));
const GEO = Object.fromEntries(BLOCKS.map(b=>[b[0],{{x:b[3],y:b[4],w:b[5],h:b[6]}}]));
{js}
{boot}</script>
</body></html>""".format(
        emoji=sem["emoji"], mn=sem["mnemonic"].upper(),
        text=(st.get("insn_parsed") or {}).get("text", "").strip(),
        file=st.get("file_short", "?"), line=st.get("line", "?"),
        addr=(st.get("insn_parsed") or {}).get("addr", "?"),
        nbytes=(st.get("insn_parsed") or {}).get("length", 0),
        step=step, total=len(steps),
        hexbytes=" ".join(f"{b:02x}" for b in code.get("bytes", [])[:pc_len]) or "-",
        changed=", ".join(changed) or "none",
        units=", ".join(sem["units"]),
        blocks=json.dumps(x86sem.BLOCKS), js=js, boot=boot)

    out = os.path.join(LAB, args.out)
    open(out, "w").write(html)
    print(f"[scene] step {step}/{len(steps)}  {sem['emoji']} {sem['mnemonic']} "
          f"-> {len(sem['units'])} blocks, {len(changed)} regs changed")
    print(f"[scene] wrote {out} ({os.path.getsize(out)/1024:.0f} KiB)")


if __name__ == "__main__":
    main()
