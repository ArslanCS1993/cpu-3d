#!/usr/bin/env python3
"""
cpu-die-3d.py - a 3D CPU die whose blocks light up per instruction.

The floorplan is NOT hand-drawn. It is read straight out of the same
`BLOCKS` table the HTML step-viewer lights up, so the 3D model and the 2D
viewer can never drift apart: both answer "which units does this instruction
drive" from one source of truth.

Emits:
  cpu-die.glb            mesh with per-block colours (open in any 3D viewer)
  die.pov                POV-Ray scene; per-instruction highlighting is a
                         #declare you can rewrite, so one scene file covers
                         every instruction in the trace.

Usage:
  gen-die.py                 # write cpu-die.glb + die.pov
  povray die.pov +Oout.png +W1280 +H800 +FC
"""
import re
import sys
import os

LAB = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, LAB)

# ---------------------------------------------------------------- floorplan
def load_blocks():
    src = open(os.path.join(LAB, "x86sem.py")).read()
    i = src.index("BLOCKS = [")
    raw = re.findall(
        r'\("(\w+)",\s+"([^"]+)",\s+"([^"]+)",\s*(\d+),\s*(\d+),\s*(\d+),\s*(\d+)\)',
        src[i:i + 4000])
    out = []
    for bid, label, sub, x, y, w, h in raw:
        out.append(dict(id=bid, label=label, sub=sub,
                        x=int(x), y=int(y), w=int(w), h=int(h)))
    if len(out) != 19:
        die(f"expected 19 blocks, parsed {len(out)} - x86sem.py BLOCKS changed shape")
    return out

# die canvas is 1000x500 in the viewer's coordinates; scale to world units
SCALE = 0.012          # 1000 units -> 12 world units wide
BASE_Z = 0.0           # top of the substrate
BLOCK_H = 0.42         # how tall a raised block stands
HOT_H = 0.62           # taller when the block is driven by this instruction

# colour per block family. Driven blocks go emissive green in the .pov.
FAMILY = {
    "fetch": "front", "rip": "front", "decode": "front", "retire": "front",
    "gpr": "state", "rsp": "state", "flags": "state",
    "ctrl": "control", "cpl": "control", "cr": "control", "msr": "control",
    "alu": "compute", "cache": "memory", "agutlb": "memory", "mem": "memory",
    "bus": "data", "seg": "data", "intc": "data", "xmm": "data",
}
COLOR = {
    "front":   (0.16, 0.19, 0.24),
    "state":   (0.13, 0.20, 0.26),
    "control": (0.22, 0.17, 0.26),
    "compute": (0.24, 0.19, 0.13),
    "memory":  (0.14, 0.22, 0.20),
    "data":    (0.19, 0.19, 0.22),
}
HOT_RGB = "<0.15,1.0,0.45>"


def die(msg):
    print(f"[cpu-die] {msg}", file=sys.stderr)
    sys.exit(1)


def wx(x):
    """viewer x -> world x (centred on the die)"""
    return x * SCALE


def wy(y):
    """viewer y -> world y; flip so +y in the viewer is -y in the world"""
    return -y * SCALE


# ---------------------------------------------------------------- .glb
def write_glb(blocks):
    import trimesh
    import numpy as np

    scene = trimesh.Scene()
    for b in blocks:
        ext = [b["w"] * SCALE, b["h"] * SCALE, BLOCK_H]
        cx = wx(b["x"] + b["w"] / 2)
        cy = wy(b["y"] + b["h"] / 2)
        cz = BASE_Z + BLOCK_H / 2
        m = trimesh.creation.box(extents=ext)
        m.apply_translation([cx, cy, cz])
        rgb = COLOR[FAMILY[b["id"]]]
        m.visual.face_colors = np.tile([int(r * 255) for r in rgb] + [255],
                                       (len(m.faces), 1))
        scene.add_geometry(m, node_name=b["id"], geom_name=b["id"])

    # substrate the blocks sit on, so it reads as a die rather than floating boxes
    sub = trimesh.creation.box(extents=[1000 * SCALE + 0.6, 500 * SCALE + 0.6, 0.35])
    sub.apply_translation([(1000 * SCALE) / 2, -(500 * SCALE) / 2, -0.175])
    sub.visual.face_colors = np.tile([26, 32, 40, 255], (len(sub.faces), 1))
    scene.add_geometry(sub, node_name="substrate", geom_name="substrate")

    out = os.path.join(LAB, "cpu-die.glb")
    scene.export(out)
    n = len(blocks) + 1
    size = os.path.getsize(out)
    print(f"[cpu-die] wrote cpu-die.glb  ({n} parts, {size/1024:.0f} KiB)")

    # round-trip check: the file must actually load back with every part intact
    back = trimesh.load(out)
    geo = back.geometry if hasattr(back, "geometry") else {}
    print(f"[cpu-die] round-trip: {len(geo)} geometries loaded")
    if len(geo) < n:
        die(f"round-trip lost parts: expected {n}, got {len(geo)}")
    return out


# ---------------------------------------------------------------- .pov
def pov_box(x0, y0, z0, x1, y1, z1):
    return (f"box {{ <{x0:.4f},{y0:.4f},{z0:.4f}>, "
            f"<{x1:.4f},{y1:.4f},{z1:.4f}> }}")


def texture(rgb, amb, dif, spec, emis=None):
    """POV-Ray 3.7 in this distro rejects a #declare'd material placed BEFORE
    the primitive (`object { MAT box{..} }` -> "Expected 'object', material
    identifier"). Verified by bisection: E, F and G all parse, A/C/D do not.
    So the texture is emitted INLINE on each object. Slightly more verbose,
    but it is the only form this build accepts."""
    t = ("texture { pigment { color rgb "
         f"<{rgb[0]:.3f},{rgb[1]:.3f},{rgb[2]:.3f}> }}"
         f" finish {{ ambient {amb} diffuse {dif} specular {spec}")
    if emis:
        t += f" emission rgb <{emis[0]:.3f},{emis[1]:.3f},{emis[2]:.3f}>"
    return t + " } }"


def write_pov(blocks, hot_ids):
    L = []
    L.append("// cpu-die.pov - generated by cpu-die-3d.py, do not hand-edit.")
    L.append("//")
    L.append("// The floorplan is parsed out of x86sem.BLOCKS - the SAME table the")
    L.append("// HTML step-viewer lights up - so the 3D die and the 2D map cannot")
    L.append("// drift apart. The driven (emissive green) set is whatever")
    L.append("// x86sem.classify() returns for the chosen instruction, not a")
    L.append("// hand-typed list, so this stays honest as the classifier grows.")
    L.append("//")
    L.append("//   python3 cpu-die-3d.py --insn \"je 0x21\"")
    L.append("//   povray die.pov +Oout.png +W1280 +H800 +FC")
    L.append("")

    # substrate
    L.append("object { " + pov_box(-0.3, -(500 * SCALE + 0.3), -0.35,
                                   1000 * SCALE + 0.3, 0.3, 0.0)
             + " " + texture((0.055, 0.070, 0.090), 0.22, 0.50, 0.05) + " }")
    L.append("")

    # blocks: driven ones get the emissive material AND a taller profile
    for b in blocks:
        x0 = wx(b["x"]); x1 = wx(b["x"] + b["w"])
        y1 = wy(b["y"]); y0 = wy(b["y"] + b["h"])      # viewer y is flipped
        fam = FAMILY[b["id"]]
        hot = b["id"] in hot_ids
        rgb, amb, dif, spec, emis = COLOR[fam], 0.30, 0.66, 0.10, None
        z1 = BASE_Z + BLOCK_H
        if hot:
            rgb, amb, dif, spec = (0.10, 0.72, 0.34), 0.34, 0.62, 0.16
            emis = (0.020, 0.150, 0.055)
            z1 = BASE_Z + HOT_H                          # taller: reads in silhouette
        L.append(f'// {b["id"]:7s} {b["label"]:12s} {b["sub"]}')
        L.append("object { " + pov_box(x0, y0, BASE_Z, x1, y1, z1)
                 + " " + texture(rgb, amb, dif, spec, emis) + " }")

    # data bus as a low strip so the memory path is visible as a route
    L.append("")
    L.append("// data bus strip (memory path)")
    L.append("object { " + pov_box(wx(24), wy(300), 0.02, wx(884), wy(312), 0.12)
             + " " + texture((0.10, 0.13, 0.17), 0.28, 0.60, 0.08) + " }")

    # ---- labels
    # POV-Ray `text` needs a real TTF; without a font file the label silently
    # renders nothing, so check it exists before emitting the objects.
    font = None
    for cand in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
                 "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"):
        if os.path.exists(cand):
            font = cand
            break
    if font:
        L.append("")
        L.append(f'#declare FONTFILE = "{font}";')
        for b in blocks:
            x0 = wx(b["x"]); x1 = wx(b["x"] + b["w"])
            y1 = wy(b["y"]); y0 = wy(b["y"] + b["h"])
            hot = b["id"] in hot_ids
            # label only the blocks this instruction actually drives: that is
            # the whole point of the image, and labelling all 19 produces
            # overlapping unreadable text. Wide-enough check keeps it legible.
            if not hot or (x1 - x0) < 1.6:
                continue
            z = (BASE_Z + (HOT_H if hot else BLOCK_H)) + 0.06
            col = "<0.35,1.0,0.60>" if hot else "<0.62,0.68,0.76>"
            L.append(f'// label {b["label"]}')
            L.append(f'text {{')
            L.append(f'  ttf "{font}" "{b["label"]}" 0.105, 0')
            L.append("  scale <-1, 1, 1>")   # POV-Ray text faces -Z: flip to read
            L.append(f'  translate <{(x0 + x1) / 2:.3f}, {(y0 + y1) / 2:.3f}, {z:.3f}>')
            L.append(f'  pigment {{ color rgb {col} }}')
            L.append(f'}}')
    L.append("")
    cx, cy = (1000 * SCALE) / 2, -(500 * SCALE) / 2
    L.append("camera {")
    L.append(f"  location <{cx - 5.5:.3f}, {cy - 13.5:.3f}, 15.0>")
    L.append(f"  look_at  <{cx:.3f}, {cy:.3f}, 0.0>")
    L.append("  angle 40")
    L.append("}")
    L.append("")
    L.append("light_source { <6, -9, 14> color rgb <0.95,0.97,1.0>*0.85 }")
    L.append(f"light_source {{ <{cx + 4:.3f}, {cy + 5:.3f}, 7> color rgb <1.0,0.85,0.6>*0.35 }}")
    L.append(f"light_source {{ <{cx:.3f}, {cy - 2:.3f}, 3.5> color rgb <0.5,0.7,1.0>*0.25 shadowless }}")
    L.append("background { color rgb <0.02,0.03,0.05> }")

    out = os.path.join(LAB, "die.pov")
    open(out, "w").write("\n".join(L) + "\n")
    print(f"[cpu-die] wrote die.pov  ({len(blocks)} blocks, "
          f"{len(hot_ids)} driven)")
    return out


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--insn", default="push rbp",
                    help="instruction to highlight; the driven blocks come "
                         "from x86sem.classify(), not from a hand-typed list")
    ap.add_argument("--no-glb", action="store_true")
    args = ap.parse_args()

    blocks = load_blocks()

    import x86sem
    sem = x86sem.classify(args.insn)
    hot = list(sem["units"])
    print(f"[cpu-die] {sem['emoji']}  {args.insn}")
    print(f"[cpu-die] classifier says {len(hot)} blocks driven: {', '.join(hot)}")

    if not args.no_glb:
        write_glb(blocks)
    write_pov(blocks, hot)


if __name__ == "__main__":
    main()
