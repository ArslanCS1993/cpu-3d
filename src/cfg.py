"""Control-flow graph of a trace: instruction rectangles, condition diamonds,
block bands, and edges that admit what they do not know.

A trace is a single path, so a plain flowchart of it would be a straight line
with 20 decorations. Three things make the picture worth drawing:

1. BRANCH OUTCOME IS DATA. Every conditional has a computed target; if the next
   executed instruction sits at that address the branch was TAKEN, otherwise it
   FELL THROUGH. Both edges are drawn and the road not taken is greyed - the
   trace says which way it went, instead of the diamond being decoration.
2. INDIRECT JUMPS GET THEIR TARGET FROM THE TRACE. `jmp *-0x7ebffe60(,%rsi,8)`
   has no computable destination, but the next traced step IS where the CPU went.
3. FILE IS A COLOUR. The trace crosses 13 files; colouring by source file turns
   the graph into a map of where the CPU went.

ALL geometry is computed here, at build time, deterministically - including the
SVG path strings and the per-row font sizes. The page injects strings; there is
no JS layout to get subtly wrong and every number here is assertable.

TWO CONVENTIONS THAT ARE EASY TO GET WRONG (both verified against objdump):

* The disassembler in the trace prints a branch operand as `target - the address
  of the jump instruction`, NOT as a displacement. `je 0xa` at 0xffffffff81156a76
  is the two bytes `74 08` = "je +8", whose real target is 0xffffffff81156a80 =
  0x...a76 + 0xa. The textbook `target = addr + length + disp` puts every
  diamond 2-6 bytes past the truth, which then reads as "no branch was ever
  taken".
* `call 0xfffffffffff569b8` is a rel32 shown sign-extended, so it must be read
  back as a negative number before being added to the address.

The trace is contiguous: 99 of 119 consecutive pairs are addr+length and every
one of the 20 exceptions is a control-flow instruction. A next step matching
neither the fall-through nor the computed target would mean the tracer skipped
code, so that case is labelled "trace gap" rather than guessed at.

LAYOUT: one rectangle per instruction, flowed top-to-bottom into newspaper
columns of ~COLMAX height, with a tinted band behind each basic block. One
rectangle per instruction (rather than a card per block) is what keeps the
canvas short enough to see whole: a card per block inherits the height of the
longest run, and this trace has a 37-instruction straight-line PUSH_AND_CLEAR_REGS
run, which alone made the canvas 3760px tall.
"""

RET = ("ret", "retq", "iret", "iretd", "iretq")

# 13 files cross the syscall trace, 8 the scheduler one.
FILE_HUES = [206, 96, 32, 172, 264, 12, 140, 44, 320, 76, 232, 188, 356, 120]

ROW_W, ROW_H = 202, 25
HEAD_H, BLOCK_GAP, COL_GAP, COLMAX, PADTOP, PADX = 17, 9, 46, 1000, 30, 30
FS, FS_MIN = 8.6, 6.4
CH = 5.4                                  # px per char at 10px monospace


def _mn(insn):
    parts = insn["text"].split(None, 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def _is_flow(mn):
    return (mn.startswith("j") or mn.startswith("loop") or mn.startswith("call")
            or mn in RET)


def _target_delta(ops):
    """Signed `target - addr` as printed, or None for an indirect operand."""
    t = ops.strip().split()[0] if ops.strip() else ""
    t = t.rstrip(",")
    neg = t.startswith("-")
    if neg or t.startswith("+"):
        t = t[1:]
    if not t or not all(c in "0123456789abcdefABCDEFx" for c in t):
        return None
    try:
        v = int(t, 16) if t.lower().startswith("0x") else int(t, 10)
    except ValueError:
        return None
    if neg:
        v = -v
    if v >= 1 << 63:
        v -= 1 << 64                  # a sign-extended rel32
    return v


def build_flow(steps):
    n = len(steps)
    addr2i = {int(s["insn_parsed"]["addr"], 16): i for i, s in enumerate(steps)}

    nodes = []
    for i, s in enumerate(steps):
        p = s["insn_parsed"]
        mn, ops = _mn(p)
        a, ln = int(p["addr"], 16), p["length"]
        kind = "flow" if _is_flow(mn) else "plain"
        cond = kind == "flow" and not (mn == "jmp" or mn.startswith("call")
                                       or mn in RET)
        tgt, indirect = None, False
        if kind == "flow" and mn not in RET:
            d = _target_delta(ops)
            if d is None:
                indirect = True
            else:
                tgt = a + d
        nodes.append(dict(i=i, addr=a, length=ln, text=p["text"], mn=mn,
                          ops=ops, kind=kind, cond=cond, tgt=tgt,
                          indirect=indirect, file=s["file_short"], line=s["line"]))

    # ---- basic blocks: split after every control-flow instruction, and at
    # every invisible hand-off (the next step is not the fall-through address).
    blocks, cur = [], []
    for i, nd in enumerate(nodes):
        cur.append(i)
        nxt = nodes[i + 1] if i + 1 < n else None
        if (nd["kind"] == "flow" or nxt is None
                or nxt["addr"] != nd["addr"] + nd["length"]):
            blocks.append(dict(id=len(blocks), steps=list(cur)))
            cur = []
    if cur:
        blocks.append(dict(id=len(blocks), steps=list(cur)))
    for b in blocks:
        b["first"], b["last"] = b["steps"][0], b["steps"][-1]
        b["file"] = nodes[b["first"]]["file"]
        b["line0"], b["line1"] = nodes[b["first"]]["line"], nodes[b["last"]]["line"]
        b["addr0"], b["addr1"] = nodes[b["first"]]["addr"], nodes[b["last"]]["addr"]
        b["term"] = nodes[b["last"]] if nodes[b["last"]]["kind"] == "flow" else None

    b_of_step = {i: b["id"] for b in blocks for i in b["steps"]}

    # ---- edges
    edges = []
    stats = dict(taken=0, nottaken=0, alt=0, gap=0, call_in=0, call_out=0,
                 jump_in=0, jump_out=0, ret=0, back=0, indirect=0)

    def add(**kw):
        kw["id"] = len(edges)
        edges.append(kw)
        return kw

    for b in blocks:
        t = b["term"]
        nxt_b = b_of_step.get(b["last"] + 1)
        if t is None:
            if nxt_b is not None and nxt_b != b["id"]:
                add(frm=b["id"], to=nxt_b, kind="hidden")
            continue
        if t["mn"] in RET:
            stats["ret"] += 1
            continue

        fall = t["addr"] + t["length"]
        tgt_step = addr2i.get(t["tgt"]) if t["tgt"] is not None else None
        real_next = nodes[b["last"] + 1]["addr"] if b["last"] + 1 < n else None

        if t["cond"]:
            took = tgt_step is not None and real_next == t["tgt"]
            fell = real_next == fall
            if took:
                add(frm=b["id"], to=b_of_step[tgt_step], kind="taken", label="taken")
                stats["taken"] += 1
                add(frm=b["id"], to=b_of_step[tgt_step], kind="alt", label="not taken")
                stats["alt"] += 1
            elif fell:
                add(frm=b["id"], to=nxt_b, kind="nottaken", label="not taken")
                stats["nottaken"] += 1
                if tgt_step is not None:
                    add(frm=b["id"], to=b_of_step[tgt_step], kind="alt",
                        label="taken")
                    stats["alt"] += 1
            else:
                # neither target nor fall-through: the tracer skipped code.
                add(frm=b["id"], to=nxt_b, kind="gap", label="trace gap")
                stats["gap"] += 1
        else:
            kind = "call" if t["mn"].startswith("call") else "jmp"
            if t["indirect"]:
                stats["indirect"] += 1
                dst = nxt_b
            else:
                dst = b_of_step[tgt_step] if tgt_step is not None else None
            if dst is not None:
                add(frm=b["id"], to=dst, kind=kind, indirect=t["indirect"],
                    label=kind)
                stats["call_in" if kind == "call" else "jump_in"] += 1
            else:
                add(frm=b["id"], to=None, kind="outside", target=t["tgt"],
                    indirect=t["indirect"],
                    label=("callee not in trace" if kind == "call"
                           else "target not in trace"))
                stats["call_out" if kind == "call" else "jump_out"] += 1

    # ---- rows: one rectangle per instruction, sized to fit its own text.
    # Shared by both views; only the positions differ.
    rows = []
    for nd in nodes:
        txt = nd["text"]
        fs = FS
        need = len(txt) * CH * (fs / 10.0)
        if need > ROW_W - 34:                     # 22px step no. + 12px padding
            fs = max(FS_MIN, fs * (ROW_W - 34) / need)
        rows.append(dict(i=nd["i"], addr=nd["addr"], text=txt, fs=round(fs, 2),
                         kind=nd["kind"], cond=nd["cond"], mn=nd["mn"],
                         hue=0, shape="diamond" if nd["cond"] else "rect"))

    files = sorted({nd["file"] for nd in nodes})
    fcol = {f: FILE_HUES[k % len(FILE_HUES)] for k, f in enumerate(files)}
    for b in blocks:
        b["hue"] = fcol[b["file"]]
    for r, nd in zip(rows, nodes):
        r["hue"] = fcol[nd["file"]]

    # Band headers: `file:lines` on the left, `#first-#last` on the right, and
    # they collide at 214px - the longest path here is 59 characters
    # (/tmp/kobj64/./arch/x86/include/generated/asm/syscalls_64.h). Fit the
    # text at BUILD time and keep the informative TAIL of a path, since the
    # leaf name is what identifies it; the full path goes in the tooltip.
    for b in blocks:
        # A range that DESCENDS (`common.c:72-42`) is real - an inlined macro
        # makes the block start later in the file than it ends - but as a label
        # it reads as a mistake, so only ascend ranges get one.
        rng = (str(b["line0"]) if b["line1"] <= b["line0"]
               else "%d–%d" % (b["line0"], b["line1"]))
        lab = b["file"] + ":" + rng
        b["rt"] = "#%d–#%d" % (b["first"], b["last"])
        b["lab_full"] = lab
        b["lab"] = lab if len(lab) <= 30 else "…" + lab[-(30 - 1):]

    addr_order = sorted(blocks, key=lambda b: b["addr0"])

    def layout(ordered, tag):
        """Position an ordering of the blocks. Returns plain geometry dicts -
        the shared row/block/edge records are copied, never mutated, so the two
        views cannot contaminate each other."""
        def block_h(b):
            return HEAD_H + ROW_H * len(b["steps"]) + (12 if b["term"] else 0)

        total = sum(block_h(b) + BLOCK_GAP for b in ordered)
        ncols = max(2, -(-total // COLMAX))
        y, col, maxh = PADTOP, 0, PADTOP
        vb = []
        for b in ordered:
            if y > PADTOP + COLMAX and col < ncols - 1:
                maxh = max(maxh, y)
                col += 1
                y = PADTOP
            b["x"] = PADX + col * (ROW_W + COL_GAP)
            b["y"] = y
            b["h"] = block_h(b)
            b["w"] = ROW_W + 12
            b["col"] = col
            y += b["h"] + BLOCK_GAP
            maxh = max(maxh, y)
            vb.append(dict(id=b["id"], x=b["x"], y=b["y"], w=b["w"], h=b["h"],
                           col=b["col"]))
        W = PADX * 2 + ncols * (ROW_W + COL_GAP)
        H = maxh + 24

        vr = []
        for b in ordered:
            for k, i in enumerate(b["steps"]):
                r = rows[i]
                vr.append(dict(i=i, x=b["x"] + 6, y=b["y"] + HEAD_H + k * ROW_H,
                               w=ROW_W, h=ROW_H - 3,
                               cx=b["x"] + 6 + ROW_W / 2.0,
                               cy=b["y"] + HEAD_H + k * ROW_H + (ROW_H - 3) / 2.0,
                               bid=b["id"]))
        pos = {b["id"]: b for b in ordered}

        def out_pt(b):
            return (b["x"] + ROW_W / 2.0 + 6, b["y"] + b["h"] + 2)

        def in_pt(b):
            return (b["x"] + ROW_W / 2.0 + 6, b["y"] - 4)

        ve, back = [], 0
        for e in edges:
            s = pos[e["frm"]]
            if e["to"] is None:
                ve.append(dict(id=e["id"], kind=e["kind"], label=e.get("label", ""),
                               d="", back=False, x=s["x"] + ROW_W, y=s["y"] + s["h"],
                               target=e.get("target")))
                continue
            d = pos[e["to"]]
            isback = d["y"] < s["y"] - 1
            back += 1 if isback else 0
            x0, y0 = out_pt(s)
            x1, y1 = in_pt(d)
            if not isback and d["x"] == s["x"]:
                path = (f"M{x0:.0f},{y0:.0f} C{x0:.0f},{y0 + 14:.0f} "
                        f"{x1:.0f},{y1 - 14:.0f} {x1:.0f},{y1:.0f}")
                lx, ly = (x0 + x1) / 2.0 + 5, (y0 + y1) / 2.0
            elif isback:
                lane = min(s["x"], d["x"]) - 22
                path = (f"M{x0:.0f},{y0:.0f} C{lane:.0f},{y0 + 10:.0f} "
                        f"{lane:.0f},{y1 - 10:.0f} {x1 - 4:.0f},{y1:.0f}")
                lx, ly = lane - 4, (y0 + y1) / 2.0
            else:
                lane = max(s["x"] + ROW_W, d["x"] + ROW_W) + 20
                path = (f"M{x0:.0f},{y0:.0f} C{lane:.0f},{y0 + 12:.0f} "
                        f"{lane:.0f},{y1 - 12:.0f} {x1:.0f},{y1:.0f}")
                lx, ly = lane + 3, (y0 + y1) / 2.0
            ve.append(dict(id=e["id"], kind=e["kind"], label=e.get("label", ""),
                           d=path, back=isback, lx=lx, ly=ly))

        vg = []
        for k in range(1, len(ordered)):
            prev, cur = ordered[k - 1], ordered[k]
            g = cur["addr0"] - (prev["addr1"] + nodes[prev["last"]]["length"])
            if g > 0:
                vg.append(dict(y=(prev["y"] + prev["h"] + cur["y"]) / 2.0,
                               x=min(prev["x"], cur["x"]) + 6, nbytes=g,
                               after=prev["id"], before=cur["id"]))
        return dict(blocks=vb, rows=vr, edges=ve, gaps=vg,
                    geom=dict(w=W, h=H, roww=ROW_W, rowh=ROW_H, headh=HEAD_H,
                              ncols=ncols, padtop=PADTOP, padx=PADX),
                    back=back)

    views = {"exec": layout(list(blocks), "exec"),
             "addr": layout(addr_order, "addr")}
    # `back` is a property of the ORDERING, not of the trace: a jump that goes
    # forward in execution can still point backwards in memory, so the address
    # view legitimately counts more of them. The headline number is the exec one.
    stats["back"] = views["exec"]["back"]
    stats["back_addr"] = views["addr"]["back"]
    assert views["exec"]["back"] == sum(1 for e in views["exec"]["edges"]
                                        if e["back"]), "back-edge count mismatch"

    return dict(rows=rows, blocks=blocks, edges=edges, files=files, hues=fcol,
                addr_order=[b["id"] for b in addr_order], stats=stats, views=views)


def _self_test(name, steps):
    f = build_flow(steps)
    st = f["stats"]
    n = len(steps)
    seen = {}
    for b in f["blocks"]:
        for i in b["steps"]:
            assert i not in seen, "instruction in two blocks"
            seen[i] = b["id"]
    assert set(seen) == set(range(n)), "blocks must partition the trace"
    for tag, v in f["views"].items():
        g = v["geom"]
        assert len(v["rows"]) == n, f"{tag}: {len(v['rows'])} rows for {n} steps"
        assert len(v["blocks"]) == len(f["blocks"])
        for r in v["rows"]:
            assert 0 <= r["x"] and r["x"] + r["w"] <= g["w"], f"{tag} row {r['i']} off canvas"
            assert 0 <= r["y"] and r["y"] + r["h"] <= g["h"], f"{tag} row {r['i']} off canvas"
        for b in v["blocks"]:
            assert b["x"] + b["w"] <= g["w"] and b["y"] + b["h"] <= g["h"], \
                f"{tag} block {b['id']} off canvas"
        for i in range(len(v["rows"])):
            for j in range(i + 1, len(v["rows"])):
                a, b = v["rows"][i], v["rows"][j]
                assert not (abs(a["x"] - b["x"]) < 1 and abs(a["y"] - b["y"]) < 1), \
                    f"{tag}: rows {a['i']} and {b['i']} overlap"
        for e in v["edges"]:
            if e["kind"] == "outside":
                continue
            assert e["d"].startswith("M"), f"{tag} edge {e['id']} has no path"
    assert f["views"]["exec"]["back"] == st["back"], "back-edge count mismatch"
    assert st["gap"] == 0, f"{st['gap']} unexplained gaps in {name}"
    print(f"=== {name}: {n} instructions -> {len(f['blocks'])} blocks, "
          f"{len(f['edges'])} edges")
    print(f"    {st}")
    for tag, v in f["views"].items():
        g = v["geom"]
        print(f"    {tag:5} canvas {g['w']:.0f}x{g['h']:.0f} in {g['ncols']} cols, "
              f"{len(v['edges'])} paths, {len(v['gaps'])} address gaps")
    print(f"    {len(f['files'])} files")
    print("    partition / no overlaps / in-bounds / paths / edge accounting: OK")
    return f


if __name__ == "__main__":
    import json, os, sys, importlib.util
    lab = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, lab)
    spec = importlib.util.spec_from_file_location("bv", os.path.join(lab, "build-viewer.py"))
    bv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bv)
    for name in ("trace.json", "trace-sched.json"):
        tr = bv.build(json.load(open(os.path.join(lab, name))),
                      os.path.join(lab, "vmlinux"))
        _self_test(name, tr["steps"])