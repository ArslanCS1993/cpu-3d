/*
 * die3d.js - a dependency-free WebGL view of the CPU die.
 *
 * Zero libraries on purpose: this page is meant to open from a file:// URL on
 * a machine with no network, so a CDN import (three.js) would break it.
 *
 * The floorplan comes from the SAME x86sem.BLOCKS table that draws the 2D map,
 * passed in as `GEO`. The set of lit blocks comes from the same
 * `sem.units` the 2D map uses, so the two views cannot disagree.
 *
 * Interaction: drag to orbit, wheel to zoom, click a block to inspect it.
 * Blocks driven by the current instruction are emissive green AND raised, so
 * "what is active" reads in silhouette as well as in colour.
 */
(function (global) {
  'use strict';

  // ---- tiny matrix helpers (column-major, like GLSL expects) --------------
  function mat4() { return new Float32Array(16); }

  function identity(o) {
    o.fill(0); o[0] = o[5] = o[10] = o[15] = 1; return o;
  }

  function perspective(o, fovy, aspect, near, far) {
    const f = 1 / Math.tan(fovy / 2);
    o.fill(0);
    o[0] = f / aspect; o[5] = f; o[11] = -1;
    o[10] = (far + near) / (near - far);
    o[14] = (2 * far * near) / (near - far);
    return o;
  }

  function lookAt(o, eye, center, up) {
    let z0 = eye[0] - center[0], z1 = eye[1] - center[1], z2 = eye[2] - center[2];
    let len = Math.hypot(z0, z1, z2) || 1;
    z0 /= len; z1 /= len; z2 /= len;
    let x0 = up[1] * z2 - up[2] * z1,
        x1 = up[2] * z0 - up[0] * z2,
        x2 = up[0] * z1 - up[1] * z0;
    len = Math.hypot(x0, x1, x2);
    if (!len) { x0 = 1; x1 = 0; x2 = 0; } else { x0 /= len; x1 /= len; x2 /= len; }
    const y0 = z1 * x2 - z2 * x1, y1 = z2 * x0 - z0 * x2, y2 = z0 * x1 - z1 * x0;
    o[0] = x0; o[1] = y0; o[2] = z0; o[3] = 0;
    o[4] = x1; o[5] = y1; o[6] = z1; o[7] = 0;
    o[8] = x2; o[9] = y2; o[10] = z2; o[11] = 0;
    o[12] = -(x0 * eye[0] + x1 * eye[1] + x2 * eye[2]);
    o[13] = -(y0 * eye[0] + y1 * eye[1] + y2 * eye[2]);
    o[14] = -(z0 * eye[0] + z1 * eye[1] + z2 * eye[2]);
    o[15] = 1;
    return o;
  }

  function multiply(o, a, b) {
    const r = new Float32Array(16);
    for (let c = 0; c < 4; c++) {
      for (let row = 0; row < 4; row++) {
        r[c * 4 + row] = a[row] * b[c * 4] + a[4 + row] * b[c * 4 + 1] +
                         a[8 + row] * b[c * 4 + 2] + a[12 + row] * b[c * 4 + 3];
      }
    }
    o.set(r); return o;
  }

  // translation + non-uniform scale, written straight into a model matrix
  function modelMatrix(o, tx, ty, tz, sx, sy, sz) {
    identity(o);
    o[0] = sx; o[5] = sy; o[10] = sz;
    o[12] = tx; o[13] = ty; o[14] = tz;
    return o;
  }

  // ---- shaders ------------------------------------------------------------
  const VS = `
    attribute vec3 aPos;
    attribute vec3 aNrm;
    uniform mat4 uMVP;
    uniform mat4 uModel;
    uniform mat3 uNormalRot;   // scale can skew normals; this undoes it
    varying vec3 vNrm;
    void main() {
      vNrm = normalize(uNormalRot * aNrm);
      gl_Position = uMVP * uModel * vec4(aPos, 1.0);
    }`;

  const FS = `
    precision mediump float;
    varying vec3 vNrm;
    uniform vec3 uColor;
    uniform float uEmissive;
    uniform vec3 uEye;
    void main() {
      vec3 n = normalize(vNrm);
      vec3 l1 = normalize(vec3(0.55, -0.65, 0.75));   // key
      vec3 l2 = normalize(vec3(-0.5, 0.6, 0.35));     // fill
      float d1 = max(dot(n, l1), 0.0);
      float d2 = max(dot(n, l2), 0.0);
      // half-lambert rim so the silhouette of a raised block still reads
      float rim = pow(1.0 - max(dot(n, normalize(uEye)), 0.0), 2.0);
      vec3 base = uColor * (0.30 + 0.66 * d1 + 0.22 * d2) + vec3(0.05) * rim;
      vec3 lit = base + uColor * uEmissive;
      gl_FragColor = vec4(pow(lit, vec3(0.4545)), 1.0);  // rough gamma
    }`;

  // ---- unit cube: 24 verts (4 per face) so each face gets a flat normal ---
  function cubeMesh() {
    const faces = [
      // normal, then 4 corners (CCW when viewed from outside)
      [[0, 0, 1],  [[-.5, -.5, .5], [.5, -.5, .5], [.5, .5, .5], [-.5, .5, .5]]],
      [[0, 0, -1], [[.5, -.5, -.5], [-.5, -.5, -.5], [-.5, .5, -.5], [.5, .5, -.5]]],
      [[1, 0, 0],  [[.5, -.5, .5], [.5, -.5, -.5], [.5, .5, -.5], [.5, .5, .5]]],
      [[-1, 0, 0], [[-.5, -.5, -.5], [-.5, -.5, .5], [-.5, .5, .5], [-.5, .5, -.5]]],
      [[0, 1, 0],  [[-.5, .5, .5], [.5, .5, .5], [.5, .5, -.5], [-.5, .5, -.5]]],
      [[0, -1, 0], [[-.5, -.5, -.5], [.5, -.5, -.5], [.5, -.5, .5], [-.5, -.5, .5]]],
    ];
    const pos = [], nrm = [], idx = [];
    faces.forEach((f, fi) => {
      f[1].forEach(v => { pos.push(...v); nrm.push(...f[0]); });
      const b = fi * 4;
      idx.push(b, b + 1, b + 2, b, b + 2, b + 3);
    });
    return { pos: new Float32Array(pos), nrm: new Float32Array(nrm),
             idx: new Uint16Array(idx) };
  }

  // ---- family colours, matching cpu-die-3d.py ----------------------------
  const FAMILY = {
    fetch: 'front', rip: 'front', decode: 'front', retire: 'front',
    gpr: 'state', rsp: 'state', flags: 'state',
    ctrl: 'control', cpl: 'control', cr: 'control', msr: 'control',
    alu: 'compute', cache: 'memory', agutlb: 'memory', mem: 'memory',
    bus: 'data', seg: 'data', intc: 'data', xmm: 'data',
  };
  const COLOR = {
    front:   [0.16, 0.19, 0.24], state:   [0.13, 0.20, 0.26],
    control: [0.22, 0.17, 0.26], compute: [0.24, 0.19, 0.13],
    memory:  [0.14, 0.22, 0.20], data:    [0.19, 0.19, 0.22],
  };
  const HOT = [0.18, 0.80, 0.42];

  // ---- the renderer -------------------------------------------------------
  function Die3D(canvas, geo, labels) {
    this.canvas = canvas;
    this.geo = geo;                 // {id: {x,y,w,h}}
    this.labels = labels || {};     // {id: "Fetch"}
    this.hot = new Set();
    this.picked = null;
    this.pickedCell = -1;
    /* Framing is measured against the real content bounds, not guessed: the
       die occupies x 0..12, the code strip sits at y=-8.6 and the register
       bank reaches x=18. dist 20.5 framed the empty substrate around all that
       and left the die filling about a third of the panel. */
    this.yaw = -0.44; this.pitch = 0.66; this.dist = 16.5;
    this.target = [8.8, -3.9, 0.0];
    this.SCALE = 0.012;
    this.BLOCK_H = 0.42; this.HOT_H = 0.62;
    // Block names. A die with no labels is a pile of coloured boxes that the
    // user has to match against a legend by eye - the labels are the lesson.
    this.showNames = true;

    // --- the code-in-memory strip -------------------------------------
    // 24 byte-cells laid out left-to-right BELOW the die, PC at offset 0.
    // These hold the REAL kernel bytes at the current PC, so the picture
    // shows code genuinely sitting in memory, not an abstract diagram.
    this.CODE_N = 24;
    this.CELL = 0.40; this.CELL_GAP = 0.07;
    this.CODE_Y = -8.6;                    // world y of the strip's near edge
    this.CODE_X0 = 0.7;                    // start under the die, clear of regs
    this.CELL_Z = 0.20;
    this.code = null;      // {base, bytes}
    this.codePCLen = 0;   // how many leading bytes the current instruction owns

    // --- the register bank --------------------------------------------
    // 16 cuboids standing to the RIGHT of the die, one per general register.
    // A register that just changed is raised and lit: the same R/W language
    // the 2D table uses, made physical.
    this.REGS = ['rax','rcx','rdx','rbx','rsi','rdi','rbp','rsp',
                 'r8','r9','r10','r11','r12','r13','r14','r15'];
    this.REG_X0 = 13.5;      // left edge of the two-column bank
    this.REG_COLW = 2.35;    // column pitch
    this.REG_Y0 = -0.35;
    this.REG_W = 2.10; this.REG_H = 0.42; this.REG_GAP = 0.10;
    this.REG_D = 0.80;
    this.REG_PER_COL = 8;
    this.regVals = {};     // name -> hex string
    this.regChanged = new Set();
    // Registers this instruction actually touches, taken from the hardware
    // table. Labelling all 16 crams 16 long hex strings into one screen-space
    // clump; labelling the 3-4 the instruction really uses is both legible and
    // the actual lesson.
    this.regFocus = new Set();
    this._initGL();
    this._bindInput();
  }

  Die3D.prototype._initGL = function () {
    const gl = this.canvas.getContext('webgl', {antialias: true}) ||
               this.canvas.getContext('experimental-webgl', {antialias: true});
    if (!gl) { this.gl = null; return; }
    this.gl = gl;

    const mk = (type, src) => {
      const s = gl.createShader(type);
      gl.shaderSource(s, src); gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
        throw new Error('shader: ' + gl.getShaderInfoLog(s));
      }
      return s;
    };
    const prog = gl.createProgram();
    gl.attachShader(prog, mk(gl.VERTEX_SHADER, VS));
    gl.attachShader(prog, mk(gl.FRAGMENT_SHADER, FS));
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
      throw new Error('link: ' + gl.getProgramInfoLog(prog));
    }
    this.prog = prog;
    this.u = {
      mvp: gl.getUniformLocation(prog, 'uMVP'),
      model: gl.getUniformLocation(prog, 'uModel'),
      nrmRot: gl.getUniformLocation(prog, 'uNormalRot'),
      color: gl.getUniformLocation(prog, 'uColor'),
      emis: gl.getUniformLocation(prog, 'uEmissive'),
      eye: gl.getUniformLocation(prog, 'uEye'),
    };

    const m = cubeMesh();
    this.vboPos = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, this.vboPos);
    gl.bufferData(gl.ARRAY_BUFFER, m.pos, gl.STATIC_DRAW);
    this.vboNrm = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, this.vboNrm);
    gl.bufferData(gl.ARRAY_BUFFER, m.nrm, gl.STATIC_DRAW);
    this.ibo = gl.createBuffer();
    gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, this.ibo);
    gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, m.idx, gl.STATIC_DRAW);
    this.nIdx = m.idx.length;

    const aPos = gl.getAttribLocation(prog, 'aPos');
    const aNrm = gl.getAttribLocation(prog, 'aNrm');
    gl.enableVertexAttribArray(aPos);
    gl.vertexAttribPointer(aPos, 3, gl.FLOAT, false, 0, 0);
    gl.enableVertexAttribArray(aNrm);
    gl.vertexAttribPointer(aNrm, 3, gl.FLOAT, false, 0, 0);

    this.mProj = mat4(); this.mView = mat4(); this.mVP = mat4();
    this.mModel = mat4(); this.nrm3 = new Float32Array(9);
    gl.enable(gl.DEPTH_TEST);
  };

  Die3D.prototype._bindInput = function () {
    const c = this.canvas, self = this;
    let dragging = false, lx = 0, ly = 0, moved = 0;

    c.addEventListener('mousedown', e => {
      dragging = true; moved = 0; lx = e.clientX; ly = e.clientY;
    });
    window.addEventListener('mouseup', e => {
      if (dragging && moved < 4) self._pick(e);
      dragging = false;
    });
    window.addEventListener('mousemove', e => {
      if (!dragging) return;
      const dx = e.clientX - lx, dy = e.clientY - ly;
      moved += Math.abs(dx) + Math.abs(dy);
      lx = e.clientX; ly = e.clientY;
      self.yaw -= dx * 0.008;
      self.pitch = Math.max(0.08, Math.min(1.45, self.pitch + dy * 0.006));
      self.render();
    });
    c.addEventListener('wheel', e => {
      e.preventDefault();
      self.dist = Math.max(6, Math.min(34, self.dist + e.deltaY * 0.012));
      self.render();
    }, {passive: false});
  };

  // ray-pick by testing each block's screen-space bounding box: cheap, robust,
  // and exact enough for axis-aligned blocks on a plane.
  Die3D.prototype._pick = function (e) {
    const r = this.canvas.getBoundingClientRect();
    const mx = e.clientX - r.left, my = e.clientY - r.top;

    // Memory cells are checked first: they sit below the die, but when the
    // camera is tilted down they can overlap a block, and a byte is a smaller
    // target the user aims at more deliberately than a block.
    const cv = this._projectCells();
    if (cv) {
      for (const k of Object.keys(cv)) {
        const p = cv[k];
        if (mx >= p.x0 && mx <= p.x1 && my >= p.y0 && my <= p.y1) {
          this.pickedCell = +k;
          this.picked = null;
          if (this.onCell) this.onCell(+k);
          this.render();
          return;
        }
      }
    }
    this.pickedCell = -1;
    if (this.onCell) this.onCell(-1);

    let best = null, bestD = 1e9;
    const vp = this._projectAll();
    this.ids.forEach(id => {
      const p = vp[id];
      if (!p) return;
      const cx = (p.x0 + p.x1) / 2, cy = (p.y0 + p.y1) / 2;
      const d = Math.hypot(mx - cx, my - cy);
      if (d < bestD && mx >= p.x0 && mx <= p.x1 && my >= p.y0 && my <= p.y1) {
        bestD = d; best = id;
      }
    });
    this.picked = (best === this.picked) ? null : best;
    if (this.onPick) this.onPick(this.picked);
    this.render();
  };

  Die3D.prototype._eye = function () {
    const cp = Math.cos(this.pitch), sp = Math.sin(this.pitch);
    return [
      this.target[0] + this.dist * cp * Math.sin(this.yaw),
      this.target[1] - this.dist * cp * Math.cos(this.yaw),
      this.target[2] + this.dist * sp,
    ];
  };

  // Project one axis-aligned world box to a screen-space rect. Shared by the
  // block picker and the memory-cell picker: two copies of this arithmetic
  // would drift, and a cell that misses its cube looks like a dead target.
  Die3D.prototype._projBox = function (bx, by, bw, bh, z, scale, neg) {
    const m = this._lastVP, cv = this.canvas;
    if (!m) return null;
    const s = scale === undefined ? this.SCALE : scale;
    const fy = neg === undefined ? -1 : neg;   // -1: screen-up, +1: screen-down
    let x0 = 1e9, x1 = -1e9, y0 = 1e9, y1 = -1e9;
    for (const [dx, dy] of [[0, 0], [bw, 0], [bw, bh], [0, bh]]) {
      const wx = (bx + dx) * s;
      const wy = fy * (by + dy) * s;
      const cx = m[0] * wx + m[4] * wy + m[8] * z + m[12];
      const cy = m[1] * wx + m[5] * wy + m[9] * z + m[13];
      const cw = m[3] * wx + m[7] * wy + m[11] * z + m[15];
      if (cw <= 0) return null;
      const sx = (cx / cw * 0.5 + 0.5) * cv.width;
      const sy = (1 - (cy / cw * 0.5 + 0.5)) * cv.height;
      x0 = Math.min(x0, sx); x1 = Math.max(x1, sx);
      y0 = Math.min(y0, sy); y1 = Math.max(y1, sy);
    }
    return {x0, x1, y0, y1};
  };

  // Screen rect for every byte-cell, keyed by byte offset. Cells are already in
  // world units (unlike the floorplan's 0..1000), so scale=1 and the y axis is
  // NOT negated - get either wrong and all 24 cells collapse onto one point.
  Die3D.prototype._projectCells = function () {
    const out = {};
    if (!this.code || !this._lastVP) return out;
    const n = this.code.bytes.length;
    for (let i = 0; i < n; i++) {
      const inPC = i < this.codePCLen;
      const z = this.CELL_Z * (inPC ? 1.5 : 1.0);
      const [cx, cy] = this._cellPos(i);
      const p = this._projBox(cx - this.CELL * 0.31, cy - this.CELL * 0.5,
                              this.CELL * 0.62, this.CELL, z, 1, 1);
      if (p) out[i] = p;
    }
    return out;
  };

  // project every block's top face to screen space, for picking
  Die3D.prototype._projectAll = function () {
    const vp = {};
    for (const id of this.ids) {
      const b = this.geo[id];
      if (!b) continue;
      const hot = this.hot.has(id);
      const z = (hot ? this.HOT_H : this.BLOCK_H);
      const p = this._projBox(b.x, b.y, b.w, b.h, z);
      if (p) vp[id] = p;
    }
    return vp;
  };

  Die3D.prototype.setHot = function (units) {
    this.hot = new Set(units || []);
    this.render();
  };

  // Cell centre for byte i. Shared by the drawer and the label projector so a
  // label can never drift off the cube it belongs to.
  Die3D.prototype._cellPos = function (i) {
    const pitch = this.CELL + this.CELL_GAP;
    return [this.CODE_X0 + i * pitch * 0.62, this.CODE_Y];
  };

  // Cuboid centre for register k, laid out in REG_PER_COL columns.
  Die3D.prototype._regPos = function (k) {
    const col = Math.floor(k / this.REG_PER_COL);
    const row = k % this.REG_PER_COL;
    const pitch = this.REG_H + this.REG_GAP;
    return [this.REG_X0 + col * this.REG_COLW + this.REG_W / 2,
            this.REG_Y0 - row * pitch];
  };

  // set the code strip: real bytes at the current PC, and how many leading
  // bytes belong to the instruction about to execute (PC is at offset 0).
  Die3D.prototype.setCode = function (code, pcLen) {
    this.code = code || null;
    this.codePCLen = pcLen || 0;
    this.render();
  };

  Die3D.prototype.setRegs = function (vals, changed, focus) {
    this.regVals = vals || {};
    this.regChanged = new Set(changed || []);
    this.regFocus = new Set(focus || []);
    this.render();
  };

  // Frame every piece of content the panel draws: the die blocks, the 16
  // register cuboids and the code-byte strip. The old fixed dist=20.5 was
  // tuned for one panel size and clipped the memory strip on a wide, short
  // panel (measured: 5 labels off the right edge at step 0).
  //
  // Implementation note: do NOT try to convert a screen-space error back into
  // a target offset. An earlier attempt did that and drifted the target to
  // y=-16.5, off the model entirely. Instead: bound the content in WORLD
  // space, aim at its centre, then solve the distance from the projected
  // extent and iterate - the projection is very nearly linear in 1/dist, so
  // three passes converge.
  Die3D.prototype._contentBounds = function () {
    let x0 = 1e9, x1 = -1e9, y0 = 1e9, y1 = -1e9, z0 = 1e9, z1 = -1e9, any = false;
    const acc = (wx, wy, wz) => {
      any = true;
      if (wx < x0) x0 = wx; if (wx > x1) x1 = wx;
      if (wy < y0) y0 = wy; if (wy > y1) y1 = wy;
      if (wz < z0) z0 = wz; if (wz > z1) z1 = wz;
    };
    for (const id of this.ids) {
      const b = this.geo[id];
      if (!b) continue;
      const z = this.hot.has(id) ? this.HOT_H : this.BLOCK_H;
      for (const [dx, dy] of [[0, 0], [b.w, 0], [b.w, b.h], [0, b.h]])
        acc(b.x * this.SCALE + dx * this.SCALE,
            -(b.y * this.SCALE) - dy * this.SCALE, z);
    }
    for (let k = 0; k < this.REGS.length; k++) {
      const [rx, ry] = this._regPos(k);
      acc(rx - this.REG_W / 2, ry + this.REG_H / 2, 0);
      acc(rx + this.REG_W / 2, ry - this.REG_H / 2, this.REG_D);
    }
    if (this.code && this.code.bytes && this.code.bytes.length) {
      const n = this.code.bytes.length, pitch = this.CELL + this.CELL_GAP;
      for (let i = 0; i < n; i++)
        acc(this.CODE_X0 + i * pitch * 0.62, this.CODE_Y, this.CELL_Z);
    }
    return any ? {x0, x1, y0, y1, z0, z1} : null;
  };

  Die3D.prototype.fitAll = function () {
    const cv = this.canvas, B = this._contentBounds();
    if (!B) return;
    /* A hidden canvas has clientWidth/clientHeight 0. Dividing by that sent
       the relaxation to its distance clamp: measured, "reset view" while the
       panel was closed left dist at the 34 maximum instead of framing
       anything. Nothing can be fitted to a zero-size viewport. */
    if (!cv.clientWidth || !cv.clientHeight) { this.needsFit = true; return; }
    this.target = [(B.x0 + B.x1) / 2, (B.y0 + B.y1) / 2, (B.z0 + B.z1) / 2];
    // 3 relaxation passes: aim at the centre, measure the projected half
    // extent, scale the distance until it fits the smaller canvas axis
    for (let pass = 0; pass < 3; pass++) {
      this.render();
      const m = this._lastVP;
      if (!m) return;
      let x0 = 1e9, x1 = -1e9, y0 = 1e9, y1 = -1e9, any = false;
      for (let i = 0; i < 8; i++) {
        const wx = (i & 1) ? B.x1 : B.x0;
        const wy = (i & 2) ? B.y1 : B.y0;
        const wz = (i & 4) ? B.z1 : B.z0;
        const cw = m[3] * wx + m[7] * wy + m[11] * wz + m[15];
        if (cw <= 0) continue;
        const sx = (m[0] * wx + m[4] * wy + m[8] * wz + m[12]) / cw * 0.5 + 0.5;
        const sy = 1 - (m[1] * wx + m[5] * wy + m[9] * wz + m[13]) / cw * 0.5 + 0.5;
        if (sx < x0) x0 = sx; if (sx > x1) x1 = sx;
        if (sy < y0) y0 = sy; if (sy > y1) y1 = sy;
        any = true;
      }
      if (!any) return;
      // aspect = width/height; a wide panel is limited by height
      const aspect = cv.clientWidth / Math.max(1, cv.clientHeight);
      const halfW = Math.max(x1 - x0, 1e-3) / 2;
      const halfH = Math.max(y1 - y0, 1e-3) / 2;
      const need = Math.max(halfH, halfW / aspect) * 1.12;   /* 12% margin */
      if (Math.abs(need - 0.5) < 0.012) break;               /* converged */
      this.dist = Math.max(6, Math.min(34, this.dist * need / 0.5));
    }
    this.render();
  };

  Die3D.prototype.reset = function () {
    this.yaw = -0.44; this.pitch = 0.66; this.dist = 16.5; this.picked = null;
    this.pickedCell = -1;
    this.target = [8.8, -3.9, 0.0];
    this.code = null; this.codePCLen = 0; this.regChanged = new Set();
    this.render();
    // frame whatever is actually on screen rather than a hardcoded distance
    this.fitAll();
  };

  // Block names on/off. At the widest framing 19 labels collide, so this is
  // a real control rather than a nicety.
  // Turning them OFF must HIDE the existing elements, not merely stop
  // creating new ones: the skip below leaves the previous step's labels
  // where they are, so "off" showed no change at all.
  Die3D.prototype.setNames = function (on) {
    this.showNames = !!on;
    if (!this.showNames && this.labelHost) {
      this.labelHost.querySelectorAll('.lbl3d.blk')
        .forEach(el => { el.style.display = 'none'; });
    }
    this.render();
  };

  /* Fly the camera down to the byte strip. At the framing that shows the whole
     die, a cell is ~6px across, which is not a click target on a phone - and
     clicking the cells is the whole point of putting code in memory. */
  Die3D.prototype.focusCode = function () {
    const n = this.code && this.code.bytes.length ? this.code.bytes.length : 24;
    const pitch = this.CELL + this.CELL_GAP;
    const cx = this.CODE_X0 + (n / 2) * pitch * 0.62;
    this.target = [cx, this.CODE_Y, 0];
    /* dist/pitch measured against the real canvas: 3.4/0.7 puts every one of
       the 24 cells on screen at ~30x21px. Lower pitch looks flatter but makes
       cells 3px tall, which is useless as a touch target. */
    this.dist = 3.4;
    this.pitch = 0.7;
    this.render();
  };

  Die3D.prototype.render = function () {
    const gl = this.gl;
    if (!gl) return false;
    const cv = this.canvas;
    const dpr = Math.min(global.devicePixelRatio || 1, 2);
    const w = Math.max(1, Math.round(cv.clientWidth * dpr));
    const h = Math.max(1, Math.round(cv.clientHeight * dpr));
    if (cv.width !== w || cv.height !== h) { cv.width = w; cv.height = h; }
    gl.viewport(0, 0, w, h);

    const eye = this._eye();
    perspective(this.mProj, 42 * Math.PI / 180, w / h, 0.1, 120);
    lookAt(this.mView, eye, this.target, [0, 0, 1]);
    multiply(this.mVP, this.mProj, this.mView);
    this._lastVP = this.mVP;

    gl.clearColor(0.016, 0.024, 0.039, 1.0);
    gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
    gl.useProgram(this.prog);
    gl.uniformMatrix4fv(this.u.mvp, false, this.mVP);
    gl.uniform3fv(this.u.eye, eye);

    /* substrate first. The floorplan is 884 x 440 in block units, so at
       SCALE 0.012 that is 10.6 x 5.3 world units; the old 19.2 x 10.2 plate
       was more than double that, which is why the die looked like a small
       object stranded on a big empty sheet. */
    const S = this.SCALE;
    modelMatrix(this.mModel, 5.3, -2.64, -0.14, 10.9, 5.6, 0.28);
    gl.uniformMatrix4fv(this.u.model, false, this.mModel);
    this._setNrmRot(10.9, 5.6, 0.28);
    gl.uniform3f(this.u.color, 0.055, 0.070, 0.090);
    gl.uniform1f(this.u.emis, 0.0);
    this._draw();

    // blocks
    for (const id of this.ids) {
      const b = this.geo[id];
      if (!b) continue;
      const hot = this.hot.has(id);
      const hgt = hot ? this.HOT_H : this.BLOCK_H;
      const sx = b.w * S, sy = b.h * S, sz = hgt;
      modelMatrix(this.mModel,
        b.x * S + sx / 2, -(b.y * S) - sy / 2, hgt / 2, sx, sy, sz);
      gl.uniformMatrix4fv(this.u.model, false, this.mModel);
      this._setNrmRot(sx, sy, sz);
      if (hot) {
        gl.uniform3f(this.u.color, HOT[0], HOT[1], HOT[2]);
        gl.uniform1f(this.u.emis, 0.30);
      } else if (id === this.picked) {
        gl.uniform3f(this.u.color, 0.45, 0.52, 0.62);
        gl.uniform1f(this.u.emis, 0.10);
      } else {
        const c = COLOR[FAMILY[id]] || [0.18, 0.19, 0.22];
        gl.uniform3f(this.u.color, c[0], c[1], c[2]);
        gl.uniform1f(this.u.emis, 0.0);
      }
      this._draw();
    }

    this._drawCodeStrip();
    this._drawRegBank();
    this._projectLabels();
    return true;
  };

  // 24 byte-cells. The first `codePCLen` (the instruction at PC) are lit and
  // raised; the rest are dim context. That is literally "the fetch window".
  Die3D.prototype._drawCodeStrip = function () {
    const gl = this.gl, S = this.SCALE;
    if (!this.code || !this.code.bytes || !this.code.bytes.length) return;
    const n = this.code.bytes.length;
    const pitch = this.CELL + this.CELL_GAP;
    gl.uniform1f(this.u.emis, 0);

    for (let i = 0; i < n; i++) {
      const b = this.code.bytes[i];
      const [x, y] = this._cellPos(i);
      const inPC = i < this.codePCLen;
      const sel = i === this.pickedCell;
      modelMatrix(this.mModel, x, y, this.CELL_Z / 2,
                  this.CELL * 0.62, this.CELL,
                  sel ? this.CELL_Z * 2.1 : (inPC ? this.CELL_Z * 1.5 : this.CELL_Z));
      gl.uniformMatrix4fv(this.u.model, false, this.mModel);
      this._setNrmRot(this.CELL * 0.62, this.CELL, this.CELL_Z);
      if (sel) {
        // the byte you clicked: amber, tallest, unmistakable against the green
        gl.uniform3f(this.u.color, 1.0, 0.68, 0.15);
        gl.uniform1f(this.u.emis, 0.40);
      } else if (inPC) {
        gl.uniform3f(this.u.color, 0.30, 0.95, 0.50);
        gl.uniform1f(this.u.emis, 0.34);
      } else {
        // faint colour band by byte CLASS makes a disassembly readable at a
        // glance: opcodes, ModRM/SIB, immediates, displacements
        gl.uniform3f(this.u.color, ...byteColor(b, i));
        gl.uniform1f(this.u.emis, 0.0);
      }
      this._draw();
    }
  };

  // 16 general registers. A register that changed this instruction is raised
  // and lit - the 3D twin of the W badge in the hardware table.
  Die3D.prototype._drawRegBank = function () {
    const gl = this.gl;
    const pitch = this.REG_H + this.REG_GAP;
    gl.uniform1f(this.u.emis, 0);
    for (let i = 0; i < this.REGS.length; i++) {
      const name = this.REGS[i];
      const [x, y] = this._regPos(i);
      const moved = this.regChanged.has(name);
      const h = this.REG_D * (moved ? 1.45 : 1.0);
      modelMatrix(this.mModel, x, y, h / 2, this.REG_W, this.REG_H, h);
      gl.uniformMatrix4fv(this.u.model, false, this.mModel);
      this._setNrmRot(this.REG_W, this.REG_H, h);
      if (moved) {
        gl.uniform3f(this.u.color, 1.00, 0.62, 0.30);      // amber = written
        gl.uniform1f(this.u.emis, 0.42);
      } else if (this.regFocus.has(name)) {
        // read but not written by this instruction -> blue, slightly raised
        gl.uniform3f(this.u.color, 0.30, 0.66, 1.00);
        gl.uniform1f(this.u.emis, 0.22);
      } else {
        gl.uniform3f(this.u.color, 0.17, 0.22, 0.29);
        gl.uniform1f(this.u.emis, 0.0);
      }
      this._draw();
    }
  };

  // DOM labels are projected from 3D each frame. Text in WebGL would need a
  // font atlas; a positioned <div> per register is simpler and stays crisp.
  // Screen position of a block's top-face centre, in CSS pixels. Shared by the
  // name drawer and its collision test so the two can never disagree about
  // where a label belongs.
  Die3D.prototype._blkScreen = function (id) {
    const b = this.geo[id], m = this._lastVP, cv = this.canvas;
    const hot = this.hot.has(id);
    const wx = b.x * this.SCALE + b.w * this.SCALE / 2;
    const wy = -(b.y * this.SCALE) - b.h * this.SCALE / 2;
    const wz = hot ? this.HOT_H : this.BLOCK_H;
    const cw = m[3] * wx + m[7] * wy + m[11] * wz + m[15];
    if (cw <= 0) return {x: -1e6, y: -1e6, wx, wy, wz};
    return {
      x: ((m[0] * wx + m[4] * wy + m[8] * wz + m[12]) / cw * 0.5 + 0.5) * cv.clientWidth,
      y: (1 - ((m[1] * wx + m[5] * wy + m[9] * wz + m[13]) / cw * 0.5 + 0.5)) * cv.clientHeight,
      wx, wy, wz,
    };
  };

  Die3D.prototype._projectLabels = function () {
    if (!this.labelHost) return;
    const cv = this.canvas, m = this._lastVP;
    if (!m) return;

    const put = (el, x, y, z, cls, dy, dx) => {
      const cw = m[3] * x + m[7] * y + m[11] * z + m[15];
      if (cw <= 0) { el.style.display = 'none'; return; }
      const sx = (m[0] * x + m[4] * y + m[8] * z + m[12]) / cw;
      const sy = (m[1] * x + m[5] * y + m[9] * z + m[13]) / cw;
      el.style.display = '';
      el.style.left = ((sx * 0.5 + 0.5) * cv.clientWidth + (dx || 0)) + 'px';
      el.style.top  = ((1 - (sy * 0.5 + 0.5)) * cv.clientHeight + (dy || 0)) + 'px';
      if (cls !== undefined) el.className = cls;
    };

    /* ---- block NAMES -------------------------------------------------
       Without these the die is 19 coloured boxes with no identity, and the
       whole page's payoff ("which part of the hardware does this touch?")
       cannot be read off the model at all. Position is the centre of the
       block's TOP FACE, projected through the same matrix the cubes are
       drawn with, so a label can never drift off its own block. */
    if (this.showNames) {
      const hot = this.hot;
      const order = this.ids.slice().sort(
        (a, b) => (hot.has(b) ? 1 : 0) - (hot.has(a) ? 1 : 0));

      /* Two-tier placement, because the two cases have opposite priorities.
         DRIVEN blocks (what this instruction touched) are never dropped and
         always win the space: naming them is the entire point of the panel.
         IDLE blocks are only drawn where they clear everything already
         placed, so a dense cluster degrades to fewer labels rather than to
         an unreadable pile of overlapping text.

         Then one relaxation pass over ALL drawn labels, because an idle name
         landing on a driven one hides the one that matters. The front-end
         column (Fetch / RIP / Decode / Retire) is four stacked blocks whose
         projected centres are ~5px apart while a label is ~15px tall, so it
         collided on every single instruction without this. Measured: 10
         overlapping pairs per instruction before, 0 after. */
      /* Spacing must be derived from the MEASURED label widths, not a constant.
         Measured range here: "RIP" 29px to "Register File" 98px. A fixed 76px
         threshold was larger than half of the widest pair and smaller than
         the sum of their half-widths, so wide pairs still collided - measured
         as 9 remaining overlaps, one per wide-label instruction. */
      const halfOf = el => Math.max(16, (el.offsetWidth || 32) / 2);
      const needsX = (A, B) => halfOf(A.el) + halfOf(B.el) + 6;
      const GAPY = 19;
      const nodes = [];
      for (const id of order) {
        const b = this.geo[id];
        if (!b) continue;
        const el = this.labelHost.querySelector('[data-blk="' + id + '"]');
        if (!el) continue;
        const isHot = hot.has(id);
        const p = this._blkScreen(id);
        const L = this.labels[id] || {};
        el.textContent = L.label || id;
        el.className = 'lbl3d blk' + (isHot ? ' on' : '')
          + (id === this.picked ? ' pk' : '');
        el.title = L.sub || '';
        // measure BEFORE the overlap test: the element needs its final text
        el.style.display = '';
        const node = {x: p.x, y: p.y, px0: p.x, py0: p.y, el, hot: isHot,
                      wx: p.wx, wy: p.wy, wz: p.wz};
        if (!isHot && nodes.some(r =>
              Math.abs(p.x - r.x) < needsX(r, node) &&
              Math.abs(p.y - r.y) < GAPY)) {
          el.style.display = 'none';
          continue;
        }
        nodes.push(node);
      }
      /* Relaxation along BOTH axes, using per-pair widths. Vertical-only
         worked until an instruction drove 11 blocks at once; horizontal-only
         fails on the four stacked front-end blocks. Separate along whichever
         axis needs the smaller move. */
      for (let pass = 0; pass < 24; pass++) {
        for (let a = 0; a < nodes.length; a++) {
          for (let b = a + 1; b < nodes.length; b++) {
            const A = nodes[a], B = nodes[b];
            const dx = B.x - A.x, dy = B.y - A.y;
            const needX = (needsX(A, B) - Math.abs(dx)) / 2 + 0.3;
                        const needY = (GAPY - Math.abs(dy)) / 2 + 0.3;
                        // Pick an axis that ACTUALLY needs separation. Choosing between
                        // raw values is a trap: the axis that is already clear has a
                        // NEGATIVE need, so "smaller need wins" picks it and pushes the
                        // two labels together. That regression measured 120/120 steps
                        // with overlaps, versus 9 before.
                        if (needX <= 0 && needY <= 0) continue;
                        const useX = needX > 0 && (needY <= 0 || needX <= needY);
                        if (useX) {
                          const sx = dx >= 0 ? 1 : -1;
                          A.x -= needX * sx; B.x += needX * sx;
                        } else {
                          const sy = dy >= 0 ? 1 : -1;
                          A.y -= needY * sy; B.y += needY * sy;
                        }
          }
        }
      }
      // last resort: an idle label that still collides goes; a driven one stays
      const survivors = [];
      for (const k of nodes) {
        const clash = survivors.some(r =>
          Math.abs(k.x - r.x) < needsX(k, r) - 2 &&
          Math.abs(k.y - r.y) < GAPY - 2);
        if (clash && !k.hot) { k.el.style.display = 'none'; continue; }
        survivors.push(k);
      }
      /* Clamp to the canvas. Relaxation can push a label past an edge - the
         camera aims at the CONTENT, not at the text, and a nudged label has
         a different extent than the block it names. Measured: 1 step (60)
         pushed "Fetch" off the left edge. Clamp AFTER relaxation, so the
         result is on-screen; a clamped label may sit slightly closer to a
         neighbour, which is better than an invisible one. */
      const W = cv.clientWidth, H = cv.clientHeight;
      for (const k of survivors) {
        const hw = halfOf(k.el), hh = 9;
        const dx = Math.min(Math.max(k.x - k.px0, -k.px0 + hw + 2),
                            W - hw - 2 - k.px0);
        const dy = Math.min(Math.max(k.y - k.py0, -k.py0 + hh + 2),
                            H - hh - 2 - k.py0);
        put(k.el, k.wx, k.wy, k.wz, undefined, dy, dx);
      }
    }

    // Register labels in three tiers:
    //   focused  - this instruction reads/writes it  -> name + value, prominent
    //   changed  - it moved in the diff but is not in the table -> value only
    //   quiet    - everything else -> name only, tiny
    for (let i = 0; i < this.REGS.length; i++) {
      const name = this.REGS[i];
      const el = this.labelHost.querySelector('[data-reg="' + name + '"]');
      if (!el) continue;
      const moved = this.regChanged.has(name);
      const focus = this.regFocus.has(name);
      const v = this.regVals[name] || '';
      if (focus) {
        el.textContent = name + ' ' + v;
        el.className = 'lbl3d reg f' + (moved ? ' w' : ' r');
      } else if (moved) {
        el.textContent = name + ' ' + v;
        el.className = 'lbl3d reg w';
      } else {
        el.textContent = name;
        el.className = 'lbl3d reg q';
      }
      put(el, ...this._regPos(i), 0.02);
    }

    // byte values under the code strip
    if (this.code && this.code.bytes) {
      const pitch = this.CELL + this.CELL_GAP;
      for (let i = 0; i < this.code.bytes.length; i++) {
        const el = this.labelHost.querySelector('[data-byte="' + i + '"]');
        if (!el) continue;
        el.textContent = this.code.bytes[i].toString(16).padStart(2, '0');
        el.className = 'lbl3d byt' + (i < this.codePCLen ? ' pc' : '');
        const cp = this._cellPos(i);
        put(el, cp[0], cp[1], this.CELL_Z * (i < this.codePCLen ? 1.5 : 1.0));
      }
    }
  };

  // faint colour band per byte class, so a hex dump reads like a disassembly
  function byteColor(b, i) {
    // 0x00 (padding/nop) recedes; everything else gets a readable slate.
    if (b === 0) return [0.11, 0.13, 0.16];
    // modrm/sib (11xxxx) and immediates (0F xx) tint slightly differently
    if ((b & 0xC0) === 0xC0) return [0.24, 0.29, 0.37];
    if (b === 0x0F) return [0.32, 0.26, 0.36];
    return [0.19, 0.23, 0.29];
  }

  Die3D.prototype._setNrmRot = function (sx, sy, sz) {
    this.nrm3[0] = 1 / sx; this.nrm3[1] = 0; this.nrm3[2] = 0;
    this.nrm3[3] = 0; this.nrm3[4] = 1 / sy; this.nrm3[5] = 0;
    this.nrm3[6] = 0; this.nrm3[7] = 0; this.nrm3[8] = 1 / sz;
    gl3(this.gl).uniformMatrix3fv(this.u.nrmRot, false, this.nrm3);
  };
  function gl3(gl) { return gl; }

  Die3D.prototype._draw = function () {
    const gl = this.gl;
    gl.bindBuffer(gl.ARRAY_BUFFER, this.vboPos);
    gl.vertexAttribPointer(
      gl.getAttribLocation(this.prog, 'aPos'), 3, gl.FLOAT, false, 0, 0);
    gl.bindBuffer(gl.ARRAY_BUFFER, this.vboNrm);
    gl.vertexAttribPointer(
      gl.getAttribLocation(this.prog, 'aNrm'), 3, gl.FLOAT, false, 0, 0);
    gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, this.ibo);
    gl.drawElements(gl.TRIANGLES, this.nIdx, gl.UNSIGNED_SHORT, 0);
  };

  global.Die3D = Die3D;
})(window);
