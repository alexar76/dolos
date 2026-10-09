/**
 * DOLOS hero: the live chain, the fork peeled off it, and what happens on the fork.
 *
 * The scene is the product argument, not decoration. A live chain runs along the bottom and is
 * never written to. A branch peels up off it into a throwaway fork; attacks arrive there. Two
 * invariants hold — a green ring, the honest negative. One breaks — the block cracks crimson.
 * The patcher closes the guard, the same attack is refused, and the whole fork dissolves: none of
 * it ever existed. Then it happens again, because that is the loop.
 *
 * Everything is built procedurally from three.js primitives — no downloaded assets.
 */
import * as THREE from "three";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";
import { RoundedBoxGeometry } from "three/addons/geometries/RoundedBoxGeometry.js";
import { EffectComposer } from "three/addons/postprocessing/EffectComposer.js";
import { RenderPass } from "three/addons/postprocessing/RenderPass.js";
import { UnrealBloomPass } from "three/addons/postprocessing/UnrealBloomPass.js";
import { OutputPass } from "three/addons/postprocessing/OutputPass.js";

const CRIMSON = 0xe5484d;
const GREEN = 0x00ff88;
const GOLD = 0xe8c36a;
const STEEL = 0x3d4a61;

const LIVE_N = 5;
const FORK_N = 4;
const GAP = 1.9;
const LIVE_Y = -1.42;
const FORK_Y = 1.48;
const FORK_X0 = -GAP; // the fork branches off the live block directly below it

/** The timeline, in seconds. One pass tells the whole story; then it repeats. */
const LOOP = 18;
const BEATS = [
  { at: 0.0, phase: "fork" },
  { at: 2.6, phase: "attack", block: 1, breaks: false },
  { at: 5.0, phase: "attack", block: 3, breaks: false },
  { at: 7.4, phase: "attack", block: 2, breaks: true },
  { at: 9.8, phase: "fix", block: 2 },
  { at: 12.0, phase: "attack", block: 2, breaks: false, retry: true },
  { at: 14.6, phase: "dissolve" },
];

export function mountForkScene(canvas, opts = {}) {
  const host = canvas.parentElement || canvas;
  const compact = Boolean(opts.compact);
  const hud = opts.hud || null;
  const mobile =
    matchMedia("(max-width: 820px), (pointer: coarse)").matches || compact;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

  const renderer = new THREE.WebGLRenderer({
    canvas,
    alpha: true,
    antialias: true,
    powerPreference: "high-performance",
  });
  // Sized by hand and stretched by CSS, so three's own pixel-ratio scaling stays out of the
  // composer's viewport maths (same arrangement as the BASANOS touchstone).
  const dpr = Math.min(devicePixelRatio || 1, mobile ? 1.35 : 1.8);
  renderer.setPixelRatio(1);
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.34;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 120);
  camera.position.set(0.2, 0.4, 11.5);

  const controls = new OrbitControls(camera, canvas);
  controls.enableDamping = true;
  controls.dampingFactor = 0.06;
  controls.enablePan = false;
  controls.rotateSpeed = 0.5;
  controls.autoRotate = !reduced;
  controls.autoRotateSpeed = 0.24;
  controls.minPolarAngle = Math.PI * 0.22;
  controls.maxPolarAngle = Math.PI * 0.78;
  controls.target.set(0, 0.08, 0);

  const key = new THREE.DirectionalLight(0xffe9e6, 1.9);
  key.position.set(3.6, 5.0, 5.2);
  const rim = new THREE.PointLight(CRIMSON, 26, 30);
  rim.position.set(-3.4, 3.2, 2.4);
  const cool = new THREE.PointLight(0x8ad4ff, 14, 26);
  cool.position.set(4.2, -2.6, 3.0);
  // A dim fill from the reader's side so the untouched chain reads as metal, not as a silhouette.
  const fill = new THREE.DirectionalLight(0xbcd0ea, 0.7);
  fill.position.set(-1.4, 0.4, 7);
  scene.add(
    new THREE.AmbientLight(0x4d3b44, 1.35),
    new THREE.HemisphereLight(0xa8bcd4, 0x1c1216, 0.6),
    key,
    rim,
    cool,
    fill,
  );

  const world = new THREE.Group();
  world.rotation.set(-0.06, 0.1, 0);
  scene.add(world);

  // ── geometry shared by every block ────────────────────────────────────────────────
  const blockGeo = new RoundedBoxGeometry(1.1, 0.86, 0.86, 3, 0.11);
  const linkGeo = new THREE.CylinderGeometry(0.035, 0.035, GAP - 1.1, 8);
  linkGeo.rotateZ(Math.PI / 2);

  function makeRow(count, x0, y, z, material, linkColor, linkOpacity) {
    const group = new THREE.Group();
    const blocks = [];
    for (let i = 0; i < count; i++) {
      const mesh = new THREE.Mesh(blockGeo, material.clone());
      mesh.position.set(x0 + i * GAP, y, z);
      group.add(mesh);
      blocks.push(mesh);
      if (i > 0) {
        const link = new THREE.Mesh(
          linkGeo,
          new THREE.MeshBasicMaterial({
            color: linkColor,
            transparent: true,
            opacity: linkOpacity,
            blending: THREE.AdditiveBlending,
            depthWrite: false,
          }),
        );
        link.position.set(x0 + (i - 0.5) * GAP, y, z);
        group.add(link);
      }
    }
    world.add(group);
    return { group, blocks };
  }

  // ── the live chain: solid, cool, untouched ────────────────────────────────────────
  const live = makeRow(
    LIVE_N,
    -((LIVE_N - 1) / 2) * GAP,
    LIVE_Y,
    0,
    new THREE.MeshPhysicalMaterial({
      color: STEEL,
      metalness: 0.5,
      roughness: 0.33,
      clearcoat: 0.7,
      clearcoatRoughness: 0.26,
      emissive: 0x121a28,
    }),
    0x6f7c93,
    0.5,
  );

  // ── the fork: ghostly, crimson, disposable ────────────────────────────────────────
  const fork = makeRow(
    FORK_N,
    FORK_X0,
    FORK_Y,
    -0.35,
    new THREE.MeshPhysicalMaterial({
      color: 0x622c36,
      metalness: 0.22,
      roughness: 0.4,
      emissive: 0x3a161c,
      emissiveIntensity: 1,
      transparent: true,
      opacity: 0.9,
      clearcoat: 0.4,
    }),
    CRIMSON,
    0.45,
  );

  // A dashed cage around the fork: the safety boundary, drawn rather than asserted.
  const cage = new THREE.LineSegments(
    new THREE.EdgesGeometry(
      new THREE.BoxGeometry((FORK_N - 1) * GAP + 2.1, 2.0, 1.9),
    ),
    new THREE.LineDashedMaterial({
      color: CRIMSON,
      dashSize: 0.18,
      gapSize: 0.13,
      transparent: true,
      opacity: 0.55,
    }),
  );
  cage.computeLineDistances();
  cage.position.set(FORK_X0 + ((FORK_N - 1) / 2) * GAP, FORK_Y, -0.35);
  world.add(cage);

  // ── the branch: a tube from the live block up into the fork ───────────────────────
  const branchCurve = new THREE.CatmullRomCurve3([
    new THREE.Vector3(FORK_X0, LIVE_Y + 0.42, 0),
    new THREE.Vector3(FORK_X0 - 0.55, LIVE_Y + 1.3, -0.1),
    new THREE.Vector3(FORK_X0 - 0.45, FORK_Y - 1.1, -0.28),
    new THREE.Vector3(FORK_X0, FORK_Y - 0.44, -0.35),
  ]);
  const branch = new THREE.Mesh(
    new THREE.TubeGeometry(branchCurve, 64, 0.045, 8, false),
    new THREE.MeshBasicMaterial({
      color: CRIMSON,
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    }),
  );
  branch.geometry.setDrawRange(0, 0);
  world.add(branch);
  const BRANCH_VERTS = branch.geometry.index.count;

  // A spark that runs the branch while it grows — the fork being taken.
  const spark = new THREE.Mesh(
    new THREE.SphereGeometry(0.075, 12, 12),
    new THREE.MeshBasicMaterial({ color: 0xffd7d9, blending: THREE.AdditiveBlending }),
  );
  spark.visible = false;
  world.add(spark);

  // ── darts, rings and cracks, pooled ───────────────────────────────────────────────
  const dartGeo = new THREE.ConeGeometry(0.085, 0.52, 7);
  dartGeo.rotateX(Math.PI); // point down the -y travel direction
  const ringGeo = new THREE.RingGeometry(0.34, 0.42, 48);

  const darts = [];
  const rings = [];
  // One reusable flash: an impact you can see even when the ring is off-axis.
  const flash = new THREE.PointLight(0xffffff, 0, 8);
  world.add(flash);
  let flashLife = 0;

  function spawnDart(target, color) {
    const dart = new THREE.Mesh(
      dartGeo,
      new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    dart.position.copy(target).add(new THREE.Vector3(0, 2.6, 0.9));
    world.add(dart);
    darts.push({ mesh: dart, from: dart.position.clone(), to: target.clone(), t: 0 });
  }

  function spawnRing(at, color, scale = 1) {
    const ring = new THREE.Mesh(
      ringGeo,
      new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        opacity: 0.9,
        side: THREE.DoubleSide,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    ring.position.copy(at);
    world.add(ring);
    rings.push({ mesh: ring, t: 0, scale });
    flash.color.setHex(color);
    flash.position.copy(at);
    flash.intensity = 26;
    flashLife = 1;
  }

  // A cracked shell that only appears on the block that gave way.
  const cracks = fork.blocks.map((block) => {
    const shell = new THREE.Mesh(
      new THREE.IcosahedronGeometry(0.78, 1),
      new THREE.MeshBasicMaterial({
        color: CRIMSON,
        wireframe: true,
        transparent: true,
        opacity: 0,
        blending: THREE.AdditiveBlending,
        depthWrite: false,
      }),
    );
    shell.position.copy(block.position);
    world.add(shell);
    return shell;
  });

  // A ground grid far below: depth cues, faint enough never to compete with the blocks.
  const floor = new THREE.GridHelper(34, 34, 0x3d4a61, 0x232634);
  floor.position.y = LIVE_Y - 1.35;
  floor.material.transparent = true;
  floor.material.opacity = 0.13;
  floor.material.depthWrite = false;
  world.add(floor);

  // ── dust ──────────────────────────────────────────────────────────────────────────
  const count = mobile ? 220 : 520;
  const positions = new Float32Array(count * 3);
  const colors = new Float32Array(count * 3);
  const palette = [new THREE.Color(CRIMSON), new THREE.Color(0x8f9aab), new THREE.Color(GOLD)];
  for (let i = 0; i < count; i++) {
    positions[i * 3] = (Math.random() - 0.5) * 22;
    positions[i * 3 + 1] = (Math.random() - 0.5) * 12;
    positions[i * 3 + 2] = -2 - Math.random() * 10;
    const c = palette[(Math.random() * palette.length) | 0];
    colors.set([c.r, c.g, c.b], i * 3);
  }
  const dustGeo = new THREE.BufferGeometry();
  dustGeo.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  dustGeo.setAttribute("color", new THREE.BufferAttribute(colors, 3));
  const dust = new THREE.Points(
    dustGeo,
    new THREE.PointsMaterial({
      size: 0.03,
      vertexColors: true,
      transparent: true,
      opacity: 0.45,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    }),
  );
  world.add(dust);

  // ── post ──────────────────────────────────────────────────────────────────────────
  const composer = new EffectComposer(renderer);
  composer.addPass(new RenderPass(scene, camera));
  composer.addPass(
    new UnrealBloomPass(new THREE.Vector2(1, 1), compact ? 0.42 : 0.52, 0.7, 0.82),
  );
  composer.addPass(new OutputPass());

  // What must stay in frame at any aspect: both rows plus the cage.
  const FIT_RADIUS = 4.9;

  function frameCamera() {
    const half = Math.tan(THREE.MathUtils.degToRad(camera.fov) / 2);
    const dist = Math.max(FIT_RADIUS / half, FIT_RADIUS / (half * camera.aspect)) * 1.02;
    controls.minDistance = dist * 0.6;
    controls.maxDistance = dist * 1.7;
    const dir = camera.position.clone().sub(controls.target);
    if (dir.lengthSq() < 1e-6) dir.set(0, 0.05, 1);
    camera.position.copy(controls.target).addScaledVector(dir.normalize(), dist);
    camera.updateProjectionMatrix();
  }

  function resize() {
    const box = canvas.getBoundingClientRect();
    const w = Math.max(1, Math.round(box.width || host.clientWidth));
    const h = Math.max(1, Math.round(box.height || host.clientHeight));
    renderer.setSize(Math.round(w * dpr), Math.round(h * dpr), false);
    composer.setSize(Math.round(w * dpr), Math.round(h * dpr));
    camera.aspect = w / h;
    camera.fov = compact ? 44 : 38;
    camera.updateProjectionMatrix();
    frameCamera();
  }
  resize();
  const ro = typeof ResizeObserver === "function" ? new ResizeObserver(resize) : null;
  if (ro) ro.observe(host);
  addEventListener("resize", resize);

  // ── the timeline ──────────────────────────────────────────────────────────────────
  let lastBeat = -1;
  const broken = new Set();

  function say(phase, detail) {
    if (hud && hud.phase) hud.phase.textContent = phase;
    if (hud && hud.detail) hud.detail.textContent = detail;
    if (hud && hud.verdict) {
      hud.verdict.textContent = phase;
      // W, not opts.words: the vocabulary is swapped in place when the reader changes language.
      hud.verdict.dataset.tone = phase === W.exploited ? "bad" : "good";
    }
  }

  const W = Object.assign(
    {
      fork: "FORK",
      forkDetail: "a copy-on-write clone of the live chain",
      held: "HELD",
      heldDetail: "the invariant refused the attack — an honest negative",
      exploited: "EXPLOITED",
      exploitedDetail: "the invariant broke — a signed finding",
      fix: "FIXED",
      fixDetail: "guard inserted · forge test still green",
      refused: "REFUSED",
      refusedDetail: "the same attack is now refused",
      gone: "TORN DOWN",
      goneDetail: "none of it ever existed",
    },
    opts.words || {},
  );

  function runBeat(beat) {
    if (beat.phase === "fork") {
      broken.clear();
      cracks.forEach((c) => (c.material.opacity = 0));
      fork.blocks.forEach((b) => b.material.emissive.setHex(0x3a161c));
      say(W.fork, W.forkDetail);
      return;
    }
    if (beat.phase === "fix") {
      const block = fork.blocks[beat.block];
      broken.delete(beat.block);
      block.material.emissive.setHex(0x0d3a22);
      cracks[beat.block].material.opacity = 0;
      spawnRing(block.position, GREEN, 1.5);
      say(W.fix, W.fixDetail);
      return;
    }
    if (beat.phase === "dissolve") {
      say(W.gone, W.goneDetail);
    }
  }

  function land(dart) {
    const beat = dart.beat;
    const block = fork.blocks[beat.block];
    if (beat.breaks) {
      broken.add(beat.block);
      block.material.emissive.setHex(0x7a1016);
      cracks[beat.block].material.opacity = 0.85;
      spawnRing(block.position, CRIMSON, 1.25);
      say(W.exploited, W.exploitedDetail);
    } else {
      spawnRing(block.position, GREEN, 1);
      say(beat.retry ? W.refused : W.held, beat.retry ? W.refusedDetail : W.heldDetail);
    }
  }

  const t0 = performance.now();
  let raf = 0;

  function frame() {
    raf = requestAnimationFrame(frame);
    const elapsed = (performance.now() - t0) / 1000;
    const t = reduced ? 6.2 : elapsed % LOOP;

    // fire the beat whose time we just crossed
    let idx = -1;
    for (let i = 0; i < BEATS.length; i++) if (t >= BEATS[i].at) idx = i;
    if (idx !== lastBeat) {
      lastBeat = idx;
      const beat = BEATS[idx];
      if (beat.phase === "attack") {
        spawnDart(fork.blocks[beat.block].position, beat.breaks ? CRIMSON : GREEN);
        darts[darts.length - 1].beat = beat;
      } else {
        runBeat(beat);
      }
    }

    // the branch draws itself in, then retracts as the fork dissolves
    const grow = THREE.MathUtils.clamp(t / 2.0, 0, 1);
    const fade = THREE.MathUtils.clamp((t - 14.6) / 2.6, 0, 1);
    const drawn = Math.round(BRANCH_VERTS * grow * (1 - fade));
    branch.geometry.setDrawRange(0, drawn);
    spark.visible = !reduced && grow < 1;
    if (spark.visible) spark.position.copy(branchCurve.getPointAt(grow));

    // fork blocks pop in on the way up and shrink away at the end
    fork.blocks.forEach((block, i) => {
      const born = THREE.MathUtils.clamp((t - 1.5 - i * 0.22) / 0.5, 0, 1);
      const s = born * (1 - fade);
      block.scale.setScalar(THREE.MathUtils.lerp(0.001, 1, s));
      block.material.opacity = 0.9 * s;
      cracks[i].scale.copy(block.scale);
      cracks[i].position.copy(block.position);
      if (broken.has(i)) {
        block.rotation.z = Math.sin(elapsed * 22 + i) * 0.035;
        cracks[i].rotation.y = elapsed * 0.6;
      } else {
        block.rotation.z *= 0.9;
      }
    });
    fork.group.children.forEach((child) => {
      if (child.material && child.material.blending === THREE.AdditiveBlending) {
        child.material.opacity = 0.45 * (1 - fade) * grow;
      }
    });
    cage.material.opacity = 0.55 * (1 - fade) * grow;

    // the live chain is untouched: it only breathes
    live.blocks.forEach((block, i) => {
      block.position.y = LIVE_Y + Math.sin(elapsed * 0.7 + i * 0.6) * 0.03;
    });

    // darts fly, land once, and are reclaimed
    for (let i = darts.length - 1; i >= 0; i--) {
      const d = darts[i];
      d.t += 0.028;
      const p = THREE.MathUtils.clamp(d.t, 0, 1);
      d.mesh.position.lerpVectors(d.from, d.to, p * p);
      d.mesh.lookAt(d.to);
      d.mesh.rotateX(Math.PI / 2);
      d.mesh.material.opacity = 1 - p * 0.35;
      if (p >= 1) {
        if (d.beat) land(d);
        world.remove(d.mesh);
        d.mesh.material.dispose();
        darts.splice(i, 1);
      }
    }

    // impact rings expand and fade
    for (let i = rings.length - 1; i >= 0; i--) {
      const r = rings[i];
      r.t += 0.016;
      r.mesh.scale.setScalar((0.5 + r.t * 2.4) * r.scale);
      r.mesh.material.opacity = Math.max(0, 0.95 - r.t * 1.05);
      r.mesh.quaternion.copy(camera.quaternion);
      if (r.t >= 1) {
        world.remove(r.mesh);
        r.mesh.material.dispose();
        rings.splice(i, 1);
      }
    }

    if (flashLife > 0) {
      flashLife = Math.max(0, flashLife - 0.05);
      flash.intensity = 26 * flashLife * flashLife;
    }

    dust.rotation.y = elapsed * 0.008;
    controls.update();
    composer.render();
  }
  frame();

  return {
    /** Swap the narration's vocabulary when the reader changes language, without remounting. */
    setWords(next) {
      Object.assign(W, next || {});
    },
    /** Jump the narration to a phase — used by the console panel, which has a real verdict. */
    setPhase(name) {
      const beat = BEATS.find((b) => b.phase === name);
      if (beat) runBeat(beat);
    },
    dispose() {
      cancelAnimationFrame(raf);
      removeEventListener("resize", resize);
      if (ro) ro.disconnect();
      controls.dispose();
      composer.dispose();
      renderer.dispose();
    },
  };
}
