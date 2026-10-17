// The vault door on the sign-in screen, built from primitives in three.js.
// typed(n): the combination dial turns as a token is typed
// unlock(): dial to zero, wheel turns, bolts retract, door swings open (resolves when open)
// deny():   the door shudders and a red lamp flashes
// close():  back to a locked door

import * as THREE from "./vendor/three.module.min.js";
import { RoomEnvironment } from "./vendor/RoomEnvironment.js";

const BRASS = 0xc9a24a;

function dialTexture() {
  const c = document.createElement("canvas");
  c.width = c.height = 1024;
  const g = c.getContext("2d");
  const cx = 512;
  const grad = g.createRadialGradient(cx, cx, 60, cx, cx, 512);
  grad.addColorStop(0, "#2a2620");
  grad.addColorStop(1, "#0f0e0c");
  g.fillStyle = grad;
  g.fillRect(0, 0, 1024, 1024);
  g.translate(cx, cx);
  for (let i = 0; i < 100; i++) {
    g.save();
    g.rotate((i / 100) * Math.PI * 2);
    g.fillStyle = "#d9b55e";
    const long = i % 10 === 0, mid = i % 5 === 0;
    g.fillRect(-3, -500, 6, long ? 70 : mid ? 46 : 28);
    if (long) {
      g.font = "600 64px Georgia, serif";
      g.textAlign = "center";
      g.fillText(String(i), 0, -370);
    }
    g.restore();
  }
  g.strokeStyle = "#d9b55e";
  g.lineWidth = 6;
  g.beginPath();
  g.arc(0, 0, 300, 0, Math.PI * 2);
  g.stroke();
  const tex = new THREE.CanvasTexture(c);
  tex.colorSpace = THREE.SRGBColorSpace;
  tex.anisotropy = 4;
  return tex;
}

export function createVault(canvas, { reducedMotion = false } = {}) {
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  } catch {
    return null;
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.ACESFilmicToneMapping;
  renderer.toneMappingExposure = 1.05;

  const scene = new THREE.Scene();
  const pmrem = new THREE.PMREMGenerator(renderer);
  scene.environment = pmrem.fromScene(new RoomEnvironment(), 0.04).texture;

  const camera = new THREE.PerspectiveCamera(32, 1, 0.1, 100);
  camera.position.set(0, 0.2, 15);

  const steel = new THREE.MeshStandardMaterial({ color: 0x8c9196, metalness: 0.88, roughness: 0.32 });
  const darkSteel = new THREE.MeshStandardMaterial({ color: 0x3b4044, metalness: 0.85, roughness: 0.45 });
  const brass = new THREE.MeshStandardMaterial({ color: BRASS, metalness: 1, roughness: 0.28 });
  const wallMat = new THREE.MeshStandardMaterial({ color: 0x0c0e0e, metalness: 0.2, roughness: 0.95, envMapIntensity: 0.12 });

  // ---------------------------------------------------------------- wall + frame
  const wallShape = new THREE.Shape();
  wallShape.moveTo(-20, -15).lineTo(20, -15).lineTo(20, 15).lineTo(-20, 15).lineTo(-20, -15);
  const opening = new THREE.Path();
  opening.absarc(0, 0, 3.32, 0, Math.PI * 2, true);
  wallShape.holes.push(opening);
  const wall = new THREE.Mesh(new THREE.ShapeGeometry(wallShape, 64), wallMat);
  wall.position.z = -0.8;
  scene.add(wall);
  const frameRing = new THREE.Mesh(new THREE.TorusGeometry(3.55, 0.32, 24, 96), darkSteel);
  frameRing.position.z = -0.35;
  scene.add(frameRing);
  const recess = new THREE.Mesh(new THREE.CylinderGeometry(3.3, 3.3, 1.2, 96, 1, true),
    new THREE.MeshStandardMaterial({ color: 0x0b0c0c, metalness: 0.6, roughness: 0.7, side: THREE.BackSide }));
  recess.rotation.x = Math.PI / 2;
  recess.position.z = -1;
  scene.add(recess);
  // what is inside: warm light on stacked deposit boxes
  const inside = new THREE.Group();
  inside.position.z = -2.4;
  scene.add(inside);
  const boxMat = new THREE.MeshStandardMaterial({ color: 0x6d5a2c, metalness: 0.9, roughness: 0.38 });
  for (let r = -2; r <= 2; r++) for (let c = -2; c <= 2; c++) {
    if (r * r + c * c > 6) continue;
    const b = new THREE.Mesh(new THREE.BoxGeometry(1.05, 0.62, 0.3), boxMat);
    b.position.set(c * 1.12, r * 0.7, 0);
    inside.add(b);
    const knob = new THREE.Mesh(new THREE.SphereGeometry(0.05, 10, 8), brass);
    knob.position.set(c * 1.12, r * 0.7, 0.17);
    inside.add(knob);
  }
  const warm = new THREE.PointLight(0xffc56b, 0, 9, 1.6);
  warm.position.set(0, 0, -0.6);
  scene.add(warm);

  // ---------------------------------------------------------------- the door (pivots on its left hinge)
  const hinge = new THREE.Group();
  hinge.position.set(-3.25, 0, 0);
  scene.add(hinge);
  const door = new THREE.Group();
  door.position.set(3.25, 0, 0);
  hinge.add(door);

  const slab = new THREE.Mesh(new THREE.CylinderGeometry(3.2, 3.2, 0.9, 128), steel);
  slab.rotation.x = Math.PI / 2;
  door.add(slab);
  for (const [r, t] of [[2.95, 0.05], [2.2, 0.035], [1.35, 0.03]]) {
    const ring = new THREE.Mesh(new THREE.TorusGeometry(r, t, 12, 128), darkSteel);
    ring.position.z = 0.46;
    door.add(ring);
  }
  // locking bolts around the rim
  const bolts = [];
  for (let i = 0; i < 12; i++) {
    const a = (i / 12) * Math.PI * 2;
    const bolt = new THREE.Mesh(new THREE.CylinderGeometry(0.16, 0.16, 0.7, 20), steel);
    bolt.rotation.z = a + Math.PI / 2;
    bolt.userData = { a, out: 3.25, in: 2.55 };
    bolt.position.set(Math.cos(a) * 3.25, Math.sin(a) * 3.25, 0);
    door.add(bolt);
    bolts.push(bolt);
    const rivet = new THREE.Mesh(new THREE.SphereGeometry(0.09, 12, 8), brass);
    rivet.position.set(Math.cos(a + Math.PI / 12) * 2.6, Math.sin(a + Math.PI / 12) * 2.6, 0.46);
    door.add(rivet);
  }
  // combination dial
  const dial = new THREE.Group();
  dial.position.set(0, 1.3, 0.48);
  door.add(dial);
  const dialFace = new THREE.Mesh(new THREE.CylinderGeometry(0.95, 1.0, 0.16, 96),
    [darkSteel, new THREE.MeshStandardMaterial({ map: dialTexture(), metalness: 0.5, roughness: 0.4 }), darkSteel]);
  dialFace.rotation.x = Math.PI / 2;
  dial.add(dialFace);
  const knob = new THREE.Mesh(new THREE.CylinderGeometry(0.34, 0.4, 0.34, 48), brass);
  knob.rotation.x = Math.PI / 2;
  knob.position.z = 0.2;
  dial.add(knob);
  const index = new THREE.Mesh(new THREE.ConeGeometry(0.09, 0.2, 3), brass);
  index.position.set(0, 2.38, 0.5);
  index.rotation.z = Math.PI;
  door.add(index);
  // spoked handle wheel
  const wheel = new THREE.Group();
  wheel.position.set(0, -1.3, 0.56);
  door.add(wheel);
  const hub = new THREE.Mesh(new THREE.CylinderGeometry(0.32, 0.36, 0.3, 40), brass);
  hub.rotation.x = Math.PI / 2;
  wheel.add(hub);
  for (let i = 0; i < 3; i++) {
    const a = (i / 3) * Math.PI * 2 + Math.PI / 2;
    const spoke = new THREE.Mesh(new THREE.CylinderGeometry(0.065, 0.065, 0.95, 16), brass);
    spoke.position.set(Math.cos(a) * 0.48, Math.sin(a) * 0.48, 0.1);
    spoke.rotation.z = a + Math.PI / 2;
    wheel.add(spoke);
    const ball = new THREE.Mesh(new THREE.SphereGeometry(0.15, 20, 14), brass);
    ball.position.set(Math.cos(a) * 0.96, Math.sin(a) * 0.96, 0.1);
    wheel.add(ball);
  }
  // hinges
  for (const y of [1.6, -1.6]) {
    const h = new THREE.Mesh(new THREE.CylinderGeometry(0.22, 0.22, 0.9, 24), darkSteel);
    h.position.set(-3.3, y, 0.2);
    scene.add(h);
  }
  // status lamp above the door
  const lampMat = new THREE.MeshStandardMaterial({ color: 0x2b1a14, emissive: 0x000000, metalness: 0.2, roughness: 0.3 });
  const lamp = new THREE.Mesh(new THREE.SphereGeometry(0.16, 20, 14), lampMat);
  lamp.position.set(0, 4.15, 0);
  scene.add(lamp);

  // ---------------------------------------------------------------- lights
  scene.add(new THREE.AmbientLight(0xffffff, 0.15));
  const key = new THREE.DirectionalLight(0xfff1d6, 2.2);
  key.position.set(-5, 6, 9);
  scene.add(key);
  const rim = new THREE.DirectionalLight(0x9fb7c9, 1.0);
  rim.position.set(6, -3, 4);
  scene.add(rim);

  // ---------------------------------------------------------------- state + animation
  const st = { dial: 0, dialTarget: 0, wheel: 0, wheelTarget: 0, open: 0, openTarget: 0, boltIn: 0, boltTarget: 0, shake: 0, red: 0, green: 0, tiltX: 0, tiltY: 0, px: 0, py: 0 };
  const ease = (cur, target, k, dt) => cur + (target - cur) * Math.min(1, dt * k);
  const wait = (ms) => new Promise((r) => setTimeout(r, reducedMotion ? Math.min(ms, 120) : ms));

  function resize() {
    const w = canvas.clientWidth, h = canvas.clientHeight;
    if (!w || !h) return;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    // keep the whole door in view on narrow screens
    camera.position.z = 17.2 * Math.max(1, h / w); // the whole door + frame always fits
    camera.updateProjectionMatrix();
  }

  window.addEventListener("pointermove", (e) => {
    st.px = (e.clientX / innerWidth) * 2 - 1;
    st.py = (e.clientY / innerHeight) * 2 - 1;
  });

  let raf = 0, last = performance.now();
  function frame(now) {
    raf = requestAnimationFrame(frame);
    if (document.hidden || canvas.offsetParent === null) { last = now; return; }
    const dt = Math.min((now - last) / 1000, 0.05);
    last = now;
    const t = now / 1000;
    if (!reducedMotion) {
      st.tiltX = ease(st.tiltX, st.py * 0.08, 3, dt);
      st.tiltY = ease(st.tiltY, st.px * 0.12, 3, dt);
    }
    st.dial = ease(st.dial, st.dialTarget, 6, dt);
    st.wheel = ease(st.wheel, st.wheelTarget, 4, dt);
    st.boltIn = ease(st.boltIn, st.boltTarget, 5, dt);
    st.open = ease(st.open, st.openTarget, 2.2, dt);
    st.shake = Math.max(0, st.shake - dt * 2.5);
    st.red = Math.max(0, st.red - dt * 0.9);

    scene.rotation.set(st.tiltX, st.tiltY, 0);
    dial.rotation.z = st.dial;
    wheel.rotation.z = st.wheel;
    for (const b of bolts) {
      const r = b.userData.out - (b.userData.out - b.userData.in) * st.boltIn;
      b.position.set(Math.cos(b.userData.a) * r, Math.sin(b.userData.a) * r, 0);
    }
    hinge.rotation.y = -st.open * 1.75;
    hinge.position.x = -3.25 + Math.sin(t * 60) * st.shake * 0.06;
    warm.intensity = st.open * 22;
    lampMat.emissive.setRGB(st.red * 1.4 + st.green * 0.1, st.green * 1.1, st.green * 0.4);
    renderer.render(scene, camera);
  }

  const ro = new ResizeObserver(resize);
  ro.observe(canvas);
  resize();
  raf = requestAnimationFrame(frame);

  return {
    typed(n) { st.dialTarget = -n * 0.42; },
    async unlock() {
      st.green = 1;
      st.dialTarget = Math.round(st.dialTarget / (Math.PI * 2) - 1) * Math.PI * 2; // spin back to 0
      await wait(420);
      st.wheelTarget -= Math.PI * 0.75;
      await wait(380);
      st.boltTarget = 1;
      await wait(380);
      st.openTarget = 1;
      await wait(900);
    },
    deny() {
      st.shake = 1;
      st.red = 1;
      st.dialTarget += 2.2;
    },
    close() {
      st.openTarget = 0;
      st.boltTarget = 0;
      st.wheelTarget = 0;
      st.dialTarget = 0;
      st.green = 0;
    },
    dispose() { cancelAnimationFrame(raf); ro.disconnect(); renderer.dispose(); },
  };
}
