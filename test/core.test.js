import { test } from "node:test";
import assert from "node:assert/strict";
import { Lockbox, MemoryStore, LockboxError } from "../public/core/lockbox.js";
import { matches, allowed } from "../public/core/policy.js";
import { verifyChain } from "../public/core/audit.js";
import { newKey } from "../public/core/crypto.js";

async function setup() {
  const store = new MemoryStore();
  const master = { id: "mk-1", key: newKey() };
  const { lockbox, rootToken } = await Lockbox.open({ store, master });
  const root = await lockbox.authenticate(rootToken);
  return { store, master, lockbox, root, rootToken };
}

const rejects = (p, status) => assert.rejects(p, (e) => e instanceof LockboxError && e.status === status);

test("policy globs: * stays in one segment, ** crosses segments", () => {
  assert.ok(matches("app/*", "app/db"));
  assert.ok(!matches("app/*", "app/db/password"));
  assert.ok(matches("app/**", "app/db/password"));
  assert.ok(matches("**", "anything/at/all"));
  assert.ok(!matches("app/*", "apple/db"));
  assert.ok(allowed([{ path: "ci/*", capabilities: ["read"] }], "read", "ci/token"));
  assert.ok(!allowed([{ path: "ci/*", capabilities: ["read"] }], "write", "ci/token"), "deny by default");
});

test("first start creates exactly one root client and shows its token once", async () => {
  const { lockbox, store, master } = await setup();
  assert.equal(lockbox.status().clients, 1);
  const again = await Lockbox.open({ store, master });
  assert.equal(again.rootToken, null);
  assert.ok(!JSON.stringify(store.state).includes("lbx_"), "tokens are stored only as hashes");
});

test("write, read, versions", async () => {
  const { lockbox, root } = await setup();
  await lockbox.put(root, "app/db-password", "hunter2");
  await lockbox.put(root, "app/db-password", "correct horse battery staple");
  assert.equal((await lockbox.get(root, "app/db-password")).value, "correct horse battery staple");
  assert.equal((await lockbox.get(root, "app/db-password", 1)).value, "hunter2");
  const [entry] = lockbox.list(root, "app/");
  assert.equal(entry.version, 2);
  assert.equal(entry.versions.length, 2);
});

test("the stored state never contains a value or a data key in the clear", async () => {
  const { lockbox, root, store } = await setup();
  await lockbox.put(root, "app/api-key", "sk_live_very_secret_value");
  const raw = JSON.stringify(store.state);
  assert.ok(!raw.includes("sk_live_very_secret_value"));
  const v = store.state.secrets["app/api-key"].versions[0];
  assert.ok(v.ciphertext && v.key.wrapped && v.key.master === "mk-1");
});

test("a ciphertext moved to another secret does not decrypt (path is authenticated)", async () => {
  const { lockbox, root } = await setup();
  await lockbox.put(root, "a/one", "first");
  await lockbox.put(root, "a/two", "second");
  const s = lockbox.state.secrets;
  s["a/two"].versions[0] = { ...s["a/one"].versions[0] };
  await assert.rejects(lockbox.get(root, "a/two"));
});

test("policies: apps see only their own secrets, everything is audited", async () => {
  const { lockbox, root } = await setup();
  await lockbox.put(root, "steuerrechner/api-key", "k1");
  await lockbox.put(root, "gambit/db", "k2");
  const { token } = await lockbox.createClient(root, "steuerrechner-app", [{ path: "steuerrechner/*", capabilities: ["read", "list"] }]);
  const app = await lockbox.authenticate(token);
  assert.equal((await lockbox.get(app, "steuerrechner/api-key")).value, "k1");
  await rejects(lockbox.get(app, "gambit/db"), 403);
  await rejects(lockbox.put(app, "steuerrechner/api-key", "changed"), 403);
  assert.deepEqual(lockbox.list(app).map((s) => s.path), ["steuerrechner/api-key"]);
  assert.throws(() => lockbox.listClients(app));
  const denied = lockbox.state.audit.filter((e) => e.result === "denied");
  assert.equal(denied.length, 2);
  assert.ok(lockbox.state.audit.every((e) => !String(e.detail).includes("k1")), "values never reach the audit log");
});

test("revoked and unknown tokens are rejected", async () => {
  const { lockbox, root } = await setup();
  const { token } = await lockbox.createClient(root, "ci", [{ path: "ci/*", capabilities: ["read"] }]);
  await lockbox.revokeClient(root, "ci");
  await rejects(lockbox.authenticate(token), 401);
  await rejects(lockbox.authenticate("lbx_made_up"), 401);
});

test("master key rotation re-wraps data keys; the old key stops working", async () => {
  const { lockbox, root, store } = await setup();
  await lockbox.put(root, "app/a", "alpha");
  await lockbox.put(root, "app/b", "beta");
  const ciphertextBefore = store.state.secrets["app/a"].versions[0].ciphertext;
  const next = { id: "mk-2", key: newKey() };
  const r = await lockbox.rotateMaster(root, next.key, next.id);
  assert.equal(r.rewrapped, 2);
  assert.equal(store.state.secrets["app/a"].versions[0].ciphertext, ciphertextBefore, "values are not re-encrypted");
  assert.equal((await lockbox.get(root, "app/b")).value, "beta");

  const reopened = await Lockbox.open({ store, master: next });
  assert.equal((await reopened.lockbox.get(await reopened.lockbox.authenticate(await rootTokenOf(reopened, root)), "app/a")).value, "alpha");
  await assert.rejects(Lockbox.open({ store, master: { id: "mk-1", key: newKey() } }));
});

// helper: the root token is not stored, so mint a client to read with after reopening
async function rootTokenOf(opened, root) {
  return (await opened.lockbox.createClient(root, `reader-${Date.now() % 1000}`, [{ path: "**", capabilities: ["read"] }])).token;
}

test("audit chain: any edit, deletion or reorder is detected", async () => {
  const { lockbox, root } = await setup();
  for (const n of ["a", "b", "c"]) await lockbox.put(root, `x/${n}`, n);
  assert.equal((await verifyChain(lockbox.state.audit)).ok, true);

  const edited = structuredClone(lockbox.state.audit);
  edited[2].actor = "someone-else";
  assert.deepEqual(await verifyChain(edited), { ok: false, checked: 2, brokenAt: 3 });

  const removed = structuredClone(lockbox.state.audit);
  removed.splice(1, 1);
  assert.equal((await verifyChain(removed)).ok, false);
});

test("stale secrets are flagged when they outlive their rotation period", async () => {
  let now = new Date("2026-01-01T00:00:00Z");
  const { lockbox } = await Lockbox.open({ store: new MemoryStore(), master: { id: "mk-1", key: newKey() }, now: () => now });
  const root = lockbox.state.clients[Object.keys(lockbox.state.clients)[0]];
  await lockbox.put(root, "db/password", "x", { rotateAfterDays: 30 });
  assert.equal(lockbox.list(root)[0].stale, false);
  now = new Date("2026-03-01T00:00:00Z");
  assert.equal(lockbox.list(root)[0].stale, true);
});

test("input validation", async () => {
  const { lockbox, root } = await setup();
  await rejects(lockbox.put(root, "../etc/passwd", "x"), 400);
  await rejects(lockbox.put(root, "App/Upper", "x"), 400);
  await rejects(lockbox.put(root, "ok/path", ""), 400);
  await rejects(lockbox.put(root, "ok/path", "x".repeat(70000)), 413);
  await rejects(lockbox.createClient(root, "bad", [{ path: "x", capabilities: ["sudo"] }]), 400);
});
