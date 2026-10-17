import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { createApp } from "../src/server.js";
import { Lockbox, MemoryStore } from "../public/core/lockbox.js";
import { newKey } from "../public/core/crypto.js";

const run = promisify(execFile);
let server, base, root;

before(async () => {
  const { lockbox, rootToken } = await Lockbox.open({ store: new MemoryStore(), master: { id: "mk-1", key: newKey() } });
  root = rootToken;
  server = createServer(await createApp({ lockbox }));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const call = (method, path, token, body) => fetch(base + path, {
  method,
  headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body ? { "content-type": "application/json" } : {}) },
  body: body ? JSON.stringify(body) : undefined,
});

test("health is public, everything else needs a token", async () => {
  assert.equal((await call("GET", "/v1/health")).status, 200);
  assert.equal((await call("GET", "/v1/list")).status, 401);
});

test("put and get through the API, with security headers", async () => {
  const put = await call("PUT", "/v1/secrets/shop/db-password", root, { value: "s3cret", rotateAfterDays: 90 });
  assert.equal(put.status, 200);
  const res = await call("GET", "/v1/secrets/shop/db-password", root);
  assert.equal((await res.json()).value, "s3cret");
  assert.equal(res.headers.get("cache-control"), "no-store");
  assert.equal(res.headers.get("x-frame-options"), "DENY");
});

test("writes require JSON (no cross-site form posts)", async () => {
  const res = await fetch(`${base}/v1/secrets/shop/x`, { method: "PUT", headers: { authorization: `Bearer ${root}`, "content-type": "text/plain" }, body: "value=1" });
  assert.equal(res.status, 415);
});

test("clients get scoped tokens", async () => {
  const created = await (await call("POST", "/v1/clients", root, { name: "shop-app", policies: [{ path: "shop/*", capabilities: ["read", "list"] }] })).json();
  assert.match(created.token, /^lbx_/);
  assert.equal((await call("GET", "/v1/secrets/shop/db-password", created.token)).status, 200);
  assert.equal((await call("PUT", "/v1/secrets/shop/db-password", created.token, { value: "x" })).status, 403);
  assert.equal((await call("GET", "/v1/clients", created.token)).status, 403);
});

test("CLI run injects secrets as environment variables, without the LOCKBOX token", async () => {
  await call("PUT", "/v1/secrets/shop/api-key", root, { value: "key-123" });
  const cli = fileURLToPath(new URL("../src/cli.js", import.meta.url));
  const { stdout } = await run(process.execPath, [cli, "run", "--prefix", "shop/", "--", process.execPath, "-e",
    "console.log([process.env.DB_PASSWORD, process.env.API_KEY, process.env.LOCKBOX_TOKEN ?? 'none'].join(','))"],
  { env: { ...process.env, LOCKBOX_ADDR: base, LOCKBOX_TOKEN: root } });
  assert.equal(stdout.trim(), "s3cret,key-123,none");
});

test("audit endpoint returns the log and a valid chain", async () => {
  const body = await (await call("GET", "/v1/audit", root)).json();
  assert.equal(body.chain.ok, true);
  assert.ok(body.entries.some((e) => e.action === "read" && e.path === "shop/db-password"));
});

test("brute force: 10 bad tokens per minute, then 429", async () => {
  for (let i = 0; i < 10; i++) await call("GET", "/v1/list", `lbx_guess_${i}`);
  assert.equal((await call("GET", "/v1/list", "lbx_guess_x")).status, 429);
});
