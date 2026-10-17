// LOCKBOX HTTP API + web UI.
//
//   LOCKBOX_MASTER_KEY   base64, 32 bytes (required unless LOCKBOX_DEV=1)
//   LOCKBOX_MASTER_ID    id of that key, e.g. mk-1 (default mk-1)
//   LOCKBOX_DATA         data file (default ./data/lockbox.json)
//   PORT                 default 8200

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { Lockbox, LockboxError, MemoryStore } from "../public/core/lockbox.js";
import { newKey } from "../public/core/crypto.js";
import { FileStore } from "./filestore.js";

const PUBLIC = fileURLToPath(new URL("../public/", import.meta.url));
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml" };
const HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "cache-control": "no-store",
  "content-security-policy": "default-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; frame-ancestors 'none'",
};

// brute-force brake: 10 failed logins per minute per address
const failures = new Map();
function tooManyFailures(ip) {
  const now = Date.now();
  const recent = (failures.get(ip) || []).filter((t) => now - t < 60_000);
  failures.set(ip, recent);
  return recent.length >= 10;
}

export async function createApp({ lockbox }) {
  const send = (res, status, body, type) => {
    const json = type === undefined;
    res.writeHead(status, { ...HEADERS, "content-type": type || "application/json; charset=utf-8" });
    res.end(json ? JSON.stringify(body) : body);
  };

  async function body(req) {
    if (!String(req.headers["content-type"] || "").startsWith("application/json")) throw new LockboxError(415, "send JSON");
    let raw = "";
    for await (const c of req) { raw += c; if (raw.length > 100_000) throw new LockboxError(413, "body too large"); }
    try { return JSON.parse(raw || "{}"); } catch { throw new LockboxError(400, "invalid JSON"); }
  }

  async function auth(req) {
    const ip = req.socket.remoteAddress || "?";
    if (tooManyFailures(ip)) throw new LockboxError(429, "too many failed logins, wait a minute");
    const token = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
    try {
      return await lockbox.authenticate(token);
    } catch (err) {
      failures.get(ip).push(Date.now());
      throw err;
    }
  }

  async function api(req, res, path, query) {
    const m = req.method;
    if (path === "/v1/health") return send(res, 200, { ok: true });
    const client = await auth(req);
    let r;
    if (m === "GET" && path === "/v1/me") return send(res, 200, { name: client.name, policies: client.policies });
    if (m === "GET" && path === "/v1/list") return send(res, 200, lockbox.list(client, query.get("prefix") || ""));
    if ((r = path.match(/^\/v1\/secrets\/(.+)$/))) {
      const secret = decodeURIComponent(r[1]);
      if (m === "GET") return send(res, 200, await lockbox.get(client, secret, query.get("version")));
      if (m === "PUT") { const b = await body(req); return send(res, 200, await lockbox.put(client, secret, b.value, { rotateAfterDays: b.rotateAfterDays })); }
      if (m === "DELETE") { await body(req); return send(res, 200, await lockbox.destroy(client, secret)); }
    }
    if (m === "GET" && path === "/v1/clients") return send(res, 200, lockbox.listClients(client));
    if (m === "POST" && path === "/v1/clients") { const b = await body(req); return send(res, 201, await lockbox.createClient(client, b.name, b.policies)); }
    if (m === "DELETE" && (r = path.match(/^\/v1\/clients\/([a-z0-9-]+)$/))) { await body(req); return send(res, 200, await lockbox.revokeClient(client, r[1])); }
    if (m === "GET" && path === "/v1/audit") return send(res, 200, { entries: lockbox.auditLog(client), chain: await lockbox.verifyAudit() });
    if (m === "GET" && path === "/v1/sys/status") return send(res, 200, lockbox.status());
    if (m === "GET" && path === "/v1/sys/raw") return send(res, 200, lockbox.rawState(client));
    if (m === "POST" && path === "/v1/sys/rotate-master") { const b = await body(req); return send(res, 200, await lockbox.rotateMaster(client, b.key, b.id)); }
    return send(res, 404, { error: "not found" });
  }

  async function serveStatic(res, path) {
    const file = normalize(join(PUBLIC, path === "/" ? "index.html" : path));
    if (!file.startsWith(normalize(PUBLIC))) return send(res, 403, "forbidden", "text/plain");
    try { send(res, 200, await readFile(file), TYPES[extname(file)] || "application/octet-stream"); }
    catch { send(res, 404, "not found", "text/plain"); }
  }

  return async (req, res) => {
    const url = new URL(req.url, "http://lockbox");
    try {
      if (url.pathname.startsWith("/v1/")) return await api(req, res, url.pathname, url.searchParams);
      if (req.method !== "GET") return send(res, 405, { error: "method not allowed" });
      return await serveStatic(res, url.pathname);
    } catch (err) {
      const status = err instanceof LockboxError ? err.status : 500;
      if (status >= 500) console.error(err);
      return send(res, status, { error: err instanceof LockboxError ? err.message : "internal error" });
    }
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const dev = process.env.LOCKBOX_DEV === "1";
  let key = process.env.LOCKBOX_MASTER_KEY;
  if (!key && dev) { key = newKey(); console.log("DEV MODE: throwaway master key, data kept in memory only"); }
  if (!key) { console.error("LOCKBOX_MASTER_KEY is required (32 random bytes, base64). For a try-out: LOCKBOX_DEV=1"); process.exit(1); }
  const store = dev ? new MemoryStore() : new FileStore(process.env.LOCKBOX_DATA || "data/lockbox.json");
  let opened;
  try {
    opened = await Lockbox.open({ store, master: { id: process.env.LOCKBOX_MASTER_ID || "mk-1", key } });
  } catch (err) {
    console.error(`LOCKBOX refuses to start: ${err.message}`);
    process.exit(1);
  }
  const { lockbox, rootToken } = opened;
  if (rootToken) console.log(`\nFirst start. Root token (shown ONCE, store it safely):\n  ${rootToken}\n`);
  const port = Number(process.env.PORT || 8200);
  const server = createServer(await createApp({ lockbox }));
  server.listen(port, () => console.log(`LOCKBOX on :${port}`));
  process.on("SIGTERM", () => server.close(() => process.exit(0)));
}
