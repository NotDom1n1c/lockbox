// LOCKBOX core: a small secrets manager.
//
// Envelope encryption: every secret version gets its own random data key (DEK). The value is
// encrypted with the DEK, the DEK is encrypted ("wrapped") with the master key. The master key
// itself is never stored: it comes from the environment and lives only in memory.
// Rotating the master key re-wraps the data keys; no secret value has to be decrypted for that.
//
// The associated data binds each ciphertext to its path and version, so ciphertexts cannot be
// swapped between secrets in the stored file.

import { importKey, seal, open, utf8, fromUtf8, randomBytes, randomToken, sha256Hex, safeEqual } from "./crypto.js";
import { allowed, validatePolicies } from "./policy.js";
import { appendEntry, verifyChain } from "./audit.js";

export const ROOT_POLICIES = [{ path: "**", capabilities: ["read", "write", "list", "admin"] }];
const PATH_RE = /^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*){0,7}$/;
const MAX_VALUE = 64 * 1024;

export class LockboxError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const emptyState = () => ({ format: 1, secrets: {}, clients: {}, audit: [] });

export class Lockbox {
  /**
   * @param store   { load(): Promise<state|null>, save(state): Promise<void> }
   * @param master  { id, key } base64 AES-256 key, from the environment
   */
  static async open({ store, master, now = () => new Date() }) {
    const lb = new Lockbox();
    lb.store = store;
    lb.now = now;
    lb.masterId = master.id || "mk-1";
    lb.master = await importKey(master.key);
    lb.state = (await store.load()) || emptyState();
    lb.queue = Promise.resolve();
    let rootToken = null;
    if (!Object.keys(lb.state.clients).length) {
      rootToken = await lb.#addClient("root", ROOT_POLICIES, "system");
      await lb.#audit("system", "lockbox.initialized", null, "ok", "root client created");
      await lb.#save();
    }
    await lb.#checkMaster();
    return { lockbox: lb, rootToken };
  }

  // every change runs one after the other, so the audit chain stays consistent
  #serial(fn) {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => {});
    return run;
  }

  async #save() { await this.store.save(this.state); }
  #iso() { return this.now().toISOString(); }
  #audit(actor, action, path, result, detail) {
    return appendEntry(this.state.audit, { at: this.#iso(), actor, action, path, result, detail });
  }

  // refuse to start with the wrong master key instead of failing on the first read
  async #checkMaster() {
    for (const s of Object.values(this.state.secrets)) {
      const v = s.versions.at(-1);
      if (!v) continue;
      try { await this.#unwrap(s.path, v); } catch { throw new LockboxError(500, "the master key does not match the stored data keys"); }
      return;
    }
  }

  async #addClient(name, policies, actor) {
    const token = randomToken();
    const id = `c-${Object.keys(this.state.clients).length + 1}-${name}`;
    this.state.clients[id] = { id, name, policies: validatePolicies(policies), tokenHash: await sha256Hex(token), createdAt: this.#iso(), createdBy: actor, revoked: false };
    return token;
  }

  // ------------------------------------------------------------------ auth
  async authenticate(token) {
    const hash = await sha256Hex(String(token || ""));
    const client = Object.values(this.state.clients).find((c) => !c.revoked && safeEqual(c.tokenHash, hash));
    if (!client) {
      await this.#serial(async () => { await this.#audit("anonymous", "auth", null, "denied", "unknown or revoked token"); await this.#save(); });
      throw new LockboxError(401, "unknown or revoked token");
    }
    return client;
  }

  async #require(client, capability, path) {
    if (!allowed(client.policies, capability, path)) {
      await this.#audit(client.name, `${capability}`, path, "denied", "no rule allows this");
      await this.#save();
      throw new LockboxError(403, `${client.name} may not ${capability} ${path}`);
    }
  }

  // ------------------------------------------------------------------ crypto
  #aad(path, version) { return `lockbox:${path}:v${version}`; }

  async #unwrap(path, v) {
    if (v.key.master !== this.masterId) throw new LockboxError(500, `data key is wrapped with ${v.key.master}, not ${this.masterId}`);
    return open(this.master, { iv: v.key.iv, ct: v.key.wrapped }, `${this.#aad(path, v.version)}:dek:${v.key.master}`);
  }

  async #encrypt(path, version, value) {
    const dekRaw = randomBytes(32);
    const dek = await importKey(dekRaw);
    const data = await seal(dek, utf8(value), this.#aad(path, version));
    const wrapped = await seal(this.master, dekRaw, `${this.#aad(path, version)}:dek:${this.masterId}`);
    dekRaw.fill(0);
    return { iv: data.iv, ciphertext: data.ct, key: { master: this.masterId, iv: wrapped.iv, wrapped: wrapped.ct } };
  }

  // ------------------------------------------------------------------ secrets
  put(client, path, value, { rotateAfterDays = null } = {}) {
    return this.#serial(async () => {
      if (!PATH_RE.test(path || "")) throw new LockboxError(400, "paths look like app/database-password (lowercase, max 8 levels)");
      if (typeof value !== "string" || !value.length) throw new LockboxError(400, "the value must be a non-empty string");
      if (utf8(value).length > MAX_VALUE) throw new LockboxError(413, "values are limited to 64 KB");
      await this.#require(client, "write", path);
      const s = this.state.secrets[path] || (this.state.secrets[path] = { path, versions: [], createdAt: this.#iso(), rotateAfterDays: null });
      const version = (s.versions.at(-1)?.version || 0) + 1;
      s.versions.push({ version, createdAt: this.#iso(), createdBy: client.name, ...(await this.#encrypt(path, version, value)) });
      if (s.versions.length > 10) s.versions.shift(); // keep the last 10 versions
      if (rotateAfterDays !== undefined) s.rotateAfterDays = rotateAfterDays ? Math.max(1, Math.min(3650, Number(rotateAfterDays))) : null;
      await this.#audit(client.name, "write", path, "ok", `version ${version}`);
      await this.#save();
      return { path, version };
    });
  }

  get(client, path, version = null) {
    return this.#serial(async () => {
      await this.#require(client, "read", path);
      const s = this.state.secrets[path];
      const v = s && (version ? s.versions.find((x) => x.version === Number(version)) : s.versions.at(-1));
      if (!v) {
        await this.#audit(client.name, "read", path, "not found", version ? `version ${version}` : null);
        await this.#save();
        throw new LockboxError(404, `no secret at ${path}${version ? ` version ${version}` : ""}`);
      }
      const dek = await importKey(await this.#unwrap(path, v));
      let value;
      try {
        value = fromUtf8(await open(dek, { iv: v.iv, ct: v.ciphertext }, this.#aad(path, v.version)));
      } catch {
        await this.#audit(client.name, "read", path, "integrity error", `version ${v.version}`);
        await this.#save();
        throw new LockboxError(500, "the stored ciphertext failed authentication (tampered or moved)");
      }
      await this.#audit(client.name, "read", path, "ok", `version ${v.version}`);
      await this.#save();
      return { path, version: v.version, value, createdAt: v.createdAt };
    });
  }

  list(client, prefix = "") {
    const out = [];
    const nowMs = this.now().getTime();
    for (const s of Object.values(this.state.secrets)) {
      if (!s.path.startsWith(prefix) || !allowed(client.policies, "list", s.path)) continue;
      const last = s.versions.at(-1);
      const ageDays = (nowMs - new Date(last.createdAt).getTime()) / 864e5;
      out.push({
        path: s.path, version: last.version, versions: s.versions.map((v) => ({ version: v.version, createdAt: v.createdAt, createdBy: v.createdBy })),
        updatedAt: last.createdAt, rotateAfterDays: s.rotateAfterDays,
        stale: Boolean(s.rotateAfterDays && ageDays > s.rotateAfterDays),
        canRead: allowed(client.policies, "read", s.path), canWrite: allowed(client.policies, "write", s.path),
      });
    }
    return out.sort((a, b) => a.path.localeCompare(b.path));
  }

  destroy(client, path) {
    return this.#serial(async () => {
      await this.#require(client, "write", path);
      if (!this.state.secrets[path]) throw new LockboxError(404, `no secret at ${path}`);
      const n = this.state.secrets[path].versions.length;
      delete this.state.secrets[path]; // the wrapped data keys are gone: the values are unrecoverable
      await this.#audit(client.name, "destroy", path, "ok", `${n} versions`);
      await this.#save();
      return { path, destroyed: n };
    });
  }

  // ------------------------------------------------------------------ clients
  createClient(client, name, policies) {
    return this.#serial(async () => {
      await this.#require(client, "admin", "sys/clients");
      if (!/^[a-z0-9][a-z0-9-]{1,40}$/.test(name || "")) throw new LockboxError(400, "client names are lowercase letters, digits and dashes");
      if (Object.values(this.state.clients).some((c) => c.name === name && !c.revoked)) throw new LockboxError(409, `a client called ${name} exists`);
      let token;
      try { token = await this.#addClient(name, policies, client.name); } catch (err) { throw new LockboxError(400, err.message); }
      await this.#audit(client.name, "client.create", `sys/clients/${name}`, "ok", JSON.stringify(validatePolicies(policies)));
      await this.#save();
      return { name, token }; // the token is shown once; only its hash is stored
    });
  }

  listClients(client) {
    if (!allowed(client.policies, "admin", "sys/clients")) throw new LockboxError(403, `${client.name} may not see clients`);
    return Object.values(this.state.clients).map(({ tokenHash, ...c }) => c);
  }

  revokeClient(client, name) {
    return this.#serial(async () => {
      await this.#require(client, "admin", "sys/clients");
      const c = Object.values(this.state.clients).find((x) => x.name === name && !x.revoked);
      if (!c) throw new LockboxError(404, `no active client ${name}`);
      if (c.id === client.id) throw new LockboxError(400, "you cannot revoke yourself");
      c.revoked = true;
      c.revokedAt = this.#iso();
      await this.#audit(client.name, "client.revoke", `sys/clients/${name}`, "ok", null);
      await this.#save();
      return { name, revoked: true };
    });
  }

  // ------------------------------------------------------------------ system
  auditLog(client) {
    if (!allowed(client.policies, "admin", "sys/audit")) throw new LockboxError(403, `${client.name} may not read the audit log`);
    return this.state.audit;
  }

  verifyAudit() { return verifyChain(this.state.audit); }

  // new master key: unwrap every data key with the old one, wrap it with the new one
  rotateMaster(client, newKeyB64, newId) {
    return this.#serial(async () => {
      await this.#require(client, "admin", "sys/master");
      if (!/^mk-[a-z0-9-]{1,20}$/.test(newId || "") || newId === this.masterId) throw new LockboxError(400, "give the new key a new id like mk-2");
      const next = await importKey(newKeyB64);
      let count = 0;
      for (const s of Object.values(this.state.secrets)) {
        for (const v of s.versions) {
          const dekRaw = await this.#unwrap(s.path, v);
          const wrapped = await seal(next, dekRaw, `${this.#aad(s.path, v.version)}:dek:${newId}`);
          dekRaw.fill(0);
          v.key = { master: newId, iv: wrapped.iv, wrapped: wrapped.ct };
          count++;
        }
      }
      const old = this.masterId;
      this.master = next;
      this.masterId = newId;
      await this.#audit(client.name, "master.rotate", "sys/master", "ok", `${old} -> ${newId}, ${count} data keys re-wrapped`);
      await this.#save();
      return { from: old, to: newId, rewrapped: count };
    });
  }

  status() {
    const secrets = Object.values(this.state.secrets);
    return {
      masterKey: this.masterId,
      secrets: secrets.length,
      versions: secrets.reduce((n, s) => n + s.versions.length, 0),
      clients: Object.values(this.state.clients).filter((c) => !c.revoked).length,
      auditEntries: this.state.audit.length,
    };
  }

  // what someone who steals the data file gets: ciphertext, wrapped keys and token hashes
  rawState(client) {
    if (!allowed(client.policies, "admin", "sys/raw")) throw new LockboxError(403, `${client.name} may not see the raw store`);
    return this.state;
  }
}

export class MemoryStore {
  constructor(state = null) { this.state = state; }
  async load() { return this.state ? structuredClone(this.state) : null; }
  async save(state) { this.state = structuredClone(state); }
}
