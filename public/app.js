// LOCKBOX web UI. Talks to the HTTP API, or (playground) to a Lockbox running in this browser tab.

import { newKey } from "./core/crypto.js";

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const DEMO = location.hostname.endsWith("github.io") || new URLSearchParams(location.search).has("demo");

let api, me, tab = "secrets", selected = null, revealed = null, demo = null;
let vault = null; // the 3D door on the sign-in screen
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function toast(text) {
  const t = $("#toast");
  t.textContent = text;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), 3600);
}

const when = (iso) => new Date(iso).toLocaleString("de-CH", { dateStyle: "medium", timeStyle: "short" });
const ago = (iso) => {
  const d = (Date.now() - new Date(iso).getTime()) / 864e5;
  return d < 1 ? "today" : d < 2 ? "yesterday" : `${Math.floor(d)} days ago`;
};

// ------------------------------------------------------------------ api: HTTP or in-browser
function httpApi(token) {
  const call = async (method, path, body) => {
    const res = await fetch(path, {
      method,
      headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error(data.error || `HTTP ${res.status}`), { status: res.status });
    return data;
  };
  return {
    me: () => call("GET", "/v1/me"),
    list: () => call("GET", "/v1/list"),
    get: (p, v) => call("GET", `/v1/secrets/${p}${v ? `?version=${v}` : ""}`),
    put: (p, value, rotateAfterDays) => call("PUT", `/v1/secrets/${p}`, { value, rotateAfterDays }),
    destroy: (p) => call("DELETE", `/v1/secrets/${p}`, {}),
    clients: () => call("GET", "/v1/clients"),
    createClient: (name, policies) => call("POST", "/v1/clients", { name, policies }),
    revoke: (name) => call("DELETE", `/v1/clients/${name}`, {}),
    audit: () => call("GET", "/v1/audit"),
    raw: () => call("GET", "/v1/sys/raw"),
    status: () => call("GET", "/v1/sys/status"),
    rotate: (key, id) => call("POST", "/v1/sys/rotate-master", { key, id }),
  };
}

function localApi(lockbox, token) {
  const as = () => lockbox.authenticate(token);
  const wrap = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { throw Object.assign(new Error(e.message), { status: e.status }); } };
  return {
    me: wrap(async () => { const c = await as(); return { name: c.name, policies: c.policies }; }),
    list: wrap(async () => lockbox.list(await as())),
    get: wrap(async (p, v) => lockbox.get(await as(), p, v)),
    put: wrap(async (p, value, r) => lockbox.put(await as(), p, value, { rotateAfterDays: r })),
    destroy: wrap(async (p) => lockbox.destroy(await as(), p)),
    clients: wrap(async () => lockbox.listClients(await as())),
    createClient: wrap(async (n, pol) => lockbox.createClient(await as(), n, pol)),
    revoke: wrap(async (n) => lockbox.revokeClient(await as(), n)),
    audit: wrap(async () => ({ entries: structuredClone(lockbox.auditLog(await as())), chain: await lockbox.verifyAudit() })),
    raw: wrap(async () => structuredClone(lockbox.rawState(await as()))),
    status: wrap(async () => lockbox.status()),
    rotate: wrap(async (k, id) => lockbox.rotateMaster(await as(), k, id)),
  };
}

const isAdmin = () => me?.policies.some((p) => p.capabilities.includes("admin"));

// ------------------------------------------------------------------ login
async function signIn(token) {
  const candidate = DEMO ? localApi(demo.lockbox, token) : httpApi(token);
  let who;
  try {
    who = await candidate.me();
  } catch (err) {
    $("#login-error").textContent = err.status === 429 ? "Too many failed attempts. Wait a minute." : `Denied: ${err.message}. This attempt is in the ledger.`;
    $("#login-error").hidden = false;
    $("#door-caption").textContent = "Access denied · logged";
    $("#door-caption").className = "door__caption is-denied";
    vault?.deny();
    return;
  }
  $("#login-error").hidden = true;
  $("#door-caption").textContent = `Opening for ${who.name}`;
  $("#door-caption").className = "door__caption is-open";
  if (vault && !$("#login").hidden) await vault.unlock();
  me = who;
  api = candidate;
  if (!DEMO) sessionStorage.setItem("lockbox-token", token);
  $("#login").hidden = true;
  $("#app").hidden = false;
  $("#who").innerHTML = `signed in as <b>${esc(me.name)}</b>`;
  document.querySelectorAll("[data-admin]").forEach((b) => (b.hidden = !isAdmin()));
  tab = "secrets"; selected = null; revealed = null;
  render();
}

function showLogin() {
  me = null; api = null;
  sessionStorage.removeItem("lockbox-token");
  $("#app").hidden = true;
  $("#login").hidden = false;
  $("#login-error").hidden = true;
  $("#token").value = "";
  $("#door-caption").textContent = "Locked · AES-256-GCM";
  $("#door-caption").className = "door__caption";
  vault?.close();
}

// ------------------------------------------------------------------ views
async function render() {
  document.querySelectorAll("#tabs [data-tab]").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === tab)));
  const view = $("#view");
  try {
    if (tab === "secrets") await renderSecrets(view);
    if (tab === "clients") await renderClients(view);
    if (tab === "audit") await renderAudit(view);
    if (tab === "storage") await renderStorage(view);
  } catch (err) {
    view.innerHTML = `<div class="denied">${esc(err.message)}</div>`;
  }
}

function canWriteSomewhere() { return me.policies.some((p) => p.capabilities.includes("write")); }

async function renderSecrets(view) {
  const items = await api.list();
  if (selected && !items.some((s) => s.path === selected)) selected = null;
  const groups = {};
  const plate = new Map(items.map((s, i) => [s.path, String(i + 1).padStart(3, "0")]));
  for (const s of items) (groups[s.path.split("/")[0]] ||= []).push(s);
  const cur = items.find((s) => s.path === selected);

  view.innerHTML = `
    <div class="split">
      <aside class="panel">
        <div class="head"><h2>Deposit boxes</h2>${canWriteSomewhere() ? '<button class="btn btn--brass btn--sm" id="new" type="button">New</button>' : ""}</div>
        ${items.length ? `<ul class="list">${Object.entries(groups).map(([g, list]) => `
          <li class="group">${esc(g)}</li>
          ${list.map((s) => `<li><button type="button" data-path="${esc(s.path)}" aria-current="${s.path === selected}">
            <span class="plate">No.${plate.get(s.path)}</span>
            <span class="name">${esc(s.path.slice(g.length + 1))}</span>
            <span class="keyhole" aria-hidden="true"></span>
            ${s.stale ? '<span class="badge badge--warn">rotate</span>' : ""}
            <span class="lock">v${s.version}</span></button></li>`).join("")}`).join("")}</ul>`
          : `<p class="empty">You may not list any secrets.</p>`}
        <form class="stack mt" id="try">
          <span class="label">Read any path</span>
          <input name="path" placeholder="ci/ghcr-token" spellcheck="false">
          <button class="btn btn--sm" type="submit">Try to read</button>
        </form>
      </aside>
      <section class="panel doc" id="detail">${cur ? detail(cur) : newForm()}</section>
    </div>`;

  view.querySelectorAll("[data-path]").forEach((b) => b.addEventListener("click", () => { selected = b.dataset.path; revealed = null; render(); }));
  view.querySelector("#new")?.addEventListener("click", () => { selected = null; render(); });
  view.querySelector("#try").addEventListener("submit", async (e) => {
    e.preventDefault();
    const path = e.target.path.value.trim();
    try {
      const r = await api.get(path);
      selected = path; revealed = { version: r.version, value: r.value };
      render();
    } catch (err) {
      $("#detail").innerHTML = `<div class="denied"><b>${err.status === 403 ? "Access denied" : "Not possible"}</b> ${esc(err.message)}.<br>
        ${err.status === 403 ? "LOCKBOX refused before decrypting anything, and wrote the attempt to the audit log." : ""}</div>`;
    }
  });
  wireDetail(cur);
}

function newForm() {
  if (!canWriteSomewhere()) return `<div class="empty">Pick a secret on the left.<br><span class="small">${esc(me.name)} can read, not write.</span></div>`;
  return `
    <h2>Deposit a secret</h2>
    <p class="muted small">Encrypted with its own data key, which is wrapped with the master key. Only the ciphertext is stored.</p>
    <form class="stack" id="create">
      <label class="label" for="c-path">Path</label>
      <input id="c-path" name="path" placeholder="${me.name === "ci-pipeline" ? "ci/build-signing-key" : "steuerrechner/smtp-password"}" spellcheck="false" required>
      <div class="form-grid">
        <div><label class="label" for="c-value">Value</label><input id="c-value" name="value" type="password" required></div>
        <div><label class="label" for="c-rot">Rotate after (days)</label><input id="c-rot" name="rot" type="number" min="1" max="3650" placeholder="90"></div>
      </div>
      <button class="btn btn--brass" type="submit">Encrypt and store</button>
    </form>`;
}

function detail(s) {
  const shown = revealed && revealed.version ? revealed : null;
  return `
    <div class="head"><p class="secret__path">${esc(s.path)}</p>
      <span class="row">${s.stale ? '<span class="badge badge--warn">due for rotation</span>' : ""}<span class="badge badge--brass">version ${s.version}</span></span></div>
    <div class="value">
      <code>${shown ? esc(shown.value) : '<span class="dots">••••••••••••••••</span>'}</code>
      ${s.canRead ? `<button class="btn btn--sm" id="reveal" type="button">${shown ? "Hide" : "Reveal"}</button>
        <button class="btn btn--sm" id="copy" type="button">Copy</button>` : '<span class="badge badge--bad">no read access</span>'}
    </div>
    ${shown && shown.version !== s.version ? `<p class="small muted">Showing version ${shown.version} (not the newest).</p>` : ""}
    <dl class="meta">
      <dt>Updated</dt><dd>${esc(when(s.updatedAt))} (${esc(ago(s.updatedAt))})</dd>
      <dt>Rotation</dt><dd>${s.rotateAfterDays ? `every ${s.rotateAfterDays} days` : "no reminder"}</dd>
      <dt>Reads</dt><dd>every reveal is written to the audit log</dd>
    </dl>
    <h3>Versions</h3>
    <table class="versions"><thead><tr><th>v</th><th>written</th><th>by</th><th></th></tr></thead><tbody>
      ${[...s.versions].reverse().map((v) => `<tr><td class="mono">${v.version}</td><td>${esc(when(v.createdAt))}</td><td class="mono">${esc(v.createdBy)}</td>
        <td>${s.canRead ? `<button class="btn btn--sm btn--ghost" data-version="${v.version}" type="button">Reveal v${v.version}</button>` : ""}</td></tr>`).join("")}
    </tbody></table>
    ${s.canWrite ? `
      <h3>Rotate: write a new version</h3>
      <form class="row" id="rotate"><input class="grow" name="value" type="password" placeholder="new value" required>
        <button class="btn btn--brass" type="submit">Save version ${s.version + 1}</button></form>
      <div class="row mt"><button class="btn btn--danger btn--sm" id="destroy" type="button">Destroy all versions</button></div>` : ""}`;
}

function wireDetail(s) {
  const d = $("#detail");
  d.querySelector("#create")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      const r = await api.put(f.path.value.trim(), f.value.value, f.rot.value ? Number(f.rot.value) : null);
      selected = r.path; revealed = null;
      toast(`${r.path} stored as version ${r.version}`);
      render();
    } catch (err) { toast(err.message); }
  });
  if (!s) return;
  d.querySelector("#reveal")?.addEventListener("click", async () => {
    if (revealed) { revealed = null; return render(); }
    try { const r = await api.get(s.path); revealed = { version: r.version, value: r.value }; render(); } catch (err) { toast(err.message); }
  });
  d.querySelector("#copy")?.addEventListener("click", async () => {
    try { const r = await api.get(s.path); await navigator.clipboard.writeText(r.value); toast("Copied. The read is in the audit log."); } catch (err) { toast(err.message); }
  });
  d.querySelectorAll("[data-version]").forEach((b) => b.addEventListener("click", async () => {
    try { const r = await api.get(s.path, b.dataset.version); revealed = { version: r.version, value: r.value }; render(); } catch (err) { toast(err.message); }
  }));
  d.querySelector("#rotate")?.addEventListener("submit", async (e) => {
    e.preventDefault();
    try { const r = await api.put(s.path, e.target.value.value); revealed = null; toast(`Version ${r.version} saved. Apps get it on their next read.`); render(); } catch (err) { toast(err.message); }
  });
  d.querySelector("#destroy")?.addEventListener("click", async () => {
    if (!confirm(`Destroy every version of ${s.path}? The data keys are deleted, so the values cannot be recovered.`)) return;
    try { await api.destroy(s.path); selected = null; toast(`${s.path} destroyed`); render(); } catch (err) { toast(err.message); }
  });
}

async function renderClients(view) {
  const clients = await api.clients();
  view.innerHTML = `
    <div class="cols2">
      <section class="panel">
        <div class="head"><h2>Clients</h2><p class="muted small">Apps and people. Each has its own token and only the rules it needs.</p></div>
        <div class="table-wrap"><table class="data"><thead><tr><th>Name</th><th>Rules</th><th>Created</th><th></th></tr></thead><tbody>
          ${clients.map((c) => `<tr><td class="mono">${esc(c.name)}${c.revoked ? ' <span class="badge badge--bad">revoked</span>' : ""}</td>
            <td><div class="rules">${c.policies.map((p) => `<code>${esc(p.path)} → ${esc(p.capabilities.join(", "))}</code>`).join("")}</div></td>
            <td class="mono">${esc(when(c.createdAt))}</td>
            <td>${!c.revoked && c.name !== me.name ? `<button class="btn btn--danger btn--sm" data-revoke="${esc(c.name)}" type="button">Revoke</button>` : ""}</td></tr>`).join("")}
        </tbody></table></div>
      </section>
      <section class="panel">
        <h2>New client</h2>
        <p class="muted small">Least privilege: give it only the paths and capabilities it needs.</p>
        <form class="stack" id="client">
          <label class="label" for="cl-name">Name</label>
          <input id="cl-name" name="name" placeholder="gambit-app" required>
          <span class="label">Rules</span>
          <div class="rule-row">
            <input name="rpath" value="gambit/*" spellcheck="false">
            <div class="caps">${["read", "list", "write", "admin"].map((c) => `<label><input type="checkbox" name="cap" value="${c}" ${c === "read" || c === "list" ? "checked" : ""}>${c}</label>`).join("")}</div>
          </div>
          <button class="btn btn--brass" type="submit">Create client</button>
        </form>
        <div id="token-out"></div>
      </section>
    </div>`;
  view.querySelectorAll("[data-revoke]").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm(`Revoke ${b.dataset.revoke}? Its token stops working immediately.`)) return;
    try { await api.revoke(b.dataset.revoke); toast(`${b.dataset.revoke} revoked`); render(); } catch (err) { toast(err.message); }
  }));
  view.querySelector("#client").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    const caps = [...f.querySelectorAll("[name=cap]:checked")].map((x) => x.value);
    try {
      const r = await api.createClient(f.name.value.trim(), [{ path: f.rpath.value.trim(), capabilities: caps }]);
      if (demo) demo.identities.splice(demo.identities.length - 1, 0, { name: r.name, label: "Created by you", desc: `${f.rpath.value.trim()} → ${caps.join(", ")}`, badge: "custom", token: r.token });
      await renderClients(view);
      $("#token-out").innerHTML = `<div class="token-box"><b>Token for ${esc(r.name)}</b> (shown once, LOCKBOX keeps only its SHA-256 hash):<code>${esc(r.token)}</code>
        ${demo ? '<span class="small muted">In the playground it also appears on the sign-in screen. Try it.</span>' : ""}</div>`;
    } catch (err) { toast(err.message); }
  });
}

async function renderAudit(view) {
  const { entries, chain } = await api.audit();
  const brokenAt = chain.ok ? null : chain.brokenAt;
  view.innerHTML = `
    <section class="panel ledger">
      <div class="head"><h2>The ledger</h2>${demo ? '<button class="btn btn--danger btn--sm" id="tamper" type="button">Tamper with an entry</button>' : ""}</div>
      <div class="chain ${chain.ok ? "chain--ok" : "chain--bad"}">
        ${chain.ok
          ? `<b>Verified</b><span>All ${chain.checked} entries hash-chained and intact. Head <code>${esc(chain.head.slice(0, 16))}…</code></span>`
          : `<b>Tampered</b><span>The chain breaks at entry #${brokenAt}: someone changed, removed or reordered the ledger. Nothing from there on can be trusted.</span>`}
      </div>
      <p class="muted small">Each entry stores the SHA-256 of the one before it. Values are never logged, only who touched which path.</p>
      <div class="table-wrap"><table class="data"><thead><tr><th>#</th><th>When</th><th>Who</th><th>Action</th><th>Path</th><th>Result</th><th>Hash</th></tr></thead><tbody>
        ${[...entries].reverse().slice(0, 250).map((e) => `<tr class="${brokenAt && e.seq >= brokenAt ? "broken" : ""}">
          <td class="mono">${e.seq}</td><td class="mono">${esc(when(e.at))}</td><td class="mono">${esc(e.actor)}</td><td>${esc(e.action)}</td>
          <td class="mono">${esc(e.path || "")}</td>
          <td><span class="badge ${e.result === "ok" ? "badge--ok" : e.result === "denied" ? "badge--bad" : "badge--warn"}">${esc(e.result)}</span></td>
          <td class="mono muted">${esc(e.hash.slice(0, 10))}</td></tr>`).join("")}
      </tbody></table></div>
    </section>`;
  view.querySelector("#tamper")?.addEventListener("click", async () => {
    // what an insider with access to the data file might try: hide that they read a secret
    const log = demo.lockbox.state.audit;
    const target = [...log].reverse().find((e) => e.action === "read" && e.result === "ok" && e.actor !== "intruder");
    if (!target) return toast("No read entry to hide yet.");
    target.actor = "nobody";
    toast(`Entry #${target.seq} edited: "${target.path}" now looks like it was read by "nobody".`);
    renderAudit(view);
  });
}

function rawPreview(state) {
  const cut = (s) => (typeof s === "string" && s.length > 44 ? `${s.slice(0, 44)}…` : s);
  const slim = {
    secrets: Object.fromEntries(Object.entries(state.secrets).slice(0, 3).map(([k, s]) => [k, { ...s, versions: s.versions.slice(-1).map((v) => ({ ...v, iv: cut(v.iv), ciphertext: cut(v.ciphertext), key: { ...v.key, iv: cut(v.key.iv), wrapped: cut(v.key.wrapped) } })) }])),
    clients: Object.fromEntries(Object.entries(state.clients).slice(0, 2).map(([k, c]) => [k, { name: c.name, tokenHash: c.tokenHash, policies: c.policies }])),
    audit: `[${state.audit.length} hash-chained entries]`,
  };
  return esc(JSON.stringify(slim, null, 2)).replace(/&quot;([a-zA-Z]+)&quot;:/g, '<span class="k">"$1"</span>:');
}

async function renderStorage(view) {
  const [state, status] = await Promise.all([api.raw(), api.status()]);
  view.innerHTML = `
    <div class="cols2">
      <section class="panel">
        <div class="head"><h2>What a thief gets</h2><p class="muted small">This is the stored data (shortened): everything an attacker has after stealing the database file.</p></div>
        <pre class="raw">${rawPreview(state)}</pre>
      </section>
      <section class="panel doc">
        <h2>Why that is useless</h2>
        <ul class="facts">
          <li><b>Values</b> are AES-256-GCM ciphertext, each with its <b>own data key</b>.</li>
          <li><b>Data keys</b> are wrapped with master key <code>${esc(status.masterKey)}</code>, which is <b>not in this file</b>: it comes from the environment and lives only in memory.</li>
          <li><b>Path and version</b> are authenticated: moving a ciphertext to another secret makes it fail to decrypt.</li>
          <li><b>Tokens</b> are stored as SHA-256 hashes, so the file does not let anyone sign in.</li>
          <li><b>${status.secrets} secrets</b>, ${status.versions} versions, ${status.clients} active clients, ${status.auditEntries} audit entries.</li>
        </ul>
        <h3 class="mt">Rotate the master key</h3>
        <p class="muted small">Unwraps every data key with the old master key and wraps it with a new one. No secret value is decrypted or re-encrypted.</p>
        <button class="btn btn--brass" id="rotate-master" type="button">Generate and rotate to a new master key</button>
        <div id="rotate-out"></div>
      </section>
    </div>`;
  view.querySelector("#rotate-master").addEventListener("click", async () => {
    const key = newKey();
    const id = `mk-${Number(status.masterKey.split("-")[1] || 1) + 1}`;
    try {
      const r = await api.rotate(key, id);
      await renderStorage(view);
      $("#rotate-out").innerHTML = `<div class="token-box"><b>Rotated ${esc(r.from)} → ${esc(r.to)}</b>, ${r.rewrapped} data keys re-wrapped.
        ${demo ? "" : `<code>${esc(key)}</code><span class="small">Set LOCKBOX_MASTER_KEY to this and LOCKBOX_MASTER_ID=${esc(id)} before the next restart. It is shown once.</span>`}</div>`;
    } catch (err) { toast(err.message); }
  });
}

// ------------------------------------------------------------------ start
document.querySelectorAll("#tabs [data-tab]").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; render(); }));
$("#logout").addEventListener("click", () => { showLogin(); if (demo) renderIdentities(); });
$("#login-form").addEventListener("submit", (e) => { e.preventDefault(); signIn($("#token").value.trim()); });

function renderIdentities() {
  $("#identities").hidden = false;
  $("#id-list").innerHTML = demo.identities.map((i, n) => `
    <button class="id" type="button" data-id="${n}"><b>${esc(i.name)}</b><small>${esc(i.label)}: ${esc(i.desc)}</small>
      <span class="badge ${i.badge === "admin" ? "badge--brass" : i.badge === "no access" ? "badge--bad" : ""}">${esc(i.badge)}</span></button>`).join("");
  $("#id-list").querySelectorAll("[data-id]").forEach((b) => b.addEventListener("click", () => signIn(demo.identities[Number(b.dataset.id)].token)));
}

async function startVault() {
  try {
    const { createVault } = await import("./vault.js");
    vault = createVault($("#vault"), { reducedMotion: matchMedia("(prefers-reduced-motion: reduce)").matches });
  } catch { vault = null; }
  if (!vault) $("#vault").hidden = true;
  $("#token").addEventListener("input", (e) => vault?.typed(e.target.value.length));
}

(async function start() {
  await startVault();
  if (DEMO) {
    $("#banner").hidden = false;
    $("#login").hidden = false;
    $("#identities").hidden = false;
    $("#id-list").innerHTML = '<p class="muted small">Encrypting secrets and replaying 140 days of history in your browser…</p>';
    const { createDemo } = await import("./demo.js");
    demo = await createDemo();
    renderIdentities();
    $("#login").hidden = false;
    return;
  }
  const saved = sessionStorage.getItem("lockbox-token");
  if (saved) await signIn(saved);
  if (!me) showLogin();
})();
