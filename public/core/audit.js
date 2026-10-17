// Tamper-evident audit log: every entry stores the hash of the entry before it.
// Changing, removing or reordering any entry breaks the chain from that point on.
// Secret values are never written to the log.

import { sha256Hex } from "./crypto.js";

const GENESIS = "0".repeat(64);

function canonical(e) {
  return JSON.stringify([e.seq, e.at, e.actor, e.action, e.path ?? null, e.result, e.detail ?? null]);
}

export async function appendEntry(log, { at, actor, action, path, result, detail }) {
  const prev = log.length ? log[log.length - 1].hash : GENESIS;
  const entry = { seq: log.length + 1, at, actor, action, path: path ?? null, result, detail: detail ?? null, prev };
  entry.hash = await sha256Hex(prev + canonical(entry));
  log.push(entry);
  return entry;
}

export async function verifyChain(log) {
  let prev = GENESIS;
  for (let i = 0; i < log.length; i++) {
    const e = log[i];
    const expected = await sha256Hex(prev + canonical(e));
    if (e.seq !== i + 1 || e.prev !== prev || e.hash !== expected) {
      return { ok: false, checked: i, brokenAt: e.seq ?? i + 1 };
    }
    prev = e.hash;
  }
  return { ok: true, checked: log.length, head: prev };
}
