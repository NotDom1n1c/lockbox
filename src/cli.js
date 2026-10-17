#!/usr/bin/env node
// lockbox CLI. Needs LOCKBOX_ADDR (default http://localhost:8200) and LOCKBOX_TOKEN.
//
//   lockbox ls [prefix]
//   lockbox get <path> [--version N]
//   lockbox put <path> <value|->              "-" reads the value from stdin
//   lockbox run --prefix app/ -- <command>    starts <command> with app/* as environment variables
//
// `run` is how apps get secrets without .env files: app/db-password becomes DB_PASSWORD,
// only in the memory of that one process.

import { spawn } from "node:child_process";

const addr = (process.env.LOCKBOX_ADDR || "http://localhost:8200").replace(/\/$/, "");
const token = process.env.LOCKBOX_TOKEN || "";

async function call(method, path, body) {
  const res = await fetch(addr + path, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`${res.status} ${data.error || res.statusText}`);
  return data;
}

const envName = (path) => path.split("/").pop().toUpperCase().replace(/[^A-Z0-9]/g, "_");

async function stdin() {
  let s = "";
  for await (const c of process.stdin) s += c;
  return s.replace(/\n$/, "");
}

async function main(argv) {
  const [cmd, ...rest] = argv;
  if (cmd === "ls") {
    for (const s of await call("GET", `/v1/list?prefix=${encodeURIComponent(rest[0] || "")}`)) {
      console.log(`${s.path.padEnd(40)} v${s.version}${s.stale ? "  (rotate me)" : ""}`);
    }
  } else if (cmd === "get") {
    const v = rest.indexOf("--version");
    const q = v >= 0 ? `?version=${rest[v + 1]}` : "";
    process.stdout.write((await call("GET", `/v1/secrets/${rest[0]}${q}`)).value + "\n");
  } else if (cmd === "put") {
    const value = rest[1] === "-" ? await stdin() : rest[1];
    const r = await call("PUT", `/v1/secrets/${rest[0]}`, { value });
    console.log(`${r.path} is now version ${r.version}`);
  } else if (cmd === "run") {
    const p = rest.indexOf("--prefix");
    const sep = rest.indexOf("--");
    if (p < 0 || sep < 0) throw new Error("usage: lockbox run --prefix app/ -- <command> [args]");
    const prefix = rest[p + 1];
    const env = { ...process.env };
    delete env.LOCKBOX_TOKEN; // the child gets its secrets, not the key to all of them
    for (const s of await call("GET", `/v1/list?prefix=${encodeURIComponent(prefix)}`)) {
      if (s.canRead) env[envName(s.path)] = (await call("GET", `/v1/secrets/${s.path}`)).value;
    }
    const [command, ...args] = rest.slice(sep + 1);
    // no shell: arguments pass through untouched (spaces, quotes), and nothing gets interpreted
    const child = spawn(command, args, { stdio: "inherit", env });
    child.on("exit", (code) => process.exit(code ?? 1));
    return;
  } else {
    console.log("usage: lockbox ls [prefix] | get <path> [--version N] | put <path> <value|-> | run --prefix p/ -- cmd");
    process.exitCode = 2;
  }
}

main(process.argv.slice(2)).catch((err) => { console.error(`lockbox: ${err.message}`); process.exit(1); });
