// The playground: a real Lockbox (same core, Web Crypto) in the browser, with a few months of history.
// All values are generated at random in your browser; nothing here is a real credential.

import { Lockbox, MemoryStore } from "./core/lockbox.js";
import { newKey, toB64, randomBytes } from "./core/crypto.js";

const rnd = (n) => toB64(randomBytes(n)).replace(/[+/=]/g, "").slice(0, n);

export async function createDemo() {
  let clock = Date.now() - 140 * 864e5;
  const now = () => new Date(clock ?? Date.now());
  const advance = (days) => { clock += days * 864e5 + Math.floor(Math.random() * 6 * 36e5); };

  const { lockbox, rootToken } = await Lockbox.open({ store: new MemoryStore(), master: { id: "mk-1", key: newKey() }, now });
  const root = await lockbox.authenticate(rootToken);
  const tokens = { root: rootToken };
  const client = async (name, policies) => { tokens[name] = (await lockbox.createClient(root, name, policies)).token; };
  const as = async (name) => lockbox.authenticate(tokens[name]);

  await client("steuerrechner-app", [{ path: "steuerrechner/*", capabilities: ["read", "list"] }]);
  await client("ci-pipeline", [{ path: "ci/*", capabilities: ["read", "list"] }, { path: "ci/build-*", capabilities: ["write"] }]);
  await client("lifeboat-drill", [{ path: "lifeboat/*", capabilities: ["read", "list"] }]);

  advance(2);
  await lockbox.put(root, "steuerrechner/estv-api-key", `demo-estv-${rnd(24)}`, { rotateAfterDays: 90 });
  await lockbox.put(root, "steuerrechner/db-password", rnd(20), { rotateAfterDays: 60 });
  await lockbox.put(root, "ci/ghcr-token", `demo-ghcr-${rnd(30)}`, { rotateAfterDays: 30 });
  await lockbox.put(root, "lifeboat/backup-key", toB64(randomBytes(32)), { rotateAfterDays: 365 });
  await lockbox.put(root, "monitoring/discord-webhook", `https://discord.example/api/webhooks/demo/${rnd(28)}`);
  for (let week = 0; week < 18; week++) {
    advance(7);
    await lockbox.get(await as("steuerrechner-app"), "steuerrechner/estv-api-key");
    await lockbox.get(await as("ci-pipeline"), "ci/ghcr-token");
    if (week % 3 === 0) await lockbox.put(await as("ci-pipeline"), "ci/build-cache-key", rnd(16));
    if (week === 4 || week === 13) await lockbox.put(root, "steuerrechner/db-password", rnd(20));
    if (week === 10 || week === 16) await lockbox.put(root, "ci/ghcr-token", `demo-ghcr-${rnd(30)}`);
    if (week === 8) {
      await lockbox.get(await as("lifeboat-drill"), "lifeboat/backup-key");
      await lockbox.get(await as("steuerrechner-app"), "ci/ghcr-token").catch(() => {}); // denied: not its secret
      await lockbox.authenticate("lbx_" + rnd(32)).catch(() => {}); // someone guessing tokens
    }
  }
  clock = null; // from now on the real time

  const identities = [
    { name: "root", label: "Platform admin", desc: "all paths, clients, audit log, master key", badge: "admin", token: tokens.root },
    { name: "steuerrechner-app", label: "An app", desc: "may only read steuerrechner/*", badge: "read", token: tokens["steuerrechner-app"] },
    { name: "ci-pipeline", label: "The CI pipeline", desc: "reads ci/*, may write ci/build-*", badge: "read + write", token: tokens["ci-pipeline"] },
    { name: "lifeboat-drill", label: "LIFEBOAT's nightly drill", desc: "may only read lifeboat/*", badge: "read", token: tokens["lifeboat-drill"] },
    { name: "intruder", label: "An attacker", desc: "a guessed token", badge: "no access", token: "lbx_" + rnd(32) },
  ];
  return { lockbox, identities };
}
