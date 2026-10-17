// Access rules. Deny by default: a client may do something only if one of its rules allows it.
//
//   { path: "steuerrechner/*",  capabilities: ["read"] }
//   { path: "ci/**",            capabilities: ["read", "list"] }
//
// "*" matches inside one path segment, "**" across segments. Capabilities: read, write, list, admin.

export const CAPABILITIES = ["read", "write", "list", "admin"];

function toRegex(pattern) {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*" && pattern[i + 1] === "*") { re += ".*"; i++; }
    else if (c === "*") re += "[^/]*";
    else re += c.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

export function matches(pattern, path) {
  return toRegex(pattern).test(path);
}

export function allowed(policies, capability, path) {
  return (policies || []).some((p) => p.capabilities.includes(capability) && matches(p.path, path));
}

export function validatePolicies(policies) {
  if (!Array.isArray(policies) || policies.length === 0) throw new Error("give at least one rule");
  for (const p of policies) {
    if (typeof p.path !== "string" || !/^[a-z0-9*][a-z0-9._/*-]{0,127}$/.test(p.path)) throw new Error(`invalid rule path "${p.path}"`);
    if (!Array.isArray(p.capabilities) || !p.capabilities.length || p.capabilities.some((c) => !CAPABILITIES.includes(c))) {
      throw new Error(`capabilities must be some of ${CAPABILITIES.join(", ")}`);
    }
  }
  return policies.map((p) => ({ path: p.path, capabilities: [...new Set(p.capabilities)] }));
}
