#!/usr/bin/env node
// integrity · verify — the standalone, out-of-page verifier (the "real" one from
// integrity/verifier-decision.md). Takes a URL (or local dist) and proves, OUT OF
// BAND, that the served site is exactly what an allowed identity built and logged.
//
//   node integrity/verify/verify.mjs https://bounded.tools
//   node integrity/verify/verify.mjs ./dist
//
// Unlike the zero-dep verify-site.mjs (which shells out to cosign and SKIPS the
// signature step when cosign is absent), this verifies the published Sigstore
// BUNDLE cryptographically IN-PROCESS via sigstore-js:
//   - signature over the whole-site manifest
//   - certificate chain to the Fulcio root (bundled trusted root — no network)
//   - Rekor inclusion proof (offline; NOT the deprecated Rekor query API)
//   - issuer enforced by sigstore-js; the cert SAN regex-matched here (cosign-style)
// then re-hashes every served file against the signed manifest (tolerating known,
// named CDN edge transforms — the signed body must still be intact underneath).
//
// Why a bundle, not a Rekor query: Rekor v2 removed get-by-index/leaf-hash, so the
// query path is a dead end. The bundle we publish carries its own inclusion proof,
// so verification is offline and survives the v2 transition. SRI-pinnable and
// npm-publishable (with its own Sigstore provenance) — the same core a browser
// extension or CI policy would consume.
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { verify as sigstoreVerify } from "sigstore";

const target = process.argv[2];
if (!target) { console.error("usage: verify <https://site | ./dist>"); process.exit(2); }
const isUrl = /^https?:\/\//.test(target);
const base = isUrl ? target.replace(/\/$/, "") : target;
const ISSUER = "https://token.actions.githubusercontent.com";
const sha256hex = (buf) => createHash("sha256").update(buf).digest("hex");

async function load(path) {
  if (isUrl) {
    const res = await fetch(`${base}/${path}`, { cache: "no-store" });
    if (!res.ok) throw new Error(`GET /${path} → ${res.status}`);
    return Buffer.from(await res.arrayBuffer());
  }
  return readFile(join(base, path));
}

// Known, named CDN edge transforms (see verify-site.mjs): a legitimate edge may
// rewrite a response; if stripping a NAMED transform restores the signed hash, the
// body is intact and only the edge added markup. Anything else is a real mismatch.
const KNOWN_EDGE_INJECTIONS = [
  { name: "cloudflare-js-detections", applies: (p) => /\.html$/.test(p),
    re: /<script\b[^>]*>(?:(?!<\/script>)[\s\S])*?(?:__CF\$cv\$params|cdn-cgi\/challenge-platform)(?:(?!<\/script>)[\s\S])*?<\/script>/g },
  { name: "cloudflare-managed-robots", applies: (p) => /(^|\/)robots\.txt$/.test(p),
    re: /^[\s\S]*?# END Cloudflare Managed Content\n+/ },
];
const stripKnownEdge = (buf, path) => {
  let s = buf.toString("utf8"); const hit = [];
  for (const r of KNOWN_EDGE_INJECTIONS) { if (!r.applies(path)) continue; const n = s.replace(r.re, ""); if (n !== s) { hit.push(r.name); s = n; } }
  return { stripped: Buffer.from(s, "utf8"), hit };
};

let failures = 0;
const log = (ok, msg) => { console.log(`${ok ? "✓" : "✗"} ${msg}`); if (!ok) failures++; };

// load provenance + the signed manifest + its bundle
const provenance = JSON.parse((await load("provenance.json")).toString("utf8"));
const repo = provenance?.builder?.repository || "";
const identityRe = `^https://github.com/${repo}/`;
const manifest = await load("site.sha256");
const bundle = JSON.parse((await load("site.sha256.sigstore.json")).toString("utf8"));

console.log(`· site: ${base}`);
console.log(`· builder: ${repo} @ ${(provenance?.builder?.commit || "").slice(0, 7)} · rekor#${provenance?.siteManifest?.rekorLogIndex ?? "?"}`);
if (provenance?.builtAt) {
  const ms = Date.now() - Date.parse(provenance.builtAt);
  const age = Number.isFinite(ms) ? (ms < 36e5 ? `${Math.round(ms / 6e4)}m` : ms < 864e5 ? `${Math.round(ms / 36e5)}h` : `${Math.round(ms / 864e5)}d`) : "?";
  console.log(`· built: ${provenance.builtAt} (${age} ago)`);
}

// 1: cryptographic bundle verification, in-process, offline
try {
  const signer = await sigstoreVerify(bundle, manifest, { certificateIssuer: ISSUER });
  const san = signer?.identity?.subjectAlternativeName || "";
  if (!new RegExp(identityRe).test(san)) throw new Error(`cert identity ${san} !~ ${identityRe}`);
  log(true, `bundle verified — signature + Fulcio cert + Rekor inclusion (offline), identity ${san}`);
} catch (e) {
  log(false, `bundle verification FAILED: ${e.message}`);
}

// 2: byte-for-byte integrity of every served file (edge-transform tolerant)
const entries = manifest.toString("utf8").trim().split("\n").filter(Boolean).map((l) => {
  const i = l.indexOf("  "); return { hash: l.slice(0, i), path: l.slice(i + 2) };
});
let mismatches = 0, edged = 0; const edgeNames = new Set();
for (const { hash, path } of entries) {
  try {
    const bytes = await load(path);
    if (sha256hex(bytes) === hash) continue;
    if (isUrl) {
      const { stripped, hit } = stripKnownEdge(bytes, path);
      if (hit.length && sha256hex(stripped) === hash) { edged++; hit.forEach((n) => edgeNames.add(n)); continue; }
    }
    mismatches++; console.log(`  ✗ ${path}: ${sha256hex(bytes).slice(0, 12)}… ≠ ${hash.slice(0, 12)}…`);
  } catch (e) { mismatches++; console.log(`  ✗ ${path}: ${e.message}`); }
}
log(mismatches === 0, `${entries.length} served files match the signed manifest${mismatches ? ` (${mismatches} mismatch)` : edged ? ` (${edged} after stripping known edge injections: ${[...edgeNames].join(", ")})` : ""}`);

console.log(failures ? `\n✗ verification FAILED (${failures})` : `\n✓ verified: ${base} is exactly what ${repo} built and logged`);
process.exit(failures ? 1 : 0);
