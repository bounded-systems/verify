#!/usr/bin/env -S deno run -A
// integrity · verify — the standalone, out-of-page verifier (the "real" one from
// integrity/verifier-decision.md). Takes a URL (or local dist) and proves, OUT OF
// BAND, that the served site is exactly what an allowed identity built and logged.
//
//   deno run -A jsr:@bounded-systems/verify https://bounded.tools
//   deno run -A jsr:@bounded-systems/verify ./dist
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
//
// LIBRARY + CLI. The verification logic is exported as callable functions
// (`verifyManifestBundle`, `verifySite`) with NO side effects on import. The CLI
// (argv-reading + process.exit) runs ONLY when this module is the program entry
// point (`import.meta.main`), never on import.
import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { verify as sigstoreVerify } from "sigstore";

/** The GitHub Actions OIDC issuer enforced by default. */
export const DEFAULT_ISSUER = "https://token.actions.githubusercontent.com";

const sha256hex = (buf) => createHash("sha256").update(buf).digest("hex");

// Known, named CDN edge transforms (see verify-site.mjs): a legitimate edge may
// rewrite a response; if stripping a NAMED transform restores the signed hash, the
// body is intact and only the edge added markup. Anything else is a real mismatch.
export const KNOWN_EDGE_INJECTIONS = [
  { name: "cloudflare-js-detections", applies: (p) => /\.html$/.test(p),
    re: /<script\b[^>]*>(?:(?!<\/script>)[\s\S])*?(?:__CF\$cv\$params|cdn-cgi\/challenge-platform)(?:(?!<\/script>)[\s\S])*?<\/script>/g },
  { name: "cloudflare-managed-robots", applies: (p) => /(^|\/)robots\.txt$/.test(p),
    re: /^[\s\S]*?# END Cloudflare Managed Content\n+/ },
];

/**
 * Strip known, named CDN edge transforms from a served body. Returns the stripped
 * bytes and the names of any transforms that actually applied.
 * @param {Buffer|Uint8Array} buf
 * @param {string} path
 * @returns {{ stripped: Buffer, hit: string[] }}
 */
export function stripKnownEdge(buf, path) {
  let s = Buffer.from(buf).toString("utf8"); const hit = [];
  for (const r of KNOWN_EDGE_INJECTIONS) { if (!r.applies(path)) continue; const n = s.replace(r.re, ""); if (n !== s) { hit.push(r.name); s = n; } }
  return { stripped: Buffer.from(s, "utf8"), hit };
}

/** Error thrown when bundle verification fails. `code` carries the machine reason. */
export class VerifyError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = "VerifyError";
    this.code = code;
    Object.assign(this, details);
  }
}

/**
 * Cryptographically verify a Sigstore bundle over a whole-site manifest, in-process
 * and offline. This is the core, side-effect-free verification primitive: it wraps
 * the SAME `sigstore.verify(...)` call the CLI has always made (byte-for-byte) and
 * adds the cosign-style certificate-SAN identity match.
 *
 * Resolves to a structured result on success; throws a typed {@link VerifyError}
 * (with `.code`) on any verification failure.
 *
 * @param {object} args
 * @param {object|string} args.bundle      Parsed Sigstore bundle (object) or its JSON text.
 * @param {Buffer|Uint8Array|string} args.manifest  The signed artifact bytes (e.g. `site.sha256`).
 * @param {RegExp|string} [args.identity]  Optional: the cert SAN must match this regex.
 * @param {string} [args.issuer]           OIDC issuer to enforce (default {@link DEFAULT_ISSUER}).
 * @param {Function} [args.verifyImpl]     Injectable verifier; defaults to sigstore's `verify`.
 *                                         Production callers should leave this unset.
 * @returns {Promise<{ verified: true, identity: string, issuer: string }>}
 */
export async function verifyManifestBundle({ bundle, manifest, identity, issuer = DEFAULT_ISSUER, verifyImpl = sigstoreVerify } = {}) {
  if (bundle == null) throw new VerifyError("missing bundle", "MISSING_BUNDLE");
  if (manifest == null) throw new VerifyError("missing manifest", "MISSING_MANIFEST");
  const bundleObj = typeof bundle === "string" ? JSON.parse(bundle) : bundle;
  // Keep the artifact bytes a Buffer and pass them through UNCHANGED — the
  // sigstore.verify(...) call below is byte-for-byte identical to the original CLI.
  const artifact = Buffer.isBuffer(manifest) ? manifest : Buffer.from(manifest);
  const identityRe = identity == null ? null : (identity instanceof RegExp ? identity : new RegExp(identity));

  let signer;
  try {
    signer = await verifyImpl(bundleObj, artifact, { certificateIssuer: issuer });
  } catch (e) {
    throw new VerifyError(`bundle verification FAILED: ${e.message}`, "BUNDLE_VERIFICATION_FAILED", { cause: e });
  }
  const san = signer?.identity?.subjectAlternativeName || "";
  if (identityRe && !identityRe.test(san)) {
    throw new VerifyError(`cert identity ${san} !~ ${identityRe.source}`, "IDENTITY_MISMATCH", { identity: san });
  }
  return { verified: true, identity: san, issuer };
}

/**
 * Full out-of-band site verification: loads `provenance.json`, the signed
 * `site.sha256` manifest and its `.sigstore.json` bundle from a deployed URL (or a
 * local `dist/` directory), cryptographically verifies the bundle, then re-hashes
 * every served file against the manifest (tolerating known edge transforms).
 *
 * Side-effect-free: progress is delivered to the optional `onLog` callback; nothing
 * is printed and the process is never exited. Returns a structured result.
 *
 * @param {object} args
 * @param {string} args.target           A deployed site URL or a local directory path.
 * @param {(line: string) => void} [args.onLog]  Optional progress sink.
 * @param {Function} [args.verifyImpl]   Injectable bundle verifier (see verifyManifestBundle).
 * @returns {Promise<object>} { verified, base, builder, commit, rekorLogIndex, builtAt,
 *   identity, files: { total, mismatches, edged, edgeNames }, failures }
 */
export async function verifySite({ target, onLog, verifyImpl = sigstoreVerify } = {}) {
  if (!target) throw new VerifyError("usage: verify <https://site | ./dist>", "USAGE");
  const isUrl = /^https?:\/\//.test(target);
  const base = isUrl ? target.replace(/\/$/, "") : target;
  const emit = typeof onLog === "function" ? onLog : () => {};

  const load = async (path) => {
    if (isUrl) {
      const res = await fetch(`${base}/${path}`, { cache: "no-store" });
      if (!res.ok) throw new Error(`GET /${path} → ${res.status}`);
      return Buffer.from(await res.arrayBuffer());
    }
    return readFile(join(base, path));
  };

  let failures = 0;
  const log = (ok, msg) => { emit(`${ok ? "✓" : "✗"} ${msg}`); if (!ok) failures++; };

  // load provenance + the signed manifest + its bundle
  const provenance = JSON.parse((await load("provenance.json")).toString("utf8"));
  const repo = provenance?.builder?.repository || "";
  const identityRe = new RegExp(`^https://github.com/${repo}/`);
  const manifest = await load("site.sha256");
  const bundle = JSON.parse((await load("site.sha256.sigstore.json")).toString("utf8"));

  emit(`· site: ${base}`);
  emit(`· builder: ${repo} @ ${(provenance?.builder?.commit || "").slice(0, 7)} · rekor#${provenance?.siteManifest?.rekorLogIndex ?? "?"}`);
  if (provenance?.builtAt) {
    const ms = Date.now() - Date.parse(provenance.builtAt);
    const age = Number.isFinite(ms) ? (ms < 36e5 ? `${Math.round(ms / 6e4)}m` : ms < 864e5 ? `${Math.round(ms / 36e5)}h` : `${Math.round(ms / 864e5)}d`) : "?";
    emit(`· built: ${provenance.builtAt} (${age} ago)`);
  }

  // 1: cryptographic bundle verification, in-process, offline
  let identity = "";
  try {
    const res = await verifyManifestBundle({ bundle, manifest, identity: identityRe, issuer: DEFAULT_ISSUER, verifyImpl });
    identity = res.identity;
    log(true, `bundle verified — signature + Fulcio cert + Rekor inclusion (offline), identity ${identity}`);
  } catch (e) {
    log(false, e.message);
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
      mismatches++; emit(`  ✗ ${path}: ${sha256hex(bytes).slice(0, 12)}… ≠ ${hash.slice(0, 12)}…`);
    } catch (e) { mismatches++; emit(`  ✗ ${path}: ${e.message}`); }
  }
  log(mismatches === 0, `${entries.length} served files match the signed manifest${mismatches ? ` (${mismatches} mismatch)` : edged ? ` (${edged} after stripping known edge injections: ${[...edgeNames].join(", ")})` : ""}`);

  emit(failures ? `\n✗ verification FAILED (${failures})` : `\n✓ verified: ${base} is exactly what ${repo} built and logged`);

  return {
    verified: failures === 0,
    base,
    builder: repo,
    commit: provenance?.builder?.commit || "",
    rekorLogIndex: provenance?.siteManifest?.rekorLogIndex ?? null,
    builtAt: provenance?.builtAt ?? null,
    identity,
    files: { total: entries.length, mismatches, edged, edgeNames: [...edgeNames] },
    failures,
  };
}

/** CLI entry point — argv-reading + process.exit live here, never at import time. */
async function main() {
  const target = process.argv[2];
  if (!target) { console.error("usage: verify <https://site | ./dist>"); process.exit(2); }
  const result = await verifySite({ target, onLog: (line) => console.log(line) });
  process.exit(result.verified ? 0 : 1);
}

// Run the CLI ONLY when executed directly (Deno sets import.meta.main). On `import`
// this is false, so the module has NO side effects — safe to consume as a library.
if (import.meta.main) {
  await main();
}
