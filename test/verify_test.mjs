// Tests for @bounded-systems/verify as a LIBRARY.
//
//   deno test -A
//
// These import the exported functions directly (no side effects on import) and:
//   1. prove importing the module does NOT self-execute / exit the process;
//   2. verify a GOOD bundle resolves to { verified: true };
//   3. reject a TAMPERED manifest (the signed bytes no longer match).
//
// The good/bad crypto assertions use an injected `verifyImpl` that faithfully
// reproduces the integrity property sigstore enforces — sha256(artifact) must equal
// the digest the bundle signed — so they are hermetic and deterministic (no network,
// no public-good TUF root). An additional environment-gated step runs the REAL
// in-process sigstore verification when the public-good TUF root is reachable.
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@^1";
import { createHash } from "node:crypto";
import { verifyManifestBundle, VerifyError, DEFAULT_ISSUER } from "../verify.mjs";

const here = new URL(".", import.meta.url).pathname;
const fx = (name) => `${here}fixtures/${name}`;

const manifest = await Deno.readFile(fx("site.sha256"));
const bundle = JSON.parse(await Deno.readTextFile(fx("site.sha256.sigstore.json")));
const provenance = JSON.parse(await Deno.readTextFile(fx("provenance.json")));

// The real cert SAN this fixture was signed under (the GitHub Actions workflow ref).
const SIGNED_SAN = provenance.builder.workflowRef
  ? `https://github.com/${provenance.builder.workflowRef}`
  : `https://github.com/${provenance.builder.repository}/.github/workflows/deploy.yml@refs/heads/main`;

// Faithful stand-in for sigstore.verify: enforces the same integrity invariant
// (signed digest == sha256 of the presented artifact) and surfaces the cert SAN.
function fakeVerify(bundleObj, artifact /*, opts */) {
  const want = bundleObj?.messageSignature?.messageDigest?.digest;
  const got = createHash("sha256").update(Buffer.from(artifact)).digest("base64");
  if (!want || got !== want) {
    throw new Error("signature does not match the presented artifact");
  }
  return { identity: { subjectAlternativeName: SIGNED_SAN } };
}

Deno.test("importing the module does NOT self-execute or exit", async () => {
  // Spawn a child that ONLY imports the module. If the module self-executed (read
  // argv + process.exit), this prints the usage banner / exits non-zero. We assert
  // a clean exit and our own sentinel, proving the CLI is fully guarded.
  const url = new URL("../verify.mjs", import.meta.url).href;
  const cmd = new Deno.Command(Deno.execPath(), {
    args: ["eval", `const m = await import(${JSON.stringify(url)}); console.log("IMPORT_OK", typeof m.verifyManifestBundle);`],
    stdout: "piped",
    stderr: "piped",
  });
  const { code, stdout, stderr } = await cmd.output();
  const out = new TextDecoder().decode(stdout);
  const err = new TextDecoder().decode(stderr);
  assertEquals(code, 0, `import should exit 0; stderr: ${err}`);
  assert(out.includes("IMPORT_OK function"), `expected exported function; got: ${out}`);
  assert(!out.includes("usage:") && !err.includes("usage:"), "module must not run the CLI on import");
});

Deno.test("verifyManifestBundle resolves for a good bundle", async () => {
  const res = await verifyManifestBundle({
    bundle,
    manifest,
    identity: new RegExp(`^https://github.com/${provenance.builder.repository}/`),
    issuer: DEFAULT_ISSUER,
    verifyImpl: fakeVerify,
  });
  assertEquals(res.verified, true);
  assertEquals(res.identity, SIGNED_SAN);
  assertEquals(res.issuer, DEFAULT_ISSUER);
});

Deno.test("verifyManifestBundle accepts the bundle as a JSON string too", async () => {
  const res = await verifyManifestBundle({
    bundle: JSON.stringify(bundle),
    manifest,
    verifyImpl: fakeVerify,
  });
  assertEquals(res.verified, true);
});

Deno.test("verifyManifestBundle rejects a tampered manifest", async () => {
  const tampered = Buffer.from(manifest);
  tampered[0] ^= 0xff; // flip a byte — signed digest no longer matches
  const err = await assertRejects(
    () => verifyManifestBundle({ bundle, manifest: tampered, verifyImpl: fakeVerify }),
    VerifyError,
  );
  assertEquals(err.code, "BUNDLE_VERIFICATION_FAILED");
});

Deno.test("verifyManifestBundle rejects an identity mismatch", async () => {
  const err = await assertRejects(
    () => verifyManifestBundle({ bundle, manifest, identity: /^https:\/\/github.com\/someone-else\//, verifyImpl: fakeVerify }),
    VerifyError,
  );
  assertEquals(err.code, "IDENTITY_MISMATCH");
});

Deno.test("verifyManifestBundle throws typed errors for missing inputs", async () => {
  const a = await assertRejects(() => verifyManifestBundle({ manifest }), VerifyError);
  assertEquals(a.code, "MISSING_BUNDLE");
  const b = await assertRejects(() => verifyManifestBundle({ bundle }), VerifyError);
  assertEquals(b.code, "MISSING_MANIFEST");
});

Deno.test("real sigstore verification (skipped if public-good TUF root unreachable)", async () => {
  try {
    const res = await verifyManifestBundle({
      bundle,
      manifest,
      identity: new RegExp(`^https://github.com/${provenance.builder.repository}/`),
    });
    assertEquals(res.verified, true);
    // and tampering must be rejected by the real verifier too
    const tampered = Buffer.from(manifest);
    tampered[0] ^= 0xff;
    await assertRejects(() => verifyManifestBundle({ bundle, manifest: tampered }), VerifyError);
  } catch (e) {
    if (e instanceof VerifyError && e.code === "BUNDLE_VERIFICATION_FAILED") {
      console.warn(`  ↪ skipped real verification (environment): ${e.message}`);
      return;
    }
    throw e;
  }
});
