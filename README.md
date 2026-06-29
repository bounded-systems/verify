# @bounded-systems/verify

Standalone, out-of-page verifier. Given a deployed site URL (or a local `dist/`
directory) carrying a published Sigstore **bundle**, it proves **out of band** that
the served bytes are exactly what an allowed identity built and logged — offline,
no trust in the page itself.

What it checks, in-process via [`sigstore-js`](https://github.com/sigstore/sigstore-js):

- signature over the whole-site manifest;
- certificate chain to the Fulcio root (bundled trusted root — **no network**);
- Rekor inclusion proof (offline; not the deprecated Rekor query API);
- issuer + certificate SAN matched against the site's declared builder identity;
- then re-hashes every served file against the signed manifest, tolerating known,
  named CDN edge transforms (the signed body must still be intact underneath).

## Usage

```sh
# against a deployed site
deno run -A jsr:@bounded-systems/verify https://bounded.tools

# against a local build directory
deno run -A jsr:@bounded-systems/verify ./dist
```

Inputs are read from the target: `provenance.json` (the builder identity — nothing
is hardcoded), the whole-site `site.sha256` manifest, and the `.sigstore.json`
bundle. Exit code `0` on success, `1` on any verification failure.

## Library API

The same logic is exported as side-effect-free functions — importing the module
runs **nothing** (the CLI is guarded behind `import.meta.main`):

```js
import { verifyManifestBundle, verifySite } from "jsr:@bounded-systems/verify";
```

### `verifyManifestBundle({ bundle, manifest, identity?, issuer?, verifyImpl? })`

The core primitive: cryptographically verifies a Sigstore **bundle** over a signed
manifest, in-process and offline (the same `sigstore.verify(...)` call the CLI makes).

| field | type | notes |
| --- | --- | --- |
| `bundle` | `object \| string` | parsed Sigstore bundle, or its JSON text |
| `manifest` | `Buffer \| Uint8Array \| string` | the signed artifact bytes (e.g. `site.sha256`) |
| `identity` | `RegExp \| string` (optional) | the certificate SAN must match this |
| `issuer` | `string` (optional) | OIDC issuer to enforce (default: GitHub Actions) |
| `verifyImpl` | `Function` (optional) | injectable verifier; defaults to sigstore's `verify` — leave unset in production |

Resolves to `{ verified: true, identity, issuer }`. Throws a typed `VerifyError`
(with `.code` ∈ `MISSING_BUNDLE` · `MISSING_MANIFEST` · `BUNDLE_VERIFICATION_FAILED`
· `IDENTITY_MISMATCH`) on any failure.

```js
const { verified, identity } = await verifyManifestBundle({
  bundle,                                            // from site.sha256.sigstore.json
  manifest,                                          // bytes of site.sha256
  identity: /^https:\/\/github.com\/bounded-systems\/site\//,
});
```

### `verifySite({ target, onLog?, verifyImpl? })`

The full out-of-band flow the CLI runs: loads `provenance.json`, `site.sha256` and
the bundle from a deployed URL or local `dist/`, verifies the bundle, then re-hashes
every served file (tolerating known CDN edge transforms). Progress is delivered to
the optional `onLog(line)` callback — nothing is printed and the process is never
exited. Returns a structured result:

```js
const r = await verifySite({ target: "https://bounded.tools" });
// { verified, base, builder, commit, rekorLogIndex, builtAt, identity,
//   files: { total, mismatches, edged, edgeNames }, failures }
```

Also exported: `VerifyError`, `DEFAULT_ISSUER`, `stripKnownEdge`, `KNOWN_EDGE_INJECTIONS`.

## Provenance

This repository — [`bounded-systems/verify`](https://github.com/bounded-systems/verify) —
is the canonical home of the published [`@bounded-systems/verify`](https://jsr.io/@bounded-systems/verify)
JSR package. It is published keyless via GitHub Actions OIDC — no long-lived
tokens (see [`.github/workflows/publish.yml`](./.github/workflows/publish.yml)).

The same verifier source is also vendored into
[`bounded-systems/conformance-kit`](https://github.com/bounded-systems/conformance-kit)
at `integrity/verify/verify.mjs` so sites can pull it into a hermetic build, but the
canonical, published copy lives here.

## Cut a release

Publishing is keyless via GitHub Actions OIDC — no tokens:

1. Bump `version` in [`deno.json`](./deno.json) and commit.
2. Tag and push — the tag must match `v*`:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

   [`.github/workflows/publish.yml`](./.github/workflows/publish.yml) (trigger `v*`,
   `permissions: id-token: write`) runs `deno publish --allow-slow-types`. It can
   also be run by hand from the Actions tab (`workflow_dispatch`).

Verify locally before tagging:

```sh
deno publish --dry-run --allow-slow-types
```

MIT
