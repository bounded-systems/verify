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
