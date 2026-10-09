# Changelog

Each version is published as a GitHub release and as the Docker image
`ghcr.io/kavdau/n8n-oidc:<version>`. The release notes are taken from this file.

## 2.0.2 - 2026-10-09

The hook itself is unchanged from 2.0.1; this release is about the image.

- The image is signed: GitHub attests that it was built from this repository by
  its workflow, and it carries an SBOM (list of contents). Check it with
  `gh attestation verify oci://ghcr.io/kavdau/n8n-oidc:2.0.2 --owner kavdau`.
- Every version gets a GitHub release with these notes.
- Dependabot proposes updates for the GitHub Actions, the busybox base image,
  the example compose file and the test tools.

## 2.0.1 - 2026-10-09

- Fix: the hook disabled itself on n8n 2.41 because n8n moved the service that
  knows the instance URL in 2.42. It now looks in both places and falls back to
  `N8N_EDITOR_BASE_URL`.
- New: Docker image `ghcr.io/kavdau/n8n-oidc` (only `hooks.js`, no n8n). A small
  side container delivers the hook, so n8n keeps running from the official image.
- Docs: troubleshooting for file permissions on NAS systems, proxy headers,
  provisioned vs linked accounts, and NAS interfaces (UGOS).

## 2.0.0 - 2026-10-09

Rework of [cweagans/n8n-oidc](https://github.com/cweagans/n8n-oidc) for n8n 2.x.

- Sessions through n8n's own `AuthService` instead of a hand-made cookie.
- ID tokens verified (signature, issuer, audience, expiry, nonce), PKCE S256.
- Accounts linked by the provider's `sub`; existing accounts only by verified email.
- Owner setup restricted to `OIDC_OWNER_EMAIL`.
- Access rules: groups, email domains, auto-provisioning switch.
- Unit, end-to-end and browser tests; weekly CI against the latest n8n.
