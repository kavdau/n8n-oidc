# n8n-oidc

OpenID Connect login for **n8n Community Edition**, as an external hook. Works with
[Pocket ID](https://pocket-id.org), Authentik, Keycloak, Authelia and any other
standards-compliant provider.

- Adds a "Sign in with …" button to the n8n sign-in and owner setup pages
- Signs users in through n8n's own session handling (`AuthService`), so sessions,
  cookie flags and sign-out behave exactly like a password login
- Links accounts the same way n8n's licensed OIDC integration does
  (`AuthIdentity`, keyed by the provider's `sub`)
- Never stops n8n from starting: on any problem the hook disables itself and the
  normal login keeps working
- Leaves n8n untouched: you keep running the official n8n image; a 4 MB side
  container only delivers `hooks.js`

> This is a fork of [cweagans/n8n-oidc](https://github.com/cweagans/n8n-oidc),
> reworked for n8n 2.x. See [What changed](#what-changed-since-the-original).

**Verified against n8n 2.42.6** (stable) and Pocket ID 2.18.0. CI re-tests weekly
against the current n8n `stable` and `next` releases.

## Contents

- [Quick start with Pocket ID](#quick-start-with-pocket-id)
- [Configuration](#configuration)
- [Docker image](#docker-image)
- [How it works](#how-it-works)
- [Security](#security)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Upgrading n8n](#upgrading-n8n)
- [Development and tests](#development-and-tests)
- [What changed since the original](#what-changed-since-the-original)

## Quick start with Pocket ID

### 1. Create the client in Pocket ID

In Pocket ID, open **OIDC Clients → Add OIDC Client**:

| Field | Value |
| --- | --- |
| Name | `n8n` |
| Callback URLs | `https://n8n.example.com/auth/oidc/callback` |
| Public client | off |
| PKCE | on |

Save, then copy the **Client ID** and **Client Secret**.

To limit who may use n8n, either restrict the client to a group in Pocket ID
(**Allowed user groups**), or set `OIDC_ALLOWED_GROUPS` below. Both work; Pocket ID
then refuses the login before it ever reaches n8n.

### 2. Run n8n with the hook

```bash
mkdir n8n && cd n8n
curl -fsSLO https://raw.githubusercontent.com/kavdau/n8n-oidc/main/docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/kavdau/n8n-oidc/main/.env.example -o .env
# edit .env: host, issuer, client id, owner email
mkdir -p secrets && printf '%s' 'PASTE-CLIENT-SECRET' > secrets/oidc_client_secret
docker compose up -d
docker compose logs n8n | grep 'OIDC Hook'
```

A working setup logs:

```
[OIDC Hook] v2.1.0 active on n8n 2.42.6
[OIDC Hook]   issuer:       https://id.example.com
[OIDC Hook]   redirect URI: https://n8n.example.com/auth/oidc/callback
```

Already running n8n? Add the `n8n-oidc` service and the `oidc_hook` volume from
the [example compose file](docker-compose.yml), then give your n8n service the
three hook variables, the `OIDC_*` variables, `depends_on: [n8n-oidc]` and the
read-only `oidc_hook` mount. Your n8n image stays as it is.

### 3. Sign in

- **New instance:** the setup page shows the SSO button. Only the user whose
  verified email equals `OIDC_OWNER_EMAIL` can set the instance up; they become
  the owner.
- **Existing instance:** your existing account is linked on first SSO login, if
  Pocket ID reports the email as verified. Password login keeps working.
- Everyone else in the allowed group gets a member account on first login
  (turn that off with `OIDC_AUTO_PROVISION=false`).
- On every later sign-in, name and email follow what Pocket ID says (see
  `OIDC_SYNC_PROFILE`).

## Configuration

### Required by n8n

| Variable | Value |
| --- | --- |
| `EXTERNAL_HOOK_FILES` | Path to `hooks.js` |
| `EXTERNAL_FRONTEND_HOOKS_URLS` | `/assets/oidc-frontend-hook.js` (the button) |
| `N8N_ADDITIONAL_NON_UI_ROUTES` | must include `auth`, otherwise the editor swallows `/auth/oidc/*` |
| `N8N_EDITOR_BASE_URL` | The public URL of n8n; used to build the redirect URI |

### Provider

| Variable | Default | Meaning |
| --- | --- | --- |
| `OIDC_ISSUER_URL` | *required* | Issuer URL, e.g. `https://id.example.com`. Must match the provider's `issuer` exactly. |
| `OIDC_CLIENT_ID` | *required* | Client ID |
| `OIDC_CLIENT_SECRET` / `OIDC_CLIENT_SECRET_FILE` | | Client secret, or a file containing it (Docker secrets). Leave out for a public client. |
| `OIDC_REDIRECT_URI` | `<N8N_EDITOR_BASE_URL>/auth/oidc/callback` | Only needed if n8n cannot work out its own URL |
| `OIDC_SCOPES` | `openid email profile` | `groups` is added automatically when `OIDC_ALLOWED_GROUPS` is set |
| `OIDC_TOKEN_AUTH_METHOD` | `client_secret_basic` (with secret), `none` (without) | Or `client_secret_post` |
| `OIDC_USE_PKCE` | `true` | PKCE S256. Can only be turned off for confidential clients. |

### Access

| Variable | Default | Meaning |
| --- | --- | --- |
| `OIDC_OWNER_EMAIL` | | Allows this user to set up a fresh instance through SSO |
| `OIDC_ALLOWED_GROUPS` | *(anyone)* | Comma-separated; the user needs at least one |
| `OIDC_GROUPS_CLAIM` | `groups` | Claim that carries the groups |
| `OIDC_ALLOWED_EMAIL_DOMAINS` | *(any)* | Comma-separated, exact match (`example.com` does not allow `sub.example.com`) |
| `OIDC_AUTO_PROVISION` | `true` | Create member accounts on first login. If `false`, users must be invited first. |
| `OIDC_SYNC_PROFILE` | `true` | On every sign-in, take over first name, last name and email from the provider. The email only changes when the provider marks it verified and no other n8n account uses it. Changing it signs the user out of their other n8n sessions. |
| `OIDC_REQUIRE_EMAIL_VERIFIED` | `true` | Require `email_verified: true` before creating or linking an account. An explicit `false` is always rejected. |

### Sign-in page

| Variable | Default | Meaning |
| --- | --- | --- |
| `OIDC_BUTTON_LABEL` | `Sign in with SSO` | Button text |
| `OIDC_HIDE_PASSWORD_LOGIN` | `false` | Show only the SSO button. A small link (`?showLogin=true`) keeps the password form reachable for the owner. |
| `OIDC_AUTO_REDIRECT` | `false` | Skip the sign-in page and go straight to the provider. Not after signing out, so you are not signed straight back in. |

### Diagnostics

| Variable | Meaning |
| --- | --- |
| `OIDC_DEBUG=true` | Extra log lines |
| `OIDC_N8N_PACKAGE_DIR` | Path of the n8n package, if the hook cannot find it (non-Docker installs) |

## Docker image

`ghcr.io/kavdau/n8n-oidc` contains `hooks.js` and nothing else (no n8n). Tags
follow the hook version: `2.0.1`, `2.0`, `2`, `latest`. It is built for
`linux/amd64` and `linux/arm64`, only after the tests passed. A published version
is never overwritten, so `2.0.1` always means the same image; a new image needs a
new `HOOK_VERSION` in `hooks.js` and an entry in the [changelog](CHANGELOG.md).
Every version also gets a [GitHub release](../../releases) with those notes.

**Verifying the image.** From 2.0.2 on, GitHub signs a statement that the image
was built from this repository by its own workflow, and the image carries an SBOM
(the list of its contents):

```bash
gh attestation verify oci://ghcr.io/kavdau/n8n-oidc:2.1.0 --owner kavdau
docker buildx imagetools inspect ghcr.io/kavdau/n8n-oidc:2.1.0 --format '{{ json .SBOM }}'
```

`gh attestation verify` needs the GitHub CLI signed in (`gh auth login`).

There are three ways to get `hooks.js` into n8n. All use the official n8n image.

**1. Side container (recommended, works everywhere).** This is what the example
compose file does. On start the container copies `hooks.js` into the volume
`oidc_hook` and then idles (under 1 MB of RAM), so NAS interfaces such as UGOS,
Synology or Portainer do not show the stack as failed. Its health check reports
*healthy* once the volume holds exactly its own `hooks.js`.

Use the plain `depends_on: [n8n-oidc]`. Some NAS interfaces hang on
`condition: service_healthy`, and it is not needed: copying takes milliseconds,
n8n needs seconds before it loads the hook, and the file is replaced atomically.

**2. Image volume (Docker Engine 28 or newer, plain `docker compose`).** No side
container at all; n8n mounts the file straight from the image:

```yaml
services:
  n8n:
    volumes:
      - type: image
        source: ghcr.io/kavdau/n8n-oidc:2.1.0
        target: /opt/n8n-oidc
        image:
          subpath: n8n-oidc
```

Some NAS interfaces reject this (UGOS: "image is not allowed"); use option 1 there.

**3. Plain file.** Download `hooks.js` from a pinned commit and mount it
read-only to `/opt/n8n-oidc/hooks.js`. It must be readable for UID 1000, see
[Troubleshooting](#troubleshooting).

**Updating the hook** is a tag change: set the new `n8n-oidc` tag, then
`docker compose pull && docker compose up -d`.

**Building it yourself:**

```bash
docker build -t n8n-oidc:dev "https://github.com/kavdau/n8n-oidc.git#main"
```

The Dockerfile also works with the legacy builder that some NAS systems ship
without buildx. For a locally built image, add `pull_policy: never` to the
`n8n-oidc` service so Compose does not look for it online.

## How it works

```
Browser ──GET /auth/oidc/login──▶ n8n (hook)
   │      sets an encrypted, 10-minute cookie with state, nonce, PKCE verifier, target page
   ◀──302 to Pocket ID (code_challenge=S256, nonce, state)
   │
Pocket ID  (passkey)  ──302──▶ /auth/oidc/callback?code&state&iss
                                  │ checks state (and iss, RFC 9207)
                                  │ exchanges code + verifier at the token endpoint
                                  │ verifies the ID token: signature (JWKS), iss, aud, azp, exp, iat, nonce
                                  │ applies email / group / domain rules
                                  │ resolves the user: sub ▸ verified email ▸ owner setup ▸ new member
                                  │ n8n AuthService.issueCookie()  →  normal n8n session
   ◀──302 to the page the user asked for ─┘
```

The button is added by a small script served from `/assets/oidc-frontend-hook.js`.
It only uses n8n's stable `data-test-id` attributes, so it does not depend on
CSS class names.

## Security

- **ID tokens are verified**, not just decoded: signature against the provider's
  JWKS (RS256/384/512, PS256/384/512, ES256/384/512, EdDSA; `none` and HMAC are
  rejected), plus `iss`, `aud`, `azp`, `exp`, `iat`, `nbf` and `nonce`.
  Rotated keys are picked up automatically.
- **PKCE S256**, `state`, `nonce` and the authorization response `iss` parameter
  protect against code injection, CSRF and mix-up attacks.
- **Account takeover protection:** an existing n8n account is only linked by email
  when the provider says the email is verified. After that the link uses the
  immutable `sub`, so changing the email in Pocket ID does not move the account;
  the new address is only copied into n8n when it is verified and not used by
  another n8n account.
- **Owner setup** is restricted to `OIDC_OWNER_EMAIL`. Without it, a fresh instance
  can only be set up with the normal form. (The original "first user becomes owner"
  never triggered on n8n 2.x, see issue #7.)
- **No reflected provider text:** errors reach the sign-in page as fixed codes
  (`?oidc_error=access_denied`) with fixed messages.
- **Open redirects** are blocked: only same-origin paths are accepted as targets.
- Webhooks, forms and the public API are untouched.

## Limitations

- **Signing out of n8n does not sign you out of Pocket ID.** With
  `OIDC_AUTO_REDIRECT=true` that is handled (no redirect after a sign-out), but a
  click on the button signs you in again without a prompt while your Pocket ID
  session lasts.
- **n8n's own MFA is not asked** for SSO logins; authentication strength is the
  provider's job (passkeys in Pocket ID). This matches n8n's licensed OIDC.
- **Roles are not mapped** from groups. New users are members; promote them in n8n.
  Admin roles in n8n are a licensed feature, and this hook does not unlock any.
- **Not a licensed feature.** This hook does not enable n8n Enterprise features,
  and n8n's own SSO settings page stays locked. It is an independent implementation
  that uses n8n's public external hooks plus some internal services.

## Troubleshooting

Every decision the hook makes is logged with the prefix `[OIDC Hook]`:

```bash
docker logs n8n 2>&1 | grep 'OIDC Hook'
```

| Symptom | Cause and fix |
| --- | --- |
| n8n does not start, log shows `EACCES: permission denied, open '/opt/n8n-oidc/hooks.js'` | Only with a plain file mount (the image sets the permissions itself). n8n runs as user `node` (UID 1000) and cannot read the mounted file. n8n loads hook files itself, so this happens before the hook can protect anything. `chmod 644 hooks.js` and `chmod 755` on its folder. On NAS systems with ACLs (`+` in `ls -l`), remove them first: `setfacl -b`. |
| `Cannot read OIDC_CLIENT_SECRET_FILE` | Same permission problem for the secret: `chown 1000:1000` and `chmod 400` the file. |
| `OIDC login disabled` | The line before it says why: a missing variable, `N8N_ADDITIONAL_NON_UI_ROUTES` without `auth`, or n8n internals not found after an update. n8n keeps running with the normal login. |
| `Keeping email …` in the log | Profile sync did not change the email: it is not verified at the provider, or another n8n account uses it. The login itself works. |
| Log says `Signed in … (provisioned)` but you expected your existing account | The email at the provider differs from the email of your n8n account, so a new member was created. Delete it in **Settings → Users**, make both emails match, and sign in again; the log then says `(linked)`. Set `OIDC_AUTO_PROVISION=false` if only invited users should get in. |
| `email_not_verified` | The provider does not report the email as verified. Verify it there; only set `OIDC_REQUIRE_EMAIL_VERIFIED=false` if you trust every email the provider hands out. |
| `session_expired` right after signing in | The transaction cookie did not survive the round trip, usually because `N8N_SECURE_COOKIE` is on while n8n is reached over plain HTTP, or the login was started in another tab. |
| `X-Forwarded-For` errors in the log | Not from the hook: n8n does not know it is behind a proxy. Set `N8N_PROXY_HOPS` to the number of proxies in front of n8n (`1` for one reverse proxy, `2` for Cloudflare plus Traefik). |
| The NAS interface hangs at "deploying" | `depends_on` with `condition: service_healthy`. Use the plain form `depends_on: [n8n-oidc]`, see [Docker image](#docker-image). |
| `image is not allowed` in the NAS interface | It does not support image volumes (`type: image`). Use the side container. |
| `pull access denied for n8n-oidc` | A locally built image without `pull_policy: never`, or the build has not finished. Check with `docker images n8n-oidc`. |

## Upgrading n8n

The hook relies on a few n8n internals: `AuthService`, `OwnershipService`, the
`@n8n/db` repositories and the external hooks API. They have been stable through
n8n 2.x, but they are not a public API.

1. Check the [CI status](../../actions) (it tests the newest `stable` and `next`
   every Monday) or run the tests yourself (below).
2. Upgrade n8n.
3. Look for `[OIDC Hook] v… active on n8n <new version>` in the log. If the hook
   cannot find something, it logs why and disables itself; password login keeps
   working, so you are never locked out.

## Development and tests

Requires Node 24 (what n8n 2.x needs).

```bash
node --test test/unit.test.js          # 38 unit tests, no dependencies
task test-e2e                          # installs n8n from npm, then e2e + browser tests
```

Or by hand:

```bash
mkdir -p .n8n-under-test && (cd .n8n-under-test && echo '{}' > package.json && npm i n8n@stable)
export N8N_BIN=$PWD/.n8n-under-test/node_modules/n8n/bin/n8n
node --test test/e2e.test.js           # real n8n + mock provider, 23 scenarios
npm install && node --test test/browser.test.js   # headless Chrome against the real editor
```

Dependabot proposes updates for the GitHub Actions, the busybox base image, the
example compose file and puppeteer every Monday; each one has to pass the tests.

`test/mock-idp.js` is a small provider that behaves like Pocket ID (RS256, PKCE,
`email_verified`, `groups`) and can misbehave on purpose: forged signatures, wrong
nonce or audience, expired tokens, `alg: none`.

## What changed since the original

| | Original (n8n 2.1) | This fork |
| --- | --- | --- |
| Session | hand-made JWT and hash | n8n's `AuthService.issueCookie()` |
| n8n internals | fixed `dist/` paths | located at runtime; hook disables itself if missing |
| ID token | decoded, not verified | signature and all claims verified |
| PKCE | no | S256 |
| Account linking | by email, unverified | by `sub`, email only when verified |
| Profile | set once | name and verified email kept in sync |
| Owner | "first user", never triggered on 2.x | `OIDC_OWNER_EMAIL` |
| Access control | none | groups, email domains, auto-provision switch |
| Errors | provider text in the URL | fixed codes and messages |
| Button | CSS class selectors, enterprise flag override | `data-test-id` selectors, no flags touched |
| Tests | none | unit, end-to-end and browser tests, weekly CI against the latest n8n |

Environment variable names and the callback URL are unchanged, so an existing
setup keeps working after replacing `hooks.js` (add `N8N_EDITOR_BASE_URL` if it is
not set). The fork additionally ships `hooks.js` as a Docker image, so the n8n
image itself never has to be changed.

## License

MIT. Originally created by Cameron Eagans.
