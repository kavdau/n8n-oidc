/**
 * n8n-oidc: bolt-on OpenID Connect login for n8n Community Edition.
 *
 * Loaded by n8n through EXTERNAL_HOOK_FILES. It registers three routes:
 *   GET /auth/oidc/login     starts the authorization code flow (PKCE)
 *   GET /auth/oidc/callback  validates the response and signs the user in
 *   GET /assets/oidc-frontend-hook.js  adds the SSO button to the sign-in page
 *
 * Sessions are issued through n8n's own AuthService, accounts are linked through
 * n8n's AuthIdentity table (providerType "oidc", providerId = OIDC "sub"), the
 * same data model the licensed OIDC integration uses.
 *
 * Nothing in this file may stop n8n from starting: every failure while setting
 * up is logged and the hook disables itself, leaving the normal login in place.
 *
 * Originally created by Cameron Eagans (https://github.com/cweagans/n8n-oidc), MIT.
 */

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');

const HOOK_VERSION = '2.1.1';
const LOG_PREFIX = '[OIDC Hook]';
const PROVIDER_TYPE = 'oidc';

const ROUTE_LOGIN = '/auth/oidc/login';
const ROUTE_CALLBACK = '/auth/oidc/callback';
const ROUTE_FRONTEND = '/assets/oidc-frontend-hook.js';

const TX_COOKIE = 'n8n-oidc-tx';
const TX_COOKIE_PATH = '/auth/oidc';
const TX_MAX_AGE_SECONDS = 10 * 60;

const HTTP_TIMEOUT_MS = 10_000;
const DISCOVERY_TTL_MS = 60 * 60 * 1000;
const JWKS_TTL_MS = 60 * 60 * 1000;
const JWKS_MIN_REFRESH_MS = 30 * 1000;
const CLOCK_SKEW_SECONDS = 60;
const NAME_MAX_LENGTH = 32;

/** Error codes the sign-in page knows how to explain. Never reflect IdP text. */
const ERROR_CODES = new Set([
	'login_failed',
	'session_expired',
	'access_denied',
	'email_not_verified',
	'email_missing',
	'not_provisioned',
	'instance_not_setup',
	'user_disabled',
]);

const log = {
	info: (...args) => console.log(LOG_PREFIX, ...args),
	warn: (...args) => console.warn(LOG_PREFIX, ...args),
	error: (...args) => console.error(LOG_PREFIX, ...args),
	debug: (...args) => {
		if (process.env.OIDC_DEBUG === 'true') console.log(LOG_PREFIX, '[debug]', ...args);
	},
};

class OidcLoginError extends Error {
	/**
	 * @param {string} code one of ERROR_CODES, shown to the user
	 * @param {string} detail logged only
	 */
	constructor(code, detail) {
		super(detail || code);
		this.code = ERROR_CODES.has(code) ? code : 'login_failed';
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/** Reads NAME, or the file named by NAME_FILE (Docker secrets). */
function readEnv(name, env = process.env) {
	const file = env[`${name}_FILE`];
	if (file) {
		try {
			return fs.readFileSync(file, 'utf8').trim();
		} catch (error) {
			throw new Error(`Cannot read ${name}_FILE (${file}): ${error.message}`);
		}
	}
	const value = env[name];
	return value === undefined || value.trim() === '' ? undefined : value.trim();
}

function parseBool(value, fallback) {
	if (value === undefined) return fallback;
	const normalized = value.toLowerCase();
	if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
	if (['false', '0', 'no', 'off'].includes(normalized)) return false;
	throw new Error(`Expected a boolean but got "${value}"`);
}

function parseList(value) {
	if (!value) return [];
	return value
		.split(/[,\s]+/)
		.map((item) => item.trim())
		.filter(Boolean);
}

function stripTrailingSlash(url) {
	return url.replace(/\/+$/, '');
}

/**
 * Builds the hook configuration from the environment.
 * Returns `{ config }` or `{ missing }` when required values are absent.
 */
function loadConfig(env = process.env) {
	const issuerUrl = readEnv('OIDC_ISSUER_URL', env);
	const clientId = readEnv('OIDC_CLIENT_ID', env);
	const missing = [];
	if (!issuerUrl) missing.push('OIDC_ISSUER_URL');
	if (!clientId) missing.push('OIDC_CLIENT_ID');
	if (missing.length) return { missing };

	const clientSecret = readEnv('OIDC_CLIENT_SECRET', env);
	const allowedGroups = parseList(readEnv('OIDC_ALLOWED_GROUPS', env));

	let scopes = parseList(readEnv('OIDC_SCOPES', env) || 'openid email profile');
	if (!scopes.includes('openid')) scopes.unshift('openid');
	if (allowedGroups.length && !scopes.includes('groups')) scopes.push('groups');

	const tokenAuthMethod =
		readEnv('OIDC_TOKEN_AUTH_METHOD', env) || (clientSecret ? 'client_secret_basic' : 'none');
	if (!['client_secret_basic', 'client_secret_post', 'none'].includes(tokenAuthMethod)) {
		throw new Error(`Unsupported OIDC_TOKEN_AUTH_METHOD "${tokenAuthMethod}"`);
	}
	if (tokenAuthMethod !== 'none' && !clientSecret) {
		throw new Error(`OIDC_TOKEN_AUTH_METHOD=${tokenAuthMethod} needs OIDC_CLIENT_SECRET`);
	}

	const usePkce = parseBool(readEnv('OIDC_USE_PKCE', env), true);
	if (tokenAuthMethod === 'none' && !usePkce) {
		throw new Error('A public client (no client secret) must use PKCE');
	}

	const ownerEmail = readEnv('OIDC_OWNER_EMAIL', env);

	return {
		config: {
			issuerUrl: stripTrailingSlash(issuerUrl),
			clientId,
			clientSecret,
			tokenAuthMethod,
			usePkce,
			redirectUri: readEnv('OIDC_REDIRECT_URI', env),
			scopes: scopes.join(' '),
			allowedGroups,
			groupsClaim: readEnv('OIDC_GROUPS_CLAIM', env) || 'groups',
			allowedEmailDomains: parseList(readEnv('OIDC_ALLOWED_EMAIL_DOMAINS', env)).map((d) =>
				d.toLowerCase().replace(/^@/, ''),
			),
			autoProvision: parseBool(readEnv('OIDC_AUTO_PROVISION', env), true),
			syncProfile: parseBool(readEnv('OIDC_SYNC_PROFILE', env), true),
			requireEmailVerified: parseBool(readEnv('OIDC_REQUIRE_EMAIL_VERIFIED', env), true),
			ownerEmail: ownerEmail ? ownerEmail.toLowerCase() : undefined,
			buttonLabel: readEnv('OIDC_BUTTON_LABEL', env) || 'Sign in with SSO',
			hidePasswordLogin: parseBool(readEnv('OIDC_HIDE_PASSWORD_LOGIN', env), false),
			autoRedirect: parseBool(readEnv('OIDC_AUTO_REDIRECT', env), false),
		},
	};
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function base64UrlEncode(buffer) {
	return Buffer.from(buffer).toString('base64url');
}

function base64UrlDecode(input) {
	if (typeof input !== 'string' || !/^[A-Za-z0-9_-]*$/.test(input)) {
		throw new Error('Invalid base64url input');
	}
	return Buffer.from(input, 'base64url');
}

function randomToken(bytes = 32) {
	return base64UrlEncode(crypto.randomBytes(bytes));
}

function pkceChallenge(verifier) {
	return base64UrlEncode(crypto.createHash('sha256').update(verifier).digest());
}

function isValidEmail(email) {
	return typeof email === 'string' && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Accepts only same-origin, absolute paths ("/workflow/1?x=y").
 * Anything else ("//evil", "https://...", "/\\evil", control chars) becomes "/".
 */
function sanitizeRedirectPath(value) {
	if (typeof value !== 'string' || value.length === 0 || value.length > 2048) return '/';
	if (!value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return '/';
	if (/[\u0000-\u001f\u007f\\]/.test(value)) return '/';
	try {
		const parsed = new URL(value, 'http://n8n.invalid');
		if (parsed.origin !== 'http://n8n.invalid') return '/';
		const result = parsed.pathname + parsed.search + parsed.hash;
		// Never send the user back into the login flow itself.
		if (result.startsWith('/auth/oidc') || result.startsWith('/signin')) return '/';
		return result;
	} catch {
		return '/';
	}
}

function truncate(value, max = NAME_MAX_LENGTH) {
	if (typeof value !== 'string') return undefined;
	const trimmed = value.trim();
	return trimmed ? Array.from(trimmed).slice(0, max).join('') : undefined;
}

function claimToList(value) {
	if (Array.isArray(value)) return value.filter((v) => typeof v === 'string');
	if (typeof value === 'string') return parseList(value);
	return [];
}

function isTrue(value) {
	return value === true || value === 'true';
}

function isFalse(value) {
	return value === false || value === 'false';
}

// ---------------------------------------------------------------------------
// Transaction cookie (state, nonce, PKCE verifier, redirect) - AES-256-GCM
// ---------------------------------------------------------------------------

function deriveCookieKey(secret) {
	return Buffer.from(
		crypto.hkdfSync('sha256', Buffer.from(secret, 'utf8'), 'n8n-oidc', 'oidc-transaction-cookie', 32),
	);
}

function sealTransaction(payload, key, now = Date.now()) {
	const iv = crypto.randomBytes(12);
	const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
	const body = JSON.stringify({ ...payload, iat: Math.floor(now / 1000) });
	const encrypted = Buffer.concat([cipher.update(body, 'utf8'), cipher.final()]);
	return [iv, encrypted, cipher.getAuthTag()].map(base64UrlEncode).join('.');
}

function openTransaction(sealed, key, now = Date.now()) {
	try {
		if (typeof sealed !== 'string') return null;
		const [iv, encrypted, tag] = sealed.split('.').map(base64UrlDecode);
		if (!iv || !encrypted || !tag || iv.length !== 12 || tag.length !== 16) return null;
		const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
		decipher.setAuthTag(tag);
		const body = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
		const payload = JSON.parse(body);
		const age = Math.floor(now / 1000) - payload.iat;
		if (!Number.isFinite(age) || age < -CLOCK_SKEW_SECONDS || age > TX_MAX_AGE_SECONDS) return null;
		return payload;
	} catch {
		return null;
	}
}

function safeEqual(a, b) {
	if (typeof a !== 'string' || typeof b !== 'string') return false;
	const left = Buffer.from(a);
	const right = Buffer.from(b);
	return left.length === right.length && crypto.timingSafeEqual(left, right);
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

async function fetchJson(url, options = {}) {
	let response;
	try {
		response = await fetch(url, {
			...options,
			headers: { Accept: 'application/json', ...(options.headers || {}) },
			signal: AbortSignal.timeout(HTTP_TIMEOUT_MS),
			redirect: 'error',
		});
	} catch (error) {
		throw new Error(`Request to ${url} failed: ${error.message}`);
	}
	const text = await response.text();
	let body;
	try {
		body = text ? JSON.parse(text) : {};
	} catch {
		throw new Error(
			`Expected JSON from ${url} but got HTTP ${response.status} ${response.headers.get('content-type') || ''}: ${text.slice(0, 200)}`,
		);
	}
	if (!response.ok) {
		const detail = body && (body.error_description || body.error) ? `${body.error}: ${body.error_description || ''}` : text.slice(0, 200);
		throw new Error(`HTTP ${response.status} from ${url}: ${detail}`);
	}
	return body;
}

// ---------------------------------------------------------------------------
// OIDC provider (discovery, JWKS, token exchange, ID token validation)
// ---------------------------------------------------------------------------

const JWS_ALGORITHMS = {
	RS256: { kty: 'RSA', hash: 'sha256', padding: crypto.constants.RSA_PKCS1_PADDING },
	RS384: { kty: 'RSA', hash: 'sha384', padding: crypto.constants.RSA_PKCS1_PADDING },
	RS512: { kty: 'RSA', hash: 'sha512', padding: crypto.constants.RSA_PKCS1_PADDING },
	PS256: { kty: 'RSA', hash: 'sha256', padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
	PS384: { kty: 'RSA', hash: 'sha384', padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
	PS512: { kty: 'RSA', hash: 'sha512', padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
	ES256: { kty: 'EC', hash: 'sha256', crv: 'P-256' },
	ES384: { kty: 'EC', hash: 'sha384', crv: 'P-384' },
	ES512: { kty: 'EC', hash: 'sha512', crv: 'P-521' },
	EdDSA: { kty: 'OKP', hash: null },
};

function verifyJwsSignature(alg, jwk, signingInput, signature) {
	const spec = JWS_ALGORITHMS[alg];
	if (!spec) throw new Error(`Unsupported signing algorithm ${alg}`);
	if (jwk.kty !== spec.kty) throw new Error(`Key type ${jwk.kty} does not match ${alg}`);
	if (spec.crv && jwk.crv !== spec.crv) throw new Error(`Curve ${jwk.crv} does not match ${alg}`);
	if (jwk.alg && jwk.alg !== alg) throw new Error(`Key is restricted to ${jwk.alg}`);

	const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
	const data = Buffer.from(signingInput, 'ascii');
	if (spec.kty === 'RSA') {
		return crypto.verify(
			spec.hash,
			data,
			{ key, padding: spec.padding, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST },
			signature,
		);
	}
	if (spec.kty === 'EC') {
		return crypto.verify(spec.hash, data, { key, dsaEncoding: 'ieee-p1363' }, signature);
	}
	return crypto.verify(null, data, key, signature);
}

function decodeJwt(token) {
	if (typeof token !== 'string') throw new Error('Token is not a string');
	const parts = token.split('.');
	if (parts.length !== 3) throw new Error('Token is not a compact JWS');
	const header = JSON.parse(base64UrlDecode(parts[0]).toString('utf8'));
	const claims = JSON.parse(base64UrlDecode(parts[1]).toString('utf8'));
	if (!header || typeof header !== 'object' || !claims || typeof claims !== 'object') {
		throw new Error('Token header or payload is not an object');
	}
	return { header, claims, signingInput: `${parts[0]}.${parts[1]}`, signature: base64UrlDecode(parts[2]) };
}

class OidcProvider {
	constructor(config) {
		this.config = config;
		this.discovery = null;
		this.discoveryFetchedAt = 0;
		this.jwks = null;
		this.jwksFetchedAt = 0;
	}

	async getDiscovery() {
		if (this.discovery && Date.now() - this.discoveryFetchedAt < DISCOVERY_TTL_MS) {
			return this.discovery;
		}
		const url = `${this.config.issuerUrl}/.well-known/openid-configuration`;
		const discovery = await fetchJson(url);
		// OpenID Connect Discovery 1.0, section 4.3: the issuer must match exactly.
		if (stripTrailingSlash(String(discovery.issuer || '')) !== this.config.issuerUrl) {
			throw new Error(
				`Issuer mismatch: OIDC_ISSUER_URL is "${this.config.issuerUrl}" but the provider reports "${discovery.issuer}"`,
			);
		}
		for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) {
			if (typeof discovery[field] !== 'string') throw new Error(`Discovery document lacks ${field}`);
		}
		if (
			this.config.usePkce &&
			Array.isArray(discovery.code_challenge_methods_supported) &&
			!discovery.code_challenge_methods_supported.includes('S256')
		) {
			throw new Error('Provider does not support PKCE S256; set OIDC_USE_PKCE=false to continue without it');
		}
		this.discovery = discovery;
		this.discoveryFetchedAt = Date.now();
		return discovery;
	}

	async getJwks(force = false) {
		const age = Date.now() - this.jwksFetchedAt;
		if (this.jwks && (!force ? age < JWKS_TTL_MS : age < JWKS_MIN_REFRESH_MS)) {
			return this.jwks;
		}
		const discovery = await this.getDiscovery();
		const jwks = await fetchJson(discovery.jwks_uri);
		if (!Array.isArray(jwks.keys)) throw new Error('JWKS document has no keys');
		this.jwks = jwks.keys.filter((key) => !key.use || key.use === 'sig');
		this.jwksFetchedAt = Date.now();
		return this.jwks;
	}

	async findKey(header) {
		const pick = (keys) => {
			const spec = JWS_ALGORITHMS[header.alg];
			const candidates = keys.filter((key) => key.kty === spec.kty && (!key.alg || key.alg === header.alg));
			if (header.kid) return candidates.find((key) => key.kid === header.kid);
			return candidates.length === 1 ? candidates[0] : undefined;
		};
		let key = pick(await this.getJwks());
		if (!key) key = pick(await this.getJwks(true)); // key rotation
		if (!key) throw new Error(`No signing key found for kid "${header.kid}"`);
		return key;
	}

	async buildAuthorizationUrl({ state, nonce, codeVerifier, redirectUri }) {
		const discovery = await this.getDiscovery();
		const url = new URL(discovery.authorization_endpoint);
		url.searchParams.set('response_type', 'code');
		url.searchParams.set('client_id', this.config.clientId);
		url.searchParams.set('redirect_uri', redirectUri);
		url.searchParams.set('scope', this.config.scopes);
		url.searchParams.set('state', state);
		url.searchParams.set('nonce', nonce);
		if (codeVerifier) {
			url.searchParams.set('code_challenge', pkceChallenge(codeVerifier));
			url.searchParams.set('code_challenge_method', 'S256');
		}
		return url.toString();
	}

	async exchangeCode({ code, codeVerifier, redirectUri }) {
		const discovery = await this.getDiscovery();
		const body = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri });
		const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
		const { tokenAuthMethod, clientId, clientSecret } = this.config;

		if (tokenAuthMethod === 'client_secret_basic') {
			// RFC 6749 2.3.1: both parts are form-urlencoded before base64.
			const encode = (value) => encodeURIComponent(value).replace(/%20/g, '+');
			headers.Authorization = `Basic ${Buffer.from(`${encode(clientId)}:${encode(clientSecret)}`).toString('base64')}`;
		} else {
			body.set('client_id', clientId);
			if (tokenAuthMethod === 'client_secret_post') body.set('client_secret', clientSecret);
		}
		if (codeVerifier) body.set('code_verifier', codeVerifier);

		const tokens = await fetchJson(discovery.token_endpoint, { method: 'POST', headers, body: body.toString() });
		if (typeof tokens.id_token !== 'string') throw new Error('Token response has no id_token');
		if (tokens.token_type && String(tokens.token_type).toLowerCase() !== 'bearer') {
			throw new Error(`Unexpected token_type ${tokens.token_type}`);
		}
		return tokens;
	}

	/** Validates an ID token per OpenID Connect Core 1.0, section 3.1.3.7. */
	async validateIdToken(idToken, expectedNonce, now = Date.now()) {
		const discovery = await this.getDiscovery();
		const { header, claims, signingInput, signature } = decodeJwt(idToken);

		if (typeof header.alg !== 'string' || !JWS_ALGORITHMS[header.alg]) {
			throw new Error(`ID token uses unsupported algorithm "${header.alg}"`);
		}
		const advertised = discovery.id_token_signing_alg_values_supported;
		if (Array.isArray(advertised) && !advertised.includes(header.alg)) {
			throw new Error(`ID token algorithm ${header.alg} is not advertised by the provider`);
		}
		const jwk = await this.findKey(header);
		if (!verifyJwsSignature(header.alg, jwk, signingInput, signature)) {
			throw new Error('ID token signature is invalid');
		}

		if (claims.iss !== discovery.issuer) throw new Error('ID token issuer does not match');
		const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
		if (!audiences.includes(this.config.clientId)) throw new Error('ID token audience does not match');
		if (audiences.length > 1 && claims.azp !== this.config.clientId) {
			throw new Error('ID token azp does not match');
		}
		if (claims.azp !== undefined && claims.azp !== this.config.clientId) {
			throw new Error('ID token azp does not match');
		}
		const nowSeconds = Math.floor(now / 1000);
		if (typeof claims.exp !== 'number' || claims.exp + CLOCK_SKEW_SECONDS < nowSeconds) {
			throw new Error('ID token has expired');
		}
		if (typeof claims.iat !== 'number' || claims.iat - CLOCK_SKEW_SECONDS > nowSeconds) {
			throw new Error('ID token was issued in the future');
		}
		if (typeof claims.nbf === 'number' && claims.nbf - CLOCK_SKEW_SECONDS > nowSeconds) {
			throw new Error('ID token is not valid yet');
		}
		if (!safeEqual(claims.nonce, expectedNonce)) throw new Error('ID token nonce does not match');
		if (typeof claims.sub !== 'string' || claims.sub.length === 0 || claims.sub.length > 255) {
			throw new Error('ID token has no usable sub');
		}
		return claims;
	}

	async fetchUserInfo(accessToken) {
		const discovery = await this.getDiscovery();
		if (!discovery.userinfo_endpoint || !accessToken) return {};
		return fetchJson(discovery.userinfo_endpoint, { headers: { Authorization: `Bearer ${accessToken}` } });
	}
}

// ---------------------------------------------------------------------------
// Access policy (pure, unit tested)
// ---------------------------------------------------------------------------

/**
 * Combines ID token and userinfo claims. Userinfo is only trusted when its sub
 * matches the validated ID token (OpenID Connect Core 1.0, section 5.3.2).
 */
function mergeClaims(idClaims, userInfo) {
	if (!userInfo || typeof userInfo !== 'object' || Object.keys(userInfo).length === 0) return { ...idClaims };
	if (userInfo.sub !== idClaims.sub) throw new Error('userinfo sub does not match the ID token');
	return { ...userInfo, ...idClaims };
}

/** Throws OidcLoginError when the claims are not allowed in. Returns a profile. */
function evaluateAccess(claims, config) {
	const email = typeof claims.email === 'string' ? claims.email.trim().toLowerCase() : undefined;
	if (!isValidEmail(email)) throw new OidcLoginError('email_missing', 'No valid email claim');

	if (isFalse(claims.email_verified)) {
		throw new OidcLoginError('email_not_verified', `Email ${email} is marked unverified`);
	}
	const emailVerified = isTrue(claims.email_verified);

	if (config.allowedEmailDomains.length) {
		const domain = email.split('@').pop();
		if (!config.allowedEmailDomains.includes(domain)) {
			throw new OidcLoginError('access_denied', `Email domain ${domain} is not allowed`);
		}
	}

	if (config.allowedGroups.length) {
		const groups = claimToList(claims[config.groupsClaim]);
		if (!groups.some((group) => config.allowedGroups.includes(group))) {
			throw new OidcLoginError('access_denied', `${email} is in none of the allowed groups`);
		}
	}

	const fullName = typeof claims.name === 'string' ? claims.name.trim() : '';
	const [firstFromName, ...restFromName] = fullName ? fullName.split(/\s+/) : [];

	// Names as the provider states them, for keeping existing accounts in sync.
	// undefined means "the provider said nothing", so the n8n value is kept.
	const nameClaims = {
		firstName: truncate(claims.given_name) || truncate(firstFromName),
		lastName:
			typeof claims.family_name === 'string'
				? truncate(claims.family_name) || ''
				: fullName
					? truncate(restFromName.join(' ')) || ''
					: undefined,
	};

	return {
		sub: claims.sub,
		email,
		emailVerified,
		firstName: nameClaims.firstName || truncate(claims.preferred_username) || 'User',
		lastName: nameClaims.lastName || '',
		nameClaims,
	};
}

// ---------------------------------------------------------------------------
// n8n internals
// ---------------------------------------------------------------------------

function isN8nRoot(dir) {
	try {
		const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
		return pkg.name === 'n8n' ? pkg : null;
	} catch {
		return null;
	}
}

/** Finds the installed n8n package without hard-coding the Docker layout. */
function findN8nRoot() {
	const candidates = [];
	if (process.env.OIDC_N8N_PACKAGE_DIR) candidates.push(process.env.OIDC_N8N_PACKAGE_DIR);
	for (const entry of [require.main && require.main.filename, process.argv[1]]) {
		if (!entry) continue;
		let dir = path.dirname(fs.existsSync(entry) ? fs.realpathSync(entry) : entry);
		for (let i = 0; i < 6; i++) {
			candidates.push(dir);
			const parent = path.dirname(dir);
			if (parent === dir) break;
			dir = parent;
		}
	}
	candidates.push('/usr/local/lib/node_modules/n8n');
	try {
		candidates.push(path.dirname(require.resolve('n8n/package.json')));
	} catch {}

	for (const dir of candidates) {
		const pkg = isN8nRoot(dir);
		if (pkg) return { root: dir, version: pkg.version };
	}
	throw new Error('Could not locate the n8n package; set OIDC_N8N_PACKAGE_DIR');
}

/**
 * Asks n8n's UrlService for the public instance URL, trying each place the class
 * has lived in, and falls back to N8N_EDITOR_BASE_URL so a future move inside
 * n8n does not switch the login off.
 */
function resolveInstanceBaseUrl(urlServiceLoaders, getInstance, env = process.env) {
	for (const load of urlServiceLoaders) {
		try {
			const UrlService = load();
			if (!UrlService) continue;
			const url = getInstance(UrlService).getInstanceBaseUrl();
			if (typeof url === 'string' && /^https?:\/\//.test(url)) return stripTrailingSlash(url);
		} catch (error) {
			log.debug('UrlService source unavailable:', String(error.message).split('\n')[0]);
		}
	}
	if (env.N8N_EDITOR_BASE_URL && /^https?:\/\//.test(env.N8N_EDITOR_BASE_URL)) {
		return stripTrailingSlash(env.N8N_EDITOR_BASE_URL);
	}
	return undefined;
}

function loadN8nInternals() {
	const { root, version } = findN8nRoot();
	const n8nRequire = createRequire(path.join(root, 'package.json'));
	const fromDist = (relative, exportName) => {
		const mod = n8nRequire(path.join(root, 'dist', relative));
		if (!mod[exportName]) throw new Error(`${exportName} not found in dist/${relative}`);
		return mod[exportName];
	};

	const { Container } = n8nRequire('@n8n/di');
	const db = n8nRequire('@n8n/db');
	for (const name of ['UserRepository', 'AuthIdentityRepository', 'AuthIdentity', 'GLOBAL_MEMBER_ROLE']) {
		if (!db[name]) throw new Error(`@n8n/db does not export ${name}`);
	}
	const { GlobalConfig } = n8nRequire('@n8n/config');
	const AuthService = fromDist('auth/auth.service.js', 'AuthService');
	const OwnershipService = fromDist('services/ownership.service.js', 'OwnershipService');

	// UrlService moved from n8n itself (<= 2.41) into @n8n/backend-services (>= 2.42).
	const instanceBaseUrl = resolveInstanceBaseUrl(
		[() => n8nRequire('@n8n/backend-services').UrlService, () => fromDist('services/url.service.js', 'UrlService')],
		(UrlService) => Container.get(UrlService),
	);
	if (!instanceBaseUrl) {
		log.warn('Could not read the instance URL from n8n; set N8N_EDITOR_BASE_URL or OIDC_REDIRECT_URI');
	}

	let encryptionKey;
	try {
		const { InstanceSettings } = n8nRequire('n8n-core');
		encryptionKey = Container.get(InstanceSettings).encryptionKey;
	} catch (error) {
		log.debug('InstanceSettings unavailable:', error.message);
	}

	let eventService;
	try {
		eventService = Container.get(fromDist('events/event.service.js', 'EventService'));
	} catch (error) {
		log.debug('EventService unavailable, login events are not recorded:', error.message);
	}

	const globalConfig = Container.get(GlobalConfig);
	return {
		version,
		authService: Container.get(AuthService),
		ownershipService: Container.get(OwnershipService),
		userRepository: Container.get(db.UserRepository),
		authIdentityRepository: Container.get(db.AuthIdentityRepository),
		AuthIdentity: db.AuthIdentity,
		GLOBAL_MEMBER_ROLE: db.GLOBAL_MEMBER_ROLE,
		cookieSecure: globalConfig.auth?.cookie?.secure !== false,
		nonUiRoutes: String(globalConfig.endpoints?.additionalNonUIRoutes || '').split(':'),
		instanceBaseUrl,
		encryptionKey,
		eventService,
	};
}

// ---------------------------------------------------------------------------
// Account resolution
// ---------------------------------------------------------------------------

/**
 * Finds or creates the n8n user for a verified OIDC profile.
 * Order: linked identity (sub) -> existing account by verified email ->
 * instance owner setup (OIDC_OWNER_EMAIL) -> auto-provisioned member.
 */
async function resolveUser(profile, config, n8n) {
	const identity = await n8n.authIdentityRepository.findOne({
		where: { providerId: profile.sub, providerType: PROVIDER_TYPE },
		relations: { user: { role: true } },
	});
	if (identity && identity.user) return { user: identity.user, how: 'identity' };

	const needsVerifiedEmail = () => {
		if (config.requireEmailVerified && !profile.emailVerified) {
			throw new OidcLoginError('email_not_verified', `Email ${profile.email} is not verified by the provider`);
		}
	};
	const link = async (user) => {
		await n8n.authIdentityRepository.save(
			n8n.authIdentityRepository.create({ providerId: profile.sub, providerType: PROVIDER_TYPE, userId: user.id }),
		);
	};

	const existing = await n8n.userRepository.findOne({
		where: { email: profile.email },
		relations: ['role'],
	});
	if (existing) {
		// Linking by email hands over an existing account, so the provider must vouch for it.
		needsVerifiedEmail();
		await link(existing);
		return { user: existing, how: 'linked' };
	}

	if (!(await n8n.ownershipService.hasInstanceOwner())) {
		if (!config.ownerEmail || profile.email !== config.ownerEmail) {
			throw new OidcLoginError('instance_not_setup', `Owner not set up; ${profile.email} is not OIDC_OWNER_EMAIL`);
		}
		needsVerifiedEmail();
		const owner = await n8n.ownershipService.setupOwner({
			email: profile.email,
			firstName: profile.firstName,
			lastName: profile.lastName || profile.firstName,
			// Unusable random password; the owner signs in through OIDC.
			password: randomToken(48),
		});
		await link(owner);
		const user = await n8n.userRepository.findOne({ where: { id: owner.id }, relations: ['role'] });
		return { user, how: 'owner-setup' };
	}

	if (!config.autoProvision) {
		throw new OidcLoginError('not_provisioned', `${profile.email} has no n8n account and auto-provisioning is off`);
	}
	needsVerifiedEmail();

	const user = await n8n.userRepository.manager.transaction(async (trx) => {
		const { user: created } = await n8n.userRepository.createUserWithProject(
			{
				email: profile.email,
				firstName: profile.firstName,
				lastName: profile.lastName,
				role: n8n.GLOBAL_MEMBER_ROLE,
				password: randomToken(48),
				authIdentities: [],
			},
			trx,
		);
		await trx.save(
			trx.create(n8n.AuthIdentity, { providerId: profile.sub, providerType: PROVIDER_TYPE, userId: created.id }),
		);
		return created;
	});
	return { user, how: 'provisioned' };
}

/**
 * Brings an existing account in line with the provider: first and last name, and
 * the email address. Returns the names of the changed fields.
 *
 * The email only follows when the provider marks it verified and no other n8n
 * account uses it; otherwise the old address stays and the login goes ahead.
 * Changing the email also ends the user's other n8n sessions, because n8n ties
 * its session cookie to the address.
 */
async function syncProfile(user, profile, config, n8n) {
	if (!config.syncProfile) return [];
	const changes = {};

	const { firstName, lastName } = profile.nameClaims || {};
	if (firstName !== undefined && firstName !== (user.firstName || '')) changes.firstName = firstName;
	if (lastName !== undefined && lastName !== (user.lastName || '')) changes.lastName = lastName;

	const currentEmail = String(user.email || '').toLowerCase();
	if (profile.email !== currentEmail) {
		if (!profile.emailVerified) {
			log.warn(`Keeping email ${currentEmail}: ${profile.email} is not verified by the provider`);
		} else {
			const owner = await n8n.userRepository.findOne({ where: { email: profile.email } });
			if (owner && owner.id !== user.id) {
				log.warn(`Keeping email ${currentEmail}: another n8n account already uses ${profile.email}`);
			} else {
				changes.email = profile.email;
			}
		}
	}

	const fields = Object.keys(changes);
	if (!fields.length) return [];
	// save() on the loaded entity, like n8n's own UserService.update(): only then do
	// n8n's entity subscribers see the old row and rename the personal project
	// ("First Last <email>") as well. update() skips that and n8n logs a warning.
	const current = await n8n.userRepository.findOneBy({ id: user.id });
	if (!current) throw new Error(`user ${user.id} no longer exists`);
	await n8n.userRepository.save({ ...current, ...changes }, { transaction: true });
	// The session cookie is derived from these values, so the object must match the database.
	Object.assign(user, changes);
	try {
		n8n.eventService?.emit('user-updated', { user, fieldsChanged: fields });
	} catch {}
	return fields;
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

function registerRoutes(app, { config, provider, n8n, cookieKey, redirectUri, baseUrl }) {
	const txCookieOptions = {
		httpOnly: true,
		secure: n8n.cookieSecure,
		// Must be lax: the provider redirects back with a cross-site top-level GET.
		sameSite: 'lax',
		path: TX_COOKIE_PATH,
		maxAge: TX_MAX_AGE_SECONDS * 1000,
	};
	const fail = (res, code) => {
		res.clearCookie(TX_COOKIE, { path: TX_COOKIE_PATH });
		res.redirect(`${baseUrl}/signin?oidc_error=${encodeURIComponent(code)}`);
	};

	app.get(ROUTE_LOGIN, async (req, res) => {
		try {
			const state = randomToken();
			const nonce = randomToken();
			const codeVerifier = config.usePkce ? randomToken(48) : undefined;
			const redirect = sanitizeRedirectPath(typeof req.query.redirect === 'string' ? req.query.redirect : '/');
			const authorizationUrl = await provider.buildAuthorizationUrl({ state, nonce, codeVerifier, redirectUri });

			res.cookie(TX_COOKIE, sealTransaction({ state, nonce, codeVerifier, redirect }, cookieKey), txCookieOptions);
			res.set('Cache-Control', 'no-store');
			res.redirect(authorizationUrl);
		} catch (error) {
			log.error('Could not start the login:', error.message);
			fail(res, 'login_failed');
		}
	});

	app.get(ROUTE_CALLBACK, async (req, res) => {
		res.set('Cache-Control', 'no-store');
		const tx = openTransaction(req.cookies && req.cookies[TX_COOKIE], cookieKey);
		res.clearCookie(TX_COOKIE, { path: TX_COOKIE_PATH });
		try {
			if (typeof req.query.error === 'string') {
				const code = req.query.error === 'access_denied' ? 'access_denied' : 'login_failed';
				throw new OidcLoginError(code, `Provider returned error "${req.query.error.slice(0, 100)}"`);
			}
			if (!tx) throw new OidcLoginError('session_expired', 'Transaction cookie missing, expired or invalid');
			if (!safeEqual(req.query.state, tx.state)) throw new OidcLoginError('session_expired', 'State mismatch');
			if (typeof req.query.code !== 'string' || !req.query.code) throw new Error('Missing authorization code');
			if (req.query.iss !== undefined && req.query.iss !== (await provider.getDiscovery()).issuer) {
				throw new Error('Authorization response iss does not match (RFC 9207)');
			}

			const tokens = await provider.exchangeCode({ code: req.query.code, codeVerifier: tx.codeVerifier, redirectUri });
			const idClaims = await provider.validateIdToken(tokens.id_token, tx.nonce);
			let userInfo = {};
			try {
				userInfo = await provider.fetchUserInfo(tokens.access_token);
			} catch (error) {
				log.warn('userinfo request failed, continuing with ID token claims:', error.message);
			}
			const profile = evaluateAccess(mergeClaims(idClaims, userInfo), config);

			const { user, how } = await resolveUser(profile, config, n8n);
			if (!user) throw new Error('No user after resolution');
			if (user.disabled) throw new OidcLoginError('user_disabled', `${profile.email} is disabled in n8n`);

			let updated = [];
			if (how === 'identity' || how === 'linked') {
				try {
					updated = await syncProfile(user, profile, config, n8n);
				} catch (error) {
					log.warn(`Could not update the profile of ${user.email}, signing in anyway: ${error.message}`);
				}
			}

			// usedMfa=true: multi-factor authentication is the provider's job (passkeys in
			// Pocket ID), as with n8n's licensed OIDC integration.
			n8n.authService.issueCookie(res, user, true, req.browserId);
			try {
				n8n.eventService?.emit('user-logged-in', { user, authenticationMethod: 'oidc' });
			} catch {}

			// The n8n account, which can differ from the provider's address (see syncProfile).
			log.info(`Signed in ${user.email} (${how}${updated.length ? `, updated ${updated.join(', ')}` : ''})`);
			res.redirect(`${baseUrl}${tx.redirect || '/'}`);
		} catch (error) {
			const code = error instanceof OidcLoginError ? error.code : 'login_failed';
			log.warn(`Login rejected (${code}): ${error.message}`);
			try {
				n8n.eventService?.emit('user-login-failed', {
					userEmail: 'unknown',
					authenticationMethod: 'oidc',
					reason: code,
				});
			} catch {}
			fail(res, code);
		}
	});

	const frontendScript = buildFrontendScript({
		loginUrl: `${baseUrl}${ROUTE_LOGIN}`,
		buttonLabel: config.buttonLabel,
		hidePasswordLogin: config.hidePasswordLogin,
		autoRedirect: config.autoRedirect,
		ownerSetup: Boolean(config.ownerEmail),
	});
	const frontendEtag = `"${crypto.createHash('sha256').update(frontendScript).digest('base64url').slice(0, 16)}"`;
	app.get(ROUTE_FRONTEND, (req, res) => {
		res.type('text/javascript; charset=utf-8');
		res.set('Cache-Control', 'no-cache');
		res.set('ETag', frontendEtag);
		if (req.headers['if-none-match'] === frontendEtag) return res.status(304).end();
		res.send(frontendScript);
	});
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

async function setup(server) {
	let loaded;
	try {
		loaded = loadConfig();
	} catch (error) {
		log.error(`Invalid configuration, OIDC login disabled: ${error.message}`);
		return;
	}
	if (loaded.missing) {
		log.warn(`Missing ${loaded.missing.join(', ')}; OIDC login disabled.`);
		return;
	}
	const { config } = loaded;

	let n8n;
	try {
		n8n = loadN8nInternals();
	} catch (error) {
		log.error(`Could not access n8n internals, OIDC login disabled: ${error.message}`);
		return;
	}

	const baseUrl = n8n.instanceBaseUrl || (config.redirectUri ? new URL(config.redirectUri).origin : undefined);
	if (!baseUrl) {
		log.error('Cannot determine the n8n URL; set N8N_EDITOR_BASE_URL or OIDC_REDIRECT_URI. OIDC login disabled.');
		return;
	}
	const redirectUri = config.redirectUri || `${baseUrl}${ROUTE_CALLBACK}`;
	if (new URL(redirectUri).origin !== new URL(baseUrl).origin) {
		log.warn(
			`OIDC_REDIRECT_URI (${redirectUri}) and the n8n URL (${baseUrl}) differ; ` +
				'set N8N_EDITOR_BASE_URL to the public URL, or users land on the wrong host after login.',
		);
	}
	if (!process.env.N8N_EDITOR_BASE_URL) {
		log.warn(`N8N_EDITOR_BASE_URL is not set; using ${baseUrl}. Set it when n8n runs behind a reverse proxy.`);
	}

	if (!n8n.nonUiRoutes.includes('auth')) {
		log.error(
			'N8N_ADDITIONAL_NON_UI_ROUTES must include "auth", otherwise the editor swallows /auth/oidc/*. OIDC login disabled.',
		);
		return;
	}
	if (!process.env.EXTERNAL_FRONTEND_HOOKS_URLS?.split(';').includes(ROUTE_FRONTEND)) {
		log.warn(`EXTERNAL_FRONTEND_HOOKS_URLS does not contain ${ROUTE_FRONTEND}; no SSO button will be shown.`);
	}

	let secret = n8n.encryptionKey || process.env.N8N_ENCRYPTION_KEY;
	if (!secret) {
		log.warn('No n8n encryption key found; using a per-process key (logins in flight fail on restart).');
		secret = crypto.randomBytes(32).toString('hex');
	}

	const provider = new OidcProvider(config);
	try {
		await provider.getDiscovery();
	} catch (error) {
		// Not fatal: the provider may simply be starting up. Retried on first login.
		log.warn(`Provider discovery failed (will retry on login): ${error.message}`);
	}

	const app = server && server.app;
	if (!app || typeof app.get !== 'function') {
		log.error('The n8n server object has no express app; OIDC login disabled.');
		return;
	}
	registerRoutes(app, { config, provider, n8n, cookieKey: deriveCookieKey(secret), redirectUri, baseUrl });

	log.info(`v${HOOK_VERSION} active on n8n ${n8n.version}`);
	log.info(`  issuer:       ${config.issuerUrl}`);
	log.info(`  redirect URI: ${redirectUri}`);
	log.info(
		`  PKCE: ${config.usePkce ? 'on' : 'off'}, auto-provision: ${config.autoProvision ? 'on' : 'off'}, ` +
			`profile sync: ${config.syncProfile ? 'on' : 'off'}, ` +
			`groups: ${config.allowedGroups.join(', ') || '(any)'}, domains: ${config.allowedEmailDomains.join(', ') || '(any)'}`,
	);
	if (config.ownerEmail) log.info(`  owner setup via OIDC for ${config.ownerEmail}`);
}

// ---------------------------------------------------------------------------
// Frontend script
// ---------------------------------------------------------------------------

function buildFrontendScript(options) {
	// JSON in a script body: escape "<" so the config can never close a tag.
	const json = JSON.stringify(options).replace(/</g, '\\u003c');
	return `/* n8n-oidc ${HOOK_VERSION} */\n(${frontendMain.toString()})(${json});\n`;
}

/* Runs in the browser. Kept free of anything the server scope provides. */
function frontendMain(cfg) {
	'use strict';
	var MESSAGES = {
		login_failed: 'Sign-in failed. Please try again or contact your administrator.',
		session_expired: 'The sign-in took too long or was started in another tab. Please try again.',
		access_denied: 'Your account is not allowed to use this n8n instance.',
		email_not_verified: 'Your email address is not verified by the identity provider.',
		email_missing: 'The identity provider did not send an email address.',
		not_provisioned: 'There is no n8n account for you yet. Ask an administrator to invite you.',
		instance_not_setup: 'This n8n instance has not been set up yet. Only the configured owner can do that.',
		user_disabled: 'Your n8n account is disabled.',
	};
	var BLOCK_ID = 'n8n-oidc-block';
	var GUARD_KEY = 'n8n-oidc-auto-redirect-at';
	// After a sign-out the sign-in page must not bounce to the provider, or signing
	// out signs you straight back in. n8n reloads /signin after logging out, so the
	// marker lives in sessionStorage; it is cleared by an explicit SSO click or by
	// reaching the editor again.
	var SIGNED_OUT_KEY = 'n8n-oidc-signed-out';
	var autoRedirectDone = false;

	function storage(action, key, value) {
		try {
			if (action === 'get') return sessionStorage.getItem(key);
			if (action === 'set') sessionStorage.setItem(key, value);
			if (action === 'remove') sessionStorage.removeItem(key);
		} catch (e) {}
		return null;
	}
	function markSignedOut() {
		storage('set', SIGNED_OUT_KEY, '1');
	}
	if (isPath('/signout')) markSignedOut();

	// The editor signs out with POST /rest/logout (axios uses XHR).
	function noteRequest(url) {
		if (typeof url === 'string' && /\/rest\/logout(\?|$)/.test(url)) markSignedOut();
	}
	try {
		var originalOpen = XMLHttpRequest.prototype.open;
		XMLHttpRequest.prototype.open = function (method, url) {
			noteRequest(String(url));
			return originalOpen.apply(this, arguments);
		};
		var originalFetch = window.fetch;
		window.fetch = function (input) {
			noteRequest(typeof input === 'string' ? input : input && input.url);
			return originalFetch.apply(this, arguments);
		};
	} catch (e) {}

	function params() {
		return new URLSearchParams(window.location.search);
	}
	function isPath(p) {
		return window.location.pathname.replace(/\/+$/, '').endsWith(p);
	}
	function wantsPasswordLogin() {
		return params().get('showLogin') === 'true';
	}
	function loginHref() {
		var redirect = params().get('redirect');
		// n8n double-encodes this parameter (/signin?redirect=%252Fhome%252Fcredentials).
		for (var i = 0; i < 2 && redirect && /^%2f/i.test(redirect); i++) {
			try {
				redirect = decodeURIComponent(redirect);
			} catch (e) {
				redirect = null;
			}
		}
		if (redirect && redirect.charAt(0) === '/' && redirect.charAt(1) !== '/') {
			return cfg.loginUrl + '?redirect=' + encodeURIComponent(redirect);
		}
		return cfg.loginUrl;
	}

	function buildBlock(formBox, showAdminLink) {
		var block = document.createElement('div');
		block.id = BLOCK_ID;
		block.style.cssText = 'display:flex;flex-direction:column;gap:12px;margin:8px 0 16px;';

		var code = params().get('oidc_error');
		if (code) {
			var alert = document.createElement('div');
			alert.setAttribute('role', 'alert');
			alert.style.cssText =
				'padding:10px 12px;border-radius:6px;font-size:13px;line-height:1.4;' +
				'background:var(--color-danger-tint-2,#fdecea);color:var(--color-danger,#c0392b);' +
				'border:1px solid var(--color-danger-tint-1,#f5c6cb);';
			alert.textContent = MESSAGES[code] || MESSAGES.login_failed;
			block.appendChild(alert);
		}

		var submit = formBox.querySelector('[data-test-id="form-submit-button"]');
		var button = document.createElement('button');
		button.type = 'button';
		button.setAttribute('data-test-id', 'oidc-login-button');
		button.textContent = cfg.buttonLabel;
		if (submit) {
			button.className = submit.className;
			button.style.width = '100%';
		} else {
			button.style.cssText =
				'width:100%;padding:10px 16px;font-size:14px;font-weight:600;cursor:pointer;border:none;' +
				'border-radius:6px;color:#fff;background:var(--color-primary,#ea4b30);';
		}
		button.addEventListener('click', function () {
			button.disabled = true;
			storage('remove', SIGNED_OUT_KEY);
			window.location.href = loginHref();
		});
		block.appendChild(button);

		if (showAdminLink) {
			var p = document.createElement('p');
			p.style.cssText = 'margin:0;text-align:center;font-size:12px;color:var(--color-text-light,#7d7d87);';
			var a = document.createElement('a');
			var q = params();
			q.set('showLogin', 'true');
			q.delete('oidc_error');
			a.href = window.location.pathname + '?' + q.toString();
			a.textContent = 'Sign in with email and password';
			a.style.color = 'var(--color-primary,#ea4b30)';
			p.appendChild(a);
			block.appendChild(p);
		} else {
			var divider = document.createElement('div');
			divider.style.cssText =
				'display:flex;align-items:center;gap:8px;font-size:12px;color:var(--color-text-light,#7d7d87);';
			var line1 = document.createElement('span');
			var line2 = document.createElement('span');
			line1.style.cssText = line2.style.cssText = 'flex:1;height:1px;background:var(--color-foreground-base,#dcdfe6);';
			var label = document.createElement('span');
			label.textContent = 'or';
			divider.appendChild(line1);
			divider.appendChild(label);
			divider.appendChild(line2);
			block.appendChild(divider);
		}
		return block;
	}

	function inject() {
		var onSignout = isPath('/signout');
		if (onSignout) markSignedOut();
		var onSignin = isPath('/signin') || isPath('/login');
		var onSetup = isPath('/setup') && cfg.ownerSetup;
		var existing = document.getElementById(BLOCK_ID);
		if (!onSignin && !onSetup) {
			if (existing) existing.remove();
			// Anywhere else in the editor means we are signed in again.
			if (!onSignout && !isPath('/forgot-password') && !isPath('/change-password')) {
				storage('remove', SIGNED_OUT_KEY);
			}
			return;
		}
		if (onSignin && maybeAutoRedirect()) return;
		var formBox = document.querySelector('[data-test-id="auth-form"]');
		if (!formBox || existing) return;

		var hide = onSignin && cfg.hidePasswordLogin && !wantsPasswordLogin();
		var children = Array.prototype.slice.call(formBox.children);
		var heading = children.filter(function (el) {
			return el.querySelector('h1,h2,h3,h4,[class*="heading"]');
		})[0];
		var block = buildBlock(formBox, hide);
		if (heading) heading.insertAdjacentElement('afterend', block);
		else formBox.insertBefore(block, formBox.firstChild);

		if (hide) {
			children.forEach(function (el) {
				if (el !== heading && el !== block) el.style.display = 'none';
			});
		}
	}

	function maybeAutoRedirect() {
		if (!cfg.autoRedirect || autoRedirectDone || storage('get', SIGNED_OUT_KEY)) return false;
		if (wantsPasswordLogin() || params().get('oidc_error')) return false;
		// Loop guard: if we bounced to the provider moments ago and are back here, stop.
		try {
			var last = Number(sessionStorage.getItem(GUARD_KEY) || 0);
			if (Date.now() - last < 15000) return false;
			sessionStorage.setItem(GUARD_KEY, String(Date.now()));
		} catch (e) {}
		autoRedirectDone = true;
		window.location.replace(loginHref());
		return true;
	}

	function start() {
		inject();
		new MutationObserver(inject).observe(document.body, { childList: true, subtree: true });
	}

	['pushState', 'replaceState'].forEach(function (name) {
		var original = history[name];
		history[name] = function () {
			var result = original.apply(this, arguments);
			setTimeout(inject, 0);
			return result;
		};
	});
	window.addEventListener('popstate', function () {
		setTimeout(inject, 0);
	});

	if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
	else start();
}

// ---------------------------------------------------------------------------
// Hook export
// ---------------------------------------------------------------------------

module.exports = {
	n8n: {
		ready: [
			async function (server) {
				try {
					await setup(server);
				} catch (error) {
					// Never break n8n startup because of this hook.
					log.error('Unexpected error during setup, OIDC login disabled:', error);
				}
			},
		],
	},
};

// For tests only. n8n iterates the exported object with Object.entries(), which
// skips symbol keys, so this does not register as a hook.
Object.defineProperty(module.exports, Symbol.for('n8n-oidc.internals'), {
	value: {
		loadConfig,
		sanitizeRedirectPath,
		sealTransaction,
		openTransaction,
		deriveCookieKey,
		pkceChallenge,
		verifyJwsSignature,
		decodeJwt,
		OidcProvider,
		mergeClaims,
		evaluateAccess,
		resolveUser,
		syncProfile,
		OidcLoginError,
		buildFrontendScript,
		findN8nRoot,
		resolveInstanceBaseUrl,
		HOOK_VERSION,
	},
});
