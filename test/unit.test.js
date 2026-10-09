'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const hooks = require('../hooks.js');
const t = hooks[Symbol.for('n8n-oidc.internals')];

const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

// ---------------------------------------------------------------------------

test('hook file only exposes the n8n.ready hook to n8n', () => {
	// n8n walks Object.entries(); anything else would be registered as a hook.
	assert.deepEqual(Object.keys(hooks), ['n8n']);
	assert.deepEqual(Object.keys(hooks.n8n), ['ready']);
	assert.equal(typeof hooks.n8n.ready[0], 'function');
});

test('a failing setup never throws into n8n', async () => {
	const saved = { ...process.env };
	process.env.OIDC_ISSUER_URL = 'http://127.0.0.1:1';
	process.env.OIDC_CLIENT_ID = 'x';
	process.env.OIDC_N8N_PACKAGE_DIR = '/nonexistent';
	const errors = [];
	const original = console.error;
	console.error = (...args) => errors.push(args.join(' '));
	try {
		await hooks.n8n.ready[0]({ app: {} });
	} finally {
		console.error = original;
		process.env = saved;
	}
	assert.ok(errors.some((line) => line.includes('OIDC login disabled')));
});

// ---------------------------------------------------------------------------

test('loadConfig reports missing required values', () => {
	assert.deepEqual(t.loadConfig({}).missing, ['OIDC_ISSUER_URL', 'OIDC_CLIENT_ID']);
});

test('loadConfig defaults', () => {
	const { config } = t.loadConfig({
		OIDC_ISSUER_URL: 'https://id.example.com/',
		OIDC_CLIENT_ID: 'n8n',
		OIDC_CLIENT_SECRET: 's3cret',
	});
	assert.equal(config.issuerUrl, 'https://id.example.com');
	assert.equal(config.tokenAuthMethod, 'client_secret_basic');
	assert.equal(config.usePkce, true);
	assert.equal(config.scopes, 'openid email profile');
	assert.equal(config.autoProvision, true);
	assert.equal(config.syncProfile, true);
	assert.equal(config.requireEmailVerified, true);
	assert.equal(config.hidePasswordLogin, false);
	assert.equal(config.autoRedirect, false);
});

test('loadConfig adds the groups scope when groups are restricted', () => {
	const { config } = t.loadConfig({
		OIDC_ISSUER_URL: 'https://id.example.com',
		OIDC_CLIENT_ID: 'n8n',
		OIDC_CLIENT_SECRET: 's',
		OIDC_ALLOWED_GROUPS: 'n8n-users, admins',
		OIDC_ALLOWED_EMAIL_DOMAINS: '@Example.COM',
		OIDC_OWNER_EMAIL: 'Me@Example.com',
	});
	assert.deepEqual(config.allowedGroups, ['n8n-users', 'admins']);
	assert.equal(config.scopes, 'openid email profile groups');
	assert.deepEqual(config.allowedEmailDomains, ['example.com']);
	assert.equal(config.ownerEmail, 'me@example.com');
});

test('loadConfig reads the client secret from a file', () => {
	const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'oidc-')), 'secret');
	fs.writeFileSync(file, 'from-file\n');
	const { config } = t.loadConfig({
		OIDC_ISSUER_URL: 'https://id.example.com',
		OIDC_CLIENT_ID: 'n8n',
		OIDC_CLIENT_SECRET_FILE: file,
	});
	assert.equal(config.clientSecret, 'from-file');
});

test('loadConfig rejects unsafe or invalid combinations', () => {
	const base = { OIDC_ISSUER_URL: 'https://id.example.com', OIDC_CLIENT_ID: 'n8n' };
	assert.equal(t.loadConfig(base).config.tokenAuthMethod, 'none');
	assert.throws(() => t.loadConfig({ ...base, OIDC_USE_PKCE: 'false' }), /must use PKCE/);
	assert.throws(() => t.loadConfig({ ...base, OIDC_TOKEN_AUTH_METHOD: 'client_secret_post' }), /needs OIDC_CLIENT_SECRET/);
	assert.throws(() => t.loadConfig({ ...base, OIDC_TOKEN_AUTH_METHOD: 'private_key_jwt' }), /Unsupported/);
	assert.throws(() => t.loadConfig({ ...base, OIDC_AUTO_PROVISION: 'maybe' }), /boolean/);
});

// ---------------------------------------------------------------------------

test('sanitizeRedirectPath keeps same-origin paths only', () => {
	const ok = {
		'/': '/',
		'/workflow/abc': '/workflow/abc',
		'/home/workflows?search=x#top': '/home/workflows?search=x#top',
	};
	for (const [input, expected] of Object.entries(ok)) assert.equal(t.sanitizeRedirectPath(input), expected);

	for (const bad of [
		'',
		'https://evil.example',
		'//evil.example',
		'/\\evil.example',
		'\\\\evil',
		'javascript:alert(1)',
		'/\u0000x',
		'/a\\b',
		'/auth/oidc/login',
		'/signin?x=1',
		undefined,
		42,
		'/' + 'a'.repeat(3000),
	]) {
		assert.equal(t.sanitizeRedirectPath(bad), '/', `expected "/" for ${JSON.stringify(bad)}`);
	}
});

// ---------------------------------------------------------------------------

test('transaction cookie round-trips and rejects tampering, other keys and old cookies', () => {
	const key = t.deriveCookieKey('encryption-key');
	const payload = { state: 's', nonce: 'n', codeVerifier: 'v', redirect: '/x' };
	const sealed = t.sealTransaction(payload, key);
	assert.deepEqual({ ...t.openTransaction(sealed, key), iat: undefined }, { ...payload, iat: undefined });

	const parts = sealed.split('.');
	const flipped = Buffer.from(parts[1], 'base64url');
	flipped[0] ^= 1;
	assert.equal(t.openTransaction([parts[0], flipped.toString('base64url'), parts[2]].join('.'), key), null);
	assert.equal(t.openTransaction(sealed, t.deriveCookieKey('other')), null);
	assert.equal(t.openTransaction(t.sealTransaction(payload, key, Date.now() - 11 * 60 * 1000), key), null);
	assert.equal(t.openTransaction('garbage', key), null);
	assert.equal(t.openTransaction(undefined, key), null);
});

test('PKCE challenge is base64url(SHA-256(verifier)) without padding', async () => {
	const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r7wW1gFWFOEjXk';
	// Cross-check with WebCrypto, an independent implementation.
	const digest = await crypto.webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
	const expected = Buffer.from(digest).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
	assert.equal(t.pkceChallenge(verifier), expected);
	assert.match(t.pkceChallenge(verifier), /^[A-Za-z0-9_-]{43}$/);
});

// ---------------------------------------------------------------------------

function keyPair(alg) {
	switch (alg) {
		case 'RS256':
		case 'PS256':
			return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
		case 'ES256':
			return crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
		case 'ES384':
			return crypto.generateKeyPairSync('ec', { namedCurve: 'P-384' });
		case 'EdDSA':
			return crypto.generateKeyPairSync('ed25519');
	}
}

function sign(alg, privateKey, input) {
	const data = Buffer.from(input);
	switch (alg) {
		case 'RS256':
			return crypto.sign('sha256', data, privateKey);
		case 'PS256':
			return crypto.sign('sha256', data, {
				key: privateKey,
				padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
				saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
			});
		case 'ES256':
			return crypto.sign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
		case 'ES384':
			return crypto.sign('sha384', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
		case 'EdDSA':
			return crypto.sign(null, data, privateKey);
	}
}

for (const alg of ['RS256', 'PS256', 'ES256', 'ES384', 'EdDSA']) {
	test(`verifyJwsSignature accepts valid and rejects forged ${alg} signatures`, () => {
		const { publicKey, privateKey } = keyPair(alg);
		const jwk = publicKey.export({ format: 'jwk' });
		const input = 'header.payload';
		assert.equal(t.verifyJwsSignature(alg, jwk, input, sign(alg, privateKey, input)), true);
		assert.equal(t.verifyJwsSignature(alg, jwk, 'header.tampered', sign(alg, privateKey, input)), false);
	});
}

test('verifyJwsSignature refuses mismatched keys and unknown algorithms', () => {
	const rsa = keyPair('RS256').publicKey.export({ format: 'jwk' });
	const ec = keyPair('ES256').publicKey.export({ format: 'jwk' });
	assert.throws(() => t.verifyJwsSignature('ES256', rsa, 'a.b', Buffer.alloc(64)), /does not match/);
	assert.throws(() => t.verifyJwsSignature('ES384', ec, 'a.b', Buffer.alloc(96)), /Curve/);
	assert.throws(() => t.verifyJwsSignature('HS256', rsa, 'a.b', Buffer.alloc(32)), /Unsupported/);
	assert.throws(() => t.verifyJwsSignature('none', rsa, 'a.b', Buffer.alloc(0)), /Unsupported/);
	assert.throws(() => t.verifyJwsSignature('RS256', { ...rsa, alg: 'PS256' }, 'a.b', Buffer.alloc(256)), /restricted/);
});

// ---------------------------------------------------------------------------

function makeProvider({ alg = 'RS256', keys } = {}) {
	const { publicKey, privateKey } = keyPair(alg);
	const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig' };
	const provider = new t.OidcProvider({ issuerUrl: 'https://id.example.com', clientId: 'n8n', usePkce: true });
	provider.discovery = {
		issuer: 'https://id.example.com',
		authorization_endpoint: 'https://id.example.com/authorize',
		token_endpoint: 'https://id.example.com/token',
		jwks_uri: 'https://id.example.com/jwks',
		id_token_signing_alg_values_supported: [alg],
	};
	provider.discoveryFetchedAt = Date.now();
	provider.jwks = keys || [jwk];
	provider.jwksFetchedAt = Date.now();
	const now = Math.floor(Date.now() / 1000);
	const token = (claims = {}, header = {}) => {
		const h = { alg, kid: 'k1', ...header };
		const c = { iss: 'https://id.example.com', aud: 'n8n', sub: 'user-1', iat: now, exp: now + 300, nonce: 'n1', ...claims };
		const input = `${b64(h)}.${b64(c)}`;
		return `${input}.${sign(alg, privateKey, input).toString('base64url')}`;
	};
	return { provider, token, jwk };
}

test('validateIdToken accepts a correct token', async () => {
	const { provider, token } = makeProvider();
	const claims = await provider.validateIdToken(token(), 'n1');
	assert.equal(claims.sub, 'user-1');
});

test('validateIdToken accepts ES256 tokens (Pocket ID can be configured for EC keys)', async () => {
	const { provider, token } = makeProvider({ alg: 'ES256' });
	assert.equal((await provider.validateIdToken(token(), 'n1')).sub, 'user-1');
});

test('validateIdToken rejects every broken claim', async () => {
	const { provider, token } = makeProvider();
	const now = Math.floor(Date.now() / 1000);
	const cases = [
		[token({ iss: 'https://evil.example.com' }), /issuer/],
		[token({ aud: 'other' }), /audience/],
		[token({ aud: ['n8n', 'other'] }), /azp/],
		[token({ azp: 'other' }), /azp/],
		[token({ exp: now - 3600 }), /expired/],
		[token({ iat: now + 3600 }), /future/],
		[token({ nbf: now + 3600 }), /not valid yet/],
		[token({ nonce: 'other' }), /nonce/],
		[token({ nonce: undefined }), /nonce/],
		[token({ sub: '' }), /sub/],
		[token({}, { kid: 'unknown' }), /No signing key/],
	];
	for (const [jwt, pattern] of cases) {
		await assert.rejects(provider.validateIdToken(jwt, 'n1'), pattern);
	}
	assert.ok((await provider.validateIdToken(token({ aud: ['n8n', 'other'], azp: 'n8n' }), 'n1')).sub);
});

test('validateIdToken rejects forged signatures, alg=none and HS256 confusion', async () => {
	const { provider, token } = makeProvider();
	const good = token();
	const [h, p] = good.split('.');
	const forgedPayload = b64({ ...JSON.parse(Buffer.from(p, 'base64url')), sub: 'admin' });
	await assert.rejects(provider.validateIdToken(`${h}.${forgedPayload}.${good.split('.')[2]}`, 'n1'), /signature/);

	const none = `${b64({ alg: 'none', kid: 'k1' })}.${p}.`;
	await assert.rejects(provider.validateIdToken(none, 'n1'), /unsupported algorithm/);

	// Classic key confusion: HMAC signed with the public key as secret.
	const hsHeader = b64({ alg: 'HS256', kid: 'k1' });
	const hsSig = crypto.createHmac('sha256', JSON.stringify(provider.jwks[0])).update(`${hsHeader}.${p}`).digest('base64url');
	await assert.rejects(provider.validateIdToken(`${hsHeader}.${p}.${hsSig}`, 'n1'), /unsupported algorithm/);

	await assert.rejects(provider.validateIdToken('not-a-jwt', 'n1'), /compact JWS/);
});

test('validateIdToken rejects algorithms the provider does not advertise', async () => {
	const { provider, token } = makeProvider();
	provider.discovery.id_token_signing_alg_values_supported = ['ES256'];
	await assert.rejects(provider.validateIdToken(token(), 'n1'), /not advertised/);
});

test('validateIdToken picks up rotated keys once', async () => {
	const { provider, token, jwk } = makeProvider();
	provider.jwks = [{ ...jwk, kid: 'old' }];
	provider.jwksFetchedAt = 0;
	let fetched = 0;
	provider.getJwks = async (force) => {
		fetched++;
		return force ? [jwk] : [{ ...jwk, kid: 'old' }];
	};
	assert.equal((await provider.validateIdToken(token(), 'n1')).sub, 'user-1');
	assert.equal(fetched, 2);
});

test('authorization URL carries PKCE S256 and the nonce', async () => {
	const { provider } = makeProvider();
	provider.config.scopes = 'openid email';
	const url = new URL(
		await provider.buildAuthorizationUrl({
			state: 'st',
			nonce: 'no',
			codeVerifier: 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r7wW1gFWFOEjXk',
			redirectUri: 'https://n8n.example.com/auth/oidc/callback',
		}),
	);
	assert.equal(url.searchParams.get('code_challenge'), t.pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r7wW1gFWFOEjXk'));
	assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
	assert.equal(url.searchParams.get('nonce'), 'no');
	assert.equal(url.searchParams.get('state'), 'st');
	assert.equal(url.searchParams.get('response_type'), 'code');
});

// ---------------------------------------------------------------------------

const baseConfig = {
	allowedGroups: [],
	groupsClaim: 'groups',
	allowedEmailDomains: [],
	autoProvision: true,
	requireEmailVerified: true,
	ownerEmail: undefined,
};

test('evaluateAccess normalises the profile', () => {
	const profile = t.evaluateAccess(
		{ sub: 's', email: ' Jane@Example.COM ', email_verified: true, given_name: 'Jane', family_name: 'Doe' },
		baseConfig,
	);
	assert.deepEqual(profile, {
		sub: 's',
		email: 'jane@example.com',
		emailVerified: true,
		firstName: 'Jane',
		lastName: 'Doe',
		nameClaims: { firstName: 'Jane', lastName: 'Doe' },
	});
});

test('evaluateAccess only reports names the provider actually sent', () => {
	const names = (claims) => t.evaluateAccess({ sub: 's', email: 'a@b.de', ...claims }, baseConfig).nameClaims;
	assert.deepEqual(names({ given_name: 'Ada', family_name: 'Lovelace' }), { firstName: 'Ada', lastName: 'Lovelace' });
	// An empty family_name is a statement: the last name is empty.
	assert.deepEqual(names({ given_name: 'Ada', family_name: '' }), { firstName: 'Ada', lastName: '' });
	assert.deepEqual(names({ name: 'Ada King Lovelace' }), { firstName: 'Ada', lastName: 'King Lovelace' });
	// Nothing about the last name: keep whatever n8n has.
	assert.deepEqual(names({ given_name: 'Ada' }), { firstName: 'Ada', lastName: undefined });
	// The preferred_username / "User" fallbacks are for new accounts only, never synced.
	assert.deepEqual(names({ preferred_username: 'ada' }), { firstName: undefined, lastName: undefined });
});

test('evaluateAccess falls back to name and preferred_username and truncates', () => {
	assert.equal(t.evaluateAccess({ sub: 's', email: 'a@b.de', name: 'Ada King Lovelace' }, baseConfig).lastName, 'King Lovelace');
	assert.equal(t.evaluateAccess({ sub: 's', email: 'a@b.de', preferred_username: 'ada' }, baseConfig).firstName, 'ada');
	assert.equal(t.evaluateAccess({ sub: 's', email: 'a@b.de' }, baseConfig).firstName, 'User');
	assert.equal(t.evaluateAccess({ sub: 's', email: 'a@b.de', given_name: 'x'.repeat(50) }, baseConfig).firstName.length, 32);
});

test('evaluateAccess enforces email, verification, domains and groups', () => {
	const ok = { sub: 's', email: 'jane@example.com', email_verified: true, groups: ['n8n-users'] };
	const code = (fn) => {
		try {
			fn();
		} catch (error) {
			return error.code;
		}
		return 'allowed';
	};
	assert.equal(code(() => t.evaluateAccess({ ...ok, email: undefined }, baseConfig)), 'email_missing');
	assert.equal(code(() => t.evaluateAccess({ ...ok, email: 'not-an-email' }, baseConfig)), 'email_missing');
	assert.equal(code(() => t.evaluateAccess({ ...ok, email_verified: false }, baseConfig)), 'email_not_verified');
	assert.equal(code(() => t.evaluateAccess({ ...ok, email_verified: 'false' }, baseConfig)), 'email_not_verified');

	const domains = { ...baseConfig, allowedEmailDomains: ['example.com'] };
	assert.equal(code(() => t.evaluateAccess(ok, domains)), 'allowed');
	assert.equal(code(() => t.evaluateAccess({ ...ok, email: 'jane@evil.com' }, domains)), 'access_denied');
	assert.equal(code(() => t.evaluateAccess({ ...ok, email: 'jane@sub.example.com' }, domains)), 'access_denied');

	const groups = { ...baseConfig, allowedGroups: ['n8n-users'] };
	assert.equal(code(() => t.evaluateAccess(ok, groups)), 'allowed');
	assert.equal(code(() => t.evaluateAccess({ ...ok, groups: 'n8n-users other' }, groups)), 'allowed');
	assert.equal(code(() => t.evaluateAccess({ ...ok, groups: ['other'] }, groups)), 'access_denied');
	assert.equal(code(() => t.evaluateAccess({ ...ok, groups: undefined }, groups)), 'access_denied');
	assert.equal(code(() => t.evaluateAccess({ ...ok, roles: ['n8n-users'] }, { ...groups, groupsClaim: 'roles' })), 'allowed');
});

test('mergeClaims only trusts userinfo with the same sub', () => {
	assert.deepEqual(t.mergeClaims({ sub: 'a', email: 'id@x.de' }, { sub: 'a', email: 'ui@x.de', groups: ['g'] }), {
		sub: 'a',
		email: 'id@x.de',
		groups: ['g'],
	});
	assert.deepEqual(t.mergeClaims({ sub: 'a' }, {}), { sub: 'a' });
	assert.throws(() => t.mergeClaims({ sub: 'a' }, { sub: 'b' }), /sub/);
});

// ---------------------------------------------------------------------------

function fakeN8n({ users = [], identities = [], ownerSetUp = true } = {}) {
	const created = [];
	const savedIdentities = [];
	const updates = [];
	const n8n = {
		GLOBAL_MEMBER_ROLE: { slug: 'global:member' },
		AuthIdentity: class {},
		authIdentityRepository: {
			findOne: async ({ where }) => {
				const found = identities.find((i) => i.providerId === where.providerId && where.providerType === 'oidc');
				return found ? { user: users.find((u) => u.id === found.userId) } : null;
			},
			create: (value) => value,
			save: async (value) => savedIdentities.push(value),
		},
		userRepository: {
			findOne: async ({ where }) => users.find((u) => (where.email ? u.email === where.email : u.id === where.id)) || null,
			update: async ({ id }, changes) => {
				updates.push({ id, ...changes });
				Object.assign(users.find((u) => u.id === id), changes);
			},
			createUserWithProject: async (data) => {
				const user = { id: `u${users.length + 1}`, ...data };
				users.push(user);
				created.push(user);
				return { user };
			},
			manager: {
				transaction: async (fn) =>
					fn({
						create: (_entity, value) => value,
						save: async (value) => savedIdentities.push(value),
					}),
			},
		},
		ownershipService: {
			hasInstanceOwner: async () => ownerSetUp,
			setupOwner: async (payload) => {
				const owner = { id: 'owner', role: { slug: 'global:owner' }, ...payload };
				users.push(owner);
				ownerSetUp = true;
				return owner;
			},
		},
	};
	return { n8n, created, savedIdentities, updates, users };
}

const profile = { sub: 'sub-1', email: 'jane@example.com', emailVerified: true, firstName: 'Jane', lastName: 'Doe' };

test('resolveUser prefers the linked identity', async () => {
	const { n8n } = fakeN8n({ users: [{ id: 'u1', email: 'changed@example.com' }], identities: [{ providerId: 'sub-1', userId: 'u1' }] });
	const result = await t.resolveUser(profile, baseConfig, n8n);
	assert.equal(result.user.id, 'u1');
	assert.equal(result.how, 'identity');
});

test('resolveUser links an existing account only with a verified email', async () => {
	const existing = () => fakeN8n({ users: [{ id: 'u1', email: 'jane@example.com' }] });

	const verified = existing();
	const result = await t.resolveUser(profile, baseConfig, verified.n8n);
	assert.equal(result.how, 'linked');
	assert.deepEqual(verified.savedIdentities, [{ providerId: 'sub-1', providerType: 'oidc', userId: 'u1' }]);

	const unverified = existing();
	await assert.rejects(t.resolveUser({ ...profile, emailVerified: false }, baseConfig, unverified.n8n), { code: 'email_not_verified' });
	assert.equal(unverified.savedIdentities.length, 0);
});

test('resolveUser sets up the owner only for OIDC_OWNER_EMAIL', async () => {
	const stranger = fakeN8n({ ownerSetUp: false });
	await assert.rejects(t.resolveUser(profile, baseConfig, stranger.n8n), { code: 'instance_not_setup' });
	await assert.rejects(t.resolveUser(profile, { ...baseConfig, ownerEmail: 'boss@example.com' }, stranger.n8n), {
		code: 'instance_not_setup',
	});

	const owner = fakeN8n({ ownerSetUp: false });
	const result = await t.resolveUser(profile, { ...baseConfig, ownerEmail: 'jane@example.com' }, owner.n8n);
	assert.equal(result.how, 'owner-setup');
	assert.equal(result.user.role.slug, 'global:owner');
	assert.ok(result.user.password.length >= 48, 'owner gets an unusable random password');

	const unverifiedOwner = fakeN8n({ ownerSetUp: false });
	await assert.rejects(
		t.resolveUser({ ...profile, emailVerified: false }, { ...baseConfig, ownerEmail: 'jane@example.com' }, unverifiedOwner.n8n),
		{ code: 'email_not_verified' },
	);
});

test('resolveUser provisions members unless disabled', async () => {
	const on = fakeN8n();
	const result = await t.resolveUser(profile, baseConfig, on.n8n);
	assert.equal(result.how, 'provisioned');
	assert.equal(on.created[0].role.slug, 'global:member');
	assert.deepEqual(on.savedIdentities, [{ providerId: 'sub-1', providerType: 'oidc', userId: result.user.id }]);

	const off = fakeN8n();
	await assert.rejects(t.resolveUser(profile, { ...baseConfig, autoProvision: false }, off.n8n), { code: 'not_provisioned' });

	const unverified = fakeN8n();
	await assert.rejects(t.resolveUser({ ...profile, emailVerified: false }, baseConfig, unverified.n8n), { code: 'email_not_verified' });

	const relaxed = fakeN8n();
	const r = await t.resolveUser({ ...profile, emailVerified: false }, { ...baseConfig, requireEmailVerified: false }, relaxed.n8n);
	assert.equal(r.how, 'provisioned');
});

// ---------------------------------------------------------------------------

const stored = () => ({ id: 'u1', email: 'jane@example.com', firstName: 'Jane', lastName: 'Doe' });
const syncConfig = { ...baseConfig, syncProfile: true };
const fromProvider = (claims) => t.evaluateAccess({ sub: 'sub-1', email_verified: true, ...claims }, syncConfig);

test('syncProfile changes nothing when the provider agrees', async () => {
	const { n8n, updates } = fakeN8n({ users: [stored()] });
	const user = await n8n.userRepository.findOne({ where: { id: 'u1' } });
	const fields = await t.syncProfile(user, fromProvider({ email: 'jane@example.com', given_name: 'Jane', family_name: 'Doe' }), syncConfig, n8n);
	assert.deepEqual(fields, []);
	assert.deepEqual(updates, []);
});

test('syncProfile takes over name and verified email, and updates the user object', async () => {
	const { n8n, updates } = fakeN8n({ users: [stored()] });
	const user = await n8n.userRepository.findOne({ where: { id: 'u1' } });
	const fields = await t.syncProfile(
		user,
		fromProvider({ email: 'Jane.Smith@Example.com', given_name: 'Jane', family_name: 'Smith' }),
		syncConfig,
		n8n,
	);
	assert.deepEqual(fields.sort(), ['email', 'lastName']);
	assert.deepEqual(updates, [{ id: 'u1', lastName: 'Smith', email: 'jane.smith@example.com' }]);
	// issueCookie() hashes the email, so the object in hand must already carry the new one.
	assert.equal(user.email, 'jane.smith@example.com');
});

test('syncProfile keeps the email when it is unverified or taken, but still syncs names', async () => {
	const unverified = fakeN8n({ users: [stored()] });
	const u1 = await unverified.n8n.userRepository.findOne({ where: { id: 'u1' } });
	const profile = t.evaluateAccess(
		{ sub: 'sub-1', email: 'new@example.com', given_name: 'Janet', family_name: 'Doe' },
		{ ...syncConfig, requireEmailVerified: false },
	);
	assert.deepEqual(await t.syncProfile(u1, profile, syncConfig, unverified.n8n), ['firstName']);
	assert.equal(u1.email, 'jane@example.com');

	const taken = fakeN8n({ users: [stored(), { id: 'u2', email: 'boss@example.com' }] });
	const u2 = await taken.n8n.userRepository.findOne({ where: { id: 'u1' } });
	assert.deepEqual(await t.syncProfile(u2, fromProvider({ email: 'boss@example.com', given_name: 'Jane', family_name: 'Doe' }), syncConfig, taken.n8n), []);
	assert.equal(u2.email, 'jane@example.com');
});

test('syncProfile keeps names the provider does not send, and can be switched off', async () => {
	const { n8n, updates } = fakeN8n({ users: [stored()] });
	const user = await n8n.userRepository.findOne({ where: { id: 'u1' } });
	assert.deepEqual(await t.syncProfile(user, fromProvider({ email: 'jane@example.com', preferred_username: 'jd' }), syncConfig, n8n), []);

	const off = { ...syncConfig, syncProfile: false };
	assert.deepEqual(await t.syncProfile(user, fromProvider({ email: 'x@example.com', given_name: 'X', family_name: 'Y' }), off, n8n), []);
	assert.deepEqual(updates, []);
});

// ---------------------------------------------------------------------------

test('resolveInstanceBaseUrl tries every UrlService location, then N8N_EDITOR_BASE_URL', () => {
	const service = (url) => class {
		getInstanceBaseUrl() {
			return url;
		}
	};
	const get = (Cls) => new Cls();
	const missing = () => {
		throw new Error("Cannot find module '@n8n/backend-services'");
	};

	// n8n >= 2.42: the first location works.
	assert.equal(t.resolveInstanceBaseUrl([() => service('https://n8n.example.com/'), missing], get, {}), 'https://n8n.example.com');
	// n8n <= 2.41: the package is missing, the old dist path works.
	assert.equal(t.resolveInstanceBaseUrl([missing, () => service('https://old.example.com')], get, {}), 'https://old.example.com');
	// A future move: nothing found, but N8N_EDITOR_BASE_URL is set (the case that disabled the hook).
	assert.equal(
		t.resolveInstanceBaseUrl([missing, missing], get, { N8N_EDITOR_BASE_URL: 'https://workflow.example.com/' }),
		'https://workflow.example.com',
	);
	// Garbage from the service is ignored in favour of the variable.
	assert.equal(
		t.resolveInstanceBaseUrl([() => service(undefined)], get, { N8N_EDITOR_BASE_URL: 'https://workflow.example.com' }),
		'https://workflow.example.com',
	);
	// Nothing usable at all.
	assert.equal(t.resolveInstanceBaseUrl([missing], get, {}), undefined);
	assert.equal(t.resolveInstanceBaseUrl([missing], get, { N8N_EDITOR_BASE_URL: 'workflow.example.com' }), undefined);
});

// ---------------------------------------------------------------------------

test('frontend script embeds config safely and parses', () => {
	const script = t.buildFrontendScript({ loginUrl: '/auth/oidc/login', buttonLabel: '</script><script>alert(1)</script>' });
	assert.ok(!script.includes('</script>'));
	assert.doesNotThrow(() => new Function(script));
});
