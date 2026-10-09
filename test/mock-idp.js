'use strict';

/**
 * Minimal OpenID Connect provider for tests. Behaves like Pocket ID where it
 * matters: RS256 ID tokens, PKCE S256, email_verified and groups claims.
 *
 * The signed-in user and misbehaviours are set through POST /_test/state.
 */

const crypto = require('node:crypto');
const http = require('node:http');

function createMockIdp({ port, clientId, clientSecret, redirectUri }) {
	const issuer = `http://localhost:${port}`;
	const signingKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const rogueKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
	const kid = 'test-key-1';
	const codes = new Map();
	const accessTokens = new Map();

	const state = {
		user: null,
		/** Misbehaviours: 'bad-signature' | 'wrong-nonce' | 'wrong-aud' | 'expired' | 'alg-none' */
		tamper: null,
		lastAuthorizeQuery: null,
		lastTokenRequest: null,
	};

	const b64 = (value) => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');

	function signJwt(claims, { key = signingKey.privateKey, alg = 'RS256' } = {}) {
		const header = { alg, typ: 'JWT', kid };
		const input = `${b64(header)}.${b64(claims)}`;
		if (alg === 'none') return `${input}.`;
		const signature = crypto.sign('sha256', Buffer.from(input), key).toString('base64url');
		return `${input}.${signature}`;
	}

	function send(res, status, body, headers = {}) {
		res.writeHead(status, { 'Content-Type': 'application/json', ...headers });
		res.end(JSON.stringify(body));
	}

	async function readBody(req) {
		const chunks = [];
		for await (const chunk of req) chunks.push(chunk);
		return Buffer.concat(chunks).toString('utf8');
	}

	const server = http.createServer(async (req, res) => {
		const url = new URL(req.url, issuer);
		try {
			if (url.pathname === '/.well-known/openid-configuration') {
				return send(res, 200, {
					issuer,
					authorization_endpoint: `${issuer}/authorize`,
					token_endpoint: `${issuer}/token`,
					userinfo_endpoint: `${issuer}/userinfo`,
					jwks_uri: `${issuer}/jwks`,
					end_session_endpoint: `${issuer}/end-session`,
					response_types_supported: ['code'],
					id_token_signing_alg_values_supported: ['RS256'],
					code_challenge_methods_supported: ['plain', 'S256'],
					scopes_supported: ['openid', 'profile', 'email', 'groups'],
				});
			}

			if (url.pathname === '/jwks') {
				const jwk = signingKey.publicKey.export({ format: 'jwk' });
				return send(res, 200, { keys: [{ ...jwk, kid, use: 'sig', alg: 'RS256' }] });
			}

			if (url.pathname === '/authorize') {
				const q = Object.fromEntries(url.searchParams);
				state.lastAuthorizeQuery = q;
				if (q.client_id !== clientId || q.redirect_uri !== redirectUri || q.response_type !== 'code') {
					return send(res, 400, { error: 'invalid_request' });
				}
				const target = new URL(q.redirect_uri);
				if (!state.user) {
					target.searchParams.set('error', 'access_denied');
					target.searchParams.set('error_description', '<script>alert(1)</script> injected text');
					target.searchParams.set('state', q.state);
				} else {
					const code = crypto.randomBytes(16).toString('hex');
					codes.set(code, {
						user: state.user,
						nonce: q.nonce,
						challenge: q.code_challenge,
						challengeMethod: q.code_challenge_method,
						redirectUri: q.redirect_uri,
					});
					target.searchParams.set('code', code);
					target.searchParams.set('state', q.state);
					target.searchParams.set('iss', issuer);
				}
				res.writeHead(302, { Location: target.toString() });
				return res.end();
			}

			if (url.pathname === '/token' && req.method === 'POST') {
				const form = new URLSearchParams(await readBody(req));
				state.lastTokenRequest = { headers: req.headers, form: Object.fromEntries(form) };

				let id = form.get('client_id');
				let secret = form.get('client_secret');
				const auth = req.headers.authorization;
				if (auth && auth.startsWith('Basic ')) {
					const [u, p] = Buffer.from(auth.slice(6), 'base64').toString('utf8').split(':');
					id = decodeURIComponent(u.replace(/\+/g, ' '));
					secret = decodeURIComponent(p.replace(/\+/g, ' '));
				}
				if (id !== clientId || secret !== clientSecret) return send(res, 401, { error: 'invalid_client' });

				const entry = codes.get(form.get('code'));
				codes.delete(form.get('code'));
				if (!entry || entry.redirectUri !== form.get('redirect_uri')) return send(res, 400, { error: 'invalid_grant' });
				if (entry.challenge) {
					const verifier = form.get('code_verifier') || '';
					const computed = crypto.createHash('sha256').update(verifier).digest('base64url');
					if (entry.challengeMethod !== 'S256' || computed !== entry.challenge) {
						return send(res, 400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
					}
				}

				const now = Math.floor(Date.now() / 1000);
				const user = entry.user;
				const claims = {
					iss: issuer,
					sub: user.sub,
					aud: clientId,
					iat: now,
					exp: now + 300,
					nonce: entry.nonce,
					email: user.email,
					email_verified: user.email_verified,
					given_name: user.given_name,
					family_name: user.family_name,
					name: [user.given_name, user.family_name].filter(Boolean).join(' '),
					groups: user.groups,
				};
				let options = {};
				switch (state.tamper) {
					case 'bad-signature':
						options = { key: rogueKey.privateKey };
						break;
					case 'wrong-nonce':
						claims.nonce = 'not-the-nonce';
						break;
					case 'wrong-aud':
						claims.aud = 'some-other-client';
						break;
					case 'expired':
						claims.iat = now - 3600;
						claims.exp = now - 1800;
						break;
					case 'alg-none':
						options = { alg: 'none' };
						break;
				}
				const accessToken = crypto.randomBytes(16).toString('hex');
				accessTokens.set(accessToken, user);
				return send(res, 200, {
					access_token: accessToken,
					token_type: 'Bearer',
					expires_in: 300,
					id_token: signJwt(claims, options),
				});
			}

			if (url.pathname === '/userinfo') {
				const token = (req.headers.authorization || '').replace(/^Bearer /, '');
				const user = accessTokens.get(token);
				if (!user) return send(res, 401, { error: 'invalid_token' });
				return send(res, 200, {
					sub: user.sub,
					email: user.email,
					email_verified: user.email_verified,
					given_name: user.given_name,
					family_name: user.family_name,
					groups: user.groups,
				});
			}

			if (url.pathname === '/_test/state' && req.method === 'POST') {
				Object.assign(state, JSON.parse(await readBody(req)));
				return send(res, 200, { ok: true });
			}

			if (url.pathname === '/_test/state') return send(res, 200, state);

			send(res, 404, { error: 'not_found' });
		} catch (error) {
			send(res, 500, { error: 'server_error', error_description: error.message });
		}
	});

	return {
		issuer,
		state,
		listen: () => new Promise((resolve) => server.listen(port, '127.0.0.1', resolve)),
		close: () => new Promise((resolve) => server.close(resolve)),
	};
}

module.exports = { createMockIdp };

if (require.main === module) {
	const idp = createMockIdp({
		port: Number(process.env.PORT || 9999),
		clientId: process.env.CLIENT_ID || 'n8n',
		clientSecret: process.env.CLIENT_SECRET || 'secret',
		redirectUri: process.env.REDIRECT_URI || 'http://localhost:5678/auth/oidc/callback',
	});
	idp.listen().then(() => console.log(`mock IdP on ${idp.issuer}`));
}
