'use strict';

/**
 * End-to-end test against a real n8n process and the mock IdP.
 *
 *   N8N_BIN=/path/to/node_modules/n8n/bin/n8n node --test test/e2e.test.js
 *
 * Runs n8n with SQLite in a temporary folder. Requires the Node version n8n needs.
 */

const test = require('node:test');
const assert = require('node:assert/strict');

const { startStack, users } = require('./harness');

let stack;
let BASE;
const setIdp = (patch) => stack.setIdp(patch);

function cookieValue(response, name) {
	for (const line of response.headers.getSetCookie()) {
		const [pair] = line.split(';');
		const index = pair.indexOf('=');
		if (pair.slice(0, index) === name) return { value: pair.slice(index + 1), raw: line };
	}
	return undefined;
}

/** Walks login -> provider -> callback without a browser. */
async function login(user, { redirect, tamper = null, mutateCallback, dropTxCookie = false } = {}) {
	await setIdp({ user, tamper });
	const start = await fetch(`${BASE}/auth/oidc/login${redirect ? `?redirect=${encodeURIComponent(redirect)}` : ''}`, {
		redirect: 'manual',
		headers: { Accept: 'text/html' },
	});
	assert.equal(start.status, 302, 'login redirects to the provider');
	const tx = cookieValue(start, 'n8n-oidc-tx');
	assert.ok(tx, 'transaction cookie set');

	const authorize = await fetch(start.headers.get('location'), { redirect: 'manual' });
	assert.equal(authorize.status, 302, 'provider redirects back');
	let callbackUrl = authorize.headers.get('location');
	if (mutateCallback) callbackUrl = mutateCallback(new URL(callbackUrl)).toString();

	const callback = await fetch(callbackUrl, {
		redirect: 'manual',
		headers: { Accept: 'text/html', ...(dropTxCookie ? {} : { Cookie: `n8n-oidc-tx=${tx.value}` }) },
	});
	assert.equal(callback.status, 302, 'callback redirects');
	const auth = cookieValue(callback, 'n8n-auth');
	return { start, tx, callback, location: callback.headers.get('location'), auth: auth && auth.value, authRaw: auth && auth.raw };
}

async function currentUser(authCookie) {
	const response = await fetch(`${BASE}/rest/login`, { headers: { Cookie: `n8n-auth=${authCookie}` } });
	return { status: response.status, body: response.status === 200 ? (await response.json()).data : null };
}

function errorCode(location) {
	return new URL(location, BASE).searchParams.get('oidc_error');
}

test.before(async () => {
	stack = await startStack();
	BASE = stack.base;
});

test.after(async () => {
	if (!stack) return;
	// Always show the hook's own log lines: when a run fails in CI, they say why.
	const log = process.env.E2E_PRINT_LOG === 'true' ? stack.log : stack.log.split('\n').filter((line) => line.includes('[OIDC Hook]')).join('\n');
	console.log(`\n--- n8n log ---\n${log}\n---------------`);
	await stack.stop();
});

// The order matters: the instance starts without an owner.

test('the editor page loads the frontend hook and the hook serves the script', async () => {
	const page = await (await fetch(`${BASE}/signin`, { headers: { Accept: 'text/html' } })).text();
	assert.match(page, /<script nonce="[^"]+" src="\/assets\/oidc-frontend-hook\.js"><\/script>/);

	const script = await fetch(`${BASE}/assets/oidc-frontend-hook.js`);
	assert.equal(script.status, 200);
	assert.match(script.headers.get('content-type'), /javascript/);
	const body = await script.text();
	assert.ok(body.includes('Mit Pocket ID anmelden'));
	assert.ok(body.includes(`${BASE}/auth/oidc/login`));
	assert.doesNotThrow(() => new Function(body));
});

test('the transaction cookie is httpOnly, SameSite=Lax and scoped to /auth/oidc', async () => {
	await setIdp({ user: users.owner });
	const start = await fetch(`${BASE}/auth/oidc/login`, { redirect: 'manual' });
	const { raw } = cookieValue(start, 'n8n-oidc-tx');
	assert.match(raw, /HttpOnly/i);
	assert.match(raw, /SameSite=Lax/i);
	assert.match(raw, /Path=\/auth\/oidc/i);
});

test('before setup, only OIDC_OWNER_EMAIL may sign in', async () => {
	const result = await login(users.member);
	assert.equal(errorCode(result.location), 'instance_not_setup');
	assert.equal(result.auth, undefined);
});

test('the owner sets up the instance through OIDC', async () => {
	const result = await login(users.owner);
	assert.equal(result.location, `${BASE}/`);
	assert.ok(result.auth, 'n8n-auth cookie issued');
	assert.match(result.authRaw, /HttpOnly/i);

	const me = await currentUser(result.auth);
	assert.equal(me.status, 200);
	assert.equal(me.body.email, users.owner.email);
	assert.equal(me.body.role, 'global:owner');
	assert.equal(me.body.firstName, 'Olive');
	assert.equal(me.body.isPending, false);

	const settings = await (await fetch(`${BASE}/rest/settings`)).json();
	assert.equal(settings.data.userManagement.showSetupOnFirstLoad, false, 'setup is complete');
});

test('PKCE S256 and client_secret_basic are used against the provider', async () => {
	const s = await (await fetch(`${stack.idp.issuer}/_test/state`)).json();
	assert.equal(s.lastAuthorizeQuery.code_challenge_method, 'S256');
	assert.match(s.lastAuthorizeQuery.code_challenge, /^[A-Za-z0-9_-]{43}$/);
	assert.ok(s.lastAuthorizeQuery.nonce);
	assert.equal(s.lastAuthorizeQuery.scope, 'openid email profile groups');
	assert.match(s.lastTokenRequest.headers.authorization, /^Basic /);
	assert.equal(s.lastTokenRequest.form.client_secret, undefined);
	assert.ok(s.lastTokenRequest.form.code_verifier.length >= 43);
});

test('a group member is provisioned and returned to the requested page', async () => {
	const result = await login(users.member, { redirect: '/workflow/new?x=1' });
	assert.equal(result.location, `${BASE}/workflow/new?x=1`);
	const me = await currentUser(result.auth);
	assert.equal(me.body.email, users.member.email);
	assert.equal(me.body.role, 'global:member');
});

test('later logins resolve by sub and take over a changed name and email', async () => {
	const first = await currentUser((await login(users.member)).auth);
	const renamed = await login({ ...users.member, email: 'max.new@example.com', given_name: 'Maximilian' });
	const again = await currentUser(renamed.auth);
	assert.equal(again.status, 200, 'the new session matches the new email');
	assert.equal(again.body.id, first.body.id);
	assert.equal(again.body.email, 'max.new@example.com');
	assert.equal(again.body.firstName, 'Maximilian');
	assert.match(stack.log, /Signed in max\.new@example\.com \(identity, updated firstName, email\)/);

	// Back to the original values for the tests below.
	const back = await currentUser((await login(users.member)).auth);
	assert.equal(back.body.id, first.body.id);
	assert.equal(back.body.email, users.member.email);
	assert.equal(back.body.firstName, 'Max');
});

test('an email that another account already uses is not taken over', async () => {
	const result = await login({ ...users.member, email: users.owner.email });
	const me = await currentUser(result.auth);
	assert.equal(me.status, 200, 'the login itself still works');
	assert.equal(me.body.email, users.member.email);
	assert.equal(me.body.role, 'global:member');
	assert.match(stack.log, /Keeping email member@example\.com: another n8n account already uses owner@example\.com/);
});

test('users outside the allowed groups are rejected', async () => {
	const result = await login(users.outsider);
	assert.equal(errorCode(result.location), 'access_denied');
	assert.equal(result.auth, undefined);
});

test('unverified emails are rejected', async () => {
	const result = await login(users.unverified);
	assert.equal(errorCode(result.location), 'email_not_verified');
	assert.equal(result.auth, undefined);
});

for (const tamper of ['bad-signature', 'wrong-nonce', 'wrong-aud', 'expired', 'alg-none']) {
	test(`a manipulated ID token (${tamper}) does not sign anyone in`, async () => {
		const result = await login(users.owner, { tamper });
		assert.equal(errorCode(result.location), 'login_failed');
		assert.equal(result.auth, undefined);
	});
}

test('a forged state or a missing transaction cookie is rejected', async () => {
	const forged = await login(users.owner, {
		mutateCallback: (url) => {
			url.searchParams.set('state', 'forged');
			return url;
		},
	});
	assert.equal(errorCode(forged.location), 'session_expired');
	assert.equal(forged.auth, undefined);

	const noCookie = await login(users.owner, { dropTxCookie: true });
	assert.equal(errorCode(noCookie.location), 'session_expired');
	assert.equal(noCookie.auth, undefined);
});

test('a mix-up attack with a foreign iss parameter is rejected', async () => {
	const result = await login(users.owner, {
		mutateCallback: (url) => {
			url.searchParams.set('iss', 'https://attacker.example');
			return url;
		},
	});
	assert.equal(errorCode(result.location), 'login_failed');
	assert.equal(result.auth, undefined);
});

test('provider error text is never reflected', async () => {
	const result = await login(null);
	assert.equal(result.location, `${BASE}/signin?oidc_error=access_denied`);
});

test('open redirects are neutralised', async () => {
	for (const redirect of ['//evil.example', 'https://evil.example/x', '/\\evil.example']) {
		const result = await login(users.owner, { redirect });
		assert.equal(result.location, `${BASE}/`, redirect);
	}
});

test('the authorization code cannot be replayed', async () => {
	await setIdp({ user: users.owner, tamper: null });
	const start = await fetch(`${BASE}/auth/oidc/login`, { redirect: 'manual' });
	const tx = cookieValue(start, 'n8n-oidc-tx').value;
	const authorize = await fetch(start.headers.get('location'), { redirect: 'manual' });
	const callbackUrl = authorize.headers.get('location');
	const first = await fetch(callbackUrl, { redirect: 'manual', headers: { Cookie: `n8n-oidc-tx=${tx}` } });
	assert.ok(cookieValue(first, 'n8n-auth'));
	const replay = await fetch(callbackUrl, { redirect: 'manual', headers: { Cookie: `n8n-oidc-tx=${tx}` } });
	assert.equal(cookieValue(replay, 'n8n-auth'), undefined);
	assert.ok(errorCode(replay.headers.get('location')));
});

test('logging out invalidates the session issued through OIDC', async () => {
	const { auth } = await login(users.member);
	assert.equal((await currentUser(auth)).status, 200);
	const logout = await fetch(`${BASE}/rest/logout`, { method: 'POST', headers: { Cookie: `n8n-auth=${auth}` } });
	assert.equal(logout.status, 200);
	assert.equal((await currentUser(auth)).status, 401);
});

test('the session works for the editor REST API, not only /rest/login', async () => {
	const { auth } = await login(users.owner);
	const response = await fetch(`${BASE}/rest/workflows`, { headers: { Cookie: `n8n-auth=${auth}` } });
	assert.equal(response.status, 200);
});

test('webhooks are untouched by the hook', async () => {
	const response = await fetch(`${BASE}/webhook/does-not-exist`, { method: 'POST' });
	assert.equal(response.status, 404);
});
