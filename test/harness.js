'use strict';

/** Starts a throwaway n8n (SQLite) with the hook plus the mock IdP. */

const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createMockIdp } = require('./mock-idp');

const CLIENT_ID = 'n8n-e2e';
const CLIENT_SECRET = 'e2e secret+with/odd&chars';

const users = {
	owner: { sub: 'sub-owner', email: 'owner@example.com', email_verified: true, given_name: 'Olive', family_name: 'Owner', groups: ['n8n-users'] },
	member: { sub: 'sub-member', email: 'member@example.com', email_verified: true, given_name: 'Max', family_name: 'Member', groups: ['n8n-users'] },
	outsider: { sub: 'sub-outsider', email: 'outsider@example.com', email_verified: true, given_name: 'Otto', groups: ['other'] },
	unverified: { sub: 'sub-unverified', email: 'unverified@example.com', email_verified: false, given_name: 'Una', groups: ['n8n-users'] },
};

async function startStack({ n8nPort = 5688, idpPort = 9999, env = {} } = {}) {
	const n8nBin = process.env.N8N_BIN;
	if (!n8nBin) throw new Error('Set N8N_BIN to the n8n bin/n8n script');
	const base = `http://localhost:${n8nPort}`;

	const idp = createMockIdp({ port: idpPort, clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, redirectUri: `${base}/auth/oidc/callback` });
	await idp.listen();

	const userFolder = fs.mkdtempSync(path.join(os.tmpdir(), 'n8n-oidc-e2e-'));
	let log = '';
	const child = spawn(process.execPath, [n8nBin, 'start'], {
		env: {
			PATH: process.env.PATH,
			HOME: userFolder,
			N8N_USER_FOLDER: userFolder,
			N8N_PORT: String(n8nPort),
			N8N_LISTEN_ADDRESS: '127.0.0.1',
			N8N_RUNNERS_BROKER_PORT: String(n8nPort + 1000),
			N8N_HOST: 'localhost',
			N8N_PROTOCOL: 'http',
			N8N_EDITOR_BASE_URL: base,
			N8N_SECURE_COOKIE: 'false',
			N8N_ENCRYPTION_KEY: 'e2e-encryption-key',
			N8N_DIAGNOSTICS_ENABLED: 'false',
			N8N_PERSONALIZATION_ENABLED: 'false',
			N8N_VERSION_NOTIFICATIONS_ENABLED: 'false',
			N8N_TEMPLATES_ENABLED: 'false',
			EXTERNAL_HOOK_FILES: path.resolve(__dirname, '..', 'hooks.js'),
			EXTERNAL_FRONTEND_HOOKS_URLS: '/assets/oidc-frontend-hook.js',
			N8N_ADDITIONAL_NON_UI_ROUTES: 'auth',
			OIDC_ISSUER_URL: idp.issuer,
			OIDC_CLIENT_ID: CLIENT_ID,
			OIDC_CLIENT_SECRET: CLIENT_SECRET,
			OIDC_ALLOWED_GROUPS: 'n8n-users',
			OIDC_OWNER_EMAIL: users.owner.email,
			OIDC_BUTTON_LABEL: 'Mit Pocket ID anmelden',
			...env,
		},
		stdio: ['ignore', 'pipe', 'pipe'],
	});
	child.stdout.on('data', (chunk) => (log += chunk));
	child.stderr.on('data', (chunk) => (log += chunk));

	const deadline = Date.now() + 180_000;
	while (!log.includes('[OIDC Hook] v2.0.0 active')) {
		if (child.exitCode !== null) throw new Error(`n8n exited early:\n${log.slice(-4000)}`);
		if (log.includes('OIDC login disabled')) throw new Error(`Hook disabled itself:\n${log.slice(-4000)}`);
		if (Date.now() > deadline) throw new Error(`n8n did not get ready:\n${log.slice(-4000)}`);
		await new Promise((resolve) => setTimeout(resolve, 500));
	}
	// The editor is served once the hook is active, but give the settings route a beat.
	while (Date.now() < deadline) {
		try {
			if ((await fetch(`${base}/healthz/readiness`)).ok) break;
		} catch {}
		await new Promise((resolve) => setTimeout(resolve, 250));
	}

	return {
		base,
		idp,
		get log() {
			return log;
		},
		setIdp: (patch) => fetch(`${idp.issuer}/_test/state`, { method: 'POST', body: JSON.stringify(patch) }),
		async stop() {
			if (child.exitCode === null) {
				child.kill('SIGTERM');
				await new Promise((resolve) => child.once('exit', resolve));
			}
			await idp.close();
			fs.rmSync(userFolder, { recursive: true, force: true });
		},
	};
}

module.exports = { startStack, users, CLIENT_ID, CLIENT_SECRET };
