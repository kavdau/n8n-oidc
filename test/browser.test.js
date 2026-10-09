'use strict';

/**
 * Drives the real n8n editor in headless Chromium.
 *
 *   N8N_BIN=.../n8n/bin/n8n PUPPETEER_DIR=/dir/with/node_modules CHROME_BIN=/path/to/chromium \
 *     node --test test/browser.test.js
 *
 * Screenshots land in SCREENSHOT_DIR when set.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createRequire } = require('node:module');

const { startStack, users } = require('./harness');

const requireDep = createRequire(path.join(process.env.PUPPETEER_DIR || path.resolve(__dirname, '..'), 'package.json'));
let puppeteer;
try {
	puppeteer = requireDep('puppeteer'); // bundles Chrome (CI)
} catch {
	puppeteer = requireDep('puppeteer-core'); // bring your own browser via CHROME_BIN
}

let browser;

async function shot(page, name) {
	if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: path.join(process.env.SCREENSHOT_DIR, `${name}.png`) });
}

async function newPage() {
	const context = await browser.createBrowserContext();
	const page = await context.newPage();
	await page.setViewport({ width: 1100, height: 760 });
	page.setDefaultTimeout(45_000);
	return page;
}

const pathname = (page) => new URL(page.url()).pathname;

async function waitForEditor(page, base) {
	// Poll until the editor is open AND the session is valid. Checking the URL alone
	// races with n8n's in-app redirect from "/" to "/signin".
	const handle = await page.waitForFunction(
		async (b) => {
			if (!location.href.startsWith(b) || /^\/(signin|setup|signout|auth)/.test(location.pathname)) return false;
			try {
				const response = await fetch('/rest/login', { credentials: 'include' });
				if (!response.ok) return false;
				const data = (await response.json()).data;
				return data && data.email ? JSON.stringify(data) : false;
			} catch {
				return false;
			}
		},
		{ polling: 500 },
		base,
	);
	const me = JSON.parse(await handle.jsonValue());
	assert.ok(me, `signed in (at ${page.url()})`);
	return me;
}

async function isVisible(page, selector) {
	return page.$eval(selector, (el) => el.offsetParent !== null).catch(() => false);
}

test.before(async () => {
	browser = await puppeteer.launch({
		executablePath: process.env.CHROME_BIN || (puppeteer.executablePath ? puppeteer.executablePath() : undefined),
		headless: true,
		args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu'],
	});
});

test.after(async () => {
	if (browser) await browser.close();
});

test('default config: setup page, sign-in button next to the password form, errors, deep links', async () => {
	const stack = await startStack();
	try {
		const page = await newPage();
		await stack.setIdp({ user: users.owner });

		// Fresh instance: n8n sends us to /setup, where the owner can use OIDC.
		await page.goto(`${stack.base}/`);
		await page.waitForSelector('[data-test-id="oidc-login-button"]');
		assert.equal(pathname(page), '/setup');
		assert.equal(await page.$eval('[data-test-id="oidc-login-button"]', (el) => el.textContent), 'Mit Pocket ID anmelden');
		await shot(page, '1-setup');

		await Promise.all([page.waitForNavigation(), page.click('[data-test-id="oidc-login-button"]')]);
		const owner = await waitForEditor(page, stack.base);
		assert.equal(owner.email, users.owner.email);
		assert.equal(owner.role, 'global:owner');
		await shot(page, '2-editor-owner');

		// Sign out inside the app, then the sign-in page shows the button above the form.
		await page.goto(`${stack.base}/signout`);
		await page.waitForSelector('[data-test-id="oidc-login-button"]');
		assert.equal(pathname(page), '/signin');
		assert.ok(await isVisible(page, '[data-test-id="form-submit-button"]'), 'password form stays visible');
		assert.ok(await isVisible(page, 'input[type="email"], input[name="emailOrLdapLoginId"]'), 'email input visible');
		await shot(page, '3-signin');

		// Error from a rejected login, rendered from the code, not from provider text.
		await page.goto(`${stack.base}/signin?oidc_error=access_denied`);
		await page.waitForSelector('#n8n-oidc-block [role="alert"]');
		assert.match(await page.$eval('#n8n-oidc-block [role="alert"]', (el) => el.textContent), /not allowed/);
		await shot(page, '4-signin-error');

		// A member following a deep link ends up where they wanted to go.
		await stack.setIdp({ user: users.member });
		await page.goto(`${stack.base}/signin?redirect=${encodeURIComponent('/home/credentials')}`);
		await page.waitForSelector('[data-test-id="oidc-login-button"]');
		await Promise.all([page.waitForNavigation(), page.click('[data-test-id="oidc-login-button"]')]);
		const member = await waitForEditor(page, stack.base);
		assert.equal(member.role, 'global:member');
		await page.waitForFunction(() => location.pathname === '/home/credentials');
		await shot(page, '5-member-deeplink');
	} catch (error) {
		console.log(stack.log.split('\n').filter((l) => l.includes('OIDC') || /error/i.test(l)).slice(-25).join('\n'));
		throw error;
	} finally {
		await stack.stop();
	}
});

test('hidden password form and auto-redirect, without a sign-out loop', async () => {
	const stack = await startStack({ env: { OIDC_HIDE_PASSWORD_LOGIN: 'true', OIDC_AUTO_REDIRECT: 'true' } });
	try {
		const page = await newPage();
		await stack.setIdp({ user: users.owner });

		// Set up the owner directly through the login route.
		await page.goto(`${stack.base}/auth/oidc/login`);
		await waitForEditor(page, stack.base);

		// After an in-app sign-out we must stay on /signin instead of bouncing to the provider.
		await page.goto(`${stack.base}/signout`);
		await page.waitForSelector('[data-test-id="oidc-login-button"]');
		await new Promise((resolve) => setTimeout(resolve, 1500));
		assert.equal(pathname(page), '/signin', 'no auto-redirect after sign-out');
		assert.equal(await isVisible(page, '[data-test-id="form-submit-button"]'), false, 'password form hidden');
		assert.ok(await page.$('#n8n-oidc-block a[href*="showLogin=true"]'), 'admin fallback link present');
		await shot(page, '6-signin-hidden');

		// The fallback link brings the form back.
		await page.goto(`${stack.base}/signin?showLogin=true`);
		await page.waitForSelector('[data-test-id="oidc-login-button"]');
		assert.ok(await isVisible(page, '[data-test-id="form-submit-button"]'), 'password form visible with showLogin');
		await shot(page, '7-signin-showlogin');

		// Even reloading /signin in the tab that signed out does not bounce.
		await page.goto(`${stack.base}/signin`);
		await page.waitForSelector('[data-test-id="oidc-login-button"]');
		await new Promise((resolve) => setTimeout(resolve, 1500));
		assert.equal(pathname(page), '/signin', 'still no auto-redirect in the signed-out tab');

		// Clicking the button clears the marker and signs in again.
		await Promise.all([page.waitForNavigation(), page.click('[data-test-id="oidc-login-button"]')]);
		assert.equal((await waitForEditor(page, stack.base)).email, users.owner.email);

		// A new tab that opens the instance root while signed out: n8n routes to
		// /signin in-app, and the hook continues straight to the provider.
		const fresh = await newPage();
		await fresh.goto(`${stack.base}/`);
		assert.equal((await waitForEditor(fresh, stack.base)).email, users.owner.email);
		await shot(fresh, '8-auto-redirect-from-root');

		// Same for a deep link opened in a new tab.
		const deep = await newPage();
		await deep.goto(`${stack.base}/home/credentials`);
		await waitForEditor(deep, stack.base);
		await deep.waitForFunction(() => location.pathname === '/home/credentials');
	} catch (error) {
		console.log(stack.log.split('\n').filter((l) => l.includes('OIDC') || /error/i.test(l)).slice(-25).join('\n'));
		throw error;
	} finally {
		await stack.stop();
	}
});
