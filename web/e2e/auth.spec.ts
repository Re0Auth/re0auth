import { expect, test } from '@playwright/test';
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const APP_PORT = 18081;
const IDP_PORT = 19090;
const UPSTREAM_PORT = 19091;
const CALLBACK_PORT = 18082;
const CLIENT_ID = 're0auth';
const CLIENT_REDIRECT = `http://127.0.0.1:${CALLBACK_PORT}/callback`;
const APP = `http://127.0.0.1:${APP_PORT}`;
const IDP = `http://127.0.0.1:${IDP_PORT}`;
const UPSTREAM = `http://127.0.0.1:${UPSTREAM_PORT}`;

const root = path.resolve(process.cwd(), '..');
const binary = path.join(
	root,
	'target',
	'release',
	process.platform === 'win32' ? 're0auth-server.exe' : 're0auth-server'
);

let work: string;
let server: ChildProcess | undefined;
let idp: Server | undefined;
let upstream: Server | undefined;
let callbackServer: Server | undefined;
let clientId = '';
let deviceClientId = '';
let nonce = '';
let callbacks: URLSearchParams[] = [];
let callbackWaiters: Array<(params: URLSearchParams) => void> = [];
let privateKey: KeyObject;
// Swapped by the attach test: the same mock IdP has to answer as somebody else.
let idpSubject = 'e2e-user';

function b64url(value: Buffer | string): string {
	return Buffer.from(value).toString('base64url');
}

function idToken(): string {
	const now = Math.floor(Date.now() / 1000);
	const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'e2e' }));
	const claims = b64url(
		JSON.stringify({
			iss: IDP,
			sub: idpSubject,
			aud: CLIENT_ID,
			exp: now + 300,
			iat: now,
			nonce,
			name: 'Alice'
		})
	);
	const signingInput = `${header}.${claims}`;
	const signature = sign('sha256', Buffer.from(signingInput), privateKey);
	return `${signingInput}.${b64url(signature)}`;
}

async function listen(server: Server, port: number): Promise<void> {
	await new Promise<void>((resolve, reject) => {
		server.once('error', reject);
		server.listen(port, '127.0.0.1', () => resolve());
	});
}

function waitForCallback(): Promise<URLSearchParams> {
	const queued = callbacks.shift();
	if (queued) return Promise.resolve(queued);
	return new Promise((resolve) => callbackWaiters.push(resolve));
}

async function startIdp(): Promise<void> {
	const keys = generateKeyPairSync('rsa', { modulusLength: 2048 });
	privateKey = keys.privateKey;
	const jwk = keys.publicKey.export({ format: 'jwk' }) as { n: string; e: string };
	const metadata = {
		issuer: IDP,
		authorization_endpoint: `${IDP}/authorize`,
		token_endpoint: `${IDP}/token`,
		jwks_uri: `${IDP}/jwks`,
		// OIDC Discovery 规定以下三项必填
		response_types_supported: ['code'],
		subject_types_supported: ['public'],
		id_token_signing_alg_values_supported: ['RS256']
	};

	idp = createServer((request, response) => {
		const url = new URL(request.url ?? '/', IDP);
		if (request.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
			response.setHeader('content-type', 'application/json');
			response.end(JSON.stringify(metadata));
			return;
		}
		if (request.method === 'GET' && url.pathname === '/jwks') {
			response.setHeader('content-type', 'application/json');
			response.end(
				JSON.stringify({
					keys: [{ kty: 'RSA', kid: 'e2e', use: 'sig', alg: 'RS256', n: jwk.n, e: jwk.e }]
				})
			);
			return;
		}
		if (request.method === 'GET' && url.pathname === '/authorize') {
			nonce = url.searchParams.get('nonce') ?? '';
			const redirectUri = url.searchParams.get('redirect_uri') ?? '';
			const state = url.searchParams.get('state') ?? '';
			const location = `${redirectUri}?${new URLSearchParams({ code: 'e2e-code', state })}`;
			response.statusCode = 302;
			response.setHeader('location', location);
			response.end();
			return;
		}
		if (request.method === 'POST' && url.pathname === '/token') {
			request.resume();
			request.on('end', () => {
				response.setHeader('content-type', 'application/json');
				response.end(
					JSON.stringify({
						access_token: 'e2e-access-token',
						token_type: 'Bearer',
						id_token: idToken()
					})
				);
			});
			return;
		}
		response.statusCode = 404;
		response.end('not found');
	});
	await listen(idp, IDP_PORT);
}

/// A minimal upstream that speaks the authorization-code flow: consent, code
/// exchange, and userinfo. The binding routes are the only thing under test, so
/// it returns fixed values rather than modelling a real game API.
async function startUpstream(): Promise<void> {
	upstream = createServer((request, response) => {
		const url = new URL(request.url ?? '/', UPSTREAM);
		if (request.method === 'GET' && url.pathname === '/authorize') {
			const redirectUri = url.searchParams.get('redirect_uri') ?? '';
			const state = url.searchParams.get('state') ?? '';
			response.statusCode = 302;
			response.setHeader(
				'location',
				`${redirectUri}?${new URLSearchParams({ code: 'upstream-code', state })}`
			);
			response.end();
			return;
		}
		if (request.method === 'POST' && url.pathname === '/token') {
			request.resume();
			request.on('end', () => {
				response.setHeader('content-type', 'application/json');
				response.end(JSON.stringify({ access_token: 'upstream-token' }));
			});
			return;
		}
		if (request.method === 'GET' && url.pathname === '/userinfo') {
			response.setHeader('content-type', 'application/json');
			response.end(JSON.stringify({ id: 'upstream-player-42' }));
			return;
		}
		response.statusCode = 404;
		response.end('not found');
	});
	await listen(upstream, UPSTREAM_PORT);
}

async function startCallback(): Promise<void> {
	callbackServer = createServer((request, response) => {
		const url = new URL(request.url ?? '/', `http://127.0.0.1:${CALLBACK_PORT}`);
		if (url.pathname === '/callback') {
			const params = url.searchParams;
			const waiter = callbackWaiters.shift();
			if (waiter) waiter(params);
			else callbacks.push(params);
			response.setHeader('content-type', 'text/html; charset=utf-8');
			response.end('<!doctype html><title>client callback</title><h1>client callback</h1>');
			return;
		}
		response.statusCode = 404;
		response.end('not found');
	});
	await listen(callbackServer, CALLBACK_PORT);
}

async function waitForServer(): Promise<void> {
	const deadline = Date.now() + 20_000;
	while (Date.now() < deadline) {
		try {
			const response = await fetch(`${APP}/healthz`);
			if (response.ok) return;
		} catch {
			// The process is still starting.
		}
		await new Promise((resolve) => setTimeout(resolve, 150));
	}
	throw new Error('re0auth-server did not become healthy');
}

function createClient(config: string, name: string): string {
	const created = spawnSync(
		binary,
		[
			'--config',
			config,
			'admin',
			'create-client',
			'--name',
			name,
			'--redirect-uri',
			CLIENT_REDIRECT,
			'--scope',
			'openid',
			'--scope',
			'profile',
			'--scope',
			'phigros.xtower.read',
			'--scope',
			'phigros.phihub.read'
		],
		{ cwd: work, encoding: 'utf8' }
	);
	if (created.status !== 0) {
		throw new Error(`create-client failed: ${created.stderr}\n${created.stdout}`);
	}
	return created.stdout
		.split('\n')
		.find((line) => line.startsWith('client_id='))!
		.slice('client_id='.length);
}

function createAdminSession(config: string): Array<{ name: string; value: string; url: string }> {
	const created = spawnSync(
		binary,
		['--config', config, 'admin', 'create-user', '--display-name', 'Race Admin', '--role', 'admin'],
		{ cwd: work, encoding: 'utf8' }
	);
	if (created.status !== 0) throw new Error(`create admin failed: ${created.stderr}`);
	const userId = created.stdout
		.split('\n')
		.find((line) => line.startsWith('user_id='))
		?.slice('user_id='.length);
	if (!userId) throw new Error('admin user id was not returned');
	const createdSession = spawnSync(
		binary,
		['--config', config, 'admin', 'create-session', '--user-id', userId],
		{ cwd: work, encoding: 'utf8' }
	);
	if (createdSession.status !== 0) {
		throw new Error(`create admin session failed: ${createdSession.stderr}`);
	}
	const line = createdSession.stdout
		.split('\n')
		.find((line) => line.startsWith('session_cookie='));
	if (!line) throw new Error('admin session cookie was not returned');
	const [name, value] = line.slice('session_cookie='.length).split('=');
	const csrfLine = createdSession.stdout
		.split('\n')
		.find((line) => line.startsWith('csrf_token='));
	if (!csrfLine) throw new Error('admin session CSRF token was not returned');
	const csrf = csrfLine.slice('csrf_token='.length).trim();
	return [
		{ name, value, url: APP },
		{ name: 're0auth_csrf', value: csrf, url: APP }
	];
}

async function startRe0auth(): Promise<void> {
	work = await mkdtemp(path.join(tmpdir(), 're0auth-e2e-'));
	const config = path.join(work, 'config.toml');
	// `admin create-client` derives the client-secret pepper from the master key,
	// so the key has to exist before the CLI runs. Without it the very first
	// command fails with "read encryption key file", which reads like a code bug
	// rather than a missing fixture.
	await mkdir(path.join(work, 'data'), { recursive: true });
	const masterKey = path.join(work, 'data', 'master.key');
	await writeFile(masterKey, `${'ab'.repeat(32)}\n`, { encoding: 'utf8', mode: 0o600 });
	await chmod(masterKey, 0o600);
	await writeFile(
		config,
		`[server]\nbind = "127.0.0.1:${APP_PORT}"\nissuer = "${APP}"\ntrusted_proxies = []\n\n` +
			`[database]\nurl = "sqlite://data/e2e.db"\n\n` +
			`[crypto]\nmaster_key_file = "data/master.key"
master_key_version = 1\nsigning_key_file = "data/signing-key.pem"\n\n` +
			// The mock IdP is plain HTTP on loopback. The guard refuses that by
			// default, so without this the server dies at startup and the suite
			// reports "did not become healthy" instead of what actually broke.
			`[tls]\nallow_loopback = true\n\n` +
			`[limits]\nupstream_response_bytes = 4194304\nupstream_inflight_bytes = 67108864\ninbound_body_bytes = 1048576\n\n` +
			`[identity_provider]\nissuer = "${IDP}"\nclient_id = "${CLIENT_ID}"\nclient_secret = "e2e-secret"\n` +
			`redirect_uri = "${APP}/auth/callback"\nscopes = ["openid", "profile"]\n` +
			`discovery_url = "${IDP}/.well-known/openid-configuration"\n\n` +
			// A bindable upstream: `oauth` present is what makes the binding routes
			// answer instead of 404. `base_url` is loopback HTTP, allowed above.
			`[[connectors]]\nid = "phigros"\nbase_url = "${UPSTREAM}"\nallow_loopback = true\n\n` +
			`[connectors.oauth]\nauthorization_endpoint = "${UPSTREAM}/authorize"\n` +
			`token_endpoint = "${UPSTREAM}/token"\nclient_id = "re0auth-upstream"\n` +
			`client_secret = "upstream-secret"\nscopes = ["read"]\n` +
			`userinfo_endpoint = "${UPSTREAM}/userinfo"\nsubject_field = "id"\n`,
		'utf8'
	);

	server = spawn(binary, ['--config', config], {
		cwd: work,
		stdio: ['ignore', 'pipe', 'pipe']
	});
	server.stdout?.on('data', () => {});
	server.stderr?.on('data', () => {});
	await waitForServer();

	clientId = createClient(config, 'E2E Client');
	deviceClientId = createClient(config, 'E2E Device Client');
}

test.beforeAll(async () => {
	await startIdp();
	await startUpstream();
	await startCallback();
	await startRe0auth();
});

test.afterAll(async () => {
	server?.kill();
	if (idp) await new Promise<void>((resolve) => idp!.close(() => resolve()));
	if (upstream) await new Promise<void>((resolve) => upstream!.close(() => resolve()));
	if (callbackServer)
		await new Promise<void>((resolve) => callbackServer!.close(() => resolve()));
	if (work) await rm(work, { recursive: true, force: true });
});

test.describe.configure({ mode: 'serial' });

test('login page reaches account without Node runtime', async ({ browser }) => {
	const context = await browser.newContext();
	const page = await context.newPage();
	await page.goto('/login?return_to=/account');
	await expect(page.getByRole('heading', { name: '登录 Re0Auth' })).toBeVisible();
	await page.getByRole('button', { name: /继续登录/ }).click();
	await expect(page).toHaveURL(`${APP}/account`);
	await expect(page.getByRole('heading', { name: '账号与授权' })).toBeVisible();
	await expect(page.getByText('Alice 的已授权应用')).toBeVisible();
	await context.close();
});

test('consent page approves and account can revoke', async ({ browser }) => {
	const context = await browser.newContext();
	const page = await context.newPage();
	const verifier = 'e2e-verifier-0123456789-0123456789';
	const challenge = createHash('sha256').update(verifier).digest('base64url');
	const authorize = new URL(`${APP}/oauth/authorize`);
	authorize.search = new URLSearchParams({
		response_type: 'code',
		client_id: clientId,
		redirect_uri: CLIENT_REDIRECT,
		scope: 'openid profile phigros.xtower.read phigros.phihub.read',
		code_challenge: challenge,
		code_challenge_method: 'S256',
		state: 'e2e-state'
	}).toString();

	await page.goto(authorize.toString());
	await expect(page.getByRole('heading', { name: '登录 Re0Auth' })).toBeVisible();
	await page.getByRole('button', { name: /继续登录/ }).click();
	await expect(page.getByRole('heading', { name: '确认授权' })).toBeVisible();
	await expect(page.getByText('E2E Client')).toBeVisible();
	await expect(page.getByText('读取你的 Phigros 游戏数据（Phigros Query 数据源）')).toBeVisible();
	await expect(page.getByText('读取你的 Phigros 游戏数据（PhiHub 数据源）')).toBeVisible();
	await page.getByRole('button', { name: '批准' }).click();
	await expect(page).toHaveURL(new RegExp(`127\\.0\\.0\\.1:${CALLBACK_PORT}/callback`));
	const params = await waitForCallback();
	expect(params.get('code')).toBeTruthy();
	expect(params.get('state')).toBe('e2e-state');

	await page.goto('/account');
	await expect(page.getByText('E2E Client')).toBeVisible();
	// The bindings section is fed by `/api/me/bindings`. A user who has never
	// linked an upstream still has to see the section, or the page silently
	// hides a feature that exists.
	await expect(page.getByRole('heading', { name: '已绑定的游戏账号' })).toBeVisible();
	await expect(page.getByText('还没有绑定游戏账号。')).toBeVisible();
	await page.getByRole('button', { name: /撤销 E2E Client/ }).click();
	await expect(page.getByText('还没有应用获得授权。')).toBeVisible();
	await page.getByRole('button', { name: /退出所有会话/ }).click();
	await expect(page).toHaveURL(/\/login/);
	await context.close();
});

test('device entry reaches ticket approval and token exchange', async ({ browser, request }) => {
	const authorization = await request.post('/oauth/device_authorization', {
		form: { client_id: deviceClientId, scope: 'openid profile' }
	});
	expect(authorization.ok()).toBeTruthy();
	const device = (await authorization.json()) as {
		device_code: string;
		user_code: string;
	};
	const context = await browser.newContext();
	// The approval page is server-rendered and honours Accept-Language; pin the
	// locale so assertions do not depend on the runner's browser language.
	await context.addCookies([{ name: 're0auth_lang', value: 'zh-CN', url: APP }]);
	const page = await context.newPage();
	await page.goto(`/device?user_code=${encodeURIComponent(device.user_code)}`);
	await expect(page.getByRole('heading', { name: '批准设备' })).toBeVisible();
	await page.getByRole('button', { name: /继续/ }).click();
	await expect(page.getByRole('button', { name: '批准' })).toBeVisible();
	await page.getByRole('button', { name: '批准' }).click();
	await expect(page.getByText('设备已批准')).toBeVisible();
	await context.close();

	const token = await request.post('/oauth/token', {
		form: {
			grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
			client_id: deviceClientId,
			device_code: device.device_code
		}
	});
	expect(token.ok()).toBeTruthy();
	const body = (await token.json()) as { access_token?: string };
	expect(body.access_token).toBeTruthy();
});

/// The path B9 fixed: a user could see the "connect an upstream" prompt but had
/// no way to act on it. This drives the whole loop through the browser —
/// account page, upstream consent, callback, and back — so the prompt becoming
/// an action is proven, not assumed.
test('account connects an upstream and the binding comes back active', async ({ browser }) => {
	const context = await browser.newContext();
	const page = await context.newPage();

	await page.goto('/login?return_to=/account');
	await expect(page.getByRole('heading', { name: '登录 Re0Auth' })).toBeVisible();
	await page.getByRole('button', { name: /继续登录/ }).click();
	await expect(page).toHaveURL(`${APP}/account`);

	// The portal lists the configured upstream, which is what makes a connect
	// button possible at all.
	await expect(page.getByRole('button', { name: '连接 phigros' })).toBeVisible();
	await page.getByRole('button', { name: '连接 phigros' }).click();

	// The mock upstream consents and the callback redeems the code, landing the
	// browser back on the account page.
	await expect(page).toHaveURL(`${APP}/account`);
	await expect(page.getByText('phigros')).toBeVisible();
	await expect(page.getByText('已连接')).toBeVisible();

	// The killswitch removes every binding in one action and lands on the empty
	// state, which is what proves the button is wired, not just rendered.
	await page.getByRole('button', { name: '解除全部绑定' }).click();
	await expect(page.getByText('还没有绑定游戏账号。')).toBeVisible();
	await context.close();
});

/// ADR-0050: attaching a second login method, and the refusal to leave an
/// account with none. The mock IdP answers as a different subject for the second
/// round trip, which is exactly the case where the old code would have created a
/// second account instead.
test('account attaches a second login method and keeps the last one', async ({ browser }) => {
	const context = await browser.newContext();
	const page = await context.newPage();

	await page.goto('/login?return_to=/account');
	await page.getByRole('button', { name: /继续登录/ }).click();
	await expect(page).toHaveURL(`${APP}/account`);

	const methods = page.locator('section', { has: page.getByRole('heading', { name: '登录方式' }) });
	await expect(methods.locator('.auth-row')).toHaveCount(1);

	// A second identity from the same IdP. Without the attach flow this login
	// would create a second account and the portal would still show one method.
	idpSubject = 'e2e-second';
	await page.getByRole('button', { name: '添加登录方式' }).click();
	await expect(page.getByText('已添加新的登录方式。')).toBeVisible();
	await expect(methods.locator('.auth-row')).toHaveCount(2);
	await expect(page).toHaveURL(`${APP}/account`);

	// Removing one leaves the account usable; removing the last one must not be
	// offered at all, because that would lock the account out for good.
	await methods.getByRole('button', { name: /移除来自/ }).first().click();
	await expect(methods.locator('.auth-row')).toHaveCount(1);
	await expect(methods.getByText('这是唯一的登录方式')).toBeVisible();
	await expect(methods.getByRole('button', { name: /移除来自/ })).toBeDisabled();

	idpSubject = 'e2e-user';
	await context.close();
});

test('admin audit keeps the newest filter response', async ({ browser }) => {
	const cookie = createAdminSession(path.join(work, 'config.toml'));
	const context = await browser.newContext();
	await context.addCookies([cookie]);
	const page = await context.newPage();
	const auditRow = (target: string) => ({
		id: target,
		occurred_at: 1,
		actor_user_id: null,
		client_id: null,
		action: 'user_banned',
		target,
		outcome: 'success',
		severity: 'info',
		request_id: null,
		tier: 'fact',
		detail: '{}'
	});
	const initialResponse = Promise.withResolvers<void>();
	const filteredResponse = Promise.withResolvers<void>();
	const filteredRequest = Promise.withResolvers<void>();
	const initialResponded = Promise.withResolvers<void>();
	const filteredResponded = Promise.withResolvers<void>();
	await page.route('**/api/admin/audit?*', async (route) => {
		const actor = new URL(route.request().url()).searchParams.get('actor');
		if (actor === 'race-filter') {
			filteredRequest.resolve();
			await filteredResponse.promise;
			await route.fulfill({
				json: { items: [auditRow('current-filter')], next_cursor: null }
			});
			filteredResponded.resolve();
		} else {
			await initialResponse.promise;
			await route.fulfill({
				json: { items: [auditRow('stale-filter')], next_cursor: null }
			});
			initialResponded.resolve();
		}
	});
	await page.goto('/admin/audit', { waitUntil: 'domcontentloaded' });
	await page.locator('#audit-actor').fill('race-filter');
	await page.getByRole('button', { name: '查询' }).click();
	await filteredRequest.promise;
	filteredResponse.resolve();
	await filteredResponded.promise;
	await expect(page.getByText('current-filter')).toBeVisible();
	initialResponse.resolve();
	await initialResponded.promise;
	await expect(page.getByText('current-filter')).toBeVisible();
	await expect(page.getByText('stale-filter')).toHaveCount(0);
	await context.close();
});
