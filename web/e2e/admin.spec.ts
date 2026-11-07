import { expect, test } from '@playwright/test';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

// The admin console is the only path an operator has that does not involve SSH,
// so it gets a real browser test rather than a curl transcript: the SPA has to
// read the same problem bodies, send the CSRF header on PATCH, and show a secret
// exactly once.

const APP_PORT = 18085;
const APP = `http://127.0.0.1:${APP_PORT}`;
const root = path.resolve(process.cwd(), '..');
const binary = path.join(
	root,
	'target',
	'release',
	process.platform === 'win32' ? 're0auth-server.exe' : 're0auth-server'
);

let work: string;
let server: ChildProcess | undefined;
let sessionCookie = '';
let csrfToken = '';

function field(stdout: string, key: string): string {
	const line = stdout.split(/\r?\n/).find((entry) => entry.startsWith(`${key}=`));
	if (!line) throw new Error(`missing ${key} in:\n${stdout}`);
	return line.slice(key.length + 1);
}

async function waitForServer(): Promise<void> {
	const deadline = Date.now() + 20_000;
	while (Date.now() < deadline) {
		try {
			const response = await fetch(`${APP}/healthz`);
			if (response.ok) return;
		} catch {
			// still starting
		}
		await new Promise((resolve) => setTimeout(resolve, 150));
	}
	throw new Error('re0auth-server did not become healthy');
}

test.beforeAll(async () => {
	work = await mkdtemp(path.join(tmpdir(), 're0auth-admin-e2e-'));
	const config = path.join(work, 'config.toml');
	await mkdir(path.join(work, 'data'), { recursive: true });
	const masterKey = path.join(work, 'data', 'master.key');
	await writeFile(masterKey, `${'ab'.repeat(32)}\n`, { encoding: 'utf8', mode: 0o600 });
	await chmod(masterKey, 0o600);
	await writeFile(
		config,
		`[server]\nbind = "127.0.0.1:${APP_PORT}"\nissuer = "${APP}"\ntrusted_proxies = []\n\n` +
			`[database]\nurl = "sqlite://data/admin.db"\n\n` +
			`[crypto]\nmaster_key_file = "data/master.key"\nmaster_key_version = 1\n` +
			`signing_key_file = "data/signing-key.pem"\n\n` +
			`[limits]\nupstream_response_bytes = 4194304\nupstream_inflight_bytes = 67108864\n` +
			`inbound_body_bytes = 1048576\n`,
		'utf8'
	);

	const created = spawnSync(
		binary,
		['--config', config, 'admin', 'create-user', '--display-name', 'Admin', '--role', 'admin'],
		{ cwd: work, encoding: 'utf8' }
	);
	if (created.status !== 0) throw new Error(`create-user failed: ${created.stderr}`);
	const userId = field(created.stdout, 'user_id');

	const session = spawnSync(
		binary,
		['--config', config, 'admin', 'create-session', '--user-id', userId],
		{ cwd: work, encoding: 'utf8' }
	);
	if (session.status !== 0) throw new Error(`create-session failed: ${session.stderr}`);
	sessionCookie = field(session.stdout, 'session_cookie=re0auth_session');
	csrfToken = field(session.stdout, 'csrf_token');

	server = spawn(binary, ['--config', config], {
		cwd: work,
		stdio: ['ignore', 'pipe', 'pipe']
	});
	server.stdout?.on('data', () => {});
	server.stderr?.on('data', () => {});
	await waitForServer();
});

test.afterAll(async () => {
	const child = server;
	server = undefined;
	if (child && child.exitCode === null) {
		// Wait for the process to release the SQLite file; Windows keeps the
		// handle open for a moment after the kill signal.
		await new Promise<void>((resolve) => {
			child.once('exit', () => resolve());
			child.kill();
		});
	}
	if (work) {
		await rm(work, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 }).catch(
			(cause) => console.warn(`could not remove ${work}: ${cause}`)
		);
	}
});

test.describe.configure({ mode: 'serial' });

test('the console creates a client, shows the secret once, and lists the audit trail', async ({
	page,
	context
}) => {
	await context.addCookies([
		{ name: 're0auth_session', value: sessionCookie, url: APP },
		{ name: 're0auth_csrf', value: csrfToken, url: APP }
	]);

	await page.goto(`${APP}/admin/clients`);
	await expect(page.getByRole('heading', { name: '客户端' })).toBeVisible();

	await page.getByRole('button', { name: '新建客户端' }).click();
	await page.locator('#client-name').fill('控制台客户端');
	await page.locator('#client-redirects').fill('https://console.example/callback');
	await page.locator('#client-scopes').fill('openid\nprofile');
	// Only a confidential client gets a secret; the dialog below proves it is
	// shown once rather than merely stored.
	await page.getByLabel('机密客户端（签发 secret）').check();
	await page.getByRole('button', { name: '保存' }).click();

	// The secret is minted once; the dialog is the only place it appears.
	await expect(page.getByRole('heading', { name: '请现在保存 secret' })).toBeVisible();
	const secret = await page.locator('dialog code').innerText();
	expect(secret.length).toBeGreaterThan(20);
	await page.getByRole('button', { name: '关闭' }).click();
	await expect(page.getByText('控制台客户端')).toBeVisible();

	// Editing goes through PATCH with the CSRF header the SPA reads from its cookie.
	await page.getByRole('button', { name: '编辑' }).first().click();
	await page.locator('#client-name').fill('控制台客户端改');
	await page.getByRole('button', { name: '保存' }).click();
	await expect(page.getByText('控制台客户端改')).toBeVisible();

	await page.goto(`${APP}/admin/users`);
	await expect(page.getByRole('heading', { name: '用户' })).toBeVisible();
	await expect(page.getByText('Admin')).toBeVisible();

	await page.goto(`${APP}/admin/audit`);
	await expect(page.getByRole('heading', { name: '审计' })).toBeVisible();
	await expect(page.getByText('client_created')).toBeVisible();

	await page.goto(`${APP}/admin/bindings`);
	await expect(page.getByRole('heading', { name: '绑定' })).toBeVisible();

	await page.goto(`${APP}/admin/connectors`);
	await expect(page.getByRole('heading', { name: '连接器' })).toBeVisible();
});

test('without a session the console asks for a login instead of rendering data', async ({
	page
}) => {
	await page.goto(`${APP}/admin/clients`);
	await expect(page.getByRole('button', { name: '去登录' })).toBeVisible();
	await expect(page.getByRole('heading', { name: '客户端' })).toHaveCount(0);
});
