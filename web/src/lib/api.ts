import { z } from 'zod';
import { copy } from '#lib/copy.ts';

export class ApiError extends Error {
	status: number;
	code: string;

	constructor(status: number, code: string, message: string) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
		this.code = code;
	}
}

export const providerSchema = z.object({
	name: z.string(),
	display_name: z.string()
});

export const providersSchema = z.object({
	providers: z.array(providerSchema)
});

export type Provider = z.infer<typeof providerSchema>;

export const missingBindingSchema = z.object({
	upstream_id: z.string(),
	scopes: z.array(z.string())
});

export type MissingBinding = z.infer<typeof missingBindingSchema>;

export const pendingSchema = z.object({
	request_id: z.string(),
	client_id: z.string(),
	client_name: z.string(),
	redirect_uri: z.string().url(),
	scopes: z.array(z.string()),
	expires_at: z.number().int().nonnegative(),
	// Advisory: which upstreams the requested scopes need that this user has not
	// connected. The consent screen offers the missing step; the data plane
	// re-checks the binding on every read regardless.
	missing_bindings: z.array(missingBindingSchema)
});

export type PendingConsent = z.infer<typeof pendingSchema>;

export const consentResultSchema = z.object({
	redirect_to: z.string().url()
});

export const userSchema = z.object({
	id: z.string(),
	display_name: z.string(),
	// 仅用于决定是否显示管理入口；真正的权限由服务端判定
	role: z.enum(['user', 'admin'])
});

export const meSchema = z.object({
	user: userSchema,
	csrf_token: z.string()
});

export const authorizationSchema = z.object({
	client_id: z.string(),
	client_name: z.string(),
	scopes: z.array(z.string()),
	created_at: z.number().int().nonnegative(),
	updated_at: z.number().int().nonnegative()
});

export const authorizationsSchema = z.array(authorizationSchema);

export const bindingSchema = z.object({
	id: z.string(),
	connector: z.string(),
	status: z.string(),
	created_at: z.number().int().nonnegative(),
	updated_at: z.number().int().nonnegative(),
	last_refreshed_at: z.number().int().nonnegative().nullable(),
	last_error_code: z.string().nullable()
});

export const bindingsSchema = z.array(bindingSchema);

export const bindingStartSchema = z.object({
	authorization_url: z.string().url()
});

export const bindableUpstreamsSchema = z.object({
	upstreams: z.array(z.string())
});

export const failedRevocationSchema = z.object({
	id: z.string(),
	upstream: z.string(),
	reason: z.string()
});

export const bindingRevocationSchema = z.object({
	revoked: z.number().int().nonnegative(),
	failed: z.array(failedRevocationSchema)
});

// ---- 管理 API -----------------------------------------------------------
// 字段与 re0auth_app::admin_service 的视图一一对应：
// archtest 的 *_matches_the_spa_schema 会逐字段比对，改名会红。

export const adminClientSchema = z.object({
	id: z.string(),
	name: z.string(),
	redirect_uris: z.array(z.string()),
	allowed_scopes: z.array(z.string()),
	raw_access: z.boolean(),
	status: z.string(),
	has_secret: z.boolean(),
	created_at: z.number().int().nonnegative(),
	updated_at: z.number().int().nonnegative()
});

export const adminClientPageSchema = z.object({
	items: z.array(adminClientSchema),
	next_cursor: z.string().nullable()
});

export const createdClientSchema = z.object({
	id: z.string(),
	secret: z.string().nullable()
});

export const rotatedSecretSchema = z.object({
	id: z.string(),
	secret: z.string()
});

export const adminUserSchema = z.object({
	id: z.string(),
	display_name: z.string(),
	role: z.string(),
	created_at: z.number().int().nonnegative(),
	updated_at: z.number().int().nonnegative()
});

export const adminUserPageSchema = z.object({
	items: z.array(adminUserSchema),
	next_cursor: z.string().nullable()
});

export const adminResourceSchema = z.object({
	name: z.string(),
	path: z.string(),
	scope: z.string(),
	method: z.string(),
	idempotent: z.boolean()
});

export const adminConnectorSchema = z.object({
	id: z.string(),
	name: z.string(),
	base_url: z.string(),
	allow_private_net: z.boolean(),
	allow_link_local_metadata: z.boolean(),
	resources: z.array(adminResourceSchema)
});

export const adminConnectorPageSchema = z.object({
	items: z.array(adminConnectorSchema),
	next_cursor: z.string().nullable()
});

export const adminBindingSchema = z.object({
	id: z.string(),
	user_id: z.string(),
	connector: z.string(),
	upstream_user_id: z.string(),
	status: z.string(),
	created_at: z.number().int().nonnegative(),
	updated_at: z.number().int().nonnegative(),
	last_refreshed_at: z.number().int().nonnegative().nullable(),
	last_error_code: z.string().nullable()
});

export const adminBindingPageSchema = z.object({
	items: z.array(adminBindingSchema),
	next_cursor: z.string().nullable()
});

export const adminAuditSchema = z.object({
	id: z.string(),
	occurred_at: z.number().int().nonnegative(),
	actor_user_id: z.string().nullable(),
	client_id: z.string().nullable(),
	action: z.string(),
	target: z.string(),
	outcome: z.string(),
	severity: z.string(),
	request_id: z.string().nullable(),
	tier: z.string(),
	detail: z.string()
});

export const adminAuditPageSchema = z.object({
	items: z.array(adminAuditSchema),
	next_cursor: z.string().nullable()
});

export type AdminClient = z.infer<typeof adminClientSchema>;
export type AdminUser = z.infer<typeof adminUserSchema>;
export type AdminConnector = z.infer<typeof adminConnectorSchema>;
export type AdminBinding = z.infer<typeof adminBindingSchema>;
export type AdminAudit = z.infer<typeof adminAuditSchema>;


export type Me = z.infer<typeof meSchema>;
export type Authorization = z.infer<typeof authorizationSchema>;
export type Binding = z.infer<typeof bindingSchema>;

// Two error shapes reach the SPA, and which one applies depends on the endpoint
// rather than on the failure: the OAuth protocol endpoints answer RFC 6749
// (`error` / `error_description`), while the gateway and session APIs answer
// RFC 9457 problem details (`code` / `detail`).
const oauthErrorSchema = z.object({
	error: z.string(),
	error_description: z.string().optional()
});

const problemSchema = z.object({
	code: z.string(),
	detail: z.string().optional()
});

function csrfToken(): string | null {
	// 与后端 secure_cookies 对齐：https 用 __Host- 前缀
	const prefix = location.protocol === 'https:' ? '__Host-re0auth_csrf=' : 're0auth_csrf=';
	const value = document.cookie
		.split(';')
		.map((part) => part.trim())
		.find((part) => part.startsWith(prefix));
	return value ? decodeURIComponent(value.slice(prefix.length)) : null;
}

async function decodeError(response: Response): Promise<ApiError> {
	let code = `http_${response.status}`;
	let message = response.statusText || copy.errors.requestFailed;
	try {
		const body = await response.json();
		const oauth = oauthErrorSchema.safeParse(body);
		if (oauth.success) {
			code = oauth.data.error;
			message = oauth.data.error_description ?? message;
		} else {
			const problem = problemSchema.parse(body);
			code = problem.code;
			message = problem.detail ?? message;
		}
	} catch {
		// Keep the HTTP fallback when the response is not our JSON error shape.
	}
	return new ApiError(response.status, code, message);
}

async function decode<T>(response: Response, schema: z.ZodType<T>): Promise<T> {
	if (!response.ok) {
		throw await decodeError(response);
	}
	return schema.parse(await response.json());
}

export async function apiGet<T>(path: string, schema: z.ZodType<T>): Promise<T> {
	const response = await fetch(path, {
		credentials: 'include',
		headers: { Accept: 'application/json' }
	});
	return decode(response, schema);
}

function requireCsrf(): string {
	const csrf = csrfToken();
	if (!csrf) {
		throw new ApiError(401, 'missing_csrf', copy.errors.missingCsrf);
	}
	return csrf;
}

async function send(
	path: string,
	method: 'POST' | 'PATCH' | 'DELETE',
	body?: unknown
): Promise<Response> {
	const headers: Record<string, string> = {
		Accept: 'application/json',
		'X-CSRF-Token': requireCsrf()
	};
	if (body !== undefined) {
		headers['Content-Type'] = 'application/json';
	}
	const response = await fetch(path, {
		method,
		credentials: 'include',
		headers,
		body: body === undefined ? undefined : JSON.stringify(body)
	});
	if (!response.ok) {
		throw await decodeError(response);
	}
	return response;
}

export async function apiPost<T>(
	path: string,
	body: unknown,
	schema: z.ZodType<T>
): Promise<T> {
	const response = await send(path, 'POST', body);
	return schema.parse(await response.json());
}

export async function apiPostNoContent(path: string, body?: unknown): Promise<void> {
	const response = await send(path, 'POST', body);
	await response.body?.cancel();
}

export async function apiPatch<T>(
	path: string,
	body: unknown,
	schema: z.ZodType<T>
): Promise<T> {
	const response = await send(path, 'PATCH', body);
	return schema.parse(await response.json());
}

export async function apiDelete(path: string): Promise<void> {
	const response = await send(path, 'DELETE');
	await response.body?.cancel();
}

export async function apiDeleteJson<T>(path: string, schema: z.ZodType<T>): Promise<T> {
	const response = await send(path, 'DELETE');
	return schema.parse(await response.json());
}

export async function fetchProviders(): Promise<Provider[]> {
	const body = await apiGet('/api/auth/providers', providersSchema);
	return body.providers;
}

/// Starts the IdP redirect directly. `idp` is required when several providers
/// are configured; the login page supplies it from the selector.
export function startLogin(returnTo: string, idp?: string): void {
	const query = new URLSearchParams({ return_to: returnTo });
	if (idp) query.set('idp', idp);
	window.location.assign(`/auth/login?${query.toString()}`);
}

/// Sends the browser to the login selector rather than guessing a provider.
export function openLogin(returnTo: string): void {
	const query = new URLSearchParams({ return_to: returnTo });
	window.location.assign(`/login?${query.toString()}`);
}

/// Adds the "just signed in" marker to a local path we will land on.
///
/// The value travels inside `return_to`, which the server validates as a local
/// path; a non-local value is passed through untouched so that rejection still
/// happens on the server rather than being silently rewritten here.
export function withLoginFlag(path: string): string {
	if (!path.startsWith('/') || path.startsWith('//')) return path;
	const url = new URL(path, window.location.origin);
	url.searchParams.set('login', 'ok');
	return `${url.pathname}${url.search}${url.hash}`;
}

export function currentLocation(): string {
	return `${window.location.pathname}${window.location.search}${window.location.hash}`;
}

export function readQuery(name: string): string {
	return new URLSearchParams(window.location.search).get(name) ?? '';
}
