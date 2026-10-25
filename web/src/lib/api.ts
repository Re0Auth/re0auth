import { z } from 'zod';

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
	display_name: z.string()
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

export const bindingRevocationSchema = z.object({
	revoked: z.number().int().nonnegative()
});

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
	const prefix = 're0auth_csrf=';
	const value = document.cookie
		.split(';')
		.map((part) => part.trim())
		.find((part) => part.startsWith(prefix));
	return value ? decodeURIComponent(value.slice(prefix.length)) : null;
}

async function decodeError(response: Response): Promise<ApiError> {
	let code = `http_${response.status}`;
	let message = response.statusText || '请求失败';
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
		throw new ApiError(401, 'missing_csrf', '缺少 CSRF 凭据，请重新登录。');
	}
	return csrf;
}

async function send(
	path: string,
	method: 'POST' | 'DELETE',
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

export async function apiDelete(path: string): Promise<void> {
	const response = await send(path, 'DELETE');
	await response.body?.cancel();
}

export async function apiDeleteJson<T>(path: string, schema: z.ZodType<T>): Promise<T> {
	const response = await send(path, 'DELETE');
	return schema.parse(await response.json());
}

export function startLogin(returnTo: string): void {
	const query = new URLSearchParams({ return_to: returnTo });
	window.location.assign(`/auth/login?${query.toString()}`);
}

export function currentLocation(): string {
	return `${window.location.pathname}${window.location.search}${window.location.hash}`;
}

export function readQuery(name: string): string {
	return new URLSearchParams(window.location.search).get(name) ?? '';
}
