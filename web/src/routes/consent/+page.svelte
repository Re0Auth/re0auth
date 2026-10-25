<script lang="ts">
	import { onMount } from 'svelte';
	import { AlertCircle, Check, ShieldCheck, X } from 'lucide-svelte';
	import AuthShell from '#lib/components/AuthShell.svelte';
	import {
		ApiError,
		apiGet,
		apiPost,
		bindingStartSchema,
		consentResultSchema,
		currentLocation,
		pendingSchema,
		readQuery,
		type PendingConsent
	} from '#lib/api.ts';
	import { scopeDescription } from '#lib/scopes.ts';

	let requestId = $state('');
	let pending = $state<PendingConsent | null>(null);
	let loading = $state(true);
	let submitting = $state(false);
	let connecting = $state('');
	let error = $state('');

	const clientName = $derived(pending?.client_name ?? '');
	const redirectHost = $derived.by(() => {
		if (!pending) return '';
		try {
			return new URL(pending.redirect_uri).host;
		} catch {
			return pending.redirect_uri;
		}
	});
	const expiresAt = $derived.by(() => {
		if (!pending) return '';
		return new Intl.DateTimeFormat('zh-CN', {
			hour: '2-digit',
			minute: '2-digit'
		}).format(new Date(pending.expires_at * 1000));
	});

	onMount(async () => {
		requestId = readQuery('request');
		if (!requestId) {
			error = '缺少授权请求参数，请返回发起授权的应用重新开始。';
			loading = false;
			return;
		}
		await loadPending();
	});

	async function loadPending(): Promise<void> {
		loading = true;
		error = '';
		try {
			pending = await apiGet(
				`/api/oauth/pending?request=${encodeURIComponent(requestId)}`,
				pendingSchema
			);
		} catch (cause) {
			error = describeError(cause);
		} finally {
			loading = false;
		}
	}

	async function decide(decision: 'approve' | 'deny'): Promise<void> {
		if (!pending || submitting) return;
		submitting = true;
		error = '';
		try {
			const result = await apiPost(
				'/api/oauth/consent',
				{ request_id: requestId, decision },
				consentResultSchema
			);
			window.location.assign(result.redirect_to);
		} catch (cause) {
			error = describeError(cause);
			submitting = false;
		}
	}

	async function connect(upstream: string): Promise<void> {
		if (connecting) return;
		connecting = upstream;
		error = '';
		try {
			const started = await apiPost(
				'/api/me/bindings/begin',
				{ upstream, return_to: currentLocation() },
				bindingStartSchema
			);
			window.location.assign(started.authorization_url);
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 401) {
				window.location.assign(`/auth/login?return_to=${encodeURIComponent(currentLocation())}`);
				return;
			}
			error = describeError(cause);
			connecting = '';
		}
	}

	function describeError(cause: unknown): string {
		if (cause instanceof ApiError) {
			switch (cause.status) {
				case 401:
					return '登录状态已失效，请返回发起授权的应用重新开始。';
				case 403:
					return '安全校验失败，请刷新页面后重试。';
				case 404:
					return '授权请求不存在或不属于当前登录会话，请返回应用重新发起授权。';
				default:
					return cause.message;
			}
		}
		return '请求失败，请稍后重试。';
	}

	function scopeLabel(scope: string): string {
		return scopeDescription(scope);
	}
</script>

<AuthShell
	title="确认授权"
	subtitle={pending ? `${clientName} 请求访问你的 Re0Auth 账号。` : '正在读取授权请求…'}
>
	{#if loading}
		<p class="meta">正在加载…</p>
	{:else if pending}
		<ul class="scope-list" aria-label="请求的权限范围">
			{#each pending.scopes as scope}
				<li class="scope-item">
					<ShieldCheck size={18} strokeWidth={1.8} aria-hidden="true" />
					<div>
						<div>{scopeLabel(scope)}</div>
						<div class="scope-name">{scope}</div>
					</div>
				</li>
			{/each}
		</ul>
		{#if pending.missing_bindings.length > 0}
			<div class="notice" role="status">
				<AlertCircle size={16} strokeWidth={1.8} aria-hidden="true" />
				<div>
					<p>
						授权本身可以完成，但这些权限需要先连接对应上游账号才能读取数据：
						<strong>{pending.missing_bindings.map((item) => item.upstream_id).join('、')}</strong>。
					</p>
					<div class="auth-actions">
						{#each pending.missing_bindings as missing (missing.upstream_id)}
							<button
								class="btn-secondary"
								type="button"
								disabled={connecting === missing.upstream_id}
								onclick={() => connect(missing.upstream_id)}
							>
								<ShieldCheck size={16} aria-hidden="true" />
								连接 {missing.upstream_id}
							</button>
						{/each}
					</div>
					<p class="meta">
						连接后回到本页继续授权。数据读取时才会校验绑定，未连接不会影响本次授权的完成。
					</p>
				</div>
			</div>
		{/if}
		<p class="meta">
			授权后将返回 <code>{redirectHost}</code>。请求将在 <code>{expiresAt}</code> 过期。
		</p>
		<div class="auth-actions">
			<button
				class="btn-primary"
				type="button"
				disabled={submitting}
				onclick={() => decide('approve')}
			>
				<Check size={16} aria-hidden="true" />
				批准
			</button>
			<button
				class="btn-secondary"
				type="button"
				disabled={submitting}
				onclick={() => decide('deny')}
			>
				<X size={16} aria-hidden="true" />
				拒绝
			</button>
		</div>
	{/if}

	{#if error}
		<div class="alert" role="alert">
			<AlertCircle size={16} aria-hidden="true" />
			<span>{error}</span>
		</div>
	{/if}
</AuthShell>
