<script lang="ts">
	import { onMount } from 'svelte';
	import { AlertCircle, Link2, LogOut, Plus, ShieldCheck, Unlink } from 'lucide-svelte';
	import AccountShell from '#lib/components/AccountShell.svelte';
	import {
		ApiError,
		apiDelete,
		apiDeleteJson,
		apiGet,
		apiPost,
		apiPostNoContent,
		authorizationsSchema,
		bindableUpstreamsSchema,
		bindingRevocationSchema,
		bindingStartSchema,
		bindingsSchema,
		meSchema,
		openLogin,
		type Authorization,
		type Binding,
		type Me
	} from '#lib/api.ts';
	import { scopeSummary } from '#lib/scopes.ts';

	let me = $state<Me | null>(null);
	let authorizations = $state<Authorization[]>([]);
	let bindings = $state<Binding[]>([]);
	let bindableUpstreams = $state<string[]>([]);
	let loading = $state(true);
	let error = $state('');
	let revoking = $state('');
	let unbinding = $state('');
	let unbindingAll = $state(false);
	let connecting = $state('');
	let loggingOut = $state(false);

	const connectableUpstreams = $derived(
		bindableUpstreams.filter(
			(upstream) =>
				!bindings.some((binding) => binding.connector === upstream && binding.status === 'active')
		)
	);

	onMount(async () => {
		try {
			me = await apiGet('/api/me', meSchema);
			authorizations = await apiGet('/api/me/authorizations', authorizationsSchema);
			bindings = await apiGet('/api/me/bindings', bindingsSchema);
			try {
				const available = await apiGet('/api/me/bindings/upstreams', bindableUpstreamsSchema);
				bindableUpstreams = available.upstreams;
			} catch {
				// Binding is opt-in per deployment; an unconfigured instance has none.
				bindableUpstreams = [];
			}
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 401) {
				openLogin('/account');
				return;
			}
			error = describeError(cause);
		} finally {
			loading = false;
		}
	});

	async function unlink(id: string): Promise<void> {
		if (unbinding) return;
		unbinding = id;
		error = '';
		try {
			await apiDelete(`/api/me/bindings/${encodeURIComponent(id)}`);
			bindings = bindings.filter((item) => item.id !== id);
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 401) {
				openLogin('/account');
				return;
			}
			error = describeError(cause);
		} finally {
			unbinding = '';
		}
	}

	async function revoke(clientId: string): Promise<void> {
		if (revoking) return;
		revoking = clientId;
		error = '';
		try {
			await apiDelete(`/api/me/authorizations/${encodeURIComponent(clientId)}`);
			authorizations = authorizations.filter((item) => item.client_id !== clientId);
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 401) {
				openLogin('/account');
				return;
			}
			error = describeError(cause);
		} finally {
			revoking = '';
		}
	}

	async function unlinkAll(): Promise<void> {
		if (unbindingAll) return;
		unbindingAll = true;
		error = '';
		try {
			await apiDeleteJson('/api/me/bindings', bindingRevocationSchema);
			bindings = [];
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 401) {
				openLogin('/account');
				return;
			}
			error = describeError(cause);
		} finally {
			unbindingAll = false;
		}
	}

	async function connect(upstream: string): Promise<void> {
		if (connecting) return;
		connecting = upstream;
		error = '';
		try {
			const started = await apiPost(
				'/api/me/bindings/begin',
				{ upstream, return_to: '/account' },
				bindingStartSchema
			);
			window.location.assign(started.authorization_url);
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 401) {
				openLogin('/account');
				return;
			}
			error = describeError(cause);
			connecting = '';
		}
	}

	async function logoutAll(): Promise<void> {
		if (loggingOut) return;
		loggingOut = true;
		error = '';
		try {
			await apiPostNoContent('/api/logout-all');
			window.location.assign('/login');
		} catch (cause) {
			error = describeError(cause);
			loggingOut = false;
		}
	}

	function describeError(cause: unknown): string {
		if (cause instanceof ApiError) {
			switch (cause.status) {
				case 403:
					return '安全校验失败，请刷新页面后重试。';
				case 404:
					return '这条授权已不存在，刷新页面后再试。';
				default:
					return cause.message;
			}
		}
		return '请求失败，请稍后重试。';
	}

	function formatDate(unix: number): string {
		return new Intl.DateTimeFormat('zh-CN', {
			dateStyle: 'medium',
			timeStyle: 'short'
		}).format(new Date(unix * 1000));
	}

	function bindingStatus(status: string): { label: string; hint: string } {
		switch (status) {
			case 'active':
				return { label: '已连接', hint: '' };
			case 'pending':
				return { label: '待确认', hint: '上游还没有完成绑定。' };
			case 'needs_reauth':
				return { label: '需要重新授权', hint: '上游凭证已失效，重新绑定后才能读取数据。' };
			case 'expired':
				return { label: '已过期', hint: '上游凭证已过期。' };
			default:
				return { label: status, hint: '' };
		}
	}
</script>

<AccountShell>
	<header class="account-header">
		<div>
			<h1 class="auth-title">账号与授权</h1>
			<p class="auth-subtitle">
				{me ? `${me.user.display_name} 的已授权应用` : '管理已授权应用'}
			</p>
		</div>
		{#if me}
			<button
				class="btn-secondary compact"
				type="button"
				disabled={loggingOut}
				onclick={logoutAll}
			>
				<LogOut size={15} aria-hidden="true" />
				退出所有会话
			</button>
		{/if}
	</header>

	{#if loading}
		<p class="meta">正在加载已授权应用…</p>
	{:else if error && !me}
		<div class="alert" role="alert">
			<AlertCircle size={16} aria-hidden="true" />
			<span>{error}</span>
		</div>
	{:else if authorizations.length === 0}
		<p class="meta">还没有应用获得授权。下次应用请求访问时会在这里出现。</p>
	{:else}
		<div class="account-list">
			{#each authorizations as authorization (authorization.client_id)}
				<article class="auth-row">
					<div class="auth-row-main">
						<div class="auth-row-title">
							<ShieldCheck size={17} strokeWidth={1.8} aria-hidden="true" />
							<span>{authorization.client_name}</span>
						</div>
						<p class="auth-row-scopes">{scopeSummary(authorization.scopes)}</p>
						<p class="scope-name">{authorization.scopes.join(' · ')}</p>
						<p class="meta">最近授权：{formatDate(authorization.updated_at)}</p>
					</div>
					<button
						class="btn-secondary compact revoke"
						type="button"
						disabled={revoking === authorization.client_id}
						aria-label={`撤销 ${authorization.client_name} 的授权`}
						onclick={() => revoke(authorization.client_id)}
					>
						撤销
					</button>
				</article>
			{/each}
		</div>
	{/if}

	{#if error && me}
		<div class="alert" role="alert">
			<AlertCircle size={16} aria-hidden="true" />
			<span>{error}</span>
		</div>
	{/if}

	<section class="bindings">
		<h2 class="section-title">已绑定的上游账号</h2>
		{#if bindings.length === 0}
			<p class="meta">还没有绑定上游账号。绑定后，授权应用才能读取你在上游的数据。</p>
		{:else}
			<div class="account-list">
				{#each bindings as binding (binding.id)}
					{@const state = bindingStatus(binding.status)}
					<article class="auth-row">
						<div class="auth-row-main">
							<div class="auth-row-title">
								<Link2 size={17} strokeWidth={1.8} aria-hidden="true" />
								<span>{binding.connector}</span>
							</div>
							<p class="auth-row-scopes">
								{state.label}{#if binding.last_refreshed_at}
									· 最近刷新 {formatDate(binding.last_refreshed_at)}{/if}
							</p>
							{#if state.hint}
								<p class="meta">{state.hint}</p>
							{/if}
						</div>
						<button
							class="btn-secondary compact revoke"
							type="button"
							disabled={unbinding === binding.id}
							aria-label={`解除与 ${binding.connector} 的绑定`}
							onclick={() => unlink(binding.id)}
						>
							解除
						</button>
					</article>
				{/each}
			</div>
		{/if}
		{#if bindings.length > 0}
			<div class="auth-actions">
				<button
					class="btn-secondary"
					type="button"
					disabled={unbindingAll}
					onclick={unlinkAll}
				>
					<Unlink size={16} aria-hidden="true" />
					解除全部绑定
				</button>
			</div>
		{/if}
		{#if connectableUpstreams.length > 0}
			<div class="account-list">
				{#each connectableUpstreams as upstream (upstream)}
					<article class="auth-row">
						<div class="auth-row-main">
							<div class="auth-row-title">
								<Link2 size={17} strokeWidth={1.8} aria-hidden="true" />
								<span>{upstream}</span>
							</div>
							<p class="meta">尚未连接，连接后才能读取你在该上游的数据。</p>
						</div>
						<button
							class="btn-secondary compact"
							type="button"
							disabled={connecting === upstream}
							aria-label={`连接 ${upstream}`}
							onclick={() => connect(upstream)}
						>
							<Plus size={15} aria-hidden="true" />
							连接
						</button>
					</article>
				{/each}
			</div>
		{/if}
	</section>

	<p class="meta"><a href="/">返回首页</a></p>
</AccountShell>
