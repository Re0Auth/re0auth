<script lang="ts">
	import { onMount } from 'svelte';
	import { AlertCircle, Link2, LogOut, Plus, ShieldCheck, Unlink } from 'lucide-svelte';
	import PortalLayout from '#lib/components/layouts/PortalLayout.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
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
		currentLocation,
		meSchema,
		openLogin,
		readQuery,
		type Authorization,
		type Binding,
		type Me
	} from '#lib/api.ts';
	import { scopeSummary } from '#lib/scopes.ts';
	import { copy } from '#lib/copy.ts';

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
	// Consumed once: a reload must not keep claiming a login just happened.
	let justLoggedIn = $state(false);

	const connectableUpstreams = $derived(
		bindableUpstreams.filter(
			(upstream) =>
				!bindings.some((binding) => binding.connector === upstream && binding.status === 'active')
		)
	);

	onMount(async () => {
		if (readQuery('login') === 'ok') {
			justLoggedIn = true;
			// Drop the flag from the address bar so a refresh does not repeat it.
			history.replaceState(null, '', '/account');
		}
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
			if (cause instanceof ApiError && cause.status === 401 && cause.code !== 'missing_csrf') {
				openLogin(currentLocation());
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
			if (cause instanceof ApiError && cause.status === 401 && cause.code !== 'missing_csrf') {
				openLogin(currentLocation());
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
			if (cause instanceof ApiError && cause.status === 401 && cause.code !== 'missing_csrf') {
				openLogin(currentLocation());
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
			if (cause instanceof ApiError && cause.status === 401 && cause.code !== 'missing_csrf') {
				openLogin(currentLocation());
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
			if (cause instanceof ApiError && cause.status === 401 && cause.code !== 'missing_csrf') {
				openLogin(currentLocation());
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
					return copy.errors.checkFailed;
				case 404:
					return copy.errors.authorizationGone;
				default:
					return cause.message;
			}
		}
		return copy.errors.fallback;
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
				return copy.account.bindingStatus.active;
			case 'pending':
				return copy.account.bindingStatus.pending;
			case 'needs_reauth':
				return copy.account.bindingStatus.needsReauth;
			default:
				return { label: status, hint: '' };
		}
	}
</script>

<PortalLayout>
	<header class="account-header">
		<div>
			<h1 class="auth-title">{copy.account.title}</h1>
			<p class="auth-subtitle">
				{me ? copy.account.subtitle(me.user.display_name) : copy.account.subtitleFallback}
			</p>
		</div>
		{#if me}
			<Button
				variant="outline"
				class="h-9 shrink-0 rounded-sm px-3 text-sm"
				type="button"
				disabled={loggingOut}
				onclick={logoutAll}
			>
				<LogOut size={15} aria-hidden="true" />
				{copy.account.logoutAll}
			</Button>
		{/if}
	</header>

	{#if justLoggedIn && me}
		<Alert class="mt-4 rounded-md">
			<ShieldCheck />
			<AlertDescription>{copy.account.loggedIn}</AlertDescription>
		</Alert>
	{/if}

	{#if loading}
		<p class="meta">{copy.account.loading}</p>
	{:else if error && !me}
		<Alert variant="destructive" class="mt-4 rounded-md">
			<AlertCircle />
			<AlertDescription>{error}</AlertDescription>
		</Alert>
	{:else if authorizations.length === 0}
		<p class="meta">{copy.account.noAuthorizations}</p>
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
						<p class="meta">{copy.account.lastAuthorized(formatDate(authorization.updated_at))}</p>
					</div>
					<Button
						variant="outline"
						class="h-9 shrink-0 rounded-sm px-3 text-sm text-fg-2 hover:border-danger/40 hover:text-danger"
						type="button"
						disabled={revoking === authorization.client_id}
						aria-label={copy.account.revokeLabel(authorization.client_name)}
						onclick={() => revoke(authorization.client_id)}
					>
						{copy.account.revoke}
					</Button>
				</article>
			{/each}
		</div>
	{/if}

	{#if error && me}
		<Alert variant="destructive" class="mt-4 rounded-md">
			<AlertCircle />
			<AlertDescription>{error}</AlertDescription>
		</Alert>
	{/if}

	<section class="bindings">
		<h2 class="section-title">{copy.account.bindingsTitle}</h2>
		{#if bindings.length === 0}
			<p class="meta">{copy.account.noBindings}</p>
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
									· {copy.account.lastRefreshed(formatDate(binding.last_refreshed_at))}{/if}
							</p>
							{#if state.hint}
								<p class="meta">{state.hint}</p>
							{/if}
						</div>
						<Button
							variant="outline"
							class="h-9 shrink-0 rounded-sm px-3 text-sm text-fg-2 hover:border-danger/40 hover:text-danger"
							type="button"
							disabled={unbinding === binding.id}
							aria-label={copy.account.unbindLabel(binding.connector)}
							onclick={() => unlink(binding.id)}
						>
							{copy.account.unbind}
						</Button>
					</article>
				{/each}
			</div>
		{/if}
		{#if bindings.length > 0}
			<div class="auth-actions">
				<Button
					variant="outline"
					class="h-11 w-full rounded-sm text-fg-2 hover:border-danger/40 hover:text-danger"
					type="button"
					disabled={unbindingAll}
					onclick={unlinkAll}
				>
					<Unlink size={16} aria-hidden="true" />
					{copy.account.unbindAll}
				</Button>
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
							<p class="meta">{copy.account.notConnected}</p>
						</div>
						<Button
							variant="outline"
							class="h-9 shrink-0 rounded-sm px-3 text-sm"
							type="button"
							disabled={connecting === upstream}
							aria-label={copy.account.connectLabel(upstream)}
							onclick={() => connect(upstream)}
						>
							<Plus size={15} aria-hidden="true" />
							{copy.account.connect}
						</Button>
					</article>
				{/each}
			</div>
		{/if}
	</section>

	<p class="meta"><a href="/">{copy.account.backHome}</a></p>
</PortalLayout>
