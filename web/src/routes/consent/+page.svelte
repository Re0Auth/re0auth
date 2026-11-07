<script lang="ts">
	import { onMount } from 'svelte';
	import { AlertCircle, Check, ShieldCheck, X } from 'lucide-svelte';
	import AuthLayout from '#lib/components/layouts/AuthLayout.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import {
		ApiError,
		apiGet,
		apiPost,
		bindingStartSchema,
		consentResultSchema,
		currentLocation,
		openLogin,
		pendingSchema,
		readQuery,
		type PendingConsent
	} from '#lib/api.ts';
	import { scopeDescription } from '#lib/scopes.ts';
	import { copy } from '#lib/copy.ts';

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
			error = copy.consent.missingRequest;
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
			if (cause instanceof ApiError && cause.status === 401 && cause.code !== 'missing_csrf') {
				openLogin(currentLocation());
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
					return copy.consent.sessionExpired;
				case 403:
					return copy.errors.checkFailed;
				case 404:
					return copy.consent.requestNotFound;
				default:
					return cause.message;
			}
		}
		return copy.consent.fallback;
	}

	function scopeLabel(scope: string): string {
		return scopeDescription(scope);
	}
</script>

<AuthLayout
	title={copy.consent.title}
	subtitle={pending ? copy.consent.subtitle(clientName) : copy.consent.loadingRequest}
>
	{#if loading}
		<p class="meta">{copy.consent.loading}</p>
	{:else if pending}
		<ul class="scope-list" aria-label={copy.consent.scopeList}>
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
			<Alert class="mt-4 rounded-md" role="status">
				<AlertCircle />
				<AlertDescription>
					<p>
						{copy.consent.missingLead}
						<strong>{pending.missing_bindings.map((item) => item.upstream_id).join('、')}</strong>。
					</p>
					<div class="auth-actions">
						{#each pending.missing_bindings as missing (missing.upstream_id)}
							<Button
								variant="outline"
								class="h-11 w-full rounded-sm"
								type="button"
								disabled={connecting === missing.upstream_id}
								onclick={() => connect(missing.upstream_id)}
							>
								<ShieldCheck size={16} aria-hidden="true" />
								{copy.consent.connect(missing.upstream_id)}
							</Button>
						{/each}
					</div>
					<p class="meta">
						{copy.consent.missingNote}
					</p>
				</AlertDescription>
			</Alert>
		{/if}
		<p class="meta">
			{copy.consent.redirectLead} <code>{redirectHost}</code>{copy.consent.redirectDue} <code>{expiresAt}</code> {copy.consent.redirectExpire}
		</p>
		<div class="auth-actions">
			<Button class="h-11 w-full rounded-sm" type="button" disabled={submitting} onclick={() => decide('approve')}>
				<Check size={16} aria-hidden="true" />
				{copy.consent.approve}
			</Button>
			<Button
				variant="outline"
				class="h-11 w-full rounded-sm"
				type="button"
				disabled={submitting}
				onclick={() => decide('deny')}
			>
				<X size={16} aria-hidden="true" />
				{copy.consent.deny}
			</Button>
		</div>
	{/if}

	{#if error}
		<Alert variant="destructive" class="mt-4 rounded-md">
			<AlertCircle />
			<AlertDescription>{error}</AlertDescription>
		</Alert>
	{/if}
</AuthLayout>
