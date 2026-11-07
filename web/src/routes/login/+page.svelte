<script lang="ts">
	import { onMount } from 'svelte';
	import { ArrowRight, ExternalLink, KeyRound } from 'lucide-svelte';
	import AuthLayout from '#lib/components/layouts/AuthLayout.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import {
		fetchProviders,
		readQuery,
		startLogin,
		withLoginFlag,
		type Provider
	} from '#lib/api.ts';
	import { copy } from '#lib/copy.ts';

	let returnTo = $state('/account');
	let providers = $state<Provider[]>([]);
	let loading = $state(true);
	let error = $state('');

	onMount(async () => {
		returnTo = readQuery('return_to') || '/account';
		await loadProviders();
	});

	async function loadProviders(): Promise<void> {
		loading = true;
		error = '';
		try {
			providers = await fetchProviders();
		} catch {
			error = copy.login.providersUnavailable;
		} finally {
			loading = false;
		}
	}

	function login(idp: string): void {
		// The flag rides inside return_to so it survives the IdP round trip.
		startLogin(withLoginFlag(returnTo), idp);
	}
</script>

<AuthLayout
	title={copy.login.title}
	subtitle={copy.login.subtitle}
>
	{#if loading}
		<p class="meta">{copy.login.loading}</p>
	{:else if error}
		<Alert variant="destructive" class="mb-6 rounded-md">
			<AlertDescription>{error}</AlertDescription>
		</Alert>
		<div class="auth-actions">
			<Button class="h-11 w-full rounded-sm" type="button" onclick={loadProviders}>{copy.common.retry}</Button>
		</div>
	{:else if providers.length === 0}
		<p class="meta">{copy.login.noProviders}</p>
	{:else if providers.length === 1}
		<div class="auth-actions">
			{#each providers as provider (provider.name)}
				<Button
					class="h-11 w-full rounded-sm"
					type="button"
					onclick={() => login(provider.name)}
				>
					{copy.login.continueWith}
					<ArrowRight size={16} aria-hidden="true" />
				</Button>
			{/each}
		</div>
	{:else}
		<div class="mt-6 divide-y divide-border overflow-hidden rounded-md border border-border bg-surface">
			{#each providers as provider (provider.name)}
				<button
					class="flex w-full items-center justify-between gap-3 px-4 py-3 text-left text-sm transition-colors hover:bg-hover"
					type="button"
					onclick={() => login(provider.name)}
				>
					<span class="flex items-center gap-2.5">
						<KeyRound size={15} strokeWidth={1.8} class="text-fg-3" aria-hidden="true" />
						<span>{provider.display_name}</span>
					</span>
					<ArrowRight size={15} class="text-fg-3" aria-hidden="true" />
				</button>
			{/each}
		</div>
	{/if}
	<p class="meta">
		<ExternalLink size={13} aria-hidden="true" />
		{copy.login.leaving}
	</p>
	<p class="meta">
		{copy.login.firstTime}
	</p>
</AuthLayout>
