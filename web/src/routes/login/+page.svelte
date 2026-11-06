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
			error = '无法读取登录方式，请稍后重试。';
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
	title="登录 Re0Auth"
	subtitle="通过外部身份提供商完成登录"
>
	{#if loading}
		<p class="meta">正在读取登录方式…</p>
	{:else if error}
		<Alert variant="destructive" class="mb-6 rounded-md">
			<AlertDescription>{error}</AlertDescription>
		</Alert>
		<div class="auth-actions">
			<Button class="h-11 w-full rounded-sm" type="button" onclick={loadProviders}>重试</Button>
		</div>
	{:else if providers.length === 0}
		<p class="meta">当前未配置登录方式，请联系站点管理员。</p>
	{:else if providers.length === 1}
		<div class="auth-actions">
			{#each providers as provider (provider.name)}
				<Button
					class="h-11 w-full rounded-sm"
					type="button"
					onclick={() => login(provider.name)}
				>
					继续登录
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
		登录过程会离开 Re0Auth，由外部 IdP 完成身份校验。
	</p>
	<p class="meta">
		首次登录会创建一个新账号。已经用过其他登录方式的，请继续用同一种，否则会得到两个互不相通的账号。
	</p>
</AuthLayout>
