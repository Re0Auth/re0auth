<script lang="ts">
	import { onMount } from 'svelte';
	import { ArrowRight, ExternalLink } from 'lucide-svelte';
	import AuthShell from '#lib/components/AuthShell.svelte';
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

<AuthShell
	title="登录 Re0Auth"
	subtitle="使用外部身份提供商完成登录。Re0Auth 不保存你的密码。"
>
	{#if loading}
		<p class="meta">正在读取登录方式…</p>
	{:else if error}
		<div class="alert" role="alert">
			<span>{error}</span>
		</div>
		<div class="auth-actions">
			<button class="btn-primary" type="button" onclick={loadProviders}>重试</button>
		</div>
	{:else if providers.length === 0}
		<p class="meta">当前未配置登录方式，请联系站点管理员。</p>
	{:else}
		<div class="auth-actions">
			{#each providers as provider (provider.name)}
				<button class="btn-primary" type="button" onclick={() => login(provider.name)}>
					{providers.length === 1 ? '继续登录' : `使用 ${provider.display_name} 登录`}
					<ArrowRight size={16} aria-hidden="true" />
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
</AuthShell>
