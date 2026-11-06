<script lang="ts">
	import { onMount } from 'svelte';
	import { ArrowRight, KeyRound, Link2, ShieldCheck, Unplug } from 'lucide-svelte';
	import SiteLayout from '#lib/components/layouts/SiteLayout.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { ApiError, apiGet, meSchema, openLogin, type Me } from '#lib/api.ts';

	let me = $state<Me | null>(null);
	let checked = $state(false);

	onMount(async () => {
		try {
			me = await apiGet('/api/me', meSchema);
		} catch (cause) {
			// 401 is the ordinary "not signed in" case, not an error to report.
			if (!(cause instanceof ApiError && cause.status === 401)) {
				console.error(cause);
			}
		} finally {
			checked = true;
		}
	});

	function login(): void {
		openLogin('/account');
	}

	const features = [
		{
			icon: Link2,
			title: '单点登录',
			body: '一次登录，即可适用于所有接入 Re0Auth 的下游应用，无需重复授权。'
		},
		{
			icon: ShieldCheck,
			title: '凭据隔离',
			body: '借助 OAuth2.0 等协议，Re0Auth 统一管理上游的访问凭证，不直接接触用户账号和密码。'
		},
		{
			icon: Unplug,
			title: '统一心智',
			body: '玩家减少多次重复登录，下游减少多次重复适配。'
		}
	];

	const steps = [
		{ n: '01', title: '登录', body: '通过外部身份提供商（GitHub 等）完成登录。' },
		{ n: '02', title: '绑定游戏账号', body: '连接上游游戏数据源，由其代为获取数据。' },
		{ n: '03', title: '确认授权', body: '下游应用请求数据时，逐项确认权限范围。' },
		{ n: '04', title: '撤销授权', body: '在账号页撤销单个应用，或一次性解除全部绑定。' }
	];
</script>

<SiteLayout>
	<section class="mx-auto max-w-3xl text-center">
		<h1 class="text-4xl font-semibold tracking-tight text-balance sm:text-5xl">
			一次登录，随时查分
		</h1>
		<p class="mx-auto mt-5 max-w-2xl text-base leading-relaxed text-fg-2 sm:text-lg">
			音游数据的身份与授权层，为玩家和下游提供简单、方便、统一的授权服务
		</p>
		<div class="mt-8 flex flex-col items-center justify-center gap-3 sm:flex-row">
			{#if checked && me}
				<Button class="h-11 rounded-sm px-6" href="/account">
					进入账号与授权
					<ArrowRight size={16} aria-hidden="true" />
				</Button>
			{:else}
				<Button class="h-11 rounded-sm px-6" type="button" onclick={login}>
					登录
					<ArrowRight size={16} aria-hidden="true" />
				</Button>
			{/if}
			<Button variant="outline" class="h-11 rounded-sm px-6" href="/device">
				<KeyRound size={16} aria-hidden="true" />
				批准设备
			</Button>
		</div>
		{#if checked && me}
			<p class="mt-4 text-sm text-fg-3">已登录：{me.user.display_name}</p>
		{/if}
	</section>

	<section class="mt-20 grid gap-4 sm:mt-24 sm:grid-cols-3">
		{#each features as feature (feature.title)}
			{@const Icon = feature.icon}
			<div class="rounded-md border border-border bg-surface p-5">
				<Icon size={20} strokeWidth={1.7} class="text-fg-3" aria-hidden="true" />
				<h2 class="mt-4 text-base font-semibold">{feature.title}</h2>
				<p class="mt-2 text-sm leading-relaxed text-fg-2">{feature.body}</p>
			</div>
		{/each}
	</section>

	<section class="mt-20 sm:mt-24">
		<h2 class="text-2xl font-semibold tracking-tight">工作流程</h2>
		<div class="mt-6 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
			{#each steps as step (step.n)}
				<div>
					<div class="font-mono text-sm text-fg-3">{step.n}</div>
					<h3 class="mt-2 text-base font-semibold">{step.title}</h3>
					<p class="mt-1.5 text-sm leading-relaxed text-fg-2">{step.body}</p>
				</div>
			{/each}
		</div>
	</section>
</SiteLayout>
