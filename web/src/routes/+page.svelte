<script lang="ts">
	import { onMount } from 'svelte';
	import { ArrowRight, KeyRound, ShieldCheck } from 'lucide-svelte';
	import AuthShell from '#lib/components/AuthShell.svelte';
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
</script>

<AuthShell
	title="Re0Auth"
	subtitle="音游数据的身份与委托授权层。选择一个入口继续。"
>
	{#if !checked}
		<p class="meta">正在确认登录状态…</p>
	{:else if me}
		<div class="notice">
			<ShieldCheck size={16} aria-hidden="true" />
			<span>已登录：{me.user.display_name}</span>
		</div>
		<div class="auth-actions">
			<a class="btn-primary" href="/account">
				账号与授权
				<ArrowRight size={16} aria-hidden="true" />
			</a>
			<a class="btn-secondary" href="/device">
				<KeyRound size={16} aria-hidden="true" />
				批准设备
			</a>
		</div>
	{:else}
		<div class="auth-actions">
			<button class="btn-primary" type="button" onclick={login}>
				登录
				<ArrowRight size={16} aria-hidden="true" />
			</button>
			<a class="btn-secondary" href="/device">
				<KeyRound size={16} aria-hidden="true" />
				批准设备
			</a>
		</div>
	{/if}
	<p class="meta">登录由外部身份提供商处理，Re0Auth 不保存密码。</p>
	<p class="meta"><a href="/about">这个实例由谁运营、能碰到什么</a></p>
</AuthShell>
