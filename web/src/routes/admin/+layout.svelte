<script lang="ts">
	import { onMount } from 'svelte';
	import type { Snippet } from 'svelte';
	import SiteLayout from '#lib/components/layouts/SiteLayout.svelte';
	import { Alert, AlertDescription } from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { ApiError, apiGet, currentLocation, meSchema, openLogin } from '#lib/api.ts';
	import { copy } from '#lib/copy.ts';

	let { children }: { children: Snippet } = $props();

	// 只做展示层放行；每条管理接口仍由服务端按 401/403 判定。
	let state = $state<'checking' | 'ready' | 'forbidden' | 'login' | 'error'>('checking');

	onMount(async () => {
		try {
			const me = await apiGet('/api/me', meSchema);
			state = me.user.role === 'admin' ? 'ready' : 'forbidden';
		} catch (cause) {
			state = cause instanceof ApiError && cause.status === 401 ? 'login' : 'error';
		}
	});

	const sections = [
		{ href: '/admin', label: copy.admin.nav.overview },
		{ href: '/admin/clients', label: copy.admin.nav.clients },
		{ href: '/admin/users', label: copy.admin.nav.users },
		{ href: '/admin/bindings', label: copy.admin.nav.bindings },
		{ href: '/admin/audit', label: copy.admin.nav.audit },
		{ href: '/admin/connectors', label: copy.admin.nav.connectors }
	];
</script>

<SiteLayout>
	<h1 class="text-2xl font-semibold tracking-tight">{copy.admin.title}</h1>

	{#if state === 'checking'}
		<p class="meta mt-4">{copy.admin.checking}</p>
	{:else if state === 'login'}
		<h2 class="mt-6 text-lg font-semibold">{copy.admin.loginTitle}</h2>
		<Alert class="mt-4 rounded-md">
			<AlertDescription>{copy.admin.loginBody}</AlertDescription>
		</Alert>
		<div class="auth-actions mt-4">
			<Button type="button" onclick={() => openLogin(currentLocation())}>
				{copy.admin.loginAction}
			</Button>
		</div>
	{:else if state === 'forbidden'}
		<h2 class="mt-6 text-lg font-semibold">{copy.admin.forbiddenTitle}</h2>
		<Alert variant="destructive" class="mt-4 rounded-md">
			<AlertDescription>{copy.admin.forbiddenBody}</AlertDescription>
		</Alert>
	{:else if state === 'error'}
		<Alert variant="destructive" class="mt-4 rounded-md">
			<AlertDescription>{copy.admin.loadFailed}</AlertDescription>
		</Alert>
	{:else}
		<nav class="mt-4 flex flex-wrap gap-1 border-b border-border pb-2">
			{#each sections as section (section.href)}
				<a
					class="rounded-sm px-3 py-1.5 text-sm text-fg-2 transition-colors hover:bg-hover hover:text-fg"
					href={section.href}>{section.label}</a
				>
			{/each}
		</nav>
		<div class="mt-6">
			{@render children()}
		</div>
	{/if}
</SiteLayout>
