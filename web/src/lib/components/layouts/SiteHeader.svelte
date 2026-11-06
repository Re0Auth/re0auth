<script lang="ts">
	import { onMount } from 'svelte';
	import { KeyRound, Menu, Monitor, Moon, Sun, X } from 'lucide-svelte';
	import { apiGet, meSchema, type Me } from '#lib/api.ts';

	type ThemeMode = 'light' | 'dark' | 'system';

	let me = $state<Me | null>(null);
	let open = $state(false);
	let mode = $state<ThemeMode>('system');

	onMount(async () => {
		mode = (document.documentElement.dataset.themeMode as ThemeMode) ?? 'system';
		try {
			me = await apiGet('/api/me', meSchema);
		} catch {
			me = null;
		}
	});

	const themeOrder: ThemeMode[] = ['light', 'dark', 'system'];
	const themeLabel: Record<ThemeMode, string> = {
		light: '当前亮色，点击切换到暗色',
		dark: '当前暗色，点击切换到跟随系统',
		system: '当前跟随系统，点击切换到亮色'
	};

	function applyTheme(next: ThemeMode): void {
		const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
		const resolved = next === 'system' ? (prefersDark ? 'dark' : 'light') : next;
		document.documentElement.dataset.themeMode = next;
		document.documentElement.dataset.theme = resolved;
	}

	function cycleTheme(): void {
		const next = themeOrder[(themeOrder.indexOf(mode) + 1) % themeOrder.length] ?? 'system';
		mode = next;
		localStorage.setItem('theme', next);
		applyTheme(next);
	}
</script>

<header class="sticky top-0 z-50 border-b border-border bg-bg/80 backdrop-blur-md">
	<nav class="mx-auto flex h-14 max-w-5xl items-center justify-between px-4">
		<a href="/" class="flex items-center gap-2 text-sm font-semibold text-fg">
			<KeyRound size={16} strokeWidth={1.8} aria-hidden="true" />
			Re0Auth
		</a>

		<div class="flex items-center gap-1">
			<div class="hidden items-center gap-1 sm:flex">
				<a class="rounded-sm px-3 py-1.5 text-sm text-fg-2 transition-colors hover:bg-hover hover:text-fg" href="/about">关于</a>
				<a class="rounded-sm px-3 py-1.5 text-sm text-fg-2 transition-colors hover:bg-hover hover:text-fg" href="/device">批准设备</a>
				{#if me}
					<a class="rounded-sm px-3 py-1.5 text-sm text-fg-2 transition-colors hover:bg-hover hover:text-fg" href="/account">账号与授权</a>
				{:else}
					<a class="rounded-sm px-3 py-1.5 text-sm text-fg-2 transition-colors hover:bg-hover hover:text-fg" href="/login">登录</a>
				{/if}
			</div>

			<button
				class="rounded-sm p-1.5 text-fg-2 transition-colors hover:bg-hover hover:text-fg"
				type="button"
				aria-label={themeLabel[mode]}
				onclick={cycleTheme}
			>
				{#if mode === 'light'}
					<Sun size={17} aria-hidden="true" />
				{:else if mode === 'dark'}
					<Moon size={17} aria-hidden="true" />
				{:else}
					<Monitor size={17} aria-hidden="true" />
				{/if}
			</button>

			<button
				class="rounded-sm p-1.5 text-fg-2 transition-colors hover:bg-hover hover:text-fg sm:hidden"
				type="button"
				aria-label="菜单"
				aria-expanded={open}
				onclick={() => (open = !open)}
			>
				{#if open}<X size={18} aria-hidden="true" />{:else}<Menu size={18} aria-hidden="true" />{/if}
			</button>
		</div>
	</nav>

	{#if open}
		<div class="border-t border-border px-4 py-2 sm:hidden">
			<a class="block rounded-sm px-2 py-2 text-sm text-fg-2 hover:bg-hover hover:text-fg" href="/about">关于</a>
			<a class="block rounded-sm px-2 py-2 text-sm text-fg-2 hover:bg-hover hover:text-fg" href="/device">批准设备</a>
			{#if me}
				<a class="block rounded-sm px-2 py-2 text-sm text-fg-2 hover:bg-hover hover:text-fg" href="/account">账号与授权</a>
			{:else}
				<a class="block rounded-sm px-2 py-2 text-sm text-fg-2 hover:bg-hover hover:text-fg" href="/login">登录</a>
			{/if}
		</div>
	{/if}
</header>
