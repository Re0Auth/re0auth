<script lang="ts">
	import { onMount } from 'svelte';
	import { KeyRound, Menu, Monitor, Moon, Sun, X } from 'lucide-svelte';
	import { apiGet, meSchema, type Me } from '#lib/api.ts';
	import { copy } from '#lib/copy.ts';

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
		light: copy.site.theme.light,
		dark: copy.site.theme.dark,
		system: copy.site.theme.system
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
			{copy.site.name}
		</a>

		<div class="flex items-center gap-1">
			<div class="hidden items-center gap-1 sm:flex">
				<a class="rounded-sm px-3 py-1.5 text-sm text-fg-2 transition-colors hover:bg-hover hover:text-fg" href="/about">{copy.site.nav.about}</a>
				<a class="rounded-sm px-3 py-1.5 text-sm text-fg-2 transition-colors hover:bg-hover hover:text-fg" href="/device">{copy.site.nav.device}</a>
				{#if me}
					<a class="rounded-sm px-3 py-1.5 text-sm text-fg-2 transition-colors hover:bg-hover hover:text-fg" href="/account">{copy.site.nav.account}</a>
					{#if me.user.role === 'admin'}
						<a class="rounded-sm px-3 py-1.5 text-sm text-fg-2 transition-colors hover:bg-hover hover:text-fg" href="/admin">{copy.site.nav.admin}</a>
					{/if}
				{:else}
					<a class="rounded-sm px-3 py-1.5 text-sm text-fg-2 transition-colors hover:bg-hover hover:text-fg" href="/login">{copy.site.nav.login}</a>
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
				aria-label={copy.site.nav.menu}
				aria-expanded={open}
				onclick={() => (open = !open)}
			>
				{#if open}<X size={18} aria-hidden="true" />{:else}<Menu size={18} aria-hidden="true" />{/if}
			</button>
		</div>
	</nav>

	{#if open}
		<div class="border-t border-border px-4 py-2 sm:hidden">
			<a class="block rounded-sm px-2 py-2 text-sm text-fg-2 hover:bg-hover hover:text-fg" href="/about">{copy.site.nav.about}</a>
			<a class="block rounded-sm px-2 py-2 text-sm text-fg-2 hover:bg-hover hover:text-fg" href="/device">{copy.site.nav.device}</a>
			{#if me}
				<a class="block rounded-sm px-2 py-2 text-sm text-fg-2 hover:bg-hover hover:text-fg" href="/account">{copy.site.nav.account}</a>
				{#if me.user.role === 'admin'}
					<a class="block rounded-sm px-2 py-2 text-sm text-fg-2 hover:bg-hover hover:text-fg" href="/admin">{copy.site.nav.admin}</a>
				{/if}
			{:else}
				<a class="block rounded-sm px-2 py-2 text-sm text-fg-2 hover:bg-hover hover:text-fg" href="/login">{copy.site.nav.login}</a>
			{/if}
		</div>
	{/if}
</header>
