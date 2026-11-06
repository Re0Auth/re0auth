<script lang="ts">
	import type { Snippet } from 'svelte';
	import SiteFooter from './SiteFooter.svelte';
	import SiteHeader from './SiteHeader.svelte';

	let {
		width = 'default',
		children
	}: { width?: 'narrow' | 'default'; children: Snippet } = $props();

	const container = $derived(width === 'narrow' ? 'max-w-3xl' : 'max-w-5xl');
</script>

<div class="flex min-h-dvh flex-col bg-bg text-fg">
	<SiteHeader />
	<main class="flex-1">
		<div class="mx-auto {container} px-4 py-12 sm:py-16">
			{@render children()}
		</div>
	</main>
	<SiteFooter />
</div>
