<script lang="ts">
	import type { Snippet } from 'svelte';
	import SiteLayout from './SiteLayout.svelte';

	let {
		title,
		intro = '',
		children
	}: { title: string; intro?: string; children: Snippet } = $props();
</script>

<SiteLayout width="narrow">
	<h1 class="text-3xl font-semibold tracking-tight">{title}</h1>
	{#if intro}
		<p class="mt-3 text-base leading-relaxed text-fg-2">{intro}</p>
	{/if}
	<article class="prose mt-8">
		{@render children()}
	</article>
</SiteLayout>
