<script lang="ts">
	import type { Snippet } from 'svelte';
	import SiteLayout from './SiteLayout.svelte';

	let { children }: { children: Snippet } = $props();
</script>

<SiteLayout>
	<div class="rounded-md border border-border bg-surface p-6 sm:p-8">
		{@render children()}
	</div>
</SiteLayout>
