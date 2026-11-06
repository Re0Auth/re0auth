<script lang="ts">
	import { KeyRound } from 'lucide-svelte';
	import type { Snippet } from 'svelte';

	let {
		title,
		subtitle = '',
		children
	}: { title: string; subtitle?: string; children: Snippet } = $props();
</script>

<div class="auth-page">
	<main class="auth-card">
		<div class="brand">
			<KeyRound size={16} strokeWidth={1.8} aria-hidden="true" />
			<span>Re0Auth</span>
		</div>
		<h1 class="auth-title">{title}</h1>
		{#if subtitle}
			<p class="auth-subtitle">{subtitle}</p>
		{/if}
		{@render children()}
	</main>
</div>
