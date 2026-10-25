<script lang="ts">
	import { KeyRound } from 'lucide-svelte';
	import type { Snippet } from 'svelte';

	let { children }: { children: Snippet } = $props();
</script>

<div class="auth-page">
	<main class="account-card">
		<div class="brand">
			<KeyRound size={16} strokeWidth={1.8} aria-hidden="true" />
			<span>Re0Auth</span>
		</div>
		{@render children()}
	</main>
</div>
