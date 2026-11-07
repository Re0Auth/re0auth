<script lang="ts">
	import { KeyRound } from 'lucide-svelte';
	import { copy } from '#lib/copy.ts';
</script>

<footer class="border-t border-border">
	<div
		class="mx-auto flex max-w-5xl flex-col gap-4 px-4 py-8 text-sm text-fg-3 sm:flex-row sm:items-center sm:justify-between"
	>
		<div class="flex items-center gap-2">
			<KeyRound size={14} strokeWidth={1.8} aria-hidden="true" />
			<span>{copy.site.footer}</span>
		</div>
		<div class="flex gap-4">
			<a class="transition-colors hover:text-fg" href="/about">{copy.site.nav.about}</a>
			<a class="transition-colors hover:text-fg" href="/device">{copy.site.nav.device}</a>
			<a class="transition-colors hover:text-fg" href="/login">{copy.site.nav.login}</a>
		</div>
	</div>
</footer>
